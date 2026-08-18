//! Every operation the UI can trigger.
//!
//! Guards from `parking_lot` are deliberately scoped inside blocks: an async
//! command that held one across `.await` would not be `Send`, and would also
//! stall the core supervisor for the duration of a network round-trip.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager};

use crate::core::clash::ClashApi;
use crate::core::config::{self, BuildInput, TAG_PROXY};
use crate::core::process::LogLine;
use crate::core::{ruleset, xray};
use crate::error::{AppError, Result};
use crate::link;
use crate::model::ServerNode;
use crate::settings::{Settings, SplitConfig, Subscription, TunnelMode};
use crate::state::{AppState, ConnState, Status, Traffic};
use crate::sys::autostart::{self, AutostartMode};
use crate::sys::{elevate, procs, sysproxy};

pub const EVT_STATUS: &str = "app://status";
pub const EVT_TRAFFIC: &str = "app://traffic";
pub const EVT_LOG: &str = "app://log";
pub const EVT_NODES: &str = "app://nodes";
pub const EVT_SUBS: &str = "app://subscriptions";
pub const EVT_LATENCY: &str = "app://latency";

// ---------------------------------------------------------------- payloads

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    settings: Settings,
    nodes: Vec<ServerNode>,
    subscriptions: Vec<Subscription>,
    split: SplitConfig,
    status: Status,
    traffic: Traffic,
    latency: HashMap<String, Option<u32>>,
    active_id: String,
    core_version: String,
    /// Read back from the OS, not from settings — the user may have removed the
    /// registry value or the scheduled task behind our back.
    autostart: AutostartMode,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub added: usize,
    pub skipped: usize,
    /// `(source line, reason)` pairs so the user can see *why* a node was dropped.
    pub errors: Vec<(String, String)>,
}

// ---------------------------------------------------------------- helpers

pub fn emit_status(app: &AppHandle) {
    let state = app.state::<AppState>();
    let status = state.status.read().clone();
    let _ = app.emit(EVT_STATUS, status);
}

fn set_status(app: &AppHandle, mutate: impl FnOnce(&mut Status)) {
    {
        let state = app.state::<AppState>();
        let mut status = state.status.write();
        mutate(&mut status);
    }
    emit_status(app);
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// The core logs why it is unhappy before it exits; surface that instead of a
/// generic failure the user cannot act on.
fn core_error_line(app: &AppHandle) -> Option<String> {
    let state = app.state::<AppState>();
    let core = state.core.lock();
    let logs = core.logs.lock();
    logs.snapshot()
        .iter()
        .rev()
        .find(|line| matches!(line.level.as_str(), "fatal" | "error" | "panic"))
        .map(|line| line.text.clone())
}

/// The node list with the runtime engine decisions applied.
///
/// A node whose VLESS Encryption the server was probed to reject is carried by
/// sing-box with the layer dropped — classic VLESS is what that server speaks.
/// The demotion is keyed to the exact `encryption` value that failed, so a
/// refreshed link with a new value goes back to Xray and is probed again.
fn effective_nodes(state: &AppState) -> Vec<ServerNode> {
    let overrides = state.engine_overrides.read();
    state
        .nodes
        .read()
        .iter()
        .cloned()
        .map(|mut node| {
            if overrides.get(&node.id) == Some(&node.encryption) {
                node.encryption = "none".into();
            }
            node
        })
        .collect()
}

/// Start the Xray engine if any node needs it, and report the loopback ports it
/// listens on. Returns an empty map when sing-box can handle everything.
fn start_xray_if_needed(app: &AppHandle) -> Result<HashMap<String, u16>> {
    let (nodes, log_level) = {
        let state = app.state::<AppState>();
        let nodes = effective_nodes(&state);
        let level = state.settings.read().log_level.clone();
        (nodes, level)
    };

    if !nodes.iter().any(|n| n.needs_xray()) {
        let state = app.state::<AppState>();
        if let Some(engine) = state.xray.lock().as_mut() {
            engine.stop();
        }
        state.xray_ports.write().clear();
        return Ok(HashMap::new());
    }

    let built = xray::build(&nodes, xray::DEFAULT_BASE_PORT, xray::log_level(&log_level))?
        .expect("at least one node needs xray");

    let state = app.state::<AppState>();
    let config_path = state.paths.xray_config.clone();
    std::fs::write(&config_path, serde_json::to_vec_pretty(&built.json)?)?;

    let mut guard = state.xray.lock();
    let engine = guard.as_mut().ok_or_else(|| {
        AppError::msg(
            "часть серверов требует движка Xray, но его бинарник не найден — \
             выполните npm run fetch-core или переустановите приложение",
        )
    })?;

    engine.stop();
    let log_app = app.clone();
    engine.start(&config_path, move |line: LogLine| {
        // Tag the source: two engines share one log view.
        let _ = log_app.emit(
            EVT_LOG,
            LogLine {
                text: format!("xray: {}", line.text),
                ..line
            },
        );
    })?;

    *state.xray_ports.write() = built.ports.clone();
    Ok(built.ports)
}

/// Geo sets already on disk, without touching the network.
fn cached_rule_sets(dir: &std::path::Path, split: &SplitConfig) -> HashSet<String> {
    required_rule_sets(split)
        .into_iter()
        .filter(|spec| ruleset::path_for(dir, &spec.tag).is_file())
        .map(|spec| spec.tag)
        .collect()
}

/// Which geo sets the current rules ask for.
fn required_rule_sets(split: &SplitConfig) -> Vec<ruleset::Spec> {
    let mut tags: Vec<&str> = Vec::new();
    if split.block_ads {
        tags.push("geosite-ads");
    }
    if split.bypass_ru {
        tags.extend(["geosite-ru", "geoip-ru"]);
    }
    if split.bypass_cn {
        tags.extend(["geosite-cn", "geoip-cn"]);
    }
    tags.into_iter().filter_map(ruleset::spec).collect()
}

/// Render the current model into a sing-box document and remember the tag map.
fn build_and_write(
    state: &AppState,
    xray_ports: &HashMap<String, u16>,
    rule_sets: &HashSet<String>,
) -> Result<Value> {
    let nodes = effective_nodes(state);
    let settings = state.settings.read().clone();
    let split = state.split.read().clone();
    let active_id = state.resolve_active_id();
    let xray_exe = state.xray.lock().as_ref().map(|e| e.exe().to_path_buf());

    let built = config::build(&BuildInput {
        nodes: &nodes,
        active_id: &active_id,
        settings: &settings,
        split: &split,
        clash_secret: &state.secret,
        cache_path: &state.paths.cache_file,
        xray_ports,
        xray_exe: xray_exe.as_deref(),
        rule_sets,
        rule_set_dir: &state.paths.rule_set_dir,
    })?;

    *state.tags.write() = built.tags.iter().cloned().collect();

    std::fs::create_dir_all(&state.paths.work_dir)?;
    std::fs::write(
        &state.paths.config_file,
        serde_json::to_vec_pretty(&built.json)?,
    )?;
    Ok(built.json)
}

/// Sample the counters once a second and turn them into a rate.
fn spawn_traffic_poller(app: AppHandle, session: u64) {
    tauri::async_runtime::spawn(async move {
        let mut previous: Option<(u64, u64, Instant)> = None;
        let mut failures: u32 = 0;

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let (api, still_ours) = {
                let state = app.state::<AppState>();
                let ours = state.session.load(Ordering::SeqCst) == session
                    && state.status.read().state == ConnState::Connected;
                let api = state.clash.read().clone();
                (api, ours)
            };
            if !still_ours {
                return;
            }
            let Some(api) = api else { return };

            let totals = match api.totals().await {
                Ok(totals) => {
                    failures = 0;
                    totals
                }
                Err(_) => {
                    // A single miss is usually just a busy core. A run of them
                    // means the process is gone — otherwise the UI would keep
                    // claiming "Подключено" over a dead tunnel.
                    failures += 1;
                    if failures >= 5 {
                        let dead = {
                            let state = app.state::<AppState>();
                            let mut core = state.core.lock();
                            !core.is_running()
                        };
                        if dead {
                            let reason = core_error_line(&app).unwrap_or_else(|| {
                                "ядро неожиданно завершилось — подробности в журнале".into()
                            });
                            shutdown(&app, &reason);
                            return;
                        }
                        failures = 0;
                    }
                    continue;
                }
            };

            let now = Instant::now();
            let (up_speed, down_speed) = match previous {
                Some((prev_up, prev_down, at)) => {
                    let seconds = now.duration_since(at).as_secs_f64().max(0.001);
                    (
                        ((totals.upload.saturating_sub(prev_up)) as f64 / seconds) as u64,
                        ((totals.download.saturating_sub(prev_down)) as f64 / seconds) as u64,
                    )
                }
                None => (0, 0),
            };
            previous = Some((totals.upload, totals.download, now));

            let traffic = Traffic {
                upload: totals.upload,
                download: totals.download,
                up_speed,
                down_speed,
                connections: totals.connections,
            };
            {
                let state = app.state::<AppState>();
                if state.session.load(Ordering::SeqCst) != session {
                    return;
                }
                *state.traffic.write() = traffic;
            }
            let _ = app.emit(EVT_TRAFFIC, traffic);
        }
    });
}

/// One end-to-end request through a loopback SOCKS listener: greet, CONNECT to
/// a well-known plain-HTTP endpoint, expect an HTTP status line back. Anything
/// short of that means the engine cannot actually carry traffic to its server.
async fn socks_probe(port: u16) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let attempt = async {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .ok()?;
        s.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
        let mut hello = [0u8; 2];
        s.read_exact(&mut hello).await.ok()?;
        if hello != [0x05, 0x00] {
            return None;
        }

        let host = b"www.gstatic.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&80u16.to_be_bytes());
        s.write_all(&req).await.ok()?;

        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.ok()?;
        if head[1] != 0x00 {
            return None;
        }
        // Drain BND.ADDR + BND.PORT, whose length depends on the address type.
        let addr = match head[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut len = [0u8; 1];
                s.read_exact(&mut len).await.ok()?;
                len[0] as usize
            }
            _ => return None,
        };
        let mut skip = vec![0u8; addr + 2];
        s.read_exact(&mut skip).await.ok()?;

        s.write_all(
            b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .ok()?;
        let mut status = [0u8; 12];
        s.read_exact(&mut status).await.ok()?;
        status.starts_with(b"HTTP/").then_some(())
    };

    tokio::time::timeout(Duration::from_secs(8), attempt)
        .await
        .ok()
        .flatten()
        .is_some()
}

/// Verify that the Xray-backed nodes actually carry traffic, and demote the
/// ones whose server rejects the Xray-only layer to the sing-box engine.
///
/// This is the "by connection" half of engine selection: the link decides the
/// preferred engine, the probe decides whether that choice survives contact
/// with the server. A demotion is persisted keyed to the failing `encryption`
/// value and applied by reconnecting, which rebuilds both engines' documents.
fn spawn_engine_probe(app: AppHandle, session: u64) {
    tauri::async_runtime::spawn(async move {
        // Let the engines finish their own start-up before judging them.
        tokio::time::sleep(Duration::from_secs(3)).await;

        let (ports, nodes) = {
            let state = app.state::<AppState>();
            if state.session.load(Ordering::SeqCst) != session {
                return;
            }
            let snapshot = (state.xray_ports.read().clone(), state.nodes.read().clone());
            snapshot
        };
        if ports.is_empty() {
            return;
        }

        let mut demoted: Vec<(String, String, String)> = Vec::new();
        for (id, port) in &ports {
            let Some(node) = nodes.iter().find(|n| &n.id == id) else {
                continue;
            };
            // Two attempts: the first can race the server's own warm-up.
            let mut ok = false;
            for attempt in 0..2 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                if socks_probe(*port).await {
                    ok = true;
                    break;
                }
            }
            if ok {
                continue;
            }

            if node.can_fall_back_to_singbox() {
                demoted.push((id.clone(), node.encryption.clone(), node.name.clone()));
            } else {
                let _ = app.emit(
                    EVT_LOG,
                    LogLine {
                        seq: 0,
                        level: "warn".into(),
                        text: format!(
                            "узел «{}» не отвечает через Xray, а замена движка для него невозможна (XHTTP)",
                            node.name
                        ),
                    },
                );
            }
        }
        if demoted.is_empty() {
            return;
        }

        {
            let state = app.state::<AppState>();
            if state.session.load(Ordering::SeqCst) != session {
                return;
            }
            let mut overrides = state.engine_overrides.write();
            for (id, encryption, name) in &demoted {
                overrides.insert(id.clone(), encryption.clone());
                let _ = app.emit(
                    EVT_LOG,
                    LogLine {
                        seq: 0,
                        level: "warn".into(),
                        text: format!(
                            "узел «{name}»: сервер не принял VLESS Encryption — переключаю на классический VLESS через sing-box"
                        ),
                    },
                );
            }
            // Ids that no longer exist only accumulate noise in the store.
            overrides.retain(|id, _| nodes.iter().any(|n| &n.id == id));
            let _ = state.store.save("engines", &*overrides);
        }

        // The decision lives in the generated documents; reconnect applies it.
        let _ = connect(app.clone()).await;
    });
}

/// Bring the tunnel down. Safe to call when it is already down.
fn shutdown(app: &AppHandle, message: &str) {
    let state = app.state::<AppState>();
    state.session.fetch_add(1, Ordering::SeqCst);

    {
        let mut core = state.core.lock();
        core.stop();
    }
    if let Some(engine) = state.xray.lock().as_mut() {
        engine.stop();
    }
    let _ = std::fs::remove_file(&state.paths.pid_file);
    *state.clash.write() = None;
    *state.traffic.write() = Traffic::default();

    // Only touch the system proxy if this app is the one that switched it on —
    // a user's own proxy configuration must survive a disconnect untouched.
    let ours = state.status.read().system_proxy;
    if ours {
        let _ = sysproxy::disable();
    }

    {
        let mut status = state.status.write();
        status.state = if message.is_empty() {
            ConnState::Disconnected
        } else {
            ConnState::Error
        };
        status.message = message.to_string();
        status.since_ms = None;
        status.system_proxy = false;
    }
    let _ = app.emit(EVT_TRAFFIC, Traffic::default());
    emit_status(app);
}

// ---------------------------------------------------------------- commands

#[tauri::command]
pub async fn get_snapshot(app: AppHandle) -> Result<Snapshot> {
    let state = app.state::<AppState>();
    let core_version = {
        let core = state.core.lock();
        core.version().unwrap_or_else(|_| "недоступно".into())
    };

    {
        let mut status = state.status.write();
        status.elevated = elevate::is_elevated();
        status.tunnel_mode = state.settings.read().tunnel_mode;
        status.active_id = state.resolve_active_id();
    }

    let snapshot = Snapshot {
        settings: state.settings.read().clone(),
        nodes: state.nodes.read().clone(),
        subscriptions: state.subs.read().clone(),
        split: state.split.read().clone(),
        status: state.status.read().clone(),
        traffic: *state.traffic.read(),
        latency: state.latency.read().clone(),
        active_id: state.resolve_active_id(),
        core_version,
        autostart: autostart::current(),
    };
    Ok(snapshot)
}

#[tauri::command]
pub async fn connect(app: AppHandle) -> Result<()> {
    let (tunnel_mode, mixed_port, clash_port, node_count) = {
        let state = app.state::<AppState>();
        let settings = state.settings.read();
        let node_count = state.nodes.read().len();
        let values = (
            settings.tunnel_mode,
            settings.mixed_port,
            settings.clash_port,
            node_count,
        );
        drop(settings);
        values
    };

    if node_count == 0 {
        return Err(AppError::msg(
            "нет ни одного сервера — добавьте ссылку vless:// или подписку",
        ));
    }
    if tunnel_mode == TunnelMode::Tun && !elevate::is_elevated() {
        return Err(AppError::msg(
            "ELEVATION_REQUIRED",
        ));
    }

    let resolved_active = {
        let state = app.state::<AppState>();
        state.resolve_active_id()
    };
    set_status(&app, |s| {
        s.state = ConnState::Connecting;
        s.message.clear();
        s.tunnel_mode = tunnel_mode;
        // Report the node the core will actually use, which may differ from the
        // pin when that server has since been removed.
        s.active_id = resolved_active;
    });

    let session = {
        let state = app.state::<AppState>();
        state.session.fetch_add(1, Ordering::SeqCst) + 1
    };

    // ---- geo data ---------------------------------------------------------
    // Fetched here, before the core starts, so an unreachable GitHub costs the
    // user a filter rather than the whole tunnel.
    let (split, rule_dir) = {
        let state = app.state::<AppState>();
        let split = state.split.read().clone();
        let dir = state.paths.rule_set_dir.clone();
        (split, dir)
    };
    let sets = ruleset::ensure(&required_rule_sets(&split), &rule_dir).await;
    for failure in &sets.failures {
        let _ = app.emit(
            EVT_LOG,
            LogLine {
                seq: 0,
                level: "warn".into(),
                text: format!("гео-набор {failure}"),
            },
        );
    }

    // ---- generate + validate + spawn -------------------------------------
    let start_result: Result<u32> = (|| {
        // A still-running core keeps routing with the rules of its old config
        // while the new engines come up; an Xray node added since then would
        // loop through it. Take the tunnel down before Xray starts dialling.
        {
            let state = app.state::<AppState>();
            state.core.lock().stop();
        }

        // Xray first: sing-box's config references its listeners, and a node
        // pointed at a port nobody is serving would just fail on first use.
        let xray_ports = start_xray_if_needed(&app)?;

        let state = app.state::<AppState>();
        build_and_write(&state, &xray_ports, &sets.available)?;

        let config_path = state.paths.config_file.clone();
        let pid_path = state.paths.pid_file.clone();
        let log_app = app.clone();

        let mut core = state.core.lock();
        core.stop();
        let pid = core.start(&config_path, move |line: LogLine| {
            let _ = log_app.emit(EVT_LOG, line);
        })?;
        let _ = std::fs::write(&pid_path, pid.to_string());
        Ok(pid)
    })();

    if let Err(e) = start_result {
        shutdown(&app, &e.to_string());
        return Err(e);
    }

    // ---- wait for the control plane --------------------------------------
    let secret = {
        let state = app.state::<AppState>();
        state.secret.clone()
    };
    let api = ClashApi::new(clash_port, &secret);

    if let Err(e) = api.wait_ready(Duration::from_secs(12)).await {
        // The core almost certainly logged the real reason before dying; the
        // timeout itself tells the user nothing actionable.
        let detail = core_error_line(&app).unwrap_or_else(|| e.to_string());
        shutdown(&app, &detail);
        return Err(AppError::msg(detail));
    }

    {
        let state = app.state::<AppState>();
        *state.clash.write() = Some(api.clone());
    }

    // ---- post-connect wiring ---------------------------------------------
    if tunnel_mode == TunnelMode::SystemProxy {
        if let Err(e) = sysproxy::enable(mixed_port) {
            shutdown(&app, &format!("не удалось включить системный прокси: {e}"));
            return Err(e);
        }
    }

    set_status(&app, |s| {
        s.state = ConnState::Connected;
        s.message.clear();
        s.since_ms = Some(now_ms());
        s.system_proxy = tunnel_mode == TunnelMode::SystemProxy;
    });

    spawn_traffic_poller(app.clone(), session);
    spawn_engine_probe(app.clone(), session);
    Ok(())
}

#[tauri::command]
pub async fn disconnect(app: AppHandle) -> Result<()> {
    shutdown(&app, "");
    Ok(())
}

/// Apply a change that is baked into the generated document (settings, split
/// rules) by restarting the core, but only when it is actually running.
async fn restart_if_running(app: &AppHandle) -> Result<()> {
    let running = {
        let state = app.state::<AppState>();
        let running = state.status.read().state == ConnState::Connected;
        running
    };
    if running {
        connect(app.clone()).await?;
    }
    Ok(())
}

#[tauri::command]
pub async fn save_settings(app: AppHandle, settings: Settings) -> Result<()> {
    let tunnel_mode = settings.tunnel_mode;
    {
        let state = app.state::<AppState>();
        *state.settings.write() = settings;
        state.save_settings()?;
    }
    set_status(&app, |s| s.tunnel_mode = tunnel_mode);
    restart_if_running(&app).await
}

#[tauri::command]
pub async fn set_split(app: AppHandle, split: SplitConfig) -> Result<()> {
    {
        let state = app.state::<AppState>();
        *state.split.write() = split;
        state.save_split()?;
    }
    restart_if_running(&app).await
}

#[tauri::command]
pub async fn set_active_server(app: AppHandle, id: String) -> Result<()> {
    let (api, tag) = {
        let state = app.state::<AppState>();
        {
            let nodes = state.nodes.read();
            if !nodes.iter().any(|n| n.id == id) {
                return Err(AppError::msg("сервер не найден"));
            }
        }
        *state.active_id.write() = id.clone();
        state.save_ui()?;
        let tag = state.tags.read().get(&id).cloned();
        let api = state.clash.read().clone();
        (api, tag)
    };

    set_status(&app, |s| s.active_id = id.clone());

    // While connected, retarget the selector instead of rebuilding the tunnel.
    if let (Some(api), Some(tag)) = (api, tag) {
        api.select(TAG_PROXY, &tag).await?;
    }
    Ok(())
}

#[tauri::command]
pub async fn set_clash_mode(app: AppHandle, mode: String) -> Result<()> {
    if !matches!(mode.as_str(), "Rule" | "Global" | "Direct") {
        return Err(AppError::msg("неизвестный режим маршрутизации"));
    }
    let api = {
        let state = app.state::<AppState>();
        let api = state.clash.read().clone();
        api
    };
    if let Some(api) = api {
        api.set_mode(&mode).await?;
    }
    set_status(&app, |s| s.mode = mode);
    Ok(())
}

// ---------------------------------------------------------------- servers

#[tauri::command]
pub async fn add_links(app: AppHandle, text: String) -> Result<ImportReport> {
    let report = link::parse_subscription(&text);
    let mut added = 0;
    let mut skipped = 0;

    {
        let state = app.state::<AppState>();
        let mut nodes = state.nodes.write();
        let existing: Vec<String> = nodes.iter().map(|n| n.fingerprint_key()).collect();

        for node in report.nodes {
            if existing.contains(&node.fingerprint_key()) {
                skipped += 1;
                continue;
            }
            nodes.push(node);
            added += 1;
        }
        drop(nodes);
        state.save_nodes()?;
    }

    emit_nodes(&app);
    Ok(ImportReport {
        added,
        skipped,
        errors: report.errors,
    })
}

#[tauri::command]
pub async fn delete_server(app: AppHandle, id: String) -> Result<()> {
    {
        let state = app.state::<AppState>();
        state.nodes.write().retain(|n| n.id != id);
        state.latency.write().remove(&id);
        state.save_nodes()?;
        state.save_ui()?;
    }
    emit_nodes(&app);
    restart_if_running(&app).await
}

#[tauri::command]
pub async fn update_server(app: AppHandle, node: ServerNode) -> Result<()> {
    {
        let state = app.state::<AppState>();
        let mut nodes = state.nodes.write();
        let Some(slot) = nodes.iter_mut().find(|n| n.id == node.id) else {
            return Err(AppError::msg("сервер не найден"));
        };
        *slot = node;
        drop(nodes);
        state.save_nodes()?;
    }
    emit_nodes(&app);
    restart_if_running(&app).await
}

fn emit_nodes(app: &AppHandle) {
    let resolved = {
        let state = app.state::<AppState>();
        let nodes = state.nodes.read().clone();
        let _ = app.emit(EVT_NODES, nodes);
        state.resolve_active_id()
    };

    // The list just changed: it may have gained its first node, or lost the one
    // that was pinned. The core resolves this on its own when connecting, so
    // without syncing the status the UI would report "сервер не выбран" over a
    // perfectly working tunnel.
    let changed = {
        let state = app.state::<AppState>();
        let mut status = state.status.write();
        let changed = status.active_id != resolved;
        status.active_id = resolved;
        changed
    };
    if changed {
        emit_status(app);
    }
}

/// Push the subscription list, including plan usage. Needed because refreshes
/// also happen on a timer, with no UI action to hang a reload off.
fn emit_subs(app: &AppHandle) {
    let state = app.state::<AppState>();
    let subs = state.subs.read().clone();
    let _ = app.emit(EVT_SUBS, subs);
}

// ---------------------------------------------------------- subscriptions

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubInput {
    pub name: String,
    pub url: String,
}

/// `https://panel.example.com:2096/subs/abc` → `panel.example.com:2096`.
fn host_of(url: &str) -> String {
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    if host.is_empty() {
        url.to_string()
    } else {
        host.to_string()
    }
}

#[tauri::command]
pub async fn add_subscription(app: AppHandle, input: SubInput) -> Result<ImportReport> {
    let id = uuid::Uuid::new_v4().to_string();
    {
        let state = app.state::<AppState>();
        state.subs.write().push(Subscription {
            id: id.clone(),
            name: if input.name.trim().is_empty() {
                // A full subscription URL is long and mostly opaque token; the
                // host alone identifies the panel and fits in a card.
                host_of(&input.url)
            } else {
                input.name.clone()
            },
            url: input.url.clone(),
            ..Default::default()
        });
        state.save_subs()?;
    }
    refresh_subscription(app, id).await
}

#[tauri::command]
pub async fn refresh_subscription(app: AppHandle, id: String) -> Result<ImportReport> {
    let url = {
        let state = app.state::<AppState>();
        let subs = state.subs.read();
        subs.iter()
            .find(|s| s.id == id)
            .map(|s| s.url.clone())
            .ok_or_else(|| AppError::msg("подписка не найдена"))?
    };

    let fetch = async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            // A subscription URL is normally reachable without the tunnel; going
            // through a half-configured system proxy would deadlock the refresh.
            .no_proxy()
            .user_agent("Aurora-VPN/0.1 (sing-box)")
            .build()?;

        let response = client.get(&url).send().await?.error_for_status()?;

        // The plan status rides along in headers, so read them before the body
        // is consumed.
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let usage = header("subscription-userinfo").map(|raw| link::parse_user_info(&raw));
        let interval = header("profile-update-interval")
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            .unwrap_or(0);
        let title = header("profile-title").and_then(|raw| link::parse_profile_title(&raw));

        let body = response.text().await?;
        Ok::<_, AppError>((body, usage, interval, title))
    };

    let (body, usage, interval, title) = match fetch.await {
        Ok(result) => result,
        Err(e) => {
            let state = app.state::<AppState>();
            let mut subs = state.subs.write();
            if let Some(sub) = subs.iter_mut().find(|s| s.id == id) {
                sub.last_error = e.to_string();
            }
            drop(subs);
            let _ = state.save_subs();
            return Err(e);
        }
    };

    let report = link::parse_subscription(&body);
    let fetched = report.nodes.len();

    {
        let state = app.state::<AppState>();
        let mut nodes = state.nodes.write();

        // Preserve ids across a refresh so the pinned server and its measured
        // latency survive when the provider re-issues the same node.
        let previous: HashMap<String, String> = nodes
            .iter()
            .filter(|n| n.subscription_id.as_deref() == Some(id.as_str()))
            .map(|n| (n.fingerprint_key(), n.id.clone()))
            .collect();

        nodes.retain(|n| n.subscription_id.as_deref() != Some(id.as_str()));

        for mut node in report.nodes {
            if let Some(old_id) = previous.get(&node.fingerprint_key()) {
                node.id = old_id.clone();
            }
            node.subscription_id = Some(id.clone());
            nodes.push(node);
        }
        drop(nodes);

        let mut subs = state.subs.write();
        if let Some(sub) = subs.iter_mut().find(|s| s.id == id) {
            sub.node_count = fetched;
            sub.last_updated = chrono::Utc::now().to_rfc3339();
            sub.update_interval_hours = interval;

            // A fetch that succeeded but yielded nothing usable is not a success.
            // The toast explaining why is transient; without this the card would
            // just read "0 серверов" with no reason attached.
            sub.last_error = match (fetched, report.errors.first()) {
                (0, Some((_, reason))) => reason.clone(),
                _ => String::new(),
            };

            if let Some(usage) = usage {
                sub.upload = usage.upload;
                sub.download = usage.download;
                sub.total = usage.total;
                sub.expire = usage.expire;
                sub.has_usage = true;
            }
            // Only adopt the provider's title while the entry still carries the
            // placeholder name; a name the user typed is theirs to keep.
            if let Some(title) = title {
                if sub.name == sub.url {
                    sub.name = title;
                }
            }
        }
        drop(subs);

        state.save_nodes()?;
        state.save_subs()?;
    }

    emit_nodes(&app);
    emit_subs(&app);
    Ok(ImportReport {
        added: fetched,
        skipped: 0,
        errors: report.errors,
    })
}

/// Refresh every enabled subscription. Failures are collected rather than
/// aborting the sweep, so one dead provider cannot block the others.
#[tauri::command]
pub async fn refresh_all_subscriptions(app: AppHandle) -> Result<ImportReport> {
    let ids: Vec<String> = {
        let state = app.state::<AppState>();
        let subs = state.subs.read();
        subs.iter().filter(|s| s.enabled).map(|s| s.id.clone()).collect()
    };

    let mut total = ImportReport {
        added: 0,
        skipped: 0,
        errors: Vec::new(),
    };
    for id in ids {
        let name = {
            let state = app.state::<AppState>();
            let subs = state.subs.read();
            let name = subs
                .iter()
                .find(|s| s.id == id)
                .map(|s| s.name.clone())
                .unwrap_or_default();
            name
        };
        match refresh_subscription(app.clone(), id).await {
            Ok(report) => {
                total.added += report.added;
                total.errors.extend(report.errors);
            }
            Err(e) => total.errors.push((name, e.to_string())),
        }
    }
    Ok(total)
}

/// Refresh subscriptions whose contents have gone stale. Driven by a timer in
/// `lib.rs`; silent by design, since it runs without the user asking.
pub async fn refresh_stale_subscriptions(app: &AppHandle) {
    let (interval_min, candidates) = {
        let state = app.state::<AppState>();
        let interval = state.settings.read().sub_auto_update_min;
        let subs = state.subs.read();
        let candidates: Vec<(String, String)> = subs
            .iter()
            .filter(|s| s.enabled)
            .map(|s| (s.id.clone(), s.last_updated.clone()))
            .collect();
        (interval, candidates)
    };

    if interval_min == 0 {
        return;
    }
    let max_age = chrono::Duration::minutes(i64::from(interval_min));
    let now = chrono::Utc::now();

    for (id, last_updated) in candidates {
        let stale = match chrono::DateTime::parse_from_rfc3339(&last_updated) {
            Ok(when) => now.signed_duration_since(when.with_timezone(&chrono::Utc)) >= max_age,
            // Never fetched, or an unreadable timestamp: treat as due.
            Err(_) => true,
        };
        if stale {
            let _ = refresh_subscription(app.clone(), id).await;
        }
    }
}

#[tauri::command]
pub async fn delete_subscription(app: AppHandle, id: String) -> Result<()> {
    {
        let state = app.state::<AppState>();
        state.subs.write().retain(|s| s.id != id);
        state
            .nodes
            .write()
            .retain(|n| n.subscription_id.as_deref() != Some(id.as_str()));
        state.save_subs()?;
        state.save_nodes()?;
    }
    emit_nodes(&app);
    emit_subs(&app);
    restart_if_running(&app).await
}

// ---------------------------------------------------------------- latency

/// Time a bare TCP handshake to the node. Used when the core is down, where the
/// Clash API is unavailable — it measures reachability, not proxy throughput.
async fn tcp_ping(host: &str, port: u16, timeout: Duration) -> Option<u32> {
    let target = format!("{host}:{port}");
    let started = Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(target)).await {
        Ok(Ok(_)) => Some(started.elapsed().as_millis() as u32),
        _ => None,
    }
}

#[tauri::command]
pub async fn test_latency(app: AppHandle, ids: Vec<String>) -> Result<HashMap<String, Option<u32>>> {
    let (targets, api, tags, url) = {
        let state = app.state::<AppState>();
        let nodes = state.nodes.read();
        let wanted: Vec<(String, String, u16)> = nodes
            .iter()
            .filter(|n| ids.is_empty() || ids.contains(&n.id))
            .map(|n| (n.id.clone(), n.address.clone(), n.port))
            .collect();
        let api = state.clash.read().clone();
        let tags = state.tags.read().clone();
        let url = state.settings.read().latency_url.clone();
        (wanted, api, tags, url)
    };

    // Probe concurrently; a serial sweep over 40 nodes would take a minute.
    let mut tasks = Vec::new();
    for (id, host, port) in targets {
        let api = api.clone();
        let tag = tags.get(&id).cloned();
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let value = match (api, tag) {
                (Some(api), Some(tag)) => api.delay(&tag, &url, 5000).await.unwrap_or(None),
                _ => tcp_ping(&host, port, Duration::from_secs(5)).await,
            };
            (id, value)
        }));
    }

    let mut results = HashMap::new();
    for task in tasks {
        if let Ok((id, value)) = task.await {
            results.insert(id, value);
        }
    }

    {
        let state = app.state::<AppState>();
        let mut latency = state.latency.write();
        for (id, value) in &results {
            latency.insert(id.clone(), *value);
        }
        let _ = app.emit(EVT_LATENCY, latency.clone());
    }
    Ok(results)
}

// ---------------------------------------------------------------- system

#[tauri::command]
pub async fn list_running_apps(include_system: bool) -> Result<Vec<procs::RunningApp>> {
    // Enumerating processes touches the whole process table; keep it off the UI thread.
    tokio::task::spawn_blocking(move || procs::running_apps(include_system))
        .await
        .map_err(|e| AppError::msg(format!("не удалось получить список процессов: {e}")))
}

#[tauri::command]
pub async fn get_logs(app: AppHandle) -> Result<Vec<LogLine>> {
    let state = app.state::<AppState>();
    let core = state.core.lock();
    let logs = core.logs.lock();
    Ok(logs.snapshot())
}

#[tauri::command]
pub async fn clear_logs(app: AppHandle) -> Result<()> {
    let state = app.state::<AppState>();
    let core = state.core.lock();
    core.logs.lock().clear();
    Ok(())
}

/// Render the document that *would* be used, for inspection and bug reports.
#[tauri::command]
pub async fn preview_config(app: AppHandle) -> Result<String> {
    let state = app.state::<AppState>();
    let nodes = effective_nodes(&state);
    let settings = state.settings.read().clone();
    let split = state.split.read().clone();
    let active_id = state.resolve_active_id();

    // Preview the shape the tunnel would take, including the Xray hand-off, so
    // a bug report shows what the engines actually receive.
    let xray_built = xray::build(
        &nodes,
        xray::DEFAULT_BASE_PORT,
        xray::log_level(&settings.log_level),
    )?;
    let xray_ports = xray_built
        .as_ref()
        .map(|b| b.ports.clone())
        .unwrap_or_default();
    let xray_exe = state.xray.lock().as_ref().map(|e| e.exe().to_path_buf());

    let built = config::build(&BuildInput {
        nodes: &nodes,
        active_id: &active_id,
        settings: &settings,
        split: &split,
        clash_secret: "<hidden>",
        cache_path: &state.paths.cache_file,
        xray_ports: &xray_ports,
        xray_exe: xray_exe.as_deref(),
        // Preview what the current cache allows, not an optimistic view of it.
        rule_sets: &cached_rule_sets(&state.paths.rule_set_dir, &split),
        rule_set_dir: &state.paths.rule_set_dir,
    })?;

    let mut text = serde_json::to_string_pretty(&built.json)?;
    if let Some(xray) = xray_built {
        text.push_str("\n\n// ---- Xray (второй движок) ----\n");
        text.push_str(&serde_json::to_string_pretty(&xray.json)?);
    }
    Ok(text)
}

/// Drop every live connection so applications re-dial through the current route.
/// Useful right after changing rules, when long-lived sockets would otherwise
/// keep flowing down the old path.
#[tauri::command]
pub async fn close_connections(app: AppHandle) -> Result<()> {
    let api = {
        let state = app.state::<AppState>();
        let api = state.clash.read().clone();
        api
    };
    let Some(api) = api else {
        return Err(AppError::msg("нет активного подключения"));
    };
    api.close_connections().await
}

// ---------------------------------------------------------------- updates

/// GitHub repository the updater watches. Its releases carry the NSIS
/// installer produced by the `release` workflow.
const UPDATE_REPO: &str = "JustRin/aurora-vpn";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub version: String,
    pub url: String,
    pub notes: String,
}

/// `"v1.2.3-beta"` → `[1, 2, 3]`. Lenient on purpose: a tag that fails to
/// parse compares as `0.0.0` and therefore never triggers an update.
fn parse_version(v: &str) -> [u64; 3] {
    let mut out = [0u64; 3];
    let cleaned = v.trim().trim_start_matches(['v', 'V']);
    for (i, part) in cleaned.split('.').take(3).enumerate() {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        out[i] = digits.parse().unwrap_or(0);
    }
    out
}

/// The release-asset suffix that installs on this machine.
fn installer_suffix() -> &'static str {
    if cfg!(windows) {
        "-setup.exe"
    } else if cfg!(target_os = "macos") {
        ".dmg"
    } else {
        ".AppImage"
    }
}

/// Pick the asset for this platform, preferring the matching architecture when
/// a release ships more than one (the two macOS builds, for instance). Both
/// common spellings of each architecture are accepted, because the asset
/// naming convention has already changed once.
fn pick_installer_url(assets: &[Value]) -> Option<String> {
    let suffix = installer_suffix();
    let arch: &[&str] = if std::env::consts::ARCH == "aarch64" {
        &["aarch64", "arm64"]
    } else {
        &["x64", "x86_64", "amd64"]
    };
    let named = |a: &&Value| {
        a["name"]
            .as_str()
            .is_some_and(|n| n.ends_with(suffix))
    };
    let candidates: Vec<&Value> = assets.iter().filter(named).collect();
    candidates
        .iter()
        .find(|a| {
            a["name"]
                .as_str()
                .is_some_and(|n| arch.iter().any(|m| n.contains(m)))
        })
        .or_else(|| candidates.first())
        .and_then(|a| a["browser_download_url"].as_str())
        .map(str::to_string)
}

/// The newest published release, if it is ahead of the running build.
///
/// Silence is deliberate for everything except transport errors: no releases
/// yet, a rate-limited API or a release without an installer asset are all
/// "no update", not failures the user can act on.
#[tauri::command]
pub async fn check_update(app: AppHandle) -> Result<Option<UpdateInfo>> {
    let current = app.package_info().version.to_string();
    let api = format!("https://api.github.com/repos/{UPDATE_REPO}/releases/latest");

    let resp = reqwest::Client::new()
        .get(&api)
        .header("User-Agent", "aurora-vpn-updater")
        .header("Accept", "application/vnd.github+json")
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| AppError::msg(format!("проверка обновлений: {e}")))?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let release: Value = resp
        .json()
        .await
        .map_err(|e| AppError::msg(format!("проверка обновлений: {e}")))?;

    let tag = release["tag_name"].as_str().unwrap_or_default();
    if parse_version(tag) <= parse_version(&current) {
        return Ok(None);
    }

    let assets = release["assets"].as_array().cloned().unwrap_or_default();
    // A release without an asset for this platform still gets announced — the
    // release page is a perfectly good place to send the user instead.
    let url = match pick_installer_url(&assets) {
        Some(url) => url,
        None => match release["html_url"].as_str() {
            Some(page) => page.to_string(),
            None => return Ok(None),
        },
    };

    Ok(Some(UpdateInfo {
        version: tag.trim_start_matches(['v', 'V']).to_string(),
        url,
        notes: release["body"]
            .as_str()
            .unwrap_or_default()
            .chars()
            .take(2000)
            .collect(),
    }))
}

/// Windows: download the installer, hand control to it and exit through the
/// normal teardown path so the cores and the system proxy are released before
/// the files are replaced. Elsewhere the package (or the release page) opens
/// in the browser — .dmg and .AppImage installs are inherently manual.
#[tauri::command]
pub async fn install_update(app: AppHandle, url: String) -> Result<()> {
    // The URL round-trips through the WebView; accept only GitHub's own
    // release hosts rather than trusting the IPC boundary.
    let trusted = url.starts_with("https://github.com/")
        || url.starts_with("https://objects.githubusercontent.com/");
    if !trusted {
        return Err(AppError::msg("недопустимый адрес обновления"));
    }

    if !(cfg!(windows) && url.ends_with("-setup.exe")) {
        return tauri_plugin_opener::open_url(url, None::<&str>)
            .map_err(|e| AppError::msg(format!("не удалось открыть страницу загрузки: {e}")));
    }

    let bytes = reqwest::Client::new()
        .get(&url)
        .header("User-Agent", "aurora-vpn-updater")
        .timeout(Duration::from_secs(600))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| AppError::msg(format!("не удалось скачать обновление: {e}")))?
        .bytes()
        .await
        .map_err(|e| AppError::msg(format!("не удалось скачать обновление: {e}")))?;
    // A truncated download would install nothing but still kill the session.
    if bytes.len() < 1_000_000 {
        return Err(AppError::msg("скачанный установщик неполный — попробуйте ещё раз"));
    }

    let path = std::env::temp_dir().join("aurora-vpn-update-setup.exe");
    std::fs::write(&path, &bytes)?;
    std::process::Command::new(&path)
        .spawn()
        .map_err(|e| AppError::msg(format!("не удалось запустить установщик: {e}")))?;

    // Give the installer a beat to appear, then leave through RunEvent::Exit,
    // which stops both engines and restores the system proxy.
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        app.exit(0);
    });
    Ok(())
}

/// Reveal the main window once the interface has actually painted.
///
/// The window starts hidden: showing it earlier means the user stares at an
/// empty white WebView for a beat before the dark UI replaces it.
#[tauri::command]
pub async fn app_ready(app: AppHandle) -> Result<()> {
    let start_minimized = {
        let state = app.state::<AppState>();
        let minimized = state.settings.read().start_minimized;
        minimized
    };
    if start_minimized {
        return Ok(());
    }
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
    Ok(())
}

#[tauri::command]
pub async fn get_autostart() -> Result<AutostartMode> {
    Ok(autostart::current())
}

/// Register or clear launch-at-login. Returns the mode actually in force, which
/// lets the UI correct itself if the OS refused part of the request.
#[tauri::command]
pub async fn set_autostart(mode: AutostartMode) -> Result<AutostartMode> {
    // Registering the elevated variant writes to the system task store, so it
    // must not block the UI thread.
    tokio::task::spawn_blocking(move || autostart::apply(mode))
        .await
        .map_err(|e| AppError::msg(format!("не удалось изменить автозапуск: {e}")))??;
    Ok(autostart::current())
}

/// Keep the native window chrome in step with the in-page palette.
///
/// The palette itself lives in the frontend; this only receives the two facts
/// the OS needs. Repainting the background here is what stops the *next* launch
/// from opening on the previous theme's colour.
#[tauri::command]
pub async fn set_window_theme(app: AppHandle, dark: bool, background: String) -> Result<()> {
    let Some(window) = app.get_webview_window("main") else {
        return Ok(());
    };
    apply_window_theme(&window, dark, &background);
    Ok(())
}

pub fn apply_window_theme(window: &tauri::WebviewWindow, dark: bool, background: &str) {
    let theme = if dark {
        tauri::Theme::Dark
    } else {
        tauri::Theme::Light
    };
    let _ = window.set_theme(Some(theme));

    if let Some(color) = parse_hex_color(background) {
        let _ = window.set_background_color(Some(color));
    }
}

/// `#RRGGBB` → an opaque colour. Anything malformed is ignored rather than
/// substituted, so a bad value leaves the previous background intact.
fn parse_hex_color(text: &str) -> Option<tauri::window::Color> {
    let hex = text.trim().strip_prefix('#')?;
    if hex.len() != 6 {
        return None;
    }
    let channel = |range: std::ops::Range<usize>| u8::from_str_radix(&hex[range], 16).ok();
    Some(tauri::window::Color(
        channel(0..2)?,
        channel(2..4)?,
        channel(4..6)?,
        255,
    ))
}

#[tauri::command]
pub async fn is_elevated() -> Result<bool> {
    Ok(elevate::is_elevated())
}

#[tauri::command]
pub async fn relaunch_elevated(app: AppHandle) -> Result<()> {
    // Order matters against the single-instance guard: `runas` only creates the
    // process after the user accepts the UAC prompt, so this instance releases
    // its lock — and the virtual adapter — long before the new one boots.
    elevate::relaunch_elevated()?;
    shutdown(&app, "");
    app.exit(0);
    Ok(())
}

#[tauri::command]
pub async fn open_config_dir(app: AppHandle) -> Result<()> {
    let dir = {
        let state = app.state::<AppState>();
        state.store.dir().to_path_buf()
    };
    tauri_plugin_opener::open_path(dir.to_string_lossy().to_string(), None::<&str>)
        .map_err(|e| AppError::msg(format!("не удалось открыть папку: {e}")))
}

#[cfg(test)]
mod tests {
    use super::{installer_suffix, parse_version, pick_installer_url};
    use serde_json::json;

    #[test]
    fn version_ordering_survives_prefixes_and_suffixes() {
        assert!(parse_version("v0.1.2") > parse_version("0.1.1"));
        assert!(parse_version("1.0.0") > parse_version("v0.9.9"));
        assert_eq!(parse_version("v1.2.3-beta"), [1, 2, 3]);
        // Garbage must compare as 0.0.0 and never announce an update.
        assert_eq!(parse_version("latest"), [0, 0, 0]);
    }

    #[test]
    fn installer_pick_matches_platform_and_architecture() {
        let asset = |name: &str| {
            json!({
                "name": name,
                "browser_download_url": format!("https://github.com/x/y/releases/download/v1/{name}")
            })
        };
        // One asset per platform/arch, both architecture spellings represented.
        let assets = vec![
            asset("AuroraVPN-1.0.0-windows-x64-setup.exe"),
            asset("AuroraVPN-1.0.0-linux-x64.AppImage"),
            asset("AuroraVPN-1.0.0-linux-x64.deb"),
            asset("AuroraVPN-1.0.0-macos-arm64.dmg"),
            asset("AuroraVPN-1.0.0-macos-x64.dmg"),
        ];

        let url = pick_installer_url(&assets).expect("an installer for the host platform");
        assert!(url.ends_with(installer_suffix()), "{url}");

        // On every platform the pick must be a concrete asset, never a page.
        assert!(url.starts_with("https://github.com/"));

        // The architecture preference kicks in whenever two assets share the
        // platform suffix (the macOS pair here).
        if cfg!(target_os = "macos") {
            let marker = if std::env::consts::ARCH == "aarch64" { "arm64" } else { "x64" };
            assert!(url.contains(marker), "{url}");
        }
    }
}
