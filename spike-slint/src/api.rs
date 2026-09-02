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
use crate::app::{AppHandle, Event};
use crate::core::balancer::{self, Brain, Reason, Step};
use crate::core::clash::ClashApi;
use crate::core::config::{self, BuildInput, TAG_PROXY};
use crate::core::geoip;
use crate::core::log::LogLine;
use crate::core::ruleset;
#[cfg(not(target_os = "android"))]
use crate::core::process::{CoreSupervisor, Engine};
#[cfg(not(target_os = "android"))]
use crate::core::xray;
use crate::error::{AppError, Result};
use crate::link;
use crate::model::ServerNode;
use crate::settings::{Balancer, Settings, SplitConfig, Subscription, TunnelMode};
use crate::state::{AppState, ConnState, Link, Status, Traffic};
use crate::sys::autostart::{self, AutostartMode};
use crate::sys::{elevate, procs, sysproxy};

/// Сговор ядра с интерфейсом, как `ELEVATION_REQUIRED`: подключение прервано
/// не ошибкой, а вопросом — окно уже спрашивает про ядро от прошлого сеанса.
/// До всплывашки эта строка доходить не должна (bind.rs, `silent`).
#[cfg(not(target_os = "android"))]
pub const ORPHAN_CORE: &str = "ORPHAN_CORE";

// ---------------------------------------------------------------- payloads

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub settings: Settings,
    pub nodes: Vec<ServerNode>,
    pub subscriptions: Vec<Subscription>,
    pub split: SplitConfig,
    pub status: Status,
    pub traffic: Traffic,
    pub latency: HashMap<String, Option<u32>>,
    pub active_id: String,
    pub core_version: String,
    /// Read back from the OS, not from settings — the user may have removed the
    /// registry value or the scheduled task behind our back.
    pub autostart: AutostartMode,
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
    let state = app.state();
    let status = state.status.read().clone();
    let _ = app.emit(Event::Status(status));
}

fn set_status(app: &AppHandle, mutate: impl FnOnce(&mut Status)) {
    {
        let state = app.state();
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
///
/// Хроника отдельных соединений (`is_connection_churn`) пропускается: ядро
/// пишет её как ERROR, но оборванный вкладкой запрос — не причина сбоя, и
/// показанная в тосте такая строка только уводит от настоящей.
fn core_error_line(app: &AppHandle) -> Option<String> {
    let state = app.state();
    let core = state.core.lock();
    let logs = core.logs.lock();
    logs.snapshot()
        .iter()
        .rev()
        .find(|line| {
            matches!(line.level.as_str(), "fatal" | "error" | "panic")
                && !crate::core::log::is_connection_churn(&line.text)
        })
        .map(|line| line.text.clone())
}

/// Дождаться панель управления, глядя на само ядро, а не только на часы.
///
/// Панель поднимается последней — после TUN-адаптера и маршрутов, чья первая
/// установка на Windows легко переживает жёсткие 12 секунд (драйвер wintun,
/// антивирусные фильтры). Прежний таймаут в этот момент убивал здоровое ядро —
/// уже принимавшее соединения — и показывал вместо причины последнюю ERROR-
/// строку журнала: случайный сетевой мусор. Поэтому пока процесс жив, ждём
/// дольше; а мёртвый — наоборот, не заставляет высиживать таймаут до конца.
async fn await_control_plane(app: &AppHandle, api: &ClashApi) -> std::result::Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if api.version().await.is_ok() {
            return Ok(());
        }
        let alive = {
            let state = app.state();
            let mut core = state.core.lock();
            core.is_running()
        };
        if !alive {
            return Err(core_error_line(app).unwrap_or_else(|| {
                "ядро неожиданно завершилось при запуске — подробности в журнале".into()
            }));
        }
        if Instant::now() >= deadline {
            return Err(
                "ядро запущено, но панель управления не ответила за 30 с — подробности в журнале"
                    .into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
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

/// No second engine on Android: nodes that need Xray are carried by sing-box
/// with the extra layer dropped (`can_fall_back_to_singbox`), the rest fail
/// with a readable log line. Building libxray is tracked separately.
#[cfg(target_os = "android")]
fn start_xray_if_needed(_app: &AppHandle) -> Result<HashMap<String, u16>> {
    Ok(HashMap::new())
}

/// Start the Xray engine if any node needs it, and report the loopback ports it
/// listens on. Returns an empty map when sing-box can handle everything.
#[cfg(not(target_os = "android"))]
fn start_xray_if_needed(app: &AppHandle) -> Result<HashMap<String, u16>> {
    let (nodes, log_level) = {
        let state = app.state();
        let nodes = effective_nodes(&state);
        let level = state.settings.read().log_level.clone();
        (nodes, level)
    };

    if !nodes.iter().any(|n| n.needs_xray()) {
        let state = app.state();
        if let Some(engine) = state.xray.lock().as_mut() {
            engine.stop();
        }
        state.xray_ports.write().clear();
        return Ok(HashMap::new());
    }

    let built = xray::build(&nodes, xray::DEFAULT_BASE_PORT, xray::log_level(&log_level))?
        .expect("at least one node needs xray");

    let state = app.state();
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
        let _ = log_app.emit(Event::Log(LogLine {
                text: format!("xray: {}", line.text),
                ..line
            }));
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
    #[cfg(not(target_os = "android"))]
    let xray_exe = state.xray.lock().as_ref().map(|e| e.exe().to_path_buf());
    #[cfg(target_os = "android")]
    let xray_exe: Option<std::path::PathBuf> = None;

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
        #[cfg(target_os = "android")]
        log_file: &state.paths.log_file,
    })?;

    *state.tags.write() = built.tags.iter().cloned().collect();
    *state.candidates.write() = built.candidates.clone();

    std::fs::create_dir_all(&state.paths.work_dir)?;
    std::fs::write(
        &state.paths.config_file,
        serde_json::to_vec_pretty(&built.json)?,
    )?;
    Ok(built.json)
}

/// Sample the counters once a second and turn them into a rate.
fn spawn_traffic_poller(app: AppHandle, session: u64) {
    tokio::spawn(async move {
        let mut previous: Option<(u64, u64, Instant)> = None;
        let mut failures: u32 = 0;

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let (api, still_ours, uptime_ms) = {
                let state = app.state();
                let ours = state.session.load(Ordering::SeqCst) == session
                    && state.status.read().state == ConnState::Connected;
                let api = state.clash.read().clone();
                let uptime = state.status.read().since_ms.map(|s| now_ms() - s);
                (api, ours, uptime)
            };
            if !still_ours {
                return;
            }
            let Some(api) = api else { return };

            // Туннель прожил дольше 30 секунд — прошлые аварийные старты
            // прощаются, автоперезапуск снова в полном запасе.
            if uptime_ms.unwrap_or(0) > FAST_CRASH_WINDOW_MS {
                let state = app.state();
                state.fast_crashes.store(0, Ordering::SeqCst);
            }

            let totals = match api.totals().await {
                Ok(totals) => {
                    failures = 0;
                    totals
                }
                Err(_) => {
                    // Мёртвый процесс распознаётся на первом же промахе:
                    // try_wait дёшев, а каждая секунда с «Подключено» поверх
                    // мёртвого туннеля — это оборванные соединения у
                    // пользователя.
                    let dead = {
                        let state = app.state();
                        let mut core = state.core.lock();
                        !core.is_running()
                    };
                    if dead {
                        handle_core_death(&app, session, uptime_ms).await;
                        return;
                    }
                    // A single miss is usually just a busy core; a run of them
                    // with the process alive is survivable — keep polling.
                    failures += 1;
                    if failures >= 5 {
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
                let state = app.state();
                if state.session.load(Ordering::SeqCst) != session {
                    return;
                }
                *state.traffic.write() = traffic;
            }
            let _ = app.emit(Event::Traffic(traffic));
        }
    });
}

/// Аптайм, после которого аварийное завершение ядра не считается бут-лупом.
const FAST_CRASH_WINDOW_MS: i64 = 30_000;
/// Сколько аварий подряд раньше этого окна терпим, прежде чем сдаться.
const FAST_CRASH_LIMIT: u32 = 3;

/// Ядро умерло само — не по нашей команде.
///
/// Так падает sing-box: у него есть паники, убивающие весь процесс (например,
/// типизированный nil в vmess+ws при плановом urltest-обходе узлов — апстримный
/// баг, живой и в 1.14). Ронять из-за этого туннель до ручного клика нельзя —
/// перезапускаемся сами. Но ядро, умирающее моложе 30 секунд, перезапуском не
/// лечится (битый конфиг, занятый порт): после трёх таких подряд остановка с
/// честным сообщением.
async fn handle_core_death(app: &AppHandle, session: u64, uptime_ms: Option<i64>) {
    let detail = core_error_line(app)
        .unwrap_or_else(|| "ядро неожиданно завершилось — подробности в журнале".into());

    let fast = uptime_ms.map(|u| u < FAST_CRASH_WINDOW_MS).unwrap_or(true);
    let strikes = {
        let state = app.state();
        if state.session.load(Ordering::SeqCst) != session {
            // Пока констатировали смерть, пользователь уже переподключился
            // или отключился сам — не мешаем.
            return;
        }
        if fast {
            state.fast_crashes.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            // Дожил до зрелости — серия аварийных стартов прервана.
            state.fast_crashes.store(0, Ordering::SeqCst);
            0
        }
    };

    if fast && strikes >= FAST_CRASH_LIMIT {
        shutdown(
            app,
            &format!("ядро падает сразу после запуска, автоперезапуск остановлен: {detail}"),
        );
        return;
    }

    let _ = app.emit(Event::Log(LogLine {
        seq: 0,
        level: "warn".into(),
        text: format!("ядро аварийно завершилось ({detail}) — перезапускаю туннель"),
    }));
    // Ядро упало, пока трафик шёл через хрупкий узел (vmess+ws: неудачный
    // дозвон роняет процесс) — для балансировщика это смерть узла. После
    // перезапуска он уйдёт с него, а не будет ронять ядро снова и снова.
    {
        let state = app.state();
        let routed = {
            let status = state.status.read();
            state.tags.read().get(&status.routed_id).cloned()
        };
        let mut guard = state.balancer.lock();
        if let (Some(tag), Some(brain)) = (routed, guard.as_mut()) {
            // «Вручную» уходить всё равно некуда — и хоронить узел по одной
            // аварии незачем: сторож перепроверит его через секунды.
            if brain.strategy() != Balancer::Manual && !brain.is_safe(&tag) {
                brain.mark_dead(&tag, Instant::now());
            }
        }
    }
    // connect_inner (а не connect: тот открывает новый эпизод и обнулил бы
    // счётчик аварий) сам поднимет статус, ядро и поллеры; о неудаче он тоже
    // сообщает сам — путь фоновый, причина остаётся в статусе «Ошибка».
    let _ = connect_inner(app.clone()).await;
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
    tokio::spawn(async move {
        // Let the engines finish their own start-up before judging them.
        tokio::time::sleep(Duration::from_secs(3)).await;

        let (ports, nodes) = {
            let state = app.state();
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
                let _ = app.emit(Event::Log(LogLine {
                        seq: 0,
                        level: "warn".into(),
                        text: format!(
                            "узел «{}» не отвечает через Xray, а замена движка для него невозможна (XHTTP)",
                            node.name
                        ),
                    }));
            }
        }
        if demoted.is_empty() {
            return;
        }

        {
            let state = app.state();
            if state.session.load(Ordering::SeqCst) != session {
                return;
            }
            let mut overrides = state.engine_overrides.write();
            for (id, encryption, name) in &demoted {
                overrides.insert(id.clone(), encryption.clone());
                let _ = app.emit(Event::Log(LogLine {
                        seq: 0,
                        level: "warn".into(),
                        text: format!(
                            "узел «{name}»: сервер не принял VLESS Encryption — переключаю на классический VLESS через sing-box"
                        ),
                    }));
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
    let state = app.state();
    state.session.fetch_add(1, Ordering::SeqCst);

    {
        let mut core = state.core.lock();
        core.stop();
    }
    #[cfg(not(target_os = "android"))]
    if let Some(engine) = state.xray.lock().as_mut() {
        engine.stop();
    }
    let _ = std::fs::remove_file(&state.paths.pid_file);
    *state.clash.write() = None;
    *state.balancer.lock() = None;
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
        status.routed_id.clear();
        status.link = Link::Connecting;
        status.system_proxy = false;
    }
    let _ = app.emit(Event::Traffic(Traffic::default()));
    emit_status(app);
}

// --------------------------------------------------------------- balancer

/// Строка в журнал от самого приложения — рядом со строками ядра.
fn log_line(app: &AppHandle, level: &str, text: impl Into<String>) {
    app.emit(Event::Log(LogLine {
        seq: 0,
        level: level.into(),
        text: text.into(),
    }));
}

/// Узел по тегу исходящего.
fn id_of(state: &AppState, tag: &str) -> Option<String> {
    state
        .tags
        .read()
        .iter()
        .find(|(_, t)| t.as_str() == tag)
        .map(|(id, _)| id.clone())
}

/// Имя узла по тегу — для журнала; без узла остаётся тег.
fn name_of(state: &AppState, tag: &str) -> String {
    id_of(state, tag)
        .and_then(|id| state.nodes.read().iter().find(|n| n.id == id).map(|n| n.name.clone()))
        .unwrap_or_else(|| tag.to_string())
}

fn strategy_name(strategy: Balancer) -> &'static str {
    match strategy {
        Balancer::Manual => "вручную",
        Balancer::Failover => "с резервом",
        Balancer::Fastest => "самый быстрый",
        Balancer::Rotate => "по кругу",
    }
}

/// «2 проверки», «5 проверок», «21 проверку» — для журнала.
fn checks(n: u32) -> String {
    let word = match (n % 10, n % 100) {
        (1, tail) if tail != 11 => "проверку",
        (2..=4, tail) if !(12..=14).contains(&tail) => "проверки",
        _ => "проверок",
    };
    format!("{n} {word}")
}

/// Собрать автомат под текущие настройки и конфиг. Возвращает тег узла, на
/// который должен смотреть селектор; None — узла в конфиге нет.
fn install_brain(state: &AppState) -> Option<String> {
    let settings = state.settings.read().clone();
    let mut guard = state.balancer.lock();
    let active = state.resolve_active_id();
    let primary = state.tags.read().get(&active).cloned()?;
    let cfg = balancer::Config {
        strategy: settings.balancer,
        tolerance: settings.balancer_tolerance_ms,
        interval: Duration::from_secs(60 * u64::from(settings.balancer_interval_min.max(1))),
    };
    // «Вручную» автомат тоже есть — сторожем текущего узла, без кандидатов:
    // выбирать ему не между кем, но знать, отвечает ли сервер, интерфейс
    // должен всегда, а не только под балансировщиком.
    let candidates = if settings.balancer == Balancer::Manual {
        Vec::new()
    } else {
        state.candidates.read().clone()
    };
    let mut brain = Brain::new(cfg, primary, candidates);
    if let Some(old) = guard.as_ref() {
        brain = brain.inherit(old);
    }
    let routed = brain.routed().to_string();
    *guard = Some(brain);
    state.balancer_wake.notify_one();
    Some(routed)
}

/// Стратегию сменили при живом подключении: ядро не трогают, меняется только
/// автомат.
fn apply_balancer_settings(app: &AppHandle) {
    let state = app.state();
    if state.status.read().state != ConnState::Connected {
        *state.balancer.lock() = None;
        return;
    }
    // Узел, через который идёт трафик, становится выбранным: для «вручную»
    // это и есть сервер, для «с резервом» — основной, остальным всё равно.
    // Так смена стратегии сама по себе трафик не дёргает, а пользователь
    // получает тот сервер, который видел подсвеченным, а не закреплённый до
    // балансировщика.
    let routed = state.status.read().routed_id.clone();
    let known = !routed.is_empty() && state.nodes.read().iter().any(|n| n.id == routed);
    if known && *state.active_id.read() != routed {
        *state.active_id.write() = routed.clone();
        let _ = state.save_ui();
        set_status(app, |s| s.active_id = routed);
    }
    let strategy = state.settings.read().balancer;
    install_brain(state);
    if strategy == Balancer::Manual {
        log_line(app, "info", "балансировщик выключен: сервер выбирается вручную");
    } else {
        log_line(app, "info", format!("балансировщик: режим «{}»", strategy_name(strategy)));
    }
}

/// Отметить, что показала проверка текущего сервера. Смена связи — событие:
/// она видна в шапке «Обзора» вместо «Подключено» и остаётся в журнале.
fn note_link(app: &AppHandle, alive: bool, down: bool) {
    let next = if down {
        Link::Down
    } else if alive {
        Link::Up
    } else {
        // Одна осечка — ещё не приговор, но и не подтверждение.
        return;
    };
    let (previous, name) = {
        let state = app.state();
        let mut status = state.status.write();
        if status.state != ConnState::Connected || status.link == next {
            return;
        }
        let previous = std::mem::replace(&mut status.link, next);
        let routed = status.routed_id.clone();
        drop(status);
        let name = state
            .nodes
            .read()
            .iter()
            .find(|n| n.id == routed)
            .map(|n| n.name.clone())
            .unwrap_or_default();
        (previous, name)
    };
    emit_status(app);
    match next {
        Link::Down => log_line(
            app,
            "warn",
            format!("сервер «{name}» не отвечает на проверки — трафик через туннель не идёт"),
        ),
        Link::Up if previous == Link::Down => {
            log_line(app, "info", format!("сервер «{name}» снова отвечает"));
        }
        _ => {}
    }
}

/// Пауза поводыря, которую прерывает будильник: смена сервера или стратегии
/// ставит новый узел на проверку сразу, а не после паузы.
async fn nap(app: &AppHandle, wait: Duration) {
    let state = app.state();
    tokio::select! {
        _ = tokio::time::sleep(wait) => {}
        _ = state.balancer_wake.notified() => {}
    }
}

/// Измерить узлы через ядро — один запрос на узел, все разом.
async fn probe_tags(app: &AppHandle, api: &ClashApi, tags: &[String]) -> Vec<(String, Option<u32>)> {
    let url = {
        let state = app.state();
        let url = state.settings.read().latency_url.clone();
        url
    };
    let mut tasks = Vec::with_capacity(tags.len());
    for tag in tags {
        let (api, url, tag) = (api.clone(), url.clone(), tag.clone());
        tasks.push(tokio::spawn(async move {
            let value = api.delay(&tag, &url, 5000).await.unwrap_or(None);
            (tag, value)
        }));
    }
    let mut results = Vec::with_capacity(tags.len());
    for task in tasks {
        if let Ok(pair) = task.await {
            results.push(pair);
        }
    }
    results
}

/// Замеры балансировщика — те же, что мерит кнопка «Проверить»: показать их
/// в списке, а не держать при себе.
fn publish_latency(app: &AppHandle, results: &[(String, Option<u32>)]) {
    let state = app.state();
    let mut batch: HashMap<String, Option<u32>> = HashMap::new();
    for (tag, value) in results {
        if let Some(id) = id_of(state, tag) {
            batch.insert(id, *value);
        }
    }
    if batch.is_empty() {
        return;
    }
    {
        let mut latency = state.latency.write();
        for (id, value) in &batch {
            latency.insert(id.clone(), *value);
        }
    }
    app.emit(Event::Latency(batch));
}

/// Переключить селектор по решению автомата.
async fn apply_switch(app: &AppHandle, api: &ClashApi, session: u64, from: &str, to: &str, reason: Reason) {
    let selected = api.select(TAG_PROXY, to).await;
    let (from_name, to_name, to_id) = {
        let state = app.state();
        if state.session.load(Ordering::SeqCst) != session {
            return;
        }
        {
            let mut guard = state.balancer.lock();
            let Some(brain) = guard.as_mut() else { return };
            match &selected {
                Ok(()) => brain.commit(to),
                Err(_) => brain.abort(),
            }
        }
        (name_of(state, from), name_of(state, to), id_of(state, to))
    };
    if let Err(e) = selected {
        log_line(app, "warn", format!("балансировщик: ядро отклонило переход на «{to_name}» ({e})"));
        return;
    }
    // С мёртвого узла соединения уносятся вместе с трафиком: им всё равно не
    // жить, а приложения, ждущие от него ответа, узнают об этом сразу.
    if matches!(reason, Reason::Dead { .. }) {
        let _ = api.close_via(from).await;
    }
    set_status(app, |s| {
        s.routed_id = to_id.unwrap_or_default();
        // Автомат перепроверит новый узел тут же (Brain::commit); до тех пор —
        // «Переподключение…».
        s.link = Link::Switching;
    });
    let text = match reason {
        Reason::Initial { gain } => format!(
            "балансировщик: первый обход — «{to_name}» быстрее «{from_name}» на {gain} мс, переключаюсь"
        ),
        Reason::Dead { fails } => format!(
            "балансировщик: «{from_name}» не ответил на {} подряд — переключаюсь на «{to_name}»",
            checks(fails)
        ),
        Reason::Faster { gain } => format!(
            "балансировщик: «{to_name}» быстрее «{from_name}» на {gain} мс два обхода подряд — переключаюсь"
        ),
        Reason::Recovered => format!(
            "балансировщик: основной сервер «{to_name}» снова отвечает — возвращаюсь на него"
        ),
        Reason::Rotation => format!("балансировщик: по кругу — следующий сервер «{to_name}»"),
    };
    log_line(app, "info", text);
}

/// Поводырь балансировщика: спрашивает автомат, что делать, и делает — меряет
/// узлы через панель ядра, переключает селектор, пишет в журнал. Живёт, пока
/// жив сеанс; без автомата (ручной выбор) просто ждёт — стратегию могут
/// включить на ходу.
fn spawn_balancer(app: AppHandle, session: u64) {
    tokio::spawn(async move {
        // Секунда ядру на собственный стартовый обход; дольше ждать незачем —
        // экран показывает «Подключение…», пока сторож не проверит сервер.
        tokio::time::sleep(Duration::from_secs(1)).await;
        loop {
            let (api, still_ours) = {
                let state = app.state();
                let ours = state.session.load(Ordering::SeqCst) == session
                    && state.status.read().state == ConnState::Connected;
                let api = state.clash.read().clone();
                (api, ours)
            };
            if !still_ours {
                return;
            }
            let Some(api) = api else { return };

            let step = {
                let state = app.state();
                let mut guard = state.balancer.lock();
                guard.as_mut().map(|brain| brain.next(Instant::now()))
            };
            match step {
                None => nap(&app, Duration::from_secs(5)).await,
                Some(Step::Idle(wait)) => nap(&app, wait.min(Duration::from_secs(5))).await,
                Some(Step::Probe(tags)) => {
                    let results = probe_tags(&app, &api, &tags).await;
                    let state = app.state();
                    if state.session.load(Ordering::SeqCst) != session {
                        return;
                    }
                    let verdict = {
                        let mut guard = state.balancer.lock();
                        guard.as_mut().and_then(|brain| {
                            brain.report_batch(&results, Instant::now());
                            // О связи судят только по проверке текущего узла:
                            // обход остальных о нём ничего не говорит.
                            let routed = brain.routed();
                            results
                                .iter()
                                .any(|(tag, _)| tag == routed)
                                .then(|| (brain.routed_alive(), brain.routed_down()))
                        })
                    };
                    publish_latency(&app, &results);
                    if let Some((alive, down)) = verdict {
                        note_link(&app, alive, down);
                    }
                }
                Some(Step::Switch { from, to, reason }) => {
                    apply_switch(&app, &api, session, &from, &to, reason).await;
                }
                Some(Step::Stranded) => {
                    let name = {
                        let state = app.state();
                        let routed = state
                            .balancer
                            .lock()
                            .as_ref()
                            .map(|brain| brain.routed().to_string())
                            .unwrap_or_default();
                        name_of(state, &routed)
                    };
                    log_line(
                        &app,
                        "warn",
                        format!("балансировщик: «{name}» не отвечает, а живых серверов среди остальных нет — остаюсь на нём"),
                    );
                }
            }
        }
    });
}

// ---------------------------------------------------------------- commands

pub async fn get_snapshot(app: AppHandle) -> Result<Snapshot> {
    let state = app.state();
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

pub async fn connect(app: AppHandle) -> Result<()> {
    // Явное подключение открывает новый эпизод: серия аварийных стартов,
    // из-за которой автоперезапуск когда-то сдался, к нему не относится.
    // Автоперезапуск сюда не заходит — он зовёт connect_inner напрямую,
    // иначе предохранитель обнулял бы сам себя.
    {
        let state = app.state();
        state.fast_crashes.store(0, Ordering::SeqCst);
    }
    connect_inner(app).await
}

async fn connect_inner(app: AppHandle) -> Result<()> {
    let (tunnel_mode, mixed_port, clash_port, node_count) = {
        let state = app.state();
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
    // VpnService is the only tunnel Android offers; a stale system-proxy
    // preference carried over from a desktop-era store must not disable it.
    #[cfg(target_os = "android")]
    let tunnel_mode = {
        let _ = tunnel_mode;
        TunnelMode::Tun
    };

    if node_count == 0 {
        return Err(AppError::msg(
            "нет ни одного сервера — добавьте ссылку vless:// или подписку",
        ));
    }
    #[cfg(not(target_os = "android"))]
    if tunnel_mode == TunnelMode::Tun && !elevate::is_elevated() {
        return Err(AppError::msg(
            "ELEVATION_REQUIRED",
        ));
    }
    // The one-time system consent dialog, before anything is torn down or
    // started: a refusal must leave the current state untouched.
    #[cfg(target_os = "android")]
    crate::core::android::prepare(&app).await?;

    // ---- ядро от прошлого сеанса -----------------------------------------
    // Оно открывает cache.db монопольно, и новое ядро десять секунд ждёт
    // блокировку, а потом уходит с «start service: initialize cache-file:
    // timeout». Снять его молча нельзя: процесс чужой, и через его туннель
    // прямо сейчас может идти трафик. Поэтому здесь только вопрос — окно
    // спрашивает, а подключение начинается заново по кнопке «Да».
    //
    // Проверка до set_status: отказ должен оставить экран ровно как был, а не
    // подвесить его на «Подключение».
    #[cfg(not(target_os = "android"))]
    {
        let (pid_file, core_exe) = {
            let state = app.state();
            let exe = state.core.lock().exe().to_path_buf();
            (state.paths.pid_file.clone(), exe)
        };
        let found = tokio::task::spawn_blocking(move || {
            crate::core::process::find_orphan(&pid_file, &core_exe)
        })
        .await
        .ok()
        .flatten();
        if let Some(orphan) = found {
            app.emit(Event::Orphan(orphan));
            return Err(AppError::msg(ORPHAN_CORE));
        }
    }

    let resolved_active = {
        let state = app.state();
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
        let state = app.state();
        state.session.fetch_add(1, Ordering::SeqCst) + 1
    };

    // ---- geo data ---------------------------------------------------------
    // Fetched here, before the core starts, so an unreachable GitHub costs the
    // user a filter rather than the whole tunnel.
    let (split, rule_dir) = {
        let state = app.state();
        let split = state.split.read().clone();
        let dir = state.paths.rule_set_dir.clone();
        (split, dir)
    };
    let sets = ruleset::ensure(&required_rule_sets(&split), &rule_dir).await;
    for failure in &sets.failures {
        let _ = app.emit(Event::Log(LogLine {
                seq: 0,
                level: "warn".into(),
                text: format!("гео-набор {failure}"),
            }));
    }

    // ---- generate + validate + spawn -------------------------------------
    let start_result: Result<u32> = (|| {
        // A still-running core keeps routing with the rules of its old config
        // while the new engines come up; an Xray node added since then would
        // loop through it. Take the tunnel down before Xray starts dialling.
        {
            let state = app.state();
            state.core.lock().stop();
        }

        // Xray first: sing-box's config references its listeners, and a node
        // pointed at a port nobody is serving would just fail on first use.
        let xray_ports = start_xray_if_needed(&app)?;

        let state = app.state();
        build_and_write(&state, &xray_ports, &sets.available)?;

        let config_path = state.paths.config_file.clone();
        let pid_path = state.paths.pid_file.clone();
        let log_app = app.clone();

        let mut core = state.core.lock();
        core.stop();
        let pid = core.start(&config_path, move |line: LogLine| {
            let _ = log_app.emit(Event::Log(line));
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
        let state = app.state();
        state.secret.clone()
    };
    let api = ClashApi::new(clash_port, &secret);

    if let Err(detail) = await_control_plane(&app, &api).await {
        shutdown(&app, &detail);
        return Err(AppError::msg(detail));
    }

    {
        let state = app.state();
        *state.clash.write() = Some(api.clone());
    }

    // ---- стартовый узел ---------------------------------------------------
    // Селектор помнит прошлый выбор в cache.db и ставит его выше `default`,
    // так что указать узел явно — единственный способ знать, через что идёт
    // трафик. У балансировщика это узел, на котором он остановился до
    // перезапуска ядра; без него — выбранный сервер.
    let (initial_tag, initial_id) = {
        let state = app.state();
        let tag = install_brain(state).or_else(|| {
            let active = state.resolve_active_id();
            state.tags.read().get(&active).cloned()
        });
        let id = tag.as_deref().and_then(|tag| id_of(state, tag));
        (tag, id)
    };
    if let Some(tag) = &initial_tag {
        if let Err(e) = api.select(TAG_PROXY, tag).await {
            log_line(&app, "warn", format!("не удалось указать стартовый сервер ({e})"));
        }
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
        s.routed_id = initial_id.unwrap_or_default();
        // Туннель поднят, но «Подключено» на экране появится после первой
        // удачной проверки сервера — её сделает сторож через секунду-другую.
        s.link = Link::Connecting;
        s.system_proxy = tunnel_mode == TunnelMode::SystemProxy;
    });

    spawn_traffic_poller(app.clone(), session);
    spawn_engine_probe(app.clone(), session);
    spawn_balancer(app.clone(), session);
    Ok(())
}

pub async fn disconnect(app: AppHandle) -> Result<()> {
    shutdown(&app, "");
    Ok(())
}

/// «Да» в окне про ядро от прошлого сеанса: снять его и подключиться.
///
/// Ищет заново — пока шёл разговор, пользователь мог снять процесс сам, а
/// номер мог достаться кому-то другому.
#[cfg(not(target_os = "android"))]
pub async fn kill_stale_core(app: AppHandle) -> Result<()> {
    use crate::core::process::Killed;

    let (pid_file, core_exe) = {
        let state = app.state();
        let exe = state.core.lock().exe().to_path_buf();
        (state.paths.pid_file.clone(), exe)
    };
    let outcome = tokio::task::spawn_blocking(move || {
        match crate::core::process::find_orphan(&pid_file, &core_exe) {
            Some(orphan) => crate::core::process::kill_orphan(&orphan, &pid_file),
            None => Killed::Gone,
        }
    })
    .await
    .unwrap_or(Killed::Denied);

    match outcome {
        Killed::Gone => connect(app).await,
        // Обычный процесс не завершает процесс с правами администратора, а
        // ядро от прошлого сеанса почти всегда запущено именно с ними.
        Killed::Denied => Err(AppError::msg(concat!(
            "не удалось завершить ядро от прошлого сеанса: у него больше прав, ",
            "чем у приложения. Перезапустите приложение от имени администратора ",
            "или снимите sing-box.exe в диспетчере задач",
        ))),
    }
}

/// Apply a change that is baked into the generated document (settings, split
/// rules) by restarting the core, but only when it is actually running.
async fn restart_if_running(app: &AppHandle) -> Result<()> {
    let running = {
        let state = app.state();
        let running = state.status.read().state == ConnState::Connected;
        running
    };
    if running {
        connect(app.clone()).await?;
    }
    Ok(())
}

pub async fn save_settings(app: AppHandle, settings: Settings) -> Result<()> {
    let tunnel_mode = settings.tunnel_mode;
    #[cfg(desktop)]
    let language_changed = {
        let state = app.state();
        let changed = state.settings.read().language != settings.language;
        changed
    };
    // Decided before the write below: afterwards both sides are the new value.
    let (tunnel_changed, balancer_changed) = {
        let state = app.state();
        let current = state.settings.read();
        (current.tunnel_changed(&settings), current.balancer_changed(&settings))
    };
    {
        let state = app.state();
        *state.settings.write() = settings;
        state.save_settings()?;
    }
    #[cfg(desktop)]
    if language_changed {
        let choice = {
            let state = app.state();
            let choice = state.settings.read().language.clone();
            choice
        };
        crate::update_tray_language(&app, &choice);
    }
    set_status(&app, |s| s.tunnel_mode = tunnel_mode);
    // A theme click or a tray preference must not drop a live connection —
    // only settings the core document is built from are worth a restart.
    if tunnel_changed {
        return restart_if_running(&app).await;
    }
    // Стратегия балансировщика живёт в приложении: переставляется на ходу,
    // ядро не перезапускается.
    if balancer_changed {
        apply_balancer_settings(&app);
    }
    Ok(())
}

pub async fn set_split(app: AppHandle, split: SplitConfig) -> Result<()> {
    {
        let state = app.state();
        *state.split.write() = split;
        state.save_split()?;
    }
    restart_if_running(&app).await
}

/// Выбрать сервер. Возвращает, пришлось ли ради этого выключить балансировщик.
pub async fn set_active_server(app: AppHandle, id: String) -> Result<bool> {
    let (api, tag, old_tag, turned_off) = {
        let state = app.state();
        {
            let nodes = state.nodes.read();
            if !nodes.iter().any(|n| n.id == id) {
                return Err(AppError::msg("сервер не найден"));
            }
        }
        // Выбор сервера руками — отказ от автоматики, как выбор конкретного
        // узла вместо группы в Hiddify: в списке подсвечен ровно один пункт,
        // и это тот, кто решает, куда идёт трафик. Иначе «самый быстрый»
        // увёл бы трафик обратно через минуту, а «с резервом» показывал бы
        // одно, делая другое. Основной для резерва выбирается наоборот:
        // сначала сервер, потом пункт «С резервом» — он берёт текущий.
        let strategy = state.settings.read().balancer;
        let turned_off = strategy != Balancer::Manual;
        if turned_off {
            state.settings.write().balancer = Balancer::Manual;
            state.save_settings()?;
        }
        let old_tag = {
            let status = state.status.read();
            let tags = state.tags.read();
            tags.get(&status.routed_id)
                .or_else(|| tags.get(&status.active_id))
                .cloned()
        };
        *state.active_id.write() = id.clone();
        state.save_ui()?;
        // Сторож переезжает на новый узел; без ядра тегов нет и сторожить нечего.
        if state.status.read().state == ConnState::Connected {
            install_brain(state);
        }
        let tag = state.tags.read().get(&id).cloned();
        let api = state.clash.read().clone();
        (api, tag, old_tag, turned_off)
    };

    let live = api.is_some() && tag.is_some();
    set_status(&app, |s| {
        s.active_id = id.clone();
        if live {
            s.routed_id = id.clone();
            // Новый узел ещё не проверен: «Переподключение…», пока сторож не
            // подтвердит, что он отвечает.
            s.link = Link::Switching;
        }
    });

    // While connected, retarget the selector instead of rebuilding the tunnel.
    if let (Some(api), Some(tag)) = (api, tag) {
        api.select(TAG_PROXY, &tag).await?;
        // Ручная смена — единственная, что рвёт соединения: селектор сам этого
        // больше не делает (config.rs), а доживать на прежнем узле им незачем.
        let stale = old_tag.filter(|old| *old != tag);
        let _ = api.close_via(stale.as_deref().unwrap_or(TAG_PROXY)).await;
    }
    if turned_off {
        log_line(&app, "info", "балансировщик выключен: сервер выбран вручную");
    }
    Ok(turned_off)
}

pub async fn set_clash_mode(app: AppHandle, mode: String) -> Result<()> {
    if !matches!(mode.as_str(), "Rule" | "Global" | "Direct") {
        return Err(AppError::msg("неизвестный режим маршрутизации"));
    }
    let api = {
        let state = app.state();
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

/// Split pasted import text into node-link material and subscription URLs.
///
/// Pasting the panel's subscription URL into the «Добавить» box is the natural
/// first move, so http(s) lines are routed into the subscription flow instead
/// of being refused with «протокол не поддерживается».
fn split_import_text(text: &str) -> (String, Vec<String>) {
    let mut sub_urls: Vec<String> = Vec::new();
    let mut plain = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            sub_urls.push(trimmed.to_string());
        } else {
            plain.push_str(line);
            plain.push('\n');
        }
    }
    (plain, sub_urls)
}

pub async fn add_links(app: AppHandle, text: String) -> Result<ImportReport> {
    let (plain, sub_urls) = split_import_text(&text);

    let report = link::parse_subscription(&plain);
    let mut added = 0;
    let mut skipped = 0;
    let mut errors = report.errors;

    {
        let state = app.state();
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

    for url in sub_urls {
        // A panel that is already registered just refreshes — pasting the
        // same URL twice must not produce a second identical subscription.
        let known = {
            let state = app.state();
            let subs = state.subs.read();
            subs.iter().find(|s| s.url == url).map(|s| s.id.clone())
        };
        let result = match known {
            Some(id) => refresh_subscription(app.clone(), id).await,
            None => {
                add_subscription(
                    app.clone(),
                    SubInput {
                        name: String::new(),
                        url: url.clone(),
                    },
                )
                .await
            }
        };
        match result {
            Ok(sub) => {
                added += sub.added;
                skipped += sub.skipped;
                errors.extend(sub.errors);
            }
            Err(e) => errors.push((url, e.to_string())),
        }
    }

    Ok(ImportReport {
        added,
        skipped,
        errors,
    })
}

pub async fn delete_server(app: AppHandle, id: String) -> Result<()> {
    {
        let state = app.state();
        state.nodes.write().retain(|n| n.id != id);
        state.latency.write().remove(&id);
        state.save_nodes()?;
        state.save_ui()?;
    }
    emit_nodes(&app);
    restart_if_running(&app).await
}

pub async fn update_server(app: AppHandle, node: ServerNode) -> Result<()> {
    {
        let state = app.state();
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
        let state = app.state();
        let nodes = state.nodes.read().clone();
        let _ = app.emit(Event::Nodes(nodes));
        state.resolve_active_id()
    };

    // Список изменился — в нём могли появиться адреса, страна которых ещё не
    // известна. Уже определённые берутся из кэша и не стоят ничего.
    let handle = app.clone();
    tokio::spawn(async move { refresh_countries(&handle).await });

    // The list just changed: it may have gained its first node, or lost the one
    // that was pinned. The core resolves this on its own when connecting, so
    // without syncing the status the UI would report "сервер не выбран" over a
    // perfectly working tunnel.
    let changed = {
        let state = app.state();
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
    let state = app.state();
    let subs = state.subs.read().clone();
    let _ = app.emit(Event::Subscriptions(subs));
}

/// Определить страны серверов и разослать их интерфейсу.
///
/// Тихо: без базы или без сети подпись просто останется без страны — ради
/// украшения списка ошибку показывать незачем.
pub async fn refresh_countries(app: &AppHandle) {
    let countries = geoip::resolve_nodes(app.state()).await;
    if !countries.is_empty() {
        app.emit(Event::Countries(countries));
    }
}

// ---------------------------------------------------------- subscriptions

/// Тело подписки и то, что панель сообщает о тарифе заголовками.
type Fetched = (String, Option<link::UserInfo>, u32, Option<String>);

/// Один заход за подпиской.
async fn fetch_once(url: &str, trust_any_cert: bool) -> Result<Fetched> {
    let client = crate::net::http_builder()
        .timeout(Duration::from_secs(30))
        // A subscription URL is normally reachable without the tunnel; going
        // through a half-configured system proxy would deadlock the refresh.
        .no_proxy()
        .danger_accept_invalid_certs(trust_any_cert)
        .user_agent("Aurora-VPN/0.1 (sing-box)")
        .build()?;

    let response = client.get(url).send().await?;
    // Ответ панели своими словами: reqwest говорит про неё «HTTP status client
    // error (404 Not Found) for url (…)», а человеку важно другое — дошли до
    // сервера, но по этому адресу подписки нет.
    let status = response.status();
    if !status.is_success() {
        let code = status.as_u16();
        return Err(AppError::msg(match code {
            404 | 410 => format!(
                "панель не знает такой ссылки ({code}) — проверьте адрес подписки, обычно его выдают заново"
            ),
            401 | 403 => {
                format!("панель не пустила по этой ссылке ({code}) — подписка закрыта или просрочена")
            }
            _ if status.is_server_error() => {
                format!("панель отвечает ошибкой ({code}) — попробуйте позже")
            }
            _ => format!("панель ответила {code}"),
        }));
    }

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
    Ok((body, usage, interval, title))
}

/// Похожа ли неудача на разговор о сертификате, а не на «сервера нет».
fn looks_like_tls(err: &AppError) -> bool {
    let text = err.to_string().to_lowercase();
    ["certificate", "cert", "tls", "ssl", "handshake", "unknownissuer", "expired"]
        .iter()
        .any(|marker| text.contains(marker))
}

/// Забрать подписку, пережив сломанный сертификат панели.
///
/// Панели на голом IP живут с сертификатом на шесть дней, и просроченный —
/// самая частая причина, по которой подписка вдруг перестаёт обновляться.
/// Поэтому на ошибке TLS запрос повторяется: сперва тем же https, но без
/// проверки сертификата — данные остаются зашифрованными, и подслушать их
/// со стороны по-прежнему нельзя, — и только если сервер вообще не говорит по
/// TLS, простым http.
///
/// Порядок именно такой не случайно: в теле подписки лежат ссылки с паролями и
/// UUID, и открытым текстом они уходят лишь тогда, когда других вариантов не
/// осталось. Ошибка возвращается исходная: она про настоящую причину, а не про
/// последнюю попытку.
async fn fetch_subscription(url: &str) -> Result<Fetched> {
    let first = fetch_once(url, false).await;
    let err = match first {
        Ok(result) => return Ok(result),
        Err(err) => err,
    };

    let Some(rest) = url.strip_prefix("https://") else {
        return Err(err);
    };
    if !looks_like_tls(&err) {
        return Err(err);
    }

    if let Ok(result) = fetch_once(url, true).await {
        return Ok(result);
    }
    fetch_once(&format!("http://{rest}"), false).await.map_err(|_| err)
}

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

pub async fn add_subscription(app: AppHandle, input: SubInput) -> Result<ImportReport> {
    let id = uuid::Uuid::new_v4().to_string();
    {
        let state = app.state();
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

pub async fn refresh_subscription(app: AppHandle, id: String) -> Result<ImportReport> {
    let url = {
        let state = app.state();
        let subs = state.subs.read();
        subs.iter()
            .find(|s| s.id == id)
            .map(|s| s.url.clone())
            .ok_or_else(|| AppError::msg("подписка не найдена"))?
    };

    let (body, usage, interval, title) = match fetch_subscription(&url).await {
        Ok(result) => result,
        Err(e) => {
            let state = app.state();
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
        let state = app.state();
        let mut nodes = state.nodes.write();

        // Preserve ids across a refresh so the pinned server and its measured
        // latency survive when the provider re-issues the same node.
        //
        // Каждый прежний id раздаётся не больше одного раза. Панели держат
        // по десятку строк с одним адресом и портом — отличаются они только
        // именем, а отпечаток у них общий, и раздача «по ключу» склеивала их
        // все в один id. Дальше рушилось всё, что этим id адресуется: выбор
        // сервера, задержка, удаление одной строки уносило соседние.
        let mut previous: HashMap<String, String> = nodes
            .iter()
            .filter(|n| n.subscription_id.as_deref() == Some(id.as_str()))
            .map(|n| (n.fingerprint_key(), n.id.clone()))
            .collect();

        nodes.retain(|n| n.subscription_id.as_deref() != Some(id.as_str()));

        for mut node in report.nodes {
            if let Some(old_id) = previous.remove(&node.fingerprint_key()) {
                node.id = old_id;
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
pub async fn refresh_all_subscriptions(app: AppHandle) -> Result<ImportReport> {
    let ids: Vec<String> = {
        let state = app.state();
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
            let state = app.state();
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
        let state = app.state();
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

pub async fn delete_subscription(app: AppHandle, id: String) -> Result<()> {
    {
        let state = app.state();
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

/// Задержка до узла, когда ядро не поднято.
///
/// Сначала рукопожатие TCP: оно меряет ровно ту дорогу, по которой пойдёт
/// трафик. Не вышло — спрашиваем ICMP: у Hysteria2 и TUIC порт на TCP молчит
/// по устройству (они целиком на UDP), и прочерк в этих строках означал не
/// «сервер лёг», а «мы не спрашивали».
async fn ping(host: &str, port: u16, timeout: Duration) -> Option<u32> {
    if let Some(ms) = tcp_ping(host, port, timeout).await {
        return Some(ms);
    }
    let Ok(Ok(mut addrs)) =
        tokio::time::timeout(timeout, tokio::net::lookup_host((host, port))).await
    else {
        return None;
    };
    let ip = addrs.find_map(|addr| match addr.ip() {
        std::net::IpAddr::V4(ip) => Some(ip),
        std::net::IpAddr::V6(_) => None,
    })?;
    // IcmpSendEcho блокирует поток на всё время ожидания — значит, не в цикле.
    tokio::task::spawn_blocking(move || crate::sys::icmp::ping(ip, timeout))
        .await
        .ok()
        .flatten()
}

/// Свободный порт: занимаем и тут же отпускаем — ядру он достанется через
/// доли секунды, а гадать номер вслепую значило бы иногда попадать в занятый.
#[cfg(not(target_os = "android"))]
fn free_port() -> Option<u16> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .ok()?
        .local_addr()
        .ok()
        .map(|addr| addr.port())
}

/// Задержки, измеренные собственным ядром, поднятым на время замера.
///
/// Рукопожатием TCP это не меряется, и дело не только в Hysteria2 с TUIC, у
/// которых его нет вовсе. На машине может быть поднят чужой туннель — другой
/// клиент на sing-tun принимает рукопожатие своим стеком, у себя в памяти, и
/// до любого сервера мира выходит 1–10 мс. Ядро же спрашивает каждый узел его
/// собственным протоколом, и отвечает настоящее время ответа.
///
/// Ядро поднимается без туннеля и без правил маршрутизации: только исходящие
/// и Clash API на свободном порту. Возвращает None, если поднять его не
/// удалось, — тогда остаётся старая дорога.
#[cfg(not(target_os = "android"))]
async fn probe_delays(
    app: &AppHandle,
    ids: &[String],
    tx: &tokio::sync::mpsc::UnboundedSender<(String, Option<u32>)>,
) -> Option<HashMap<String, Option<u32>>> {
    let (nodes, active_id, settings, exe, work_dir, rule_set_dir) = {
        let state = app.state();
        let nodes = effective_nodes(state);
        if nodes.is_empty() {
            return None;
        }
        (
            nodes,
            state.resolve_active_id(),
            state.settings.read().clone(),
            state.core.lock().exe().to_path_buf(),
            state.paths.work_dir.clone(),
            state.paths.rule_set_dir.clone(),
        )
    };

    let mut probe = settings.clone();
    // Ни туннеля, ни системного прокси: адаптер ради замера поднимать нельзя,
    // а входы замеру и не нужны — ядро дозванивается само.
    probe.tunnel_mode = TunnelMode::SystemProxy;
    probe.mixed_port = free_port()?;
    probe.clash_port = free_port()?;
    probe.allow_lan = false;
    let secret = uuid::Uuid::new_v4().to_string();
    let cache_path = work_dir.join("probe-cache.db");

    let built = config::build(&BuildInput {
        nodes: &nodes,
        active_id: &active_id,
        settings: &probe,
        // Правила разделения к замеру отношения не имеют, а ошибка в них
        // уронила бы всю проверку.
        split: &SplitConfig::default(),
        clash_secret: &secret,
        cache_path: &cache_path,
        xray_ports: &HashMap::new(),
        xray_exe: None,
        rule_sets: &HashSet::new(),
        rule_set_dir: &rule_set_dir,
    })
    .ok()?;

    let config_path = work_dir.join("probe.json");
    let work_dir_cache = cache_path.clone();
    std::fs::create_dir_all(&work_dir).ok()?;
    std::fs::write(&config_path, serde_json::to_vec(&built.json).ok()?).ok()?;

    let mut core = CoreSupervisor::new(Engine::SingBox, exe, work_dir);
    if core.start(&config_path, |_| {}).is_err() {
        let _ = std::fs::remove_file(&config_path);
        return None;
    }

    let api = ClashApi::new(probe.clash_port, &secret);
    let mut measured = HashMap::new();
    if api.wait_ready(Duration::from_secs(10)).await.is_ok() {
        let tags: HashMap<String, String> = built.tags.into_iter().collect();
        let mut tasks = Vec::new();
        for node in &nodes {
            if !ids.is_empty() && !ids.contains(&node.id) {
                continue;
            }
            let Some(tag) = tags.get(&node.id).cloned() else {
                continue;
            };
            let (api, url, id) = (api.clone(), probe.latency_url.clone(), node.id.clone());
            let tx = tx.clone();
            tasks.push(tokio::spawn(async move {
                let value = api.delay(&tag, &url, 5000).await.unwrap_or(None);
                // Каждое измерение уходит на экран сразу, не дожидаясь соседей.
                let _ = tx.send((id.clone(), value));
                (id, value)
            }));
        }
        for task in tasks {
            if let Ok((id, value)) = task.await {
                measured.insert(id, value);
            }
        }
    }

    core.stop();
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(work_dir_cache);
    (!measured.is_empty()).then_some(measured)
}

/// Отправщик измерений в интерфейс.
///
/// Значения копятся и уезжают пачками раз в 150 мс. По событию на каждое было
/// бы под сотню пересборок списка за шесть секунд — а список из сотни строк
/// собирается целиком, и вместо ощущения хода вышла бы дёрганая картинка.
fn spawn_publisher(
    app: AppHandle,
) -> (
    tokio::sync::mpsc::UnboundedSender<(String, Option<u32>)>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(String, Option<u32>)>();
    let task = tokio::spawn(async move {
        let mut batch: HashMap<String, Option<u32>> = HashMap::new();
        let mut tick = tokio::time::interval(Duration::from_millis(150));
        let flush = |batch: &mut HashMap<String, Option<u32>>| {
            if batch.is_empty() {
                return;
            }
            let ready = std::mem::take(batch);
            {
                let state = app.state();
                let mut latency = state.latency.write();
                for (id, value) in &ready {
                    latency.insert(id.clone(), *value);
                }
            }
            let _ = app.emit(Event::Latency(ready));
        };
        loop {
            tokio::select! {
                got = rx.recv() => match got {
                    Some((id, value)) => { batch.insert(id, value); }
                    // Отправитель закрылся — обход кончился.
                    None => break,
                },
                _ = tick.tick() => flush(&mut batch),
            }
        }
        flush(&mut batch);
    });
    (tx, task)
}

pub async fn test_latency(app: AppHandle, ids: Vec<String>) -> Result<HashMap<String, Option<u32>>> {
    let (targets, api, tags, url) = {
        let state = app.state();
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

    // Один узел без туннеля не меряется: ядро ради одной строки поднимать
    // дорого, а сокетом получится ложь — чужой туннель в системе (а он в
    // системе бывает) ответит на рукопожатие сам, у себя в памяти. Честнее
    // оставить прошлое значение.
    if api.is_none() && !ids.is_empty() {
        return Ok(HashMap::new());
    }

    // Строки помечаются «меряется» до начала обхода: дальше значения
    // подъезжают по одному, и видно, что работа идёт.
    let pending: HashSet<String> = targets.iter().map(|(id, _, _)| id.clone()).collect();
    let _ = app.emit(Event::Measuring(pending));
    let (tx, publisher) = spawn_publisher(app.clone());

    // Туннель не поднят — поднимаем своё ядро на время замера: только оно
    // умеет спросить каждый узел его же протоколом.
    #[cfg(not(target_os = "android"))]
    let probed = match api {
        Some(_) => None,
        None => probe_delays(&app, &ids, &tx).await,
    };
    #[cfg(target_os = "android")]
    let probed: Option<HashMap<String, Option<u32>>> = None;

    // Probe concurrently; a serial sweep over 40 nodes would take a minute.
    let mut tasks = Vec::new();
    for (id, host, port) in targets {
        let api = api.clone();
        let tag = tags.get(&id).cloned();
        let url = url.clone();
        let ready = probed.as_ref().and_then(|values| values.get(&id).copied());
        let tx = tx.clone();
        tasks.push(tokio::spawn(async move {
            let value = match (api, tag, ready) {
                // Ядро-замерщик уже ответило за этот узел — и уже показало.
                (_, _, Some(value)) => return (id, value),
                (Some(api), Some(tag), _) => api.delay(&tag, &url, 5000).await.unwrap_or(None),
                // Ядро поднято, но этого узла в его конфиге нет — список
                // сменился уже после подключения. Мерить самим нечем: в режиме
                // TUN рукопожатие TCP принимает сам туннель, у себя в памяти, и
                // до любого сервера мира получается честные с виду 1–10 мс.
                (Some(_), None, _) => None,
                _ => ping(&host, port, Duration::from_secs(5)).await,
            };
            let _ = tx.send((id.clone(), value));
            (id, value)
        }));
    }

    let mut results = HashMap::new();
    for task in tasks {
        if let Ok((id, value)) = task.await {
            results.insert(id, value);
        }
    }

    // Отправщик доживает до последней пачки и только потом закрывается.
    drop(tx);
    let _ = publisher.await;

    {
        let state = app.state();
        let mut latency = state.latency.write();
        for (id, value) in &results {
            latency.insert(id.clone(), *value);
        }
        let _ = app.emit(Event::Latency(latency.clone()));
    }
    // Узлы, за которые никто не отчитался (ядро-замерщик их пропустило),
    // не должны остаться дышащими навсегда.
    let _ = app.emit(Event::Measuring(HashSet::new()));
    Ok(results)
}

// ---------------------------------------------------------------- system

#[cfg(not(target_os = "android"))]
pub async fn list_running_apps(include_system: bool) -> Result<Vec<procs::RunningApp>> {
    // Enumerating processes touches the whole process table; keep it off the UI thread.
    tokio::task::spawn_blocking(move || procs::running_apps(include_system))
        .await
        .map_err(|e| AppError::msg(format!("не удалось получить список процессов: {e}")))
}

/// Same command, different well: a sandboxed app cannot see other processes,
/// but it can list installed packages. `path` carries the package name — the
/// value the tun inbound's include/exclude lists match on.
#[cfg(target_os = "android")]
pub async fn list_running_apps(
    app: AppHandle,
    include_system: bool,
) -> Result<Vec<procs::RunningApp>> {
    let packages = tokio::task::spawn_blocking(move || crate::core::android::list_packages(&app))
        .await
        .map_err(|e| AppError::msg(format!("не удалось получить список приложений: {e}")))??;
    Ok(packages
        .into_iter()
        .filter(|p| include_system || !p.system)
        .map(|p| procs::RunningApp {
            name: p.name,
            path: p.package,
            instances: 1,
            system: p.system,
        })
        .collect())
}

/// Live memory/CPU of the whole process family — GUI, WebView2 children, the
/// engines — so the user does not have to reassemble the total from scattered
/// Task Manager rows.
#[cfg(not(target_os = "android"))]
pub async fn resource_usage() -> Result<Vec<procs::ResourceGroup>> {
    // Enumerating processes touches the whole process table; keep it off the UI thread.
    tokio::task::spawn_blocking(procs::resource_usage)
        .await
        .map_err(|e| AppError::msg(format!("не удалось измерить потребление ресурсов: {e}")))
}

/// On Android everything already lives in this one process (libbox is
/// in-process) and the OS shows the app as a single entry — nothing to fold.
#[cfg(target_os = "android")]
pub async fn resource_usage() -> Result<Vec<procs::ResourceGroup>> {
    Ok(Vec::new())
}

pub async fn get_logs(app: AppHandle) -> Result<Vec<LogLine>> {
    let state = app.state();
    let core = state.core.lock();
    let logs = core.logs.lock();
    Ok(logs.snapshot())
}

pub async fn clear_logs(app: AppHandle) -> Result<()> {
    let state = app.state();
    let core = state.core.lock();
    core.logs.lock().clear();
    Ok(())
}

/// Render the document that *would* be used, for inspection and bug reports.
pub async fn preview_config(app: AppHandle) -> Result<String> {
    let state = app.state();
    let nodes = effective_nodes(&state);
    let settings = state.settings.read().clone();
    let split = state.split.read().clone();
    let active_id = state.resolve_active_id();

    // Preview the shape the tunnel would take, including the Xray hand-off, so
    // a bug report shows what the engines actually receive.
    #[cfg(not(target_os = "android"))]
    let xray_built = xray::build(
        &nodes,
        xray::DEFAULT_BASE_PORT,
        xray::log_level(&settings.log_level),
    )?;
    #[cfg(not(target_os = "android"))]
    let xray_ports = xray_built
        .as_ref()
        .map(|b| b.ports.clone())
        .unwrap_or_default();
    #[cfg(not(target_os = "android"))]
    let xray_exe = state.xray.lock().as_ref().map(|e| e.exe().to_path_buf());

    #[cfg(target_os = "android")]
    let xray_ports = HashMap::new();
    #[cfg(target_os = "android")]
    let xray_exe: Option<std::path::PathBuf> = None;

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
        #[cfg(target_os = "android")]
        log_file: &state.paths.log_file,
    })?;

    #[allow(unused_mut)]
    let mut text = serde_json::to_string_pretty(&built.json)?;
    #[cfg(not(target_os = "android"))]
    if let Some(xray) = xray_built {
        text.push_str("\n\n// ---- Xray (второй движок) ----\n");
        text.push_str(&serde_json::to_string_pretty(&xray.json)?);
    }
    Ok(text)
}

/// Drop every live connection so applications re-dial through the current route.
/// Useful right after changing rules, when long-lived sockets would otherwise
/// keep flowing down the old path.
pub async fn close_connections(app: AppHandle) -> Result<()> {
    let api = {
        let state = app.state();
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

/// Download ticks for an in-flight `install_update`, throttled on this side so
/// a fast connection does not flood the IPC bridge. `total` is absent when the
/// server sent no Content-Length.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProgress {
    pub downloaded: u64,
    pub total: Option<u64>,
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
    } else if cfg!(target_os = "android") {
        ".apk"
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
    // 32-bit ARM phones are still around: without their own row they would be
    // handed the x64 APK and refuse it as incompatible.
    let arch: &[&str] = match std::env::consts::ARCH {
        "aarch64" => &["aarch64", "arm64"],
        "arm" => &["arm32", "armv7"],
        _ => &["x64", "x86_64", "amd64"],
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
pub async fn check_update(app: AppHandle) -> Result<Option<UpdateInfo>> {
    let current = crate::app::VERSION.to_string();
    let api = format!("https://api.github.com/repos/{UPDATE_REPO}/releases/latest");

    let resp = crate::net::http_client()
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

/// Скачать файл целиком, дозакачивая после обрывов.
///
/// Релизы GitHub отдаёт CDN, который понимает Range, а связь при скачивании
/// рвётся нередко — особенно без туннеля, когда до GitHub доходят через
/// дросселирующего провайдера. «error decoding response body» у reqwest —
/// ровно такой обрыв посреди тела ответа, и до сих пор он был приговором всей
/// загрузке. Теперь — поводом попросить остаток с того же байта.
async fn download_resumable(
    url: &str,
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<Vec<u8>> {
    const ATTEMPTS: u32 = 6;
    let client = crate::net::http_client();
    let mut bytes: Vec<u8> = Vec::new();
    let mut total: Option<u64> = None;
    let mut last_error = String::new();
    for attempt in 1..=ATTEMPTS {
        if attempt > 1 {
            tokio::time::sleep(Duration::from_secs(2 * u64::from(attempt - 1))).await;
        }
        let mut request = client
            .get(url)
            .header("User-Agent", "aurora-vpn-updater")
            .timeout(Duration::from_secs(600));
        if !bytes.is_empty() {
            request = request.header("Range", format!("bytes={}-", bytes.len()));
        }
        let mut resp = match request.send().await.and_then(|r| r.error_for_status()) {
            Ok(resp) => resp,
            Err(e) => {
                last_error = e.to_string();
                continue;
            }
        };
        if resp.status() == reqwest::StatusCode::PARTIAL_CONTENT {
            // «bytes 1234-99999/100000»: полный размер — после косой черты.
            total = resp
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit('/').next())
                .and_then(|v| v.parse().ok())
                .or(total);
        } else {
            // Сервер докачку не понял и прислал файл с начала.
            bytes.clear();
            total = resp.content_length();
        }
        let mut broken = false;
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    bytes.extend_from_slice(&chunk);
                    progress(bytes.len() as u64, total);
                }
                Ok(None) => break,
                Err(e) => {
                    last_error = e.to_string();
                    broken = true;
                    break;
                }
            }
        }
        if !broken {
            if total.is_none_or(|t| bytes.len() as u64 >= t) {
                return Ok(bytes);
            }
            // Сервер закрыл соединение раньше конца файла — тот же обрыв.
            last_error = format!("получено {} из {} байт", bytes.len(), total.unwrap_or(0));
        }
    }
    Err(AppError::msg(format!(
        "не удалось скачать обновление ({ATTEMPTS} попыток): {last_error}. \
         Без туннеля до GitHub доходит не всегда — подключитесь и попробуйте ещё раз"
    )))
}

/// Windows: download the installer (streaming progress to the UI), release the
/// tunnel and the system proxy, then hand control to a silent NSIS install
/// (`/S /UPDATE /R`) that restarts the app when the files are replaced.
/// Elsewhere the package (or the release page) opens in the browser — .dmg and
/// .AppImage installs are inherently manual.
pub async fn install_update(app: AppHandle, url: String) -> Result<()> {
    // The URL round-trips through the WebView; accept only GitHub's own
    // release hosts rather than trusting the IPC boundary.
    let trusted = url.starts_with("https://github.com/")
        || url.starts_with("https://objects.githubusercontent.com/");
    if !trusted {
        return Err(AppError::msg("недопустимый адрес обновления"));
    }

    if !(cfg!(windows) && url.ends_with("-setup.exe")) {
        // Не наш случай на Windows: там установщик скачивается и запускается
        // сам. Остальным платформам открываем страницу релиза.
        return crate::sys::open::uri(&url)
            .map_err(|e| AppError::msg(format!("не удалось открыть страницу загрузки: {e}")));
    }

    let mut last_tick = Instant::now();
    let bytes = download_resumable(&url, |downloaded, total| {
        if last_tick.elapsed() >= Duration::from_millis(150) {
            last_tick = Instant::now();
            app.emit(Event::UpdateProgress(UpdateProgress { downloaded, total }));
        }
    })
    .await?;
    // A truncated download would install nothing but still kill the session.
    if bytes.len() < 1_000_000 {
        return Err(AppError::msg("скачанный установщик неполный — попробуйте ещё раз"));
    }
    // The closing tick is also the UI's cue to switch from «downloading» to
    // «installing».
    let done = bytes.len() as u64;
    let _ = app.emit(Event::UpdateProgress(UpdateProgress {
            downloaded: done,
            total: Some(done),
        }));

    let path = std::env::temp_dir().join("aurora-vpn-update-setup.exe");
    std::fs::write(&path, &bytes)?;

    #[cfg(windows)]
    {
        // A silent installer does not ask about a running instance — it
        // hard-kills it, skipping RunEvent::Exit. Tear the session down first
        // so the adapter, the engines and the system proxy are already
        // released whatever happens to this process afterwards.
        let was_connected = {
            let state = app.state();
            let connected = state.status.read().state == ConnState::Connected;
            connected
        };
        shutdown(&app, "");

        // Through the shell, not CreateProcess: the per-machine installer
        // carries a `requireAdministrator` manifest, and only the shell can
        // raise the UAC prompt for it (otherwise: os error 740). /S — no
        // installer UI at all; /UPDATE — existing shortcuts and WebView2 are
        // kept as they are; /R — the freshly installed build is started when
        // the copy is done (unelevated; the startup hand-off re-elevates it
        // through the autostart task when one is registered). The prompt
        // blocks until answered, hence the dedicated thread.
        let launch = tokio::task::spawn_blocking(move || {
            elevate::shell_launch(&path, Some("/S /UPDATE /R"))
        })
        .await
        .map_err(|e| AppError::msg(format!("не удалось запустить установщик: {e}")))?;
        if let Err(e) = launch {
            // The UAC prompt was declined: put the session back the way it was.
            if was_connected {
                let _ = connect(app.clone()).await;
            }
            return Err(e);
        }

        // Let the Ok cross the IPC bridge, then exit; the teardown above
        // already did the real work, and RunEvent::Exit is idempotent.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            app.exit();
        });
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new(&path)
            .spawn()
            .map_err(|e| AppError::msg(format!("не удалось запустить установщик: {e}")))?;
        // Give the installer a beat to appear, then leave through
        // RunEvent::Exit, which stops both engines and restores the proxy.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            app.exit(0);
        });
    }
    Ok(())
}

/// Reveal the main window once the interface has actually painted.
///
/// The window starts hidden: showing it earlier means the user stares at an
/// empty white WebView for a beat before the dark UI replaces it.
pub async fn app_ready(app: AppHandle) -> Result<()> {
    // Окно создаётся скрытым, а запуск в трей не создаёт его вовсе — поэтому к
    // моменту, когда интерфейс отчитался о первом кадре, показать его всегда
    // правильно.
    app.show_window();
    Ok(())
}

pub async fn get_autostart() -> Result<AutostartMode> {
    Ok(autostart::current())
}

/// Register or clear launch-at-login. Returns the mode actually in force, which
/// lets the UI correct itself if the OS refused part of the request.
pub async fn set_autostart(mode: AutostartMode) -> Result<AutostartMode> {
    // Registering the elevated variant writes to the system task store, so it
    // must not block the UI thread.
    tokio::task::spawn_blocking(move || autostart::apply(mode))
        .await
        .map_err(|e| AppError::msg(format!("не удалось изменить автозапуск: {e}")))??;
    Ok(autostart::current())
}

pub async fn is_elevated() -> Result<bool> {
    Ok(elevate::is_elevated())
}

pub async fn relaunch_elevated(app: AppHandle) -> Result<()> {
    // Order matters against the single-instance guard: `runas` only creates the
    // process after the user accepts the UAC prompt, so this instance releases
    // its lock — and the virtual adapter — long before the new one boots.
    // Флаг говорит новому процессу, что он поднялся на смену этому: сторож
    // единственного экземпляра ещё занят, и ждать его освобождения — нормально.
    elevate::relaunch_elevated(Some(crate::shell::RELAUNCH_FLAG))?;
    shutdown(&app, "");
    app.exit();
    Ok(())
}

/// Windows: open the system snip overlay in response to a PrintScreen press.
///
/// This app usually runs elevated (TUN needs it), and UIPI hides keystrokes
/// from lower-integrity listeners — so while our window has focus, the
/// Snipping Tool never learns that PrtScn was pressed and the key appears
/// dead. The webview does receive it, though, so the frontend relays the
/// press here and the overlay is launched by hand.
pub async fn open_screen_snip() -> Result<()> {
    #[cfg(windows)]
    {
        // Honour the user's «PrtScn opens Snipping Tool» switch (on by default
        // in Windows 11). When it is off, the key means «copy the screen to the
        // clipboard», which the OS handles fine even over an elevated window —
        // popping the overlay then would be worse than doing nothing.
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        let enabled = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey("Control Panel\\Keyboard")
            .and_then(|key| key.get_value::<u32, _>("PrintScreenKeyForSnippingEnabled"))
            .map(|value| value != 0)
            .unwrap_or(true);
        if enabled {
            crate::sys::open::uri("ms-screenclip:")
                .map_err(|e| AppError::msg(format!("не удалось открыть «Ножницы»: {e}")))?;
        }
    }
    Ok(())
}

pub async fn open_config_dir(app: AppHandle) -> Result<()> {
    let dir = {
        let state = app.state();
        state.store.dir().to_path_buf()
    };
    crate::sys::open::path(&dir).map_err(|e| AppError::msg(format!("не удалось открыть папку: {e}")))
}

#[cfg(test)]
mod tests {
    use super::{installer_suffix, parse_version, pick_installer_url, split_import_text};
    use serde_json::json;

    #[test]
    fn subscription_urls_are_split_from_node_links() {
        let text = "vless://uuid@host:443?type=tcp#node\n  https://panel.example:2096/subs/token  \nмусор\nhttp://plain.example/sub";
        let (plain, urls) = split_import_text(text);
        assert_eq!(
            urls,
            vec![
                "https://panel.example:2096/subs/token".to_string(),
                "http://plain.example/sub".to_string(),
            ]
        );
        assert!(plain.contains("vless://uuid@host:443"));
        assert!(plain.contains("мусор"));
        assert!(!plain.contains("panel.example"));
    }

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


