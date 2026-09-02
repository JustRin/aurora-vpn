//! Android engine driver: sing-box runs in-process as libbox inside a Kotlin
//! `VpnService`, not as a child process. This module is the Rust half of the
//! bridge — it exposes the same surface as `CoreSupervisor` (`start`, `stop`,
//! `is_running`, `version`, `logs`) so `commands.rs` drives both engines with
//! the same code.
//!
//! Control flow: `connect` → [`prepare`] (system VPN-consent dialog, once) →
//! `AndroidEngine::start` → Kotlin `VpnPlugin.start` → foreground `VpnService`
//! → libbox `StartOrReloadService(config)`. The Clash API on loopback stays
//! the control plane afterwards, exactly as on desktop.
//!
//! The tunnel also has a life of its own: home-screen widgets and the
//! quick-settings tile start it from the last generated config without any
//! Rust runtime, and the notification, the widgets and the system can stop it
//! behind Rust's back. [`watch`] subscribes to those events, [`sync_status`]
//! sends Rust's own view the other way so the widgets can show the server's
//! name and whether it answers.
//!
//! Logs: the generated config points `log.output` at a file in the work dir
//! (in-process libbox has no stdout to capture); a tail task feeds those lines
//! into the shared ring buffer and the `app://log` event stream.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::plugin::{Builder as PluginBuilder, PluginHandle, TauriPlugin};
use tauri::{AppHandle, Manager, Runtime, Wry};

use crate::core::log::{classify, LogBuffer, LogLine};
use crate::error::{AppError, Result};
use crate::state::{ConnState, Link, Status};

/// Handle to the Kotlin `VpnPlugin`, registered once at startup.
pub struct VpnHandle(pub PluginHandle<Wry>);

pub fn init() -> TauriPlugin<Wry> {
    PluginBuilder::<Wry>::new("auroravpn")
        .setup(|app, api| {
            let handle = api.register_android_plugin("com.aurora.vpn", "VpnPlugin")?;
            app.manage(VpnHandle(handle));
            Ok(())
        })
        .build()
}

fn plugin<R: Runtime>(app: &AppHandle<R>) -> Result<&VpnHandle> {
    app.try_state::<VpnHandle>()
        .map(|s| s.inner())
        .ok_or_else(|| AppError::msg("мост VPN-сервиса не инициализирован"))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartPayload {
    config_path: String,
}

#[derive(Serialize)]
struct Empty {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OkResponse {
    #[allow(dead_code)]
    ok: bool,
}

/// What the service reports about itself.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    pub running: bool,
    /// `idle` · `starting` · `running`.
    #[serde(default)]
    #[allow(dead_code)]
    pub phase: String,
    /// Present in the payload for adb-level debugging; the UI reads errors
    /// from the log pipeline instead.
    #[serde(default)]
    #[allow(dead_code)]
    pub last_error: String,
    /// Who brought the tunnel down last: `user` (notification, widget, tile),
    /// `revoked` (the system gave the VPN to another app), `core` (libbox
    /// stopped itself), `error` (the start failed) — or empty when Rust did.
    #[serde(default)]
    pub stop_reason: String,
    /// Wall clock of the moment the box came up, for the uptime clock of a
    /// tunnel Rust adopts rather than starts.
    #[serde(default)]
    pub started_at_ms: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionResponse {
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrepareResponse {
    granted: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageInfo {
    pub name: String,
    pub package: String,
    pub system: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackagesResponse {
    packages: Vec<PackageInfo>,
}

/// Ask the OS for VPN consent. Shows the system dialog on first use and
/// resolves once the user answers; instant on every subsequent call.
///
/// Runs on a blocking thread — the dialog can stay open for as long as the
/// user cares to stare at it.
pub async fn prepare(app: &AppHandle) -> Result<()> {
    let app = app.clone();
    let granted = tauri::async_runtime::spawn_blocking(move || -> Result<bool> {
        let handle = plugin(&app)?;
        let resp: PrepareResponse = handle
            .0
            .run_mobile_plugin("prepare", Empty {})
            .map_err(|e| AppError::msg(format!("запрос VPN-разрешения не удался: {e}")))?;
        Ok(resp.granted)
    })
    .await
    .map_err(|e| AppError::msg(format!("VPN-разрешение: {e}")))??;

    if !granted {
        return Err(AppError::msg(
            "система не выдала разрешение на VPN — подтвердите запрос и попробуйте ещё раз",
        ));
    }
    Ok(())
}

/// Installed launchable applications, for the split-tunnel picker.
pub fn list_packages(app: &AppHandle) -> Result<Vec<PackageInfo>> {
    let handle = plugin(app)?;
    let resp: PackagesResponse = handle
        .0
        .run_mobile_plugin("listPackages", Empty {})
        .map_err(|e| AppError::msg(format!("не удалось получить список приложений: {e}")))?;
    Ok(resp.packages)
}

// ------------------------------------------------------------- events

/// Something happened to the tunnel that Rust did not do itself.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEvent {
    /// `started` · `stopped` · `connectRequested`.
    pub kind: String,
    /// For `started`: `external` when a widget, the tile or a sticky restart
    /// brought the tunnel up.
    #[serde(default)]
    pub source: String,
    /// For `stopped`: same vocabulary as [`StatusResponse::stop_reason`].
    #[serde(default)]
    pub reason: String,
}

#[derive(Serialize)]
struct WatchPayload {
    channel: Channel<serde_json::Value>,
}

/// Keeps the subscription's channel alive for the life of the app.
pub struct ServiceWatch(#[allow(dead_code)] Channel<serde_json::Value>);

/// Subscribe to the service's events. Each one is handed to
/// `commands::on_service_event` on the async runtime: the channel callback
/// runs on whichever Kotlin thread sent the event — possibly the main one,
/// which every plugin call has to go through — so nothing may call back into
/// the plugin from inside it.
pub fn watch(app: &AppHandle) -> Result<()> {
    let handle = plugin(app)?;
    let owner = app.clone();
    let channel: Channel<serde_json::Value> = Channel::new(move |body: InvokeResponseBody| {
        match body.deserialize::<ServiceEvent>() {
            Ok(event) => {
                let app = owner.clone();
                tauri::async_runtime::spawn(async move {
                    crate::commands::on_service_event(app, event).await;
                });
            }
            Err(e) => eprintln!("событие VPN-сервиса не разобрано: {e}"),
        }
        Ok(())
    });
    handle
        .0
        .run_mobile_plugin::<OkResponse>(
            "watch",
            WatchPayload {
                channel: channel.clone(),
            },
        )
        .map_err(|e| AppError::msg(format!("не удалось подписаться на события VPN-сервиса: {e}")))?;
    app.manage(ServiceWatch(channel));
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncPayload {
    seq: u64,
    state: ConnState,
    link: Link,
    server_name: String,
    since_ms: i64,
}

/// Ordering guard for [`sync_status`]: deliveries can overtake each other on
/// the blocking pool, and the Kotlin side drops anything older than what it
/// has.
static SYNC_SEQ: AtomicU64 = AtomicU64::new(0);

/// Hand the widgets and the tile Rust's view of the connection — the server's
/// name and whether it answers, which only Rust knows. Fire-and-forget on a
/// worker thread: a plugin call goes through the Android main thread, and the
/// caller may be on it.
pub fn sync_status(app: &AppHandle, status: &Status, server_name: String) {
    let payload = SyncPayload {
        seq: SYNC_SEQ.fetch_add(1, Ordering::SeqCst) + 1,
        state: status.state,
        link: status.link,
        server_name,
        since_ms: status.since_ms.unwrap_or(0),
    };
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if let Ok(handle) = plugin(&app) {
            let _ = handle
                .0
                .run_mobile_plugin::<OkResponse>("syncStatus", payload);
        }
    });
}

// ------------------------------------------------------------- engine

pub struct AndroidEngine {
    app: AppHandle,
    log_file: PathBuf,
    /// Bumped on stop/start so an old tail task notices it has been replaced.
    tail_generation: Arc<AtomicU64>,
    pub logs: Arc<Mutex<LogBuffer>>,
}

impl AndroidEngine {
    pub fn new(app: AppHandle, log_file: PathBuf) -> Self {
        Self {
            app,
            log_file,
            tail_generation: Arc::new(AtomicU64::new(0)),
            logs: Arc::new(Mutex::new(LogBuffer::default())),
        }
    }

    pub fn version(&self) -> Result<String> {
        let handle = plugin(&self.app)?;
        let resp: VersionResponse = handle
            .0
            .run_mobile_plugin("version", Empty {})
            .map_err(|e| AppError::msg(format!("libbox недоступен: {e}")))?;
        Ok(format!(
            "sing-box version {}",
            resp.version.trim_start_matches(['v', 'V'])
        ))
    }

    /// The service's own account of itself; `None` when the bridge is down.
    pub fn status(&self) -> Option<StatusResponse> {
        let handle = plugin(&self.app).ok()?;
        handle
            .0
            .run_mobile_plugin::<StatusResponse>("status", Empty {})
            .ok()
    }

    pub fn is_running(&mut self) -> bool {
        self.status().map(|s| s.running).unwrap_or(false)
    }

    /// Hand the generated config to the service and start the tunnel. The call
    /// returns once libbox has either started or refused the config, so errors
    /// arrive as a message, not as a dead tunnel.
    pub fn start<F>(&mut self, config: &Path, on_log: F) -> Result<u32>
    where
        F: Fn(LogLine) + Send + Sync + 'static,
    {
        // Fresh file per run: the tail below reads from offset zero.
        let _ = std::fs::remove_file(&self.log_file);
        self.logs.lock().clear();

        let handle = plugin(&self.app)?;
        handle
            .0
            .run_mobile_plugin::<OkResponse>(
                "start",
                StartPayload {
                    config_path: config.to_string_lossy().into_owned(),
                },
            )
            .map_err(|e| AppError::msg(format!("не удалось запустить sing-box: {e}")))?;

        self.spawn_tail(on_log);
        Ok(0)
    }

    /// Follow the log of a tunnel this runtime did not start — a widget or the
    /// tile did. The file is left alone: it holds the session so far, and the
    /// tail starts from its beginning.
    pub fn attach<F>(&mut self, on_log: F)
    where
        F: Fn(LogLine) + Send + Sync + 'static,
    {
        self.logs.lock().clear();
        self.spawn_tail(on_log);
    }

    pub fn stop(&mut self) {
        self.tail_generation.fetch_add(1, Ordering::SeqCst);
        if let Ok(handle) = plugin(&self.app) {
            let _ = handle
                .0
                .run_mobile_plugin::<OkResponse>("stop", Empty {});
        }
    }

    /// Follow the libbox log file and feed new lines into the shared pipeline.
    fn spawn_tail<F>(&self, on_log: F)
    where
        F: Fn(LogLine) + Send + Sync + 'static,
    {
        let generation = self.tail_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let guard = Arc::clone(&self.tail_generation);
        let logs = Arc::clone(&self.logs);
        let path = self.log_file.clone();

        tauri::async_runtime::spawn(async move {
            let mut offset: u64 = 0;
            let mut carry = String::new();
            loop {
                tokio::time::sleep(Duration::from_millis(400)).await;
                if guard.load(Ordering::SeqCst) != generation {
                    return;
                }

                let Ok(mut file) = std::fs::File::open(&path) else {
                    continue;
                };
                let len = file.metadata().map(|m| m.len()).unwrap_or(0);
                if len < offset {
                    // The service replaced the file under us — start over.
                    offset = 0;
                    carry.clear();
                }
                if len == offset {
                    continue;
                }
                if file.seek(SeekFrom::Start(offset)).is_err() {
                    continue;
                }
                let mut chunk = String::new();
                let Ok(read) = file.take(len - offset).read_to_string(&mut chunk) else {
                    // A line was cut mid-UTF-8 sequence; retry on the next tick.
                    continue;
                };
                offset += read as u64;

                carry.push_str(&chunk);
                while let Some(pos) = carry.find('\n') {
                    let raw: String = carry.drain(..=pos).collect();
                    let trimmed = raw.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let (level, text) = classify(trimmed);
                    let entry = logs.lock().push(level, text);
                    on_log(entry);
                }
            }
        });
    }
}
