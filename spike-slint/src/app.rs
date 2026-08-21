//! Ручка приложения и канал к интерфейсу.
//!
//! Раньше это давал Tauri: команда получала `AppHandle`, доставала из него
//! состояние ядра и слала события в окно. Здесь то же самое — только события
//! едут в событийный цикл Slint, а асинхронное крутится в своей рантайме
//! tokio: у Slint цикл свой и ничего про futures не знает.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use slint::ComponentHandle;

use crate::api::UpdateProgress;
use crate::core::log::LogLine;
use crate::error::{AppError, Result};
use crate::model::ServerNode;
use crate::settings::Subscription;
use crate::state::{AppState, Status, Traffic};
use crate::AppWindow;

/// Идентификатор приложения — тот же, что стоял в tauri.conf.json. По нему
/// собирается путь к настройкам, поэтому менять его нельзя: пользователь
/// потеряет накопленные серверы.
const IDENTIFIER: &str = "com.aurora.vpn";

/// Версия приложения. Один источник — package.json, оттуда её достаёт build.rs.
pub const VERSION: &str = env!("APP_VERSION");

/// Всё, что ядро сообщает интерфейсу само, без запроса. Раньше эти же семь
/// вещей ехали событиями `app://*` через мост Tauri.
pub enum Event {
    Status(Status),
    Traffic(Traffic),
    Log(LogLine),
    Nodes(Vec<ServerNode>),
    Subscriptions(Vec<Subscription>),
    Latency(HashMap<String, Option<u32>>),
    /// Адрес узла → страна.
    Countries(HashMap<String, crate::core::geoip::Country>),
    UpdateProgress(UpdateProgress),
}

/// Рантайм для всего асинхронного. Отдельные потоки, потому что главный занят
/// циклом Slint: заблокировать его на сетевом запросе — значит подвесить окно.
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

pub fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("не удалось запустить рантайм tokio")
    })
}

#[derive(Clone)]
pub struct AppHandle {
    state: Arc<AppState>,
    ui: slint::Weak<AppWindow>,
}

impl AppHandle {
    pub fn new(state: Arc<AppState>, ui: slint::Weak<AppWindow>) -> Self {
        Self { state, ui }
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Событие в интерфейс. Раскладывает его по глобалам разметки view.rs — уже
    /// в потоке цикла, куда бы ни попал вызов.
    pub fn emit(&self, event: Event) {
        self.with_ui(move |ui| crate::view::apply(ui, event));
    }

    /// Выполнить что-нибудь над окном из чужого потока.
    pub fn with_ui(&self, f: impl FnOnce(&AppWindow) + Send + 'static) {
        let _ = self.ui.upgrade_in_event_loop(move |ui| f(&ui));
    }

    /// Показать окно: оно создаётся скрытым, чтобы не мигнуть пустым кадром.
    pub fn show_window(&self) {
        self.with_ui(|ui| {
            let window = ui.window();
            window.show().ok();
            // Из трея окно возвращают уже свёрнутым — поднять и отдать фокус.
            window.set_minimized(false);
        });
    }

    /// Завершить приложение. Цикл Slint останавливается только из своего
    /// потока, поэтому через ту же очередь.
    pub fn exit(&self) {
        self.with_ui(|_| {
            let _ = slint::quit_event_loop();
        });
    }
}

/// Папка с данными пользователя. Тот же путь, что давал Tauri
/// (`app_config_dir` = `%APPDATA%\<identifier>`), чтобы приложение подхватило
/// уже накопленные серверы, подписки и настройки, а не начало с чистого листа.
pub fn config_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));

    base.map(|dir| dir.join(IDENTIFIER))
        .ok_or_else(|| AppError::msg("не удалось определить папку настроек"))
}

/// Ядро рядом с приложением.
///
/// В собранном виде sing-box лежит рядом с exe без суффикса, в дереве сборки —
/// с целевой тройкой в имени. Проверяются обе раскладки и обе папки: своя и
/// оставшаяся от сборки Tauri, пока та не убрана.
pub fn locate_core() -> Option<PathBuf> {
    locate_binary("sing-box")
}

/// Xray необязателен: без него узлы, которые умеет только он, честно скажут об
/// этом, а всё остальное продолжит работать на sing-box.
pub fn locate_xray() -> Option<PathBuf> {
    locate_binary("xray")
}

fn locate_binary(stem: &str) -> Option<PathBuf> {
    let exe_name = if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    };
    let triple = env!("TARGET_TRIPLE");
    let suffixed = if cfg!(windows) {
        format!("{stem}-{triple}.exe")
    } else {
        format!("{stem}-{triple}")
    };

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(&exe_name));
            candidates.push(dir.join(&suffixed));
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for dir in [manifest.join("binaries"), manifest.join("../src-tauri/binaries")] {
        candidates.push(dir.join(&suffixed));
        candidates.push(dir.join(&exe_name));
    }

    candidates.into_iter().find(|p| p.is_file())
}
