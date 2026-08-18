mod commands;
mod core;
mod error;
mod link;
mod model;
mod net;
mod settings;
mod state;
mod store;
mod sys;

#[cfg(desktop)]
use std::path::PathBuf;

#[cfg(desktop)]
use tauri::menu::{MenuBuilder, MenuItemBuilder};
#[cfg(desktop)]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
#[cfg(desktop)]
use tauri::WindowEvent;
#[cfg(desktop)]
use tauri::AppHandle;
use tauri::{Manager, RunEvent};

use crate::state::AppState;

/// Locate the bundled core.
///
/// Tauri strips the target-triple suffix when it installs an `externalBin`, but
/// leaves it in place during `tauri dev`, so both layouts have to be probed.
#[cfg(desktop)]
fn locate_core() -> Option<PathBuf> {
    locate_binary("sing-box")
}

/// Xray is optional: without it, nodes that need it fail with a clear message
/// while everything sing-box can handle keeps working.
#[cfg(desktop)]
fn locate_xray() -> Option<PathBuf> {
    locate_binary("xray")
}

#[cfg(desktop)]
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
    candidates.push(manifest.join("binaries").join(&suffixed));
    candidates.push(manifest.join("binaries").join(&exe_name));

    candidates.into_iter().find(|p| p.is_file())
}

#[cfg(desktop)]
fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(desktop)]
fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItemBuilder::with_id("show", "Показать окно").build(app)?;
    let connect = MenuItemBuilder::with_id("connect", "Подключить").build(app)?;
    let disconnect = MenuItemBuilder::with_id("disconnect", "Отключить").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Выход").build(app)?;

    let menu = MenuBuilder::new(app)
        .items(&[&show])
        .separator()
        .items(&[&connect, &disconnect])
        .separator()
        .items(&[&quit])
        .build()?;

    let mut builder = TrayIconBuilder::with_id("main")
        .tooltip("Aurora VPN")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            let app = app.clone();
            match event.id().as_ref() {
                "show" => show_main_window(&app),
                "connect" => {
                    tauri::async_runtime::spawn(async move {
                        let _ = commands::connect(app).await;
                    });
                }
                "disconnect" => {
                    tauri::async_runtime::spawn(async move {
                        let _ = commands::disconnect(app).await;
                    });
                }
                "quit" => {
                    // Go through the normal exit path so the core is torn down.
                    app.exit(0);
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

/// Whether some other process is already running this same executable.
///
/// Checked before the elevated-task hand-off below: when an instance is
/// already up, the normal path must proceed so the single-instance guard can
/// focus its window instead.
#[cfg(windows)]
fn another_instance_running() -> bool {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    let Ok(me) = std::env::current_exe() else {
        return false;
    };
    let my_pid = std::process::id();
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    sys.processes()
        .values()
        .any(|p| p.pid().as_u32() != my_pid && p.exe().map(|e| e == me).unwrap_or(false))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // A manual launch while the elevated autostart task is registered used to
    // open an unelevated instance whose first advice was «перезапустите с
    // правами администратора». Handing the launch to that task starts this
    // same exe elevated with no UAC prompt — the very ability the task was
    // registered for.
    #[cfg(windows)]
    if !sys::elevate::is_elevated()
        && !another_instance_running()
        && sys::autostart::start_elevated_task()
    {
        return;
    }

    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init());

    #[cfg(desktop)]
    {
        // Autostart is handled in `sys::autostart` rather than by the plugin:
        // the plugin only knows the registry Run key, which cannot start an
        // elevated process.
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // A second launch (or the elevated relaunch) just focuses the
            // instance that already owns the tunnel.
            show_main_window(app);
        }));
    }

    // The bridge to the Kotlin VpnService that hosts libbox.
    #[cfg(target_os = "android")]
    {
        builder = builder.plugin(crate::core::android::init());
    }

    let app = builder
        .setup(|app| {
            let handle = app.handle().clone();

            #[cfg(desktop)]
            let core_exe = locate_core().ok_or_else(|| {
                std::io::Error::other(
                    "не найден бинарник ядра sing-box — положите его в src-tauri/binaries",
                )
            })?;

            let config_dir = app.path().app_config_dir()?;
            #[cfg(desktop)]
            let state = AppState::new(config_dir, core_exe, locate_xray())?;
            #[cfg(target_os = "android")]
            let state = AppState::new(config_dir, handle.clone())?;

            let (auto_connect, start_minimized, theme_dark, theme_bg, has_nodes) = {
                let settings = state.settings.read();
                (
                    settings.auto_connect,
                    settings.start_minimized,
                    settings.theme_dark,
                    settings.theme_background.clone(),
                    !state.nodes.read().is_empty(),
                )
            };

            app.manage(state);
            #[cfg(desktop)]
            build_tray(&handle)?;

            // Paint the native window in the saved theme while it is still
            // hidden, so it never opens on the previous theme's colour.
            if let Some(window) = handle.get_webview_window("main") {
                commands::apply_window_theme(&window, theme_dark, &theme_bg);
            }

            // The window is configured hidden so the user never sees an unpainted
            // white WebView. The frontend reveals it via `app_ready`; this timer
            // is the safety net for a frontend that fails to boot, so a broken
            // build cannot leave an invisible, unkillable app behind.
            if !start_minimized {
                let handle = handle.clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                    if let Some(window) = handle.get_webview_window("main") {
                        if !window.is_visible().unwrap_or(true) {
                            let _ = window.show();
                        }
                    }
                });
            }

            if auto_connect && has_nodes {
                let handle = handle.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = commands::connect(handle).await;
                });
            }

            // Keep subscriptions fresh. The cadence lives in settings; this only
            // wakes up often enough to notice when one comes due.
            {
                let handle = handle.clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                    loop {
                        commands::refresh_stale_subscriptions(&handle).await;
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    }
                });
            }

            Ok(())
        })
        .on_window_event(|_window, _event| {
            // Closing to tray only makes sense where there is a tray.
            #[cfg(desktop)]
            if let WindowEvent::CloseRequested { api, .. } = _event {
                let app = _window.app_handle();
                let close_to_tray = app
                    .try_state::<AppState>()
                    .map(|s| s.settings.read().close_to_tray)
                    .unwrap_or(false);
                if close_to_tray {
                    api.prevent_close();
                    let _ = _window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_snapshot,
            commands::connect,
            commands::disconnect,
            commands::save_settings,
            commands::set_split,
            commands::set_active_server,
            commands::set_clash_mode,
            commands::add_links,
            commands::delete_server,
            commands::update_server,
            commands::add_subscription,
            commands::refresh_subscription,
            commands::refresh_all_subscriptions,
            commands::delete_subscription,
            commands::app_ready,
            commands::get_autostart,
            commands::set_autostart,
            commands::set_window_theme,
            commands::test_latency,
            commands::list_running_apps,
            commands::get_logs,
            commands::clear_logs,
            commands::preview_config,
            commands::close_connections,
            commands::is_elevated,
            commands::relaunch_elevated,
            commands::open_config_dir,
            commands::check_update,
            commands::install_update,
        ])
        .build(tauri::generate_context!())
        .expect("не удалось инициализировать приложение");

    app.run(|app, event| {
        if let RunEvent::Exit = event {
            // Last chance to release the virtual adapter and restore the proxy
            // settings; skipping this strands the user without networking.
            if let Some(state) = app.try_state::<AppState>() {
                if state.status.read().system_proxy {
                    let _ = sys::sysproxy::disable();
                }
                state.core.lock().stop();
                #[cfg(not(target_os = "android"))]
                if let Some(engine) = state.xray.lock().as_mut() {
                    engine.stop();
                }
                let _ = std::fs::remove_file(&state.paths.pid_file);
            }
        }
    });
}
