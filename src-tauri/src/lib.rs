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
        return;
    }
    // Closed to tray — the window was destroyed to free its WebView2, so a
    // click means «build it again». The frontend shows it via `app_ready`.
    if let Err(e) = create_main_window(app) {
        eprintln!("не удалось пересоздать окно: {e}");
    }
}

/// Build the main window. It is the expensive half of the app — WebView2 keeps
/// half a dozen helper processes alive for it — so the window exists only
/// while the user is looking at it: closing to tray destroys it, and the next
/// tray click lands here to build a fresh one.
///
/// Created hidden: the frontend reveals it via `app_ready` once painted, and
/// the timer below is the safety net for a frontend that fails to boot, so a
/// broken build cannot leave an invisible, unkillable app behind.
#[cfg(desktop)]
fn create_main_window(app: &AppHandle) -> tauri::Result<tauri::WebviewWindow> {
    let window = tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::default())
        .title("Aurora VPN")
        .inner_size(1120.0, 760.0)
        .min_inner_size(960.0, 640.0)
        .center()
        .decorations(false)
        .visible(false)
        .build()?;

    // Paint it in the saved theme while it is still hidden, so it never opens
    // on the previous theme's colour.
    if let Some(state) = app.try_state::<AppState>() {
        let (dark, background) = {
            let settings = state.settings.read();
            (settings.theme_dark, settings.theme_background.clone())
        };
        commands::apply_window_theme(&window, dark, &background);
    }

    // WebView2 idles at ~150 MB spread over half a dozen helper processes.
    // The Low memory-usage target keeps its caches small and collects
    // eagerly; a UI of a few static panels never feels the difference — the
    // Task Manager column does.
    #[cfg(windows)]
    let _ = window.with_webview(|webview| unsafe {
        use webview2_com::Microsoft::Web::WebView2::Win32::{
            ICoreWebView2_19, COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL,
        };
        use windows_core::Interface;

        if let Ok(core) = webview.controller().CoreWebView2() {
            if let Ok(v19) = core.cast::<ICoreWebView2_19>() {
                // 1 = Low; the bindings expose no named constants.
                let _ = v19.SetMemoryUsageTargetLevel(
                    COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL(1),
                );
            }
        }
    });

    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(8)).await;
        if let Some(window) = handle.get_webview_window("main") {
            if !window.is_visible().unwrap_or(true) {
                let _ = window.show();
            }
        }
    });

    Ok(window)
}

/// `system` resolved through the OS locale; anything unknown falls back to
/// English rather than guessing.
#[cfg(desktop)]
pub(crate) fn resolve_lang(choice: &str) -> &'static str {
    match choice {
        "ru" => "ru",
        "en" => "en",
        _ => sys_locale::get_locale()
            .map(|l| if l.to_lowercase().starts_with("ru") { "ru" } else { "en" })
            .unwrap_or("en"),
    }
}

#[cfg(desktop)]
fn tray_menu(app: &AppHandle, lang: &str) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    let [show, connect, disconnect, quit] = match lang {
        "ru" => ["Показать окно", "Подключить", "Отключить", "Выход"],
        _ => ["Show window", "Connect", "Disconnect", "Quit"],
    };
    let show = MenuItemBuilder::with_id("show", show).build(app)?;
    let connect = MenuItemBuilder::with_id("connect", connect).build(app)?;
    let disconnect = MenuItemBuilder::with_id("disconnect", disconnect).build(app)?;
    let quit = MenuItemBuilder::with_id("quit", quit).build(app)?;

    MenuBuilder::new(app)
        .items(&[&show])
        .separator()
        .items(&[&connect, &disconnect])
        .separator()
        .items(&[&quit])
        .build()
}

/// Applied live when the language setting changes — a tray that keeps speaking
/// the old language until restart would look broken.
#[cfg(desktop)]
pub(crate) fn update_tray_language(app: &AppHandle, choice: &str) {
    if let Some(tray) = app.tray_by_id("main") {
        if let Ok(menu) = tray_menu(app, resolve_lang(choice)) {
            let _ = tray.set_menu(Some(menu));
        }
    }
}

#[cfg(desktop)]
fn build_tray(app: &AppHandle, lang: &str) -> tauri::Result<()> {
    let menu = tray_menu(app, lang)?;

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

/// The name under which the single-instance plugin registers its guard: the
/// `tauri.conf.json` identifier plus the plugin's `-sim` suffix. The plugin
/// offers no way to ask, so the name is kept in sync by hand.
#[cfg(windows)]
const SINGLE_INSTANCE_MUTEX: &str = "com.aurora.vpn-sim";

/// Whether a live instance currently holds the single-instance mutex.
///
/// This is the one liveness signal that crosses the integrity-level gap: an
/// unelevated launch may not even be able to read the elevated instance's
/// executable path (which blinds the `sysinfo` scan below), but a named
/// kernel object stays observable — worst case as an access-denied error.
#[cfg(windows)]
fn single_instance_mutex_held() -> bool {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, E_ACCESSDENIED};
    use windows::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};

    unsafe {
        match OpenMutexW(
            SYNCHRONIZATION_SYNCHRONIZE,
            false,
            &HSTRING::from(SINGLE_INSTANCE_MUTEX),
        ) {
            Ok(handle) => {
                let _ = CloseHandle(handle);
                true
            }
            // Denied access still proves the mutex exists — it just belongs
            // to an instance running at a higher integrity level.
            Err(e) => e.code() == E_ACCESSDENIED,
        }
    }
}

/// Whether some other process is already running this app.
///
/// Checked before the elevated-task hand-off below, for two reasons: when an
/// instance is already up, the normal path must proceed so the single-instance
/// guard can focus its window — and asking the Task Scheduler to start the app
/// while the previous task instance is still alive would be silently ignored
/// (`MultipleInstancesPolicy: IgnoreNew`), turning the click into nothing.
#[cfg(windows)]
fn another_instance_running() -> bool {
    if single_instance_mutex_held() {
        return true;
    }

    // Fallback for the brief window in which the other instance is alive but
    // has not registered the mutex yet.
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
    #[cfg(windows)]
    {
        if sys::elevate::is_elevated() {
            // Opt in to the single-instance «show yourself» message before the
            // plugin even starts: UIPI would otherwise drop it, and a click on
            // the shortcut while the app sits in the tray would do nothing.
            sys::elevate::allow_single_instance_message();
        } else {
            // A manual launch while the elevated autostart task is registered
            // used to open an unelevated instance whose first advice was
            // «перезапустите с правами администратора». Handing the launch to
            // that task starts this same exe elevated with no UAC prompt — the
            // very ability the task was registered for.
            let already_running = another_instance_running();
            if !already_running && sys::autostart::start_elevated_task() {
                return;
            }
            if already_running {
                // The single-instance plugin is about to swallow this launch
                // in favour of the running window; that window cannot take
                // the foreground on its own, but this process may pass on
                // the right it got from the user's click.
                sys::elevate::yield_foreground();
            }
        }
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

            let (auto_connect, start_minimized, has_nodes, language) = {
                let settings = state.settings.read();
                (
                    settings.auto_connect,
                    settings.start_minimized,
                    !state.nodes.read().is_empty(),
                    settings.language.clone(),
                )
            };

            app.manage(state);
            #[cfg(desktop)]
            build_tray(&handle, resolve_lang(&language))?;
            #[cfg(not(desktop))]
            let _ = language;

            // The window is the expensive half of the app (WebView2), so it
            // only exists while the user is looking at it: a boot straight to
            // the tray creates no window at all — `show_main_window` builds
            // one on the first click.
            #[cfg(desktop)]
            if !start_minimized {
                create_main_window(&handle)?;
            }
            #[cfg(not(desktop))]
            let _ = start_minimized;

            // On Android the window comes from tauri.android.conf.json; only
            // the saved theme needs painting before the WebView shows.
            #[cfg(target_os = "android")]
            if let Some(window) = handle.get_webview_window("main") {
                let (dark, background) = {
                    let state = handle.state::<AppState>();
                    let settings = state.settings.read();
                    (settings.theme_dark, settings.theme_background.clone())
                };
                commands::apply_window_theme(&window, dark, &background);
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
                    // Destroy rather than hide: a hidden window still keeps
                    // every WebView2 helper process (and their ~100 MB)
                    // alive, and a VPN parked in the tray should cost the
                    // app and the core — not an idle browser. The next tray
                    // click builds a fresh window via `show_main_window`.
                    let window = _window.clone();
                    tauri::async_runtime::spawn(async move {
                        let _ = window.destroy();
                    });
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
            commands::resource_usage,
            commands::get_logs,
            commands::clear_logs,
            commands::preview_config,
            commands::close_connections,
            commands::is_elevated,
            commands::relaunch_elevated,
            commands::open_config_dir,
            commands::open_screen_snip,
            commands::check_update,
            commands::install_update,
        ])
        .build(tauri::generate_context!())
        .expect("не удалось инициализировать приложение");

    app.run(|app, event| match event {
        // Every window is gone, but with close-to-tray that means «parked in
        // the tray», not «quit» — quitting goes through app.exit (the tray
        // menu, the updater), which arrives here with an explicit code.
        RunEvent::ExitRequested { code: None, api, .. } => {
            let tray_resident = app
                .try_state::<AppState>()
                .map(|s| s.settings.read().close_to_tray)
                .unwrap_or(false);
            if tray_resident {
                api.prevent_exit();
            }
        }
        RunEvent::Exit => {
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
        _ => {}
    });
}
