//! Administrator/root detection and self-relaunch.
//!
//! Creating a virtual adapter is a privileged operation on every OS we target,
//! so the UI has to know up front whether TUN mode is even reachable.

use crate::error::Result;

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows::Win32::UI::Shell::IsUserAnAdmin;
    unsafe { IsUserAnAdmin().as_bool() }
}

#[cfg(target_os = "android")]
pub fn is_elevated() -> bool {
    // No elevation concept: the TUN device comes from VpnService after a
    // one-time consent dialog, which `core::android::prepare` handles.
    true
}

#[cfg(not(any(windows, target_os = "android")))]
pub fn is_elevated() -> bool {
    // On Unix the TUN device needs root (or CAP_NET_ADMIN, which we cannot
    // detect portably without extra dependencies).
    std::env::var("EUID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .map(|uid| uid == 0)
        .unwrap_or_else(|| std::path::Path::new("/proc/1/root").read_link().is_ok())
}

/// Start an executable through the shell, so a `requireAdministrator` manifest
/// is honoured with a UAC prompt. `std::process::Command` goes through
/// CreateProcess, which refuses such binaries with os error 740 — this is
/// exactly how the per-machine NSIS updater used to fail to launch.
///
/// Blocks while the UAC prompt is on screen; a declined prompt is an `Err`.
#[cfg(windows)]
pub fn shell_launch(path: &std::path::Path, args: Option<&str>) -> Result<()> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    use crate::error::AppError;

    let file = HSTRING::from(path.as_os_str());
    let params = args.map(HSTRING::from);
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR::null(),
            PCWSTR(file.as_ptr()),
            params
                .as_ref()
                .map_or(PCWSTR::null(), |p| PCWSTR(p.as_ptr())),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW reports success as a pseudo-handle strictly greater than 32.
    if result.0 as usize <= 32 {
        return Err(AppError::msg(
            "установщик не запустился — запрос прав администратора был отклонён",
        ));
    }
    Ok(())
}

/// Restart this executable with elevated rights. The caller is expected to exit
/// immediately afterwards so only one instance survives.
///
/// `args` доезжают до нового процесса как есть: ими он узнаёт, что поднялся не
/// сам по себе, а на смену уходящему.
#[cfg(windows)]
pub fn relaunch_elevated(args: Option<&str>) -> Result<()> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    use crate::error::AppError;

    let exe = std::env::current_exe()?;
    let file = HSTRING::from(exe.as_os_str());
    let verb = HSTRING::from("runas");
    let params = args.map(HSTRING::from);

    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            params
                .as_ref()
                .map_or(PCWSTR::null(), |p| PCWSTR(p.as_ptr())),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };

    // ShellExecuteW reports success as a pseudo-handle strictly greater than 32.
    if result.0 as usize <= 32 {
        return Err(AppError::msg(
            "не удалось перезапустить с правами администратора (запрос отклонён)",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn relaunch_elevated(_args: Option<&str>) -> Result<()> {
    Err(crate::error::AppError::msg(
        "автоматическое повышение прав поддерживается только на Windows — \
         запустите приложение через sudo",
    ))
}

/// Let the single-instance «show yourself» message through UIPI.
///
/// The plugin delivers a second launch as a `WM_COPYDATA` message to a hidden
/// window, and Windows silently drops window messages sent by an unelevated
/// process to an elevated one. This app usually runs elevated (the autostart
/// task, TUN mode) while the desktop shortcut starts a plain process, so
/// without this exception the running instance never hears that click.
/// Process-wide on purpose: the target is the plugin's hidden event window,
/// whose handle this code never sees.
#[cfg(windows)]
pub fn allow_single_instance_message() {
    use windows::Win32::UI::WindowsAndMessaging::{
        ChangeWindowMessageFilter, MSGFLT_ADD, WM_COPYDATA,
    };
    unsafe {
        let _ = ChangeWindowMessageFilter(WM_COPYDATA, MSGFLT_ADD);
    }
}

/// Pass this fresh launch's right to take the foreground on to whichever
/// process ends up showing the window. A process the user just started may
/// bring itself to the front; the long-running tray instance may not — its
/// `SetForegroundWindow` would be reduced to a taskbar flash.
#[cfg(windows)]
pub fn yield_foreground() {
    use windows::Win32::UI::WindowsAndMessaging::{AllowSetForegroundWindow, ASFW_ANY};
    unsafe {
        let _ = AllowSetForegroundWindow(ASFW_ANY);
    }
}
