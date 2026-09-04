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
    // On Unix the TUN device needs root (or CAP_NET_ADMIN on Linux, which we
    // cannot detect portably without extra dependencies). The effective uid is
    // what the kernel consults and what `sudo` changes, so it is the one thing
    // to ask. Not `$EUID`: that is a bash-internal variable a child process
    // never sees. Not `/proc/1/root`: macOS has no /proc, so that probe
    // reported «no rights» even under sudo.
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
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
#[cfg(windows)]
pub fn relaunch_elevated() -> Result<()> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    use crate::error::AppError;

    let exe = std::env::current_exe()?;
    let file = HSTRING::from(exe.as_os_str());
    let verb = HSTRING::from("runas");

    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR::null(),
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

/// No UAC to go through here: root on Linux and macOS means `sudo` from a
/// terminal. The message spells out the exact command, because the binary is
/// not what the user sees — on macOS it is buried inside the `.app` bundle,
/// and an AppImage runs from a temporary mount rather than the file that was
/// downloaded (`$APPIMAGE` names that file).
#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<()> {
    let exe = std::env::var_os("APPIMAGE")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_exe().ok());
    let command = match exe {
        Some(path) => format!("sudo \"{}\"", path.display()),
        None => "sudo <путь к приложению>".to_string(),
    };
    Err(crate::error::AppError::msg(format!(
        "автоматическое повышение прав поддерживается только на Windows — \
         запустите приложение из терминала: {command}"
    )))
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

#[cfg(all(test, unix, not(target_os = "android")))]
mod tests {
    /// `id -u` reports the effective uid through a route that shares nothing
    /// with the libc binding, so the two agreeing is a real check — and one
    /// that holds whether or not the tests happen to run as root.
    #[test]
    fn is_elevated_agrees_with_id() {
        let out = std::process::Command::new("id")
            .arg("-u")
            .output()
            .expect("`id -u` exists on every Unix");
        let uid: u32 = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("`id -u` prints a number");
        assert_eq!(super::is_elevated(), uid == 0);
    }
}
