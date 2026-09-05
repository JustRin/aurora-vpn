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

/// Whether a TUN interface can be created with the rights at hand: the app
/// itself is elevated, or — macOS — the core binary carries root of its own
/// (see `grant_core_root`). This is what the UI's «elevated» flag means.
pub fn tun_allowed(_core: &std::path::Path) -> bool {
    #[cfg(target_os = "macos")]
    if core_has_root(_core) {
        return true;
    }
    is_elevated()
}

/// Whether the core binary starts as root on its own: owned by root, with the
/// set-user-ID bit. That is how TUN gets its rights on macOS — the app stays
/// an ordinary process, only the core is elevated.
#[cfg(target_os = "macos")]
pub fn core_has_root(core: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(core)
        .map(|meta| meta.uid() == 0 && meta.mode() & 0o4000 != 0)
        .unwrap_or(false)
}

/// Make the core start as root: `chown root:admin` plus mode 4750. Group
/// `admin` and nothing for others, so the setuid binary can only be run by
/// accounts that could `sudo` anyway. The bit is lost whenever the file is
/// replaced — an update or a reinstall — which is why `install_update`
/// re-applies it in the same privileged step.
///
/// Why this and not a relaunch as root: a root app would keep its settings in
/// root's home, and the login-item autostart could never start it that way.
/// A setuid core works for every launch, autostart included, and the app can
/// still signal it (the real uid stays the user's).
#[cfg(target_os = "macos")]
pub fn grant_core_root(core: &std::path::Path) -> Result<()> {
    let path = shell_quote(&core.to_string_lossy());
    run_as_root(&format!("chown root:admin {path} && chmod 4750 {path}"))?;
    if !core_has_root(core) {
        return Err(crate::error::AppError::msg(
            "права на ядро не применились — проверьте, что приложение лежит в /Applications",
        ));
    }
    Ok(())
}

/// Run a shell script as root behind the system's own password dialog.
///
/// `do shell script … with administrator privileges` is Apple's supported
/// door for an app without a signed privileged helper (SMJobBless wants a
/// Developer ID this project does not have). Executed in-process through
/// NSAppleScript rather than an `osascript` child, so the dialog reads
/// «Aurora VPN wants to make changes» instead of naming osascript. Blocks
/// until the dialog is answered — call it from a blocking thread. Returns the
/// script's stdout; a non-zero exit surfaces as an error carrying stderr.
#[cfg(target_os = "macos")]
pub fn run_as_root(script: &str) -> Result<String> {
    use objc2::rc::{autoreleasepool, Retained};
    use objc2::runtime::AnyObject;
    use objc2::AnyThread;
    use objc2_foundation::{
        NSAppleScript, NSAppleScriptErrorMessage, NSAppleScriptErrorNumber, NSDictionary,
        NSNumber, NSString,
    };

    use crate::error::AppError;

    // Inside an AppleScript string literal only the backslash and the double
    // quote are special.
    let literal = script.replace('\\', "\\\\").replace('"', "\\\"");
    let source = format!("do shell script \"{literal}\" with administrator privileges");

    autoreleasepool(|_| {
        let script = NSAppleScript::initWithSource(
            NSAppleScript::alloc(),
            &NSString::from_str(&source),
        )
        .ok_or_else(|| AppError::msg("не удалось подготовить сценарий повышения прав"))?;
        let mut error: Option<Retained<NSDictionary<NSString, AnyObject>>> = None;
        // SAFETY: the out-parameter has the type the method declares.
        let result = unsafe { script.executeAndReturnError(Some(&mut error)) };
        if let Some(error) = error {
            // SAFETY: reading Foundation's exported string constants.
            let (number_key, message_key) =
                unsafe { (NSAppleScriptErrorNumber, NSAppleScriptErrorMessage) };
            let number = error
                .objectForKey(number_key)
                .and_then(|n| n.downcast_ref::<NSNumber>().map(|n| n.integerValue()))
                .unwrap_or(0);
            // -128: the user dismissed the password dialog.
            if number == -128 {
                return Err(AppError::msg("запрос пароля отменён"));
            }
            let message = error
                .objectForKey(message_key)
                .and_then(|m| m.downcast_ref::<NSString>().map(|m| m.to_string()))
                .unwrap_or_else(|| format!("ошибка {number}"));
            return Err(AppError::msg(message));
        }
        Ok(result.stringValue().map(|s| s.to_string()).unwrap_or_default())
    })
}

/// Single quotes for `sh`: the one character that needs escaping inside them
/// is the quote itself.
#[cfg(target_os = "macos")]
pub fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// The terminal command that starts this app as root — the only way up on
/// Linux and macOS, where there is no UAC to go through. Spelled out in full,
/// because the binary is not what the user sees: on macOS it is buried inside
/// the `.app` bundle, and an AppImage runs from a temporary mount rather than
/// the file that was downloaded (`$APPIMAGE` names that file). The UI shows
/// it wherever Windows would offer a relaunch.
#[cfg(all(unix, not(target_os = "android")))]
pub fn root_command() -> Option<String> {
    let exe = std::env::var_os("APPIMAGE")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_exe().ok());
    Some(match exe {
        Some(path) => format!("sudo \"{}\"", path.display()),
        None => "sudo <путь к приложению>".to_string(),
    })
}

/// Windows elevates through UAC and Android never needs to; nothing to type.
#[cfg(any(windows, target_os = "android"))]
pub fn root_command() -> Option<String> {
    None
}

#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<()> {
    let command = root_command().unwrap_or_default();
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
