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

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    // On Unix the TUN device needs root (or CAP_NET_ADMIN, which we cannot
    // detect portably without extra dependencies).
    std::env::var("EUID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .map(|uid| uid == 0)
        .unwrap_or_else(|| std::path::Path::new("/proc/1/root").read_link().is_ok())
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

#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<()> {
    Err(crate::error::AppError::msg(
        "автоматическое повышение прав поддерживается только на Windows — \
         запустите приложение через sudo",
    ))
}
