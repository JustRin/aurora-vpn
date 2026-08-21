//! Открыть что-нибудь чужими руками: папку в проводнике, ссылку в браузере,
//! системный обработчик схемы. Раньше это делал плагин Tauri; здесь хватает
//! `ShellExecuteW` — ровно то, что плагин и звал под Windows.

use std::path::Path;

use crate::error::{AppError, Result};

/// Папка (или файл) в проводнике.
pub fn path(target: &Path) -> Result<()> {
    shell_execute(&target.to_string_lossy())
}

/// Ссылка или схема вида `ms-screenclip:` — тем, чем система её открывает.
pub fn uri(target: &str) -> Result<()> {
    shell_execute(target)
}

#[cfg(windows)]
fn shell_execute(target: &str) -> Result<()> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let target = HSTRING::from(target);
    // ShellExecuteW отдаёт «код ошибки» как псевдо-HINSTANCE: всё, что больше
    // 32, — успех. Так задокументировано, наследие 16-битного API.
    let code = unsafe {
        ShellExecuteW(
            None,
            PCWSTR::null(),
            PCWSTR(target.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if code.0 as isize > 32 {
        Ok(())
    } else {
        Err(AppError::msg(format!(
            "система отказалась открывать «{target}» (код {})",
            code.0 as isize
        )))
    }
}

#[cfg(not(windows))]
fn shell_execute(target: &str) -> Result<()> {
    let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    std::process::Command::new(opener)
        .arg(target)
        .spawn()
        .map(|_| ())
        .map_err(|e| AppError::msg(format!("не удалось открыть «{target}»: {e}")))
}
