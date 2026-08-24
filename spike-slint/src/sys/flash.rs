//! Мигание кнопки приложения в панели задач.
//!
//! Сигнал того же рода, что и уведомление, но не вместо него: уведомление
//! видно несколько секунд и только в момент показа, а мигающая кнопка ждёт
//! ровно столько, сколько нужно пользователю. Гасит её система сама, как
//! только окно выходит на передний план (FLASHW_TIMERNOFG); руками гасить
//! приходится лишь там, где окно возвращается из трея.

use slint::ComponentHandle;

use crate::AppWindow;

/// Позвать пользователя к окну: с туннелем что-то не так.
///
/// Спрятанное в трей окно не мигает и не может: кнопки в панели задач у него
/// нет. Такой случай остаётся за уведомлением.
#[cfg(windows)]
pub fn alert(ui: &AppWindow) {
    use i_slint_backend_winit::WinitWindowAccessor;
    use windows::Win32::UI::WindowsAndMessaging::{FLASHW_TIMERNOFG, FLASHW_TRAY};

    let visible = ui
        .window()
        .with_winit_window(|window| window.is_visible().unwrap_or(true))
        .unwrap_or(false);
    if !visible {
        return;
    }
    // Только кнопка в панели задач: заголовка у окна нет (decorations: false),
    // и мигать в нём нечему.
    flash(ui, FLASHW_TRAY.0 | FLASHW_TIMERNOFG.0);
}

/// Погасить мигание. Система делает это сама по выходу окна на передний план —
/// здесь остаётся дорога из трея, где «показать» и «получить фокус» происходят
/// не совсем одним действием.
#[cfg(windows)]
pub fn stop(ui: &AppWindow) {
    use windows::Win32::UI::WindowsAndMessaging::FLASHW_STOP;

    flash(ui, FLASHW_STOP.0);
}

#[cfg(windows)]
fn flash(ui: &AppWindow, flags: u32) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{FlashWindowEx, FLASHWINFO, FLASHWINFO_FLAGS};

    let Some(handle) = hwnd(ui) else { return };
    let info = FLASHWINFO {
        cbSize: std::mem::size_of::<FLASHWINFO>() as u32,
        hwnd: HWND(handle as *mut std::ffi::c_void),
        dwFlags: FLASHWINFO_FLAGS(flags),
        // Без счётчика и без таймаута: сколько мигать, решает FLASHW_TIMERNOFG.
        uCount: 0,
        dwTimeout: 0,
    };
    unsafe {
        let _ = FlashWindowEx(&info);
    }
}

#[cfg(windows)]
fn hwnd(ui: &AppWindow) -> Option<isize> {
    use i_slint_backend_winit::winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use i_slint_backend_winit::WinitWindowAccessor;

    ui.window().with_winit_window(|window| {
        let handle = window.window_handle().ok()?;
        match handle.as_raw() {
            RawWindowHandle::Win32(win32) => Some(win32.hwnd.get()),
            _ => None,
        }
    })?
}

#[cfg(not(windows))]
pub fn alert(_ui: &AppWindow) {}

#[cfg(not(windows))]
pub fn stop(_ui: &AppWindow) {}
