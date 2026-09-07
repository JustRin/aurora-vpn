//! Снимок рабочего стола — для чтения QR-кода прямо с экрана.
//!
//! Ровно то же, что делает «Ножницы»: контекст всего рабочего стола, BitBlt в
//! секцию DIB, дальше пиксели. Виртуальный экран берётся целиком, поэтому код
//! на втором мониторе находится так же, как на первом.

use crate::error::{AppError, Result};

/// Снятый экран, уже переведённый в яркость: детектору цвет не нужен, а
/// четыре байта на точку при 4K — это тридцать мегабайт впустую.
pub struct Shot {
    pub width: usize,
    pub height: usize,
    pub luma: Vec<u8>,
}

/// Вызов блокирующий и не из дешёвых — звать только из рабочего потока.
#[cfg(windows)]
pub fn capture() -> Result<Shot> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC, ReleaseDC,
        SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    };

    unsafe {
        let left = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let top = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if width <= 0 || height <= 0 {
            return Err(AppError::msg("не удалось определить размер экрана"));
        }

        let screen = GetDC(None);
        if screen.is_invalid() {
            return Err(AppError::msg("экран недоступен"));
        }
        // Всё выделенное ниже отдаётся системе обратно на любом выходе, в
        // порядке, обратном получению.
        let result = (|| -> Result<Shot> {
            let memory = CreateCompatibleDC(Some(screen));
            if memory.is_invalid() {
                return Err(AppError::msg("не удалось создать контекст рисования"));
            }
            let out = (|| -> Result<Shot> {
                let info = BITMAPINFO {
                    bmiHeader: BITMAPINFOHEADER {
                        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                        biWidth: width,
                        // Высота со знаком минус — строки сверху вниз. Без неё
                        // DIB отдаётся перевёрнутым, а зеркальный QR не читает
                        // ни один декодер.
                        biHeight: -height,
                        biPlanes: 1,
                        biBitCount: 32,
                        biCompression: BI_RGB.0,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
                let bitmap =
                    CreateDIBSection(Some(memory), &info, DIB_RGB_COLORS, &mut bits, None, 0)
                        .map_err(|e| AppError::msg(format!("не удалось выделить снимок: {e}")))?;
                let previous = SelectObject(memory, bitmap.into());
                let copied = BitBlt(memory, 0, 0, width, height, Some(screen), left, top, SRCCOPY);
                let (width, height) = (width as usize, height as usize);
                let shot = match copied {
                    // GDI отдаёт BGRA строка к строке; байт прозрачности здесь
                    // не определён и в яркости всё равно не участвует.
                    Ok(()) if !bits.is_null() => {
                        let pixels =
                            std::slice::from_raw_parts(bits as *const u8, width * height * 4);
                        crate::qr::luma_from_pixels(width, height, width * 4, 4, pixels, true)
                            .map(|luma| Shot { width, height, luma })
                            .ok_or_else(|| AppError::msg("снимок экрана пришёл обрезанным"))
                    }
                    _ => Err(AppError::msg("не удалось снять экран")),
                };
                SelectObject(memory, previous);
                let _ = DeleteObject(bitmap.into());
                shot
            })();
            let _ = DeleteDC(memory);
            out
        })();
        ReleaseDC(Some(HWND::default()), screen);
        result
    }
}

#[cfg(not(windows))]
pub fn capture() -> Result<Shot> {
    Err(AppError::msg("снимок экрана доступен только под Windows"))
}

/// Рабочая область экрана в пикселях: left, top, right, bottom — без панели
/// задач. По ней ставится полоска режима «считать с экрана»: у правого края,
/// но не под панелью.
#[cfg(windows)]
pub fn work_area() -> Option<(i32, i32, i32, i32)> {
    use windows::Win32::Foundation::RECT;
    use windows::Win32::UI::WindowsAndMessaging::{
        SystemParametersInfoW, SPI_GETWORKAREA, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
    };

    let mut area = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some((&mut area as *mut RECT).cast()),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    };
    if ok.is_err() || area.right <= area.left || area.bottom <= area.top {
        return None;
    }
    Some((area.left, area.top, area.right, area.bottom))
}

#[cfg(not(windows))]
pub fn work_area() -> Option<(i32, i32, i32, i32)> {
    None
}
