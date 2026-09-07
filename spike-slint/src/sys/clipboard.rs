//! Буфер обмена. В Slint своего API для него нет, а тянуть крейт ради этого
//! незачем: под Windows всё упирается в несколько функций user32.

use crate::error::{AppError, Result};

#[cfg(windows)]
pub fn set_text(text: &str) -> Result<()> {
    use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    // Буфер отдаётся системе вместе с завершающим нулём, в UTF-16.
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = std::mem::size_of_val(wide.as_slice());

    unsafe {
        OpenClipboard(None).map_err(|e| AppError::msg(format!("буфер обмена занят: {e}")))?;
        let result = (|| -> Result<()> {
            EmptyClipboard().map_err(|e| AppError::msg(format!("буфер обмена: {e}")))?;
            let handle: HGLOBAL = GlobalAlloc(GMEM_MOVEABLE, bytes)
                .map_err(|e| AppError::msg(format!("нет памяти под буфер: {e}")))?;
            let target = GlobalLock(handle) as *mut u16;
            if target.is_null() {
                let _ = GlobalFree(Some(handle));
                return Err(AppError::msg("не удалось закрепить буфер"));
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), target, wide.len());
            let _ = GlobalUnlock(handle);
            // С этого момента память принадлежит системе — освобождать нельзя.
            SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(handle.0)))
                .map_err(|e| AppError::msg(format!("не удалось записать в буфер: {e}")))?;
            Ok(())
        })();
        let _ = CloseClipboard();
        result
    }
}

#[cfg(not(windows))]
pub fn set_text(_text: &str) -> Result<()> {
    Err(AppError::msg("буфер обмена доступен только под Windows"))
}

/// Текст из буфера обмена. Пустая строка — там лежит не текст (картинка,
/// файлы): для кнопки «Вставить» это не ошибка, а «вставлять нечего».
#[cfg(windows)]
pub fn text() -> Result<String> {
    use windows::Win32::Foundation::HGLOBAL;
    use windows::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    };
    use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT.0 as u32).is_err() {
            return Ok(String::new());
        }
        OpenClipboard(None).map_err(|e| AppError::msg(format!("буфер обмена занят: {e}")))?;
        let result = (|| -> Result<String> {
            let handle = GetClipboardData(CF_UNICODETEXT.0 as u32)
                .map_err(|e| AppError::msg(format!("буфер обмена: {e}")))?;
            let memory = HGLOBAL(handle.0);
            let start = GlobalLock(memory) as *const u16;
            if start.is_null() {
                return Err(AppError::msg("не удалось прочитать буфер"));
            }
            // Длина считается до завершающего нуля, но не дальше самого блока:
            // владелец буфера обязан его поставить, а полагаться на это нельзя.
            let capacity = GlobalSize(memory) / 2;
            let mut length = 0usize;
            while length < capacity && *start.add(length) != 0 {
                length += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(start, length));
            let _ = GlobalUnlock(memory);
            Ok(text)
        })();
        let _ = CloseClipboard();
        result
    }
}

#[cfg(not(windows))]
pub fn text() -> Result<String> {
    Err(AppError::msg("буфер обмена доступен только под Windows"))
}
