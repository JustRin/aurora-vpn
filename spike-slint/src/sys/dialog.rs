//! Системный диалог выбора файла. Нужен в одном месте — «Выбрать .exe» на
//! странице раздельного туннеля, — поэтому вместо крейта здесь прямой вызов
//! `GetOpenFileNameW`: он же стоял за плагином диалогов в старой сборке.

use std::path::PathBuf;

/// Блокирующий вызов: звать только из рабочего потока, иначе интерфейс замрёт
/// на всё время, пока открыт диалог.
#[cfg(windows)]
pub fn pick_executable(title: &str) -> Option<PathBuf> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Controls::Dialogs::{
        GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OPENFILENAMEW,
    };

    let mut file = [0u16; 1024];
    // Пары «описание\0маска\0», список закрывается ещё одним нулём.
    let filter: Vec<u16> = "*.exe\0*.exe\0\0".encode_utf16().collect();
    let title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();

    let mut params = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: windows::core::PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        lpstrTitle: PCWSTR(title.as_ptr()),
        // NOCHANGEDIR: диалог иначе меняет рабочую папку процесса, а от неё
        // зависит поиск ядра рядом с exe.
        Flags: OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR,
        ..Default::default()
    };

    let picked = unsafe { GetOpenFileNameW(&mut params) };
    if !picked.as_bool() {
        return None;
    }
    let end = file.iter().position(|&c| c == 0).unwrap_or(file.len());
    Some(PathBuf::from(String::from_utf16_lossy(&file[..end])))
}

#[cfg(not(windows))]
pub fn pick_executable(_title: &str) -> Option<PathBuf> {
    None
}
