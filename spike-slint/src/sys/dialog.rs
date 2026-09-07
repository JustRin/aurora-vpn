//! Системный диалог выбора файла. Нужен в двух местах — «Выбрать .exe» на
//! странице раздельного туннеля и «картинка с QR-кодом» на странице серверов, —
//! поэтому вместо крейта здесь прямой вызов `GetOpenFileNameW`: он же стоял за
//! плагином диалогов в старой сборке.

use std::path::PathBuf;

/// Блокирующий вызов: звать только из рабочего потока, иначе интерфейс замрёт
/// на всё время, пока открыт диалог.
pub fn pick_executable(title: &str) -> Option<PathBuf> {
    pick(title, "*.exe\0*.exe\0\0")
}

/// Картинка с кодом: снимок экрана, фотография, сохранённый из панели .png.
/// Форматы — те, что разбирает `qr::decode_image_file`.
pub fn pick_image(title: &str) -> Option<PathBuf> {
    pick(
        title,
        "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.webp\0*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.webp\0\0",
    )
}

/// `filter` — пары «описание\0маска\0», список закрывается ещё одним нулём.
#[cfg(windows)]
fn pick(title: &str, filter: &str) -> Option<PathBuf> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Controls::Dialogs::{
        GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OPENFILENAMEW,
    };

    let mut file = [0u16; 1024];
    let filter: Vec<u16> = filter.encode_utf16().collect();
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
fn pick(_title: &str, _filter: &str) -> Option<PathBuf> {
    None
}
