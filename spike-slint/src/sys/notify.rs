//! Уведомления Windows — те, что складываются в центр уведомлений.
//!
//! Неупакованному приложению система показывает их только под собственным
//! идентификатором (AppUserModelID), а тот считает своим лишь тогда, когда в
//! меню «Пуск» есть ярлык с этим идентификатором внутри. Одной записи в
//! реестре не хватает: проверено — платформа молча отбрасывает уведомление и
//! даже не заводит приложение в списке источников.
//!
//! Поэтому при включении уведомлений создаётся ярлык. Он же нужен пользователю,
//! чтобы отключить наши уведомления средствами системы, а не только галочкой в
//! настройках.

use std::path::PathBuf;

use crate::error::{AppError, Result};

/// Идентификатор приложения для системы уведомлений. Меняться не должен:
/// вместе с ним потеряются и настройки уведомлений, которые сделал
/// пользователь.
const AUMID: &str = "AuroraVPN.Client";
/// Имя ярлыка в меню «Пуск» — оно же подпись над уведомлением.
const SHORTCUT: &str = "Aurora VPN.lnk";

/// Показать уведомление. Тихо: если система отказала, пользователю сообщать
/// нечего — он и так видит происходящее в самом приложении.
#[cfg(windows)]
pub fn show(title: &str, body: &str) {
    if let Err(err) = try_show(title, body) {
        // Единственный след — журнал ядра, куда пишет всё остальное.
        eprintln!("уведомление не показано: {err}");
    }
}

#[cfg(not(windows))]
pub fn show(_title: &str, _body: &str) {}

#[cfg(windows)]
fn try_show(title: &str, body: &str) -> Result<()> {
    use windows::core::HSTRING;
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

    let xml = format!(
        "<toast><visual><binding template=\"ToastGeneric\">\
         <text>{}</text><text>{}</text></binding></visual></toast>",
        escape(title),
        escape(body)
    );

    let document = XmlDocument::new().map_err(win)?;
    document.LoadXml(&HSTRING::from(xml)).map_err(win)?;
    let toast = ToastNotification::CreateToastNotification(&document).map_err(win)?;
    ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID))
        .map_err(win)?
        .Show(&toast)
        .map_err(win)
}

/// XML внутри шаблона — обычный XML: текст с амперсандом или угловой скобкой
/// сломал бы разбор, а строка приходит от ядра и может содержать что угодно.
#[cfg(windows)]
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(windows)]
fn win(err: windows::core::Error) -> AppError {
    AppError::msg(err.message())
}

/// Зарегистрировать приложение как источник уведомлений: запись в реестре плюс
/// ярлык в меню «Пуск». Обе части нужны — реестр даёт имя и значок, ярлык
/// делает идентификатор «своим» для платформы.
///
/// Вызывать можно сколько угодно: уже сделанное не переделывается.
#[cfg(windows)]
pub fn ensure_registered() -> Result<()> {
    register_identity()?;
    let path = shortcut_path()?;
    if path.is_file() {
        return Ok(());
    }
    create_shortcut(&path)
}

#[cfg(not(windows))]
pub fn ensure_registered() -> Result<()> {
    Ok(())
}

/// Имя и значок, под которыми уведомление подписано в центре уведомлений.
#[cfg(windows)]
fn register_identity() -> Result<()> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey_with_flags(format!("Software\\Classes\\AppUserModelId\\{AUMID}"), KEY_WRITE)
        .map_err(|e| AppError::msg(format!("реестр уведомлений: {e}")))?;
    key.set_value("DisplayName", &"Aurora VPN")
        .map_err(|e| AppError::msg(format!("реестр уведомлений: {e}")))?;
    if let Ok(exe) = std::env::current_exe() {
        // Значок берётся из самого приложения: отдельного .ico рядом с
        // установленным приложением может и не оказаться.
        let _ = key.set_value("IconUri", &exe.to_string_lossy().to_string());
    }
    Ok(())
}

#[cfg(windows)]
fn shortcut_path() -> Result<PathBuf> {
    let base = std::env::var_os("APPDATA")
        .ok_or_else(|| AppError::msg("не удалось определить папку меню «Пуск»"))?;
    Ok(PathBuf::from(base)
        .join("Microsoft\\Windows\\Start Menu\\Programs")
        .join(SHORTCUT))
}

/// Ярлык с зашитым AppUserModelID. Собирается через COM: свойство ярлыка
/// нельзя дописать ни через реестр, ни файлом — только хранилищем свойств.
#[cfg(windows)]
fn create_shortcut(path: &std::path::Path) -> Result<()> {
    use windows::core::{Interface, HSTRING, PWSTR};
    use windows::Win32::Storage::EnhancedStorage::PKEY_AppUserModel_ID;
    use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemAlloc, IPersistFile, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::System::Variant::VT_LPWSTR;
    use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

    let exe = std::env::current_exe()
        .map_err(|e| AppError::msg(format!("не удалось узнать путь приложения: {e}")))?;

    unsafe {
        // Уже поднятый COM отвечает RPC_E_CHANGED_MODE — это не помеха.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);

        let link: IShellLinkW =
            CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).map_err(win)?;
        link.SetPath(&HSTRING::from(exe.as_os_str())).map_err(win)?;
        if let Some(dir) = exe.parent() {
            link.SetWorkingDirectory(&HSTRING::from(dir.as_os_str()))
                .map_err(win)?;
        }

        // Строка свойства обязана лежать в памяти COM.
        //
        // Сперва здесь был обычный Vec<u16>: ярлык записывался, а через пару
        // секунд процесс падал с c0000374 — порчей кучи. Хранилище свойств
        // ярлыка распоряжается значением само и освобождает его через
        // CoTaskMemFree, а указатель из кучи Rust этому аллокатору чужой.
        //
        // По той же причине PropVariantClear здесь нет: если хранилище всё же
        // сделало свою копию, наши сорок байт останутся висеть — один раз за
        // жизнь процесса и только при первом включении уведомлений. Двойное
        // освобождение стоило бы дороже.
        let wide: Vec<u16> = AUMID.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes = std::mem::size_of_val(wide.as_slice());
        let buffer = CoTaskMemAlloc(bytes) as *mut u16;
        if buffer.is_null() {
            return Err(AppError::msg("нет памяти под свойство ярлыка"));
        }
        std::ptr::copy_nonoverlapping(wide.as_ptr(), buffer, wide.len());

        let mut value = PROPVARIANT::default();
        {
            // Разыменование ManuallyDrop внутри union — руками: само оно там
            // не применяется.
            let slot = &mut *value.Anonymous.Anonymous;
            slot.vt = VT_LPWSTR;
            slot.Anonymous.pwszVal = PWSTR(buffer);
        }

        let store: IPropertyStore = link.cast().map_err(win)?;
        store.SetValue(&PKEY_AppUserModel_ID, &value).map_err(win)?;
        store.Commit().map_err(win)?;

        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let file: IPersistFile = link.cast().map_err(win)?;
        file.Save(&HSTRING::from(path.as_os_str()), true)
            .map_err(win)?;
    }
    Ok(())
}
