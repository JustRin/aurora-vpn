//! System-wide proxy registration, used by the non-elevated tunnel mode.
//!
//! Whatever the machine looked like before we touched it is written to disk, not
//! just held in memory: if the process is killed — Task Manager, a crash, a
//! forced logoff — an in-memory snapshot dies with it and the user's own proxy
//! configuration is lost for good.

// Android is TUN-only; the module stays compiled (callers reference it from
// shared code paths) but nothing here ever runs.
#![cfg_attr(target_os = "android", allow(dead_code))]

use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Hosts that must never traverse the proxy, or the machine loses its own
/// loopback services and LAN devices.
pub const DEFAULT_BYPASS: &str =
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;\
172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;\
172.31.*;192.168.*;<local>";

/// The machine's proxy settings as they were before this app changed them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Previous {
    pub enable: u32,
    pub server: String,
    pub bypass: String,
}

static BACKUP_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Point the crash-safe backup at the app's data directory. Called once at
/// start-up, before anything can touch the proxy.
pub fn init(path: PathBuf) {
    let _ = BACKUP_PATH.set(path);
}

fn backup_path() -> Option<&'static PathBuf> {
    BACKUP_PATH.get()
}

fn write_backup(previous: &Previous) {
    let Some(path) = backup_path() else { return };
    if let Ok(bytes) = serde_json::to_vec_pretty(previous) {
        let _ = std::fs::write(path, bytes);
    }
}

fn read_backup() -> Option<Previous> {
    let path = backup_path()?;
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn clear_backup() {
    if let Some(path) = backup_path() {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    const INTERNET_SETTINGS: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    fn open() -> Result<RegKey> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        Ok(hkcu.open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)?)
    }

    /// WinInet caches proxy settings per process; without this broadcast, already
    /// running applications keep using the previous configuration.
    fn notify_changed() {
        use windows::Win32::Networking::WinInet::{
            InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
        };
        unsafe {
            let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
            let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
        }
    }

    fn snapshot(key: &RegKey) -> Previous {
        Previous {
            enable: key.get_value::<u32, _>("ProxyEnable").unwrap_or(0),
            server: key.get_value::<String, _>("ProxyServer").unwrap_or_default(),
            bypass: key.get_value::<String, _>("ProxyOverride").unwrap_or_default(),
        }
    }

    fn apply(key: &RegKey, previous: &Previous) -> Result<()> {
        key.set_value("ProxyServer", &previous.server)?;
        key.set_value("ProxyOverride", &previous.bypass)?;
        key.set_value("ProxyEnable", &previous.enable)?;
        Ok(())
    }

    pub fn enable(address: &str, bypass: &str) -> Result<()> {
        let key = open()?;
        // Capture once per session: a second enable without an intervening
        // disable must not overwrite the user's original values with our own.
        if read_backup().is_none() {
            write_backup(&snapshot(&key));
        }
        key.set_value("ProxyServer", &address.to_string())?;
        key.set_value("ProxyOverride", &bypass.to_string())?;
        key.set_value("ProxyEnable", &1u32)?;
        notify_changed();
        Ok(())
    }

    pub fn disable() -> Result<()> {
        let key = open()?;
        match read_backup() {
            Some(previous) => {
                apply(&key, &previous)?;
                clear_backup();
            }
            // Nothing recorded means we never enabled it; simply switch it off.
            None => key.set_value("ProxyEnable", &0u32)?,
        }
        notify_changed();
        Ok(())
    }

    pub fn is_enabled() -> bool {
        open()
            .map(|k| k.get_value::<u32, _>("ProxyEnable").unwrap_or(0) == 1)
            .unwrap_or(false)
    }

    pub fn current_server() -> String {
        open()
            .map(|k| k.get_value::<String, _>("ProxyServer").unwrap_or_default())
            .unwrap_or_default()
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn enable(_address: &str, _bypass: &str) -> Result<()> {
        Err(crate::error::AppError::msg(
            "режим системного прокси пока реализован только для Windows",
        ))
    }

    pub fn disable() -> Result<()> {
        Ok(())
    }

    pub fn is_enabled() -> bool {
        false
    }

    pub fn current_server() -> String {
        String::new()
    }
}

fn listener(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

pub fn enable(port: u16) -> Result<()> {
    imp::enable(&listener(port), DEFAULT_BYPASS)
}

pub fn disable() -> Result<()> {
    imp::disable()
}

/// Undo proxy settings left behind by a crash.
///
/// The on-disk backup is authoritative: its mere presence means a previous run
/// switched the proxy on and never got to switch it back, so every field is
/// restored verbatim. Falling back to "just turn it off" would leave our own
/// listener address sitting in the user's settings.
pub fn restore_after_crash(port: u16) -> bool {
    if read_backup().is_some() {
        return disable().is_ok();
    }
    // No backup, but the registry still points at our listener — an older build,
    // or a backup that could not be written. Switching it off at least restores
    // working networking.
    if imp::is_enabled() && imp::current_server() == listener(port) {
        return imp::disable().is_ok();
    }
    false
}
