//! Launch-at-login.
//!
//! Windows has it in two flavours. The obvious mechanism — a value under
//! `HKCU\...\Run` — cannot start a program elevated: Windows deliberately
//! refuses to raise privileges without a UAC prompt, and there is nobody to
//! click it at logon. The only supported way to get an elevated program
//! started automatically is a Scheduled Task whose principal declares
//! `HighestAvailable`. So: normal autostart uses the Run key, elevated
//! autostart uses a task, and the two are mutually exclusive — leaving both in
//! place would launch the app twice.
//!
//! macOS (a launchd agent) and Linux (an XDG autostart entry) only have the
//! normal flavour: a login session cannot hand root to a program on its own,
//! and a root daemon has no desktop to draw on.

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Sentinel the UI matches on to offer a restart-as-administrator prompt.
#[cfg_attr(target_os = "android", allow(dead_code))]
pub const ELEVATION_REQUIRED: &str = "ELEVATION_REQUIRED";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum AutostartMode {
    #[default]
    Off,
    /// Registry `Run` value. No elevation, no UAC prompt.
    Normal,
    /// Scheduled task with highest privileges. Starts the tunnel in TUN mode
    /// without any prompt, but registering it needs administrator rights once.
    Elevated,
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    use crate::error::AppError;
    use crate::sys::elevate;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const TASK_NAME: &str = "Aurora VPN Autostart";
    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const RUN_VALUE: &str = "AuroraVPN";

    fn schtasks(args: &[&str]) -> std::io::Result<std::process::Output> {
        Command::new("schtasks")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
    }

    fn exe_path() -> Result<String> {
        Ok(std::env::current_exe()?.to_string_lossy().into_owned())
    }

    fn run_key() -> Result<winreg::RegKey> {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
        let hkcu = winreg::RegKey::predef(HKEY_CURRENT_USER);
        Ok(hkcu.open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_WRITE)?)
    }

    pub fn task_exists() -> bool {
        schtasks(&["/Query", "/TN", TASK_NAME])
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    /// The executable the registered task actually points at. The task stores
    /// an absolute path from the moment it was created; after a reinstall to a
    /// different location it would start the wrong (or no) binary.
    fn task_command() -> Option<String> {
        let out = schtasks(&["/Query", "/TN", TASK_NAME, "/XML"]).ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let start = text.find("<Command>")? + "<Command>".len();
        let end = text[start..].find("</Command>")? + start;
        Some(text[start..end].trim().trim_matches('"').to_string())
    }

    /// Start the elevated autostart task, which launches this same executable
    /// with administrator rights and **no UAC prompt** — exactly the ability
    /// the task was registered for. Returns true when the hand-off happened
    /// and the calling (unelevated) process should exit.
    pub fn start_elevated_task() -> bool {
        if !task_exists() {
            return false;
        }
        // Never delegate to a task that points at some other binary: the user
        // would see their click do nothing at all.
        let same_exe = match (task_command(), std::env::current_exe()) {
            (Some(registered), Ok(current)) => registered
                .eq_ignore_ascii_case(&current.to_string_lossy()),
            _ => false,
        };
        if !same_exe {
            return false;
        }
        schtasks(&["/Run", "/TN", TASK_NAME])
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    pub fn run_key_exists() -> bool {
        run_key()
            .map(|key| key.get_value::<String, _>(RUN_VALUE).is_ok())
            .unwrap_or(false)
    }

    fn set_run_key(enabled: bool) -> Result<()> {
        let key = run_key()?;
        if enabled {
            // Quote the path: Program Files contains a space, and an unquoted
            // value would be parsed as a command plus arguments.
            key.set_value(RUN_VALUE, &format!("\"{}\"", exe_path()?))?;
        } else if key.get_value::<String, _>(RUN_VALUE).is_ok() {
            key.delete_value(RUN_VALUE)?;
        }
        Ok(())
    }

    /// The task definition. Written as XML rather than assembled from
    /// `schtasks` switches because the switch form silently applies two
    /// defaults that are wrong for a VPN client: it stops the task after 72
    /// hours, and it refuses to start on battery.
    fn task_xml(user: &str, exe: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Автозапуск Aurora VPN с правами администратора</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{exe}"</Command>
    </Exec>
  </Actions>
</Task>
"#
        )
    }

    fn current_user() -> String {
        let domain = std::env::var("USERDOMAIN").unwrap_or_default();
        let user = std::env::var("USERNAME").unwrap_or_default();
        if domain.is_empty() {
            user
        } else {
            format!("{domain}\\{user}")
        }
    }

    fn create_task() -> Result<()> {
        if !elevate::is_elevated() {
            return Err(AppError::msg(ELEVATION_REQUIRED));
        }

        let xml = task_xml(&current_user(), &exe_path()?);
        // schtasks /XML insists on UTF-16; a UTF-8 file is rejected as malformed.
        let mut bytes = vec![0xFF, 0xFE];
        for unit in xml.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }

        let path = std::env::temp_dir().join("aurora-autostart.xml");
        std::fs::write(&path, &bytes)?;

        let output = schtasks(&[
            "/Create",
            "/TN",
            TASK_NAME,
            "/XML",
            &path.to_string_lossy(),
            "/F",
        ])
        .map_err(|e| AppError::msg(format!("не удалось вызвать планировщик задач: {e}")))?;
        let _ = std::fs::remove_file(&path);

        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(AppError::msg(format!(
                "планировщик задач отклонил запрос: {}",
                if detail.is_empty() { "неизвестная ошибка".into() } else { detail }
            )));
        }
        Ok(())
    }

    fn delete_task() -> Result<()> {
        if !task_exists() {
            return Ok(());
        }
        if !elevate::is_elevated() {
            return Err(AppError::msg(ELEVATION_REQUIRED));
        }
        let output = schtasks(&["/Delete", "/TN", TASK_NAME, "/F"])
            .map_err(|e| AppError::msg(format!("не удалось вызвать планировщик задач: {e}")))?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(AppError::msg(format!("не удалось удалить задачу: {detail}")));
        }
        Ok(())
    }

    pub fn apply(mode: AutostartMode) -> Result<()> {
        match mode {
            AutostartMode::Off => {
                delete_task()?;
                set_run_key(false)?;
            }
            AutostartMode::Normal => {
                // Drop the elevated variant first, so the two never coexist.
                delete_task()?;
                set_run_key(true)?;
            }
            AutostartMode::Elevated => {
                create_task()?;
                set_run_key(false)?;
            }
        }
        Ok(())
    }
}

/// A launchd agent in `~/Library/LaunchAgents`, loaded at every login of this
/// user. No prompt: macOS 13+ only posts a «background items added»
/// notification and lists the entry under Login Items. The AppleScript route
/// (a login item made through System Events) would first need the Automation
/// consent dialog, which reads as an intrusion for a VPN client.
#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::path::PathBuf;

    use crate::error::AppError;

    /// The bundle identifier, so Login Items shows the app's own name and icon
    /// next to the entry instead of a bare label.
    const LABEL: &str = "com.aurora.vpn";

    fn plist_path() -> Result<PathBuf> {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| AppError::msg("переменная окружения HOME не задана"))?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{LABEL}.plist")))
    }

    /// `LimitLoadToSessionType: Aqua` keeps the agent out of SSH and login
    /// screen sessions, where a windowed app cannot run. `RunAtLoad` alone,
    /// no `KeepAlive`: quitting from the tray must stay quit.
    fn plist(exe: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#,
            xml_escape(exe)
        )
    }

    pub fn task_exists() -> bool {
        false
    }

    pub fn run_key_exists() -> bool {
        plist_path().map(|path| path.is_file()).unwrap_or(false)
    }

    pub fn apply(mode: AutostartMode) -> Result<()> {
        let path = plist_path()?;
        match mode {
            AutostartMode::Off => {
                if path.exists() {
                    std::fs::remove_file(&path)?;
                }
            }
            AutostartMode::Normal => {
                // The executable inside the bundle: launchd cannot exec the
                // `.app` directory itself.
                let exe = std::env::current_exe()?;
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                std::fs::write(&path, plist(&exe.to_string_lossy()))?;
            }
            AutostartMode::Elevated => {
                return Err(AppError::msg(
                    "автозапуск с правами root на macOS не поддерживается",
                ));
            }
        }
        Ok(())
    }
}

/// An XDG autostart entry in `$XDG_CONFIG_HOME/autostart`, honoured by GNOME,
/// KDE, XFCE and the rest of the freedesktop world.
#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::path::PathBuf;

    use crate::error::AppError;

    const FILE_NAME: &str = "aurora-vpn.desktop";

    fn entry_path() -> Result<PathBuf> {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|dir| dir.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .ok_or_else(|| AppError::msg("не заданы ни XDG_CONFIG_HOME, ни HOME"))?;
        Ok(config.join("autostart").join(FILE_NAME))
    }

    /// The file the user actually has. Inside an AppImage `current_exe` points
    /// into the temporary mount, which is gone by the next login; `$APPIMAGE`
    /// names the image itself.
    fn exe_path() -> Result<PathBuf> {
        match std::env::var_os("APPIMAGE") {
            Some(image) => Ok(PathBuf::from(image)),
            None => Ok(std::env::current_exe()?),
        }
    }

    /// `Exec=` quoting per the desktop-entry spec: the argument goes in double
    /// quotes, and the four characters that stay special inside them get a
    /// backslash — doubled, because the value also passes through the file's
    /// own backslash unescaping before the quoting rule applies.
    fn exec_arg(path: &str) -> String {
        let mut out = String::from("\"");
        for ch in path.chars() {
            match ch {
                '"' | '`' | '$' => {
                    out.push_str("\\\\");
                    out.push(ch);
                }
                '\\' => out.push_str("\\\\\\\\"),
                _ => out.push(ch),
            }
        }
        out.push('"');
        out
    }

    /// The icon is installed under the binary's name by the deb/rpm bundles;
    /// an AppImage has none on the system, and the entry works without it.
    fn desktop_entry(exe: &str, icon: &str) -> String {
        format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Aurora VPN\n\
             Comment=VPN client for VLESS, VMess, Trojan, Shadowsocks, Hysteria2 and TUIC servers\n\
             Exec={}\n\
             Icon={}\n\
             Terminal=false\n\
             StartupNotify=false\n\
             X-GNOME-Autostart-enabled=true\n",
            exec_arg(exe),
            icon
        )
    }

    pub fn task_exists() -> bool {
        false
    }

    pub fn run_key_exists() -> bool {
        entry_path().map(|path| path.is_file()).unwrap_or(false)
    }

    pub fn apply(mode: AutostartMode) -> Result<()> {
        let path = entry_path()?;
        match mode {
            AutostartMode::Off => {
                if path.exists() {
                    std::fs::remove_file(&path)?;
                }
            }
            AutostartMode::Normal => {
                let exe = exe_path()?;
                let icon = std::env::current_exe()
                    .ok()
                    .and_then(|bin| bin.file_stem().map(|s| s.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| "aurora-vpn".to_string());
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                std::fs::write(&path, desktop_entry(&exe.to_string_lossy(), &icon))?;
            }
            AutostartMode::Elevated => {
                return Err(AppError::msg(
                    "автозапуск с правами root на Linux не поддерживается",
                ));
            }
        }
        Ok(())
    }
}

/// Android starts nothing at boot on the app's behalf; the settings page
/// never offers the switch there.
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod imp {
    use super::*;

    pub fn task_exists() -> bool {
        false
    }

    pub fn run_key_exists() -> bool {
        false
    }

    pub fn apply(_mode: AutostartMode) -> Result<()> {
        Err(crate::error::AppError::msg(
            "автозапуск на этой платформе не поддерживается",
        ))
    }
}

/// The three characters that would break a plist string.
#[cfg(target_os = "macos")]
fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Delegate this launch to the elevated autostart task. Windows-only: the
/// concept does not exist elsewhere.
#[cfg(windows)]
pub fn start_elevated_task() -> bool {
    imp::start_elevated_task()
}

/// What the OS is actually configured to do — not what the settings file wishes.
pub fn current() -> AutostartMode {
    if imp::task_exists() {
        AutostartMode::Elevated
    } else if imp::run_key_exists() {
        AutostartMode::Normal
    } else {
        AutostartMode::Off
    }
}

pub fn apply(mode: AutostartMode) -> Result<()> {
    imp::apply(mode)
}
