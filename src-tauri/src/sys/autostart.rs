//! Launch-at-login, in two flavours.
//!
//! The obvious mechanism — a value under `HKCU\...\Run` — cannot start a program
//! elevated: Windows deliberately refuses to raise privileges without a UAC
//! prompt, and there is nobody to click it at logon. The only supported way to
//! get an elevated program started automatically is a Scheduled Task whose
//! principal declares `HighestAvailable`.
//!
//! So: normal autostart uses the Run key, elevated autostart uses a task, and
//! the two are mutually exclusive — leaving both in place would launch the app
//! twice.

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

#[cfg(not(windows))]
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
            "автозапуск пока реализован только для Windows",
        ))
    }
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
