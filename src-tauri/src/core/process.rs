//! Supervises the sing-box child process: config validation, spawn, log capture
//! and teardown. Desktop-only — on Android the engine runs in-process (libbox)
//! and is driven by `core::android` instead.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::core::log::{classify, strip_ansi, LogBuffer, LogLine};
use crate::error::{AppError, Result};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Keep the core headless — otherwise every start flashes a console window.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The two engines differ only in their command line and in how they report a
/// bad configuration, so one supervisor drives both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    SingBox,
    Xray,
}

impl Engine {
    fn run_args(self, config: &Path, workdir: &Path) -> Vec<std::ffi::OsString> {
        match self {
            Engine::SingBox => vec![
                "run".into(),
                "-c".into(),
                config.into(),
                "-D".into(),
                workdir.into(),
            ],
            Engine::Xray => vec!["run".into(), "-c".into(), config.into()],
        }
    }

    fn check_args(self, config: &Path) -> Vec<std::ffi::OsString> {
        match self {
            Engine::SingBox => vec!["check".into(), "-c".into(), config.into()],
            Engine::Xray => vec!["run".into(), "-test".into(), "-c".into(), config.into()],
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Engine::SingBox => "sing-box",
            Engine::Xray => "Xray",
        }
    }
}

pub struct CoreSupervisor {
    engine: Engine,
    exe: PathBuf,
    workdir: PathBuf,
    child: Option<Child>,
    pub logs: Arc<Mutex<LogBuffer>>,
}

impl CoreSupervisor {
    pub fn new(engine: Engine, exe: PathBuf, workdir: PathBuf) -> Self {
        Self {
            engine,
            exe,
            workdir,
            child: None,
            logs: Arc::new(Mutex::new(LogBuffer::default())),
        }
    }

    /// The binary actually spawned — sing-box has to name it in a routing rule
    /// to keep the second engine's own traffic out of the tunnel.
    pub fn exe(&self) -> &Path {
        &self.exe
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(&self.exe);
        cmd.current_dir(&self.workdir);
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd
    }

    pub fn version(&self) -> Result<String> {
        let out = self
            .base_command()
            .arg("version")
            .output()
            .map_err(|e| AppError::msg(format!("не удалось запустить ядро: {e}")))?;
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(text.lines().next().unwrap_or("").trim().to_string())
    }

    /// Validate before spawning so configuration mistakes surface as a readable
    /// message instead of a core that dies half a second after connect.
    pub fn check_config(&self, config: &Path) -> Result<()> {
        let out = self
            .base_command()
            .args(self.engine.check_args(config))
            .output()
            .map_err(|e| AppError::msg(format!("не удалось запустить проверку конфига: {e}")))?;

        if out.status.success() {
            return Ok(());
        }
        let mut detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if detail.is_empty() {
            detail = String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
        Err(AppError::msg(format!(
            "{} отклонил конфигурацию: {}",
            self.engine.label(),
            strip_ansi(&detail)
        )))
    }

    pub fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// Spawn the core. `on_log` is invoked for every captured line, from a
    /// dedicated reader thread.
    pub fn start<F>(&mut self, config: &Path, on_log: F) -> Result<u32>
    where
        F: Fn(LogLine) + Send + Sync + 'static,
    {
        if self.is_running() {
            return Err(AppError::msg("ядро уже запущено"));
        }
        self.check_config(config)?;

        let mut child = self
            .base_command()
            .args(self.engine.run_args(config, &self.workdir))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                AppError::msg(format!("не удалось запустить {}: {e}", self.engine.label()))
            })?;

        let pid = child.id();
        let on_log = Arc::new(on_log);

        // sing-box splits its output across both streams depending on the level.
        for stream in [
            child.stdout.take().map(Streams::Out),
            child.stderr.take().map(Streams::Err),
        ]
        .into_iter()
        .flatten()
        {
            let logs = Arc::clone(&self.logs);
            let sink = Arc::clone(&on_log);
            std::thread::spawn(move || {
                let reader: Box<dyn BufRead> = match stream {
                    Streams::Out(s) => Box::new(BufReader::new(s)),
                    Streams::Err(s) => Box::new(BufReader::new(s)),
                };
                for line in reader.lines() {
                    let Ok(raw) = line else { break };
                    if raw.trim().is_empty() {
                        continue;
                    }
                    let (level, text) = classify(&raw);
                    let entry = logs.lock().push(level, text);
                    sink(entry);
                }
            });
        }

        self.child = Some(child);
        Ok(pid)
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            // Reap it so the TUN adapter handle is released before we return.
            let _ = child.wait();
        }
    }
}

enum Streams {
    Out(std::process::ChildStdout),
    Err(std::process::ChildStderr),
}

impl Drop for CoreSupervisor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Kill a core left behind by a crash, so its virtual adapter does not block a
/// fresh start. Only processes whose executable matches ours are touched.
pub fn kill_orphan(pid_file: &Path, expected_exe: &Path) {
    let Ok(text) = std::fs::read_to_string(pid_file) else {
        return;
    };
    let Ok(pid) = text.trim().parse::<u32>() else {
        let _ = std::fs::remove_file(pid_file);
        return;
    };

    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
    let mut sys = System::new();
    let target = Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing().with_exe(sysinfo::UpdateKind::Always),
    );

    if let Some(proc) = sys.process(target) {
        let same_binary = proc
            .exe()
            .map(|p| p == expected_exe)
            .unwrap_or(false);
        if same_binary {
            proc.kill();
        }
    }
    let _ = std::fs::remove_file(pid_file);
}

