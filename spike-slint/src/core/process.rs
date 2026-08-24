//! Supervises the sing-box child process: config validation, spawn, log capture
//! and teardown. Desktop-only — on Android the engine runs in-process (libbox)
//! and is driven by `core::android` instead.

use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use parking_lot::Mutex;

use crate::core::log::{classify, strip_ansi, LogBuffer, LogLine};
use crate::error::{AppError, Result};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Ядро живёт совсем без консоли. CREATE_NO_WINDOW дал бы то же самое на вид,
/// но материализует скрытый conhost.exe рядом с каждым движком; весь вывод и
/// так читается через пайпы, так что консоль там не нужна вовсе.
///
/// Пробовали ради другого — чтобы ядро показывалось веткой под приложением в
/// диспетчере задач. Не помогло: связь родитель-потомок сохраняется при обоих
/// флагах, а вкладка «Процессы» строит не дерево процессов, а группы по
/// приложению и собирает в них процессы того же исполняемого файла. sing-box —
/// другой файл, и веткой он не встанет ни при каких флагах. Повторять опыт
/// незачем.
#[cfg(windows)]
const DETACHED_PROCESS: u32 = 0x0000_0008;

/// Номера ядер, которые запустили мы сами.
///
/// Поиск чужого ядра (`find_orphan`) обязан их пропускать: из того же файла
/// поднимается и замер задержки, и короткие `check`/`version` — сиротой они не
/// являются ни секунды.
fn spawned() -> &'static Mutex<HashSet<u32>> {
    static SPAWNED: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();
    SPAWNED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Задание, в котором живут все наши ядра.
///
/// Единственное на процесс и намеренно течёт: система закрывает его на выходе,
/// и в этот момент `KILL_ON_JOB_CLOSE` уносит ядро с собой — как бы приложение
/// ни ушло. Без этого аварийное закрытие оставляло sing-box жить дальше: он
/// держал `cache.db` и виртуальный адаптер, и следующее подключение падало на
/// «start service: initialize cache-file: timeout».
#[cfg(windows)]
fn job() -> Option<isize> {
    use windows::core::PCWSTR;
    use windows::Win32::System::JobObjects::{
        SetInformationJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    // isize, а не HANDLE: сырой указатель не Send, а сюда приходят из разных
    // потоков. Значение всё равно неизменное, и владелец у него один — система.
    static JOB: OnceLock<isize> = OnceLock::new();
    let raw = *JOB.get_or_init(|| unsafe {
        let Ok(handle) = CreateJobObjectW(None, PCWSTR::null()) else {
            return 0;
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = SetInformationJobObject(
            handle,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const std::ffi::c_void,
            std::mem::size_of_val(&limits) as u32,
        )
        .is_ok();
        if ok {
            handle.0 as isize
        } else {
            0
        }
    });
    (raw != 0).then_some(raw)
}

/// Взять только что запущенное ядро в задание. Не получилось — не беда:
/// подстраховкой остаётся поиск осиротевшего ядра перед подключением.
#[cfg(windows)]
fn adopt_into_job(child: &Child) {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::AssignProcessToJobObject;

    let Some(raw) = job() else { return };
    unsafe {
        let _ = AssignProcessToJobObject(
            HANDLE(raw as *mut std::ffi::c_void),
            HANDLE(child.as_raw_handle()),
        );
    }
}

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
        cmd.creation_flags(DETACHED_PROCESS);
        // Both engines are Go binaries, and Go's default GC lets the heap
        // double between collections (GOGC=100). A core that mostly shuffles
        // packet buffers does not need that headroom: collect earlier, and
        // keep a soft ceiling as the backstop against runaway growth.
        cmd.env("GOGC", "40");
        cmd.env("GOMEMLIMIT", "128MiB");
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
        // Ядро уходит вместе с приложением, чем бы то ни кончилось: падением,
        // «Снять задачу», тихим установщиком. Задание — единственный способ
        // это гарантировать, у DETACHED_PROCESS такой связи нет.
        #[cfg(windows)]
        adopt_into_job(&child);
        spawned().lock().insert(pid);

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
            spawned().lock().remove(&child.id());
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

// ------------------------------------------------------------ чужое ядро

/// Ядро, пережившее прошлый сеанс приложения.
///
/// Пока оно живо, новое не поднимется: `cache.db` открывается с
/// монопольной блокировкой, и второе ядро ждёт её десять секунд, после чего
/// уходит с «start service: initialize cache-file: timeout». Виртуальный
/// адаптер такое ядро тоже держит — и продолжает гнать через себя трафик.
#[derive(Debug, Clone)]
pub struct Orphan {
    pub pid: u32,
    pub exe: PathBuf,
    /// Сколько оно уже работает, в секундах.
    pub run_secs: u64,
}

/// Чем закончилась попытка снять чужое ядро.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Killed {
    /// Процесса больше нет — блокировка отпущена.
    Gone,
    /// Не поддался. Обычно это разница в правах: ядро осталось от экземпляра
    /// с правами администратора, а снять его пробует обычный процесс.
    Denied,
}

/// Столько процесс должен прожить, чтобы попасть под подозрение.
///
/// Из того же файла запускаются `check` и `version` — секундные и наши. По
/// списку `spawned()` они уже отсеяны, но список ведётся в памяти, а гонку со
/// вторым экземпляром приложения он не покрывает.
const ORPHAN_MIN_AGE: u64 = 5;

/// Один и тот же файл?
///
/// Просто сравнить пути мало: `current_exe()` и таблица процессов могут
/// вернуть один каталог в разном регистре или в короткой форме 8.3, и строгое
/// сравнение объявляло бы чужим собственное ядро.
fn same_exe(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    if let (Ok(a), Ok(b)) = (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        if a == b {
            return true;
        }
    }
    cfg!(windows)
        && a.as_os_str().to_string_lossy().to_lowercase()
            == b.as_os_str().to_string_lossy().to_lowercase()
}

/// Найти ядро от прошлого сеанса, ничего с ним не делая.
///
/// Смотрит шире записи в `core.pid`: та теряется (аварийный выход между
/// запуском и записью, чужая уборка), а ядро остаётся. Поэтому проверяется вся
/// таблица процессов, и своим считается всё, что запущено из нашего файла.
pub fn find_orphan(pid_file: &Path, expected_exe: &Path) -> Option<Orphan> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    let recorded: Option<u32> = std::fs::read_to_string(pid_file)
        .ok()
        .and_then(|text| text.trim().parse().ok());

    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );

    let ours = spawned().lock();
    let mut best: Option<Orphan> = None;
    for (pid, proc) in sys.processes() {
        let pid = pid.as_u32();
        if ours.contains(&pid) {
            continue;
        }
        let Some(exe) = proc.exe() else { continue };
        if !same_exe(exe, expected_exe) {
            continue;
        }
        let run_secs = proc.run_time();
        if recorded != Some(pid) && run_secs < ORPHAN_MIN_AGE {
            continue;
        }
        let found = Orphan {
            pid,
            exe: exe.to_path_buf(),
            run_secs,
        };
        // Записанное в core.pid — самое достоверное; без записи берём то, что
        // живёт дольше: у сироты фора перед всем, что могло появиться потом.
        if recorded == Some(pid) {
            return Some(found);
        }
        if best.as_ref().map(|b| b.run_secs < run_secs).unwrap_or(true) {
            best = Some(found);
        }
    }
    best
}

/// Снять чужое ядро — только по явному согласию пользователя.
///
/// Ждёт подтверждения, что процесса больше нет: `kill` возвращается сразу, а
/// блокировку `cache.db` отпускает уже разборка процесса, и запуск нового ядра
/// в ту же миллисекунду упёрся бы в неё снова.
pub fn kill_orphan(orphan: &Orphan, pid_file: &Path) -> Killed {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    let target = Pid::from_u32(orphan.pid);
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );

    let alive = match sys.process(target) {
        // Номер за время разговора мог достаться кому угодно — бьём только по
        // своему файлу.
        Some(proc) if proc.exe().map(|p| same_exe(p, &orphan.exe)).unwrap_or(false) => {
            proc.kill();
            true
        }
        _ => false,
    };
    if !alive {
        let _ = std::fs::remove_file(pid_file);
        return Killed::Gone;
    }

    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[target]),
            true,
            ProcessRefreshKind::nothing(),
        );
        if sys.process(target).is_none() {
            let _ = std::fs::remove_file(pid_file);
            return Killed::Gone;
        }
    }
    // Запись оставляем: она единственный след, по которому запуск с правами
    // администратора найдёт это ядро и снимет его.
    Killed::Denied
}

/// Убрать запись о ядре, которого уже нет.
///
/// Стирается только когда процесс действительно ушёл. Прежняя уборка удаляла
/// файл всегда — в том числе когда снять ядро не удалось, и тогда сирота
/// становилась невидимой: следующий запуск, даже с правами администратора, уже
/// не знал её номера.
pub fn forget_dead_pid(pid_file: &Path, expected_exe: &Path) {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    let Ok(text) = std::fs::read_to_string(pid_file) else {
        return;
    };
    let Ok(pid) = text.trim().parse::<u32>() else {
        let _ = std::fs::remove_file(pid_file);
        return;
    };

    let target = Pid::from_u32(pid);
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let ours = sys
        .process(target)
        .and_then(|proc| proc.exe())
        .map(|exe| same_exe(exe, expected_exe))
        .unwrap_or(false);
    if !ours {
        let _ = std::fs::remove_file(pid_file);
    }
}

