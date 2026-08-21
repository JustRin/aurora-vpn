//! Enumerates running applications so the split-tunnelling picker can offer real
//! choices instead of asking the user to type executable names from memory —
//! and measures this app's own process family for the in-app resource monitor.

#[cfg(not(target_os = "android"))]
use std::collections::HashMap;
#[cfg(not(target_os = "android"))]
use std::sync::LazyLock;

#[cfg(not(target_os = "android"))]
use parking_lot::Mutex;
use serde::Serialize;
#[cfg(not(target_os = "android"))]
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningApp {
    /// Executable file name, which is what sing-box matches on.
    pub name: String,
    pub path: String,
    /// How many live processes share this executable (Chrome-style multi-process
    /// apps would otherwise fill the list with duplicates).
    pub instances: usize,
    pub system: bool,
}

/// Heuristic: binaries living under the Windows directory are OS plumbing rather
/// than something a user would knowingly route.
#[cfg(not(target_os = "android"))]
fn looks_like_system(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.starts_with("c:\\windows\\")
        || lower.starts_with("/usr/lib")
        || lower.starts_with("/system/")
}

// On Android the split-tunnel picker asks the Kotlin side for installed
// packages instead (`commands::list_running_apps`) — only the payload struct
// above is shared.

#[cfg(not(target_os = "android"))]
pub fn running_apps(include_system: bool) -> Vec<RunningApp> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );

    let mut merged: HashMap<String, RunningApp> = HashMap::new();

    for process in sys.processes().values() {
        let Some(exe) = process.exe() else { continue };
        let path = exe.to_string_lossy().to_string();
        if path.is_empty() {
            continue;
        }
        let name = exe
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }

        let system = looks_like_system(&path);
        if system && !include_system {
            continue;
        }

        merged
            .entry(path.to_lowercase())
            .and_modify(|a| a.instances += 1)
            .or_insert(RunningApp {
                name,
                path,
                instances: 1,
                system,
            });
    }

    let mut apps: Vec<RunningApp> = merged.into_values().collect();
    apps.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then(a.path.cmp(&b.path))
    });
    apps
}

/// One row of the in-app resource monitor: the app is really a family of
/// processes (GUI, WebView2 renderers, the engines), folded here into a
/// handful of readable groups.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceGroup {
    pub id: &'static str,
    pub processes: usize,
    /// Resident memory, bytes.
    pub memory: u64,
    /// Share of the whole machine, like the Task Manager CPU column.
    pub cpu: f32,
}

/// Kept alive between calls: sysinfo derives per-process CPU from the delta
/// against the previous refresh, so a fresh `System` would always report 0%.
#[cfg(not(target_os = "android"))]
static MONITOR: LazyLock<Mutex<System>> = LazyLock::new(|| Mutex::new(System::new()));

#[cfg(not(target_os = "android"))]
pub fn resource_usage() -> Vec<ResourceGroup> {
    let mut sys = MONITOR.lock();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_memory().with_cpu(),
    );

    // Child index over the whole table, to collect this process's descendants.
    let mut children: HashMap<Pid, Vec<Pid>> = HashMap::new();
    for (pid, process) in sys.processes() {
        if let Some(parent) = process.parent() {
            children.entry(parent).or_default().push(*pid);
        }
    }

    let cores = std::thread::available_parallelism().map_or(1, |n| n.get()) as f32;

    // Walk the tree top-down; a helper nobody recognises (conhost.exe under
    // sing-box) is billed to whichever group spawned it.
    let mut groups: HashMap<&'static str, ResourceGroup> = HashMap::new();
    let mut queue = vec![(Pid::from_u32(std::process::id()), "app")];
    while let Some((pid, inherited)) = queue.pop() {
        let Some(process) = sys.process(pid) else { continue };
        let name = process.name().to_string_lossy().to_lowercase();
        let group = if name.contains("webview") {
            "ui"
        } else if name.starts_with("sing-box") {
            "core"
        } else if name.starts_with("xray") {
            "xray"
        } else {
            inherited
        };

        let entry = groups.entry(group).or_insert(ResourceGroup {
            id: group,
            processes: 0,
            memory: 0,
            cpu: 0.0,
        });
        entry.processes += 1;
        // Private working set where the OS can tell us (the user compares
        // these rows against Task Manager digit for digit); the full working
        // set otherwise.
        #[cfg(windows)]
        {
            entry.memory += private_working_set(pid.as_u32()).unwrap_or_else(|| process.memory());
        }
        #[cfg(not(windows))]
        {
            entry.memory += process.memory();
        }
        entry.cpu += process.cpu_usage() / cores;

        for child in children.get(&pid).into_iter().flatten() {
            queue.push((*child, group));
        }
    }

    // Fixed order for the UI; absent groups (Xray runs rarely) just drop out.
    ["app", "ui", "core", "xray"]
        .into_iter()
        .filter_map(|id| groups.remove(id))
        .collect()
}

/// The figure Task Manager's memory column shows: the process's private
/// working set, without the system DLLs shared across every process.
/// (sysinfo only exposes the full working set, which reads ~2-3× higher.)
#[cfg(windows)]
fn private_working_set(pid: u32) -> Option<u64> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX2,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut counters = PROCESS_MEMORY_COUNTERS_EX2::default();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX2>() as u32;
        let ok = K32GetProcessMemoryInfo(
            handle,
            &mut counters as *mut PROCESS_MEMORY_COUNTERS_EX2 as *mut PROCESS_MEMORY_COUNTERS,
            counters.cb,
        );
        let _ = CloseHandle(handle);
        if !ok.as_bool() {
            return None;
        }
        Some(counters.PrivateWorkingSetSize as u64)
    }
}
