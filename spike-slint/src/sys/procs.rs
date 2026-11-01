//! Enumerates running applications so the split-tunnelling picker can offer real
//! choices instead of asking the user to type executable names from memory.

#[cfg(not(target_os = "android"))]
use std::collections::HashMap;

use serde::Serialize;
#[cfg(not(target_os = "android"))]
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

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
