use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "android")]
use crate::core::android::AndroidEngine;
use crate::core::clash::ClashApi;
#[cfg(not(target_os = "android"))]
use crate::core::process::{CoreSupervisor, Engine};
use crate::error::Result;
use crate::model::ServerNode;
use crate::settings::{Settings, SplitConfig, Subscription, TunnelMode};
use crate::store::Store;
use crate::sys::elevate;

pub struct Paths {
    /// User documents: servers, settings, split rules.
    pub config_dir: PathBuf,
    /// Working directory handed to the core: rule-set cache and fake-ip database.
    pub work_dir: PathBuf,
    pub config_file: PathBuf,
    #[cfg_attr(target_os = "android", allow(dead_code))]
    pub xray_config: PathBuf,
    pub cache_file: PathBuf,
    pub pid_file: PathBuf,
    /// In-process libbox has no stdout to capture; it writes here instead.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub log_file: PathBuf,
    /// Cached geo rule-sets, downloaded by us rather than by the core.
    pub rule_set_dir: PathBuf,
}

impl Paths {
    pub fn new(config_dir: PathBuf) -> Self {
        let work_dir = config_dir.join("core");
        Self {
            config_file: work_dir.join("config.json"),
            xray_config: work_dir.join("xray.json"),
            cache_file: work_dir.join("cache.db"),
            pid_file: work_dir.join("core.pid"),
            log_file: work_dir.join("core.log"),
            rule_set_dir: work_dir.join("rulesets"),
            work_dir,
            config_dir,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum ConnState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub state: ConnState,
    pub message: String,
    /// Unix milliseconds of the moment the tunnel came up, for the uptime clock.
    pub since_ms: Option<i64>,
    pub mode: String,
    pub tunnel_mode: TunnelMode,
    pub active_id: String,
    pub elevated: bool,
    pub system_proxy: bool,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            state: ConnState::Disconnected,
            message: String::new(),
            since_ms: None,
            mode: "Rule".into(),
            tunnel_mode: TunnelMode::default(),
            active_id: String::new(),
            elevated: false,
            system_proxy: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Traffic {
    pub upload: u64,
    pub download: u64,
    pub up_speed: u64,
    pub down_speed: u64,
    pub connections: usize,
}

/// Small companion document for things the UI remembers but that are not
/// settings proper.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UiState {
    pub active_id: String,
}

pub struct AppState {
    pub paths: Paths,
    pub store: Store,
    /// Bearer token for the core's control API, regenerated on every launch so a
    /// stale value can never be replayed against a new core.
    pub secret: String,

    pub settings: RwLock<Settings>,
    pub nodes: RwLock<Vec<ServerNode>>,
    pub subs: RwLock<Vec<Subscription>>,
    pub split: RwLock<SplitConfig>,
    pub active_id: RwLock<String>,

    /// node id → last measured latency; `None` means "probed and unreachable".
    pub latency: RwLock<HashMap<String, Option<u32>>>,
    /// node id → outbound tag of the currently running core.
    pub tags: RwLock<HashMap<String, String>>,

    /// node id → the `encryption` value its server was probed to reject.
    /// While the node's link still carries that exact value, the node is
    /// demoted to the sing-box engine with the layer dropped; once the link
    /// changes, the entry goes stale and the node is probed again.
    pub engine_overrides: RwLock<HashMap<String, String>>,
    /// node id → loopback SOCKS port of the running Xray engine, kept for the
    /// post-connect probe that verifies those nodes actually carry traffic.
    pub xray_ports: RwLock<HashMap<String, u16>>,

    #[cfg(not(target_os = "android"))]
    pub core: Mutex<CoreSupervisor>,
    /// On Android sing-box runs in-process (libbox) inside the VpnService;
    /// the driver mirrors the supervisor's surface so callers cannot tell.
    #[cfg(target_os = "android")]
    pub core: Mutex<AndroidEngine>,
    /// Secondary engine, present only when the Xray binary was found. Nodes that
    /// sing-box cannot speak are dialled through it.
    #[cfg(not(target_os = "android"))]
    pub xray: Mutex<Option<CoreSupervisor>>,
    pub clash: RwLock<Option<ClashApi>>,
    pub status: RwLock<Status>,
    pub traffic: RwLock<Traffic>,

    /// Incremented on every connect. Background pollers carry the value they
    /// started with and stop as soon as it no longer matches, so a fast
    /// disconnect/reconnect cannot leave two of them reporting at once.
    pub session: AtomicU64,
}

impl AppState {
    pub fn new(
        config_dir: PathBuf,
        #[cfg(target_os = "android")] app: tauri::AppHandle,
        #[cfg(not(target_os = "android"))] core_exe: PathBuf,
        #[cfg(not(target_os = "android"))] xray_exe: Option<PathBuf>,
    ) -> Result<Self> {
        let paths = Paths::new(config_dir);
        std::fs::create_dir_all(&paths.work_dir)?;

        let store = Store::new(paths.config_dir.clone())?;
        let settings: Settings = store.load("settings");
        let mut nodes: Vec<ServerNode> = store.load("servers");
        // Починка на входе: id должен быть у каждой строки свой. Прежние
        // обновления подписок раздавали один id всем узлам с общим отпечатком
        // (у панелей это десяток строк на одном адресе), а по id адресуются и
        // выбор сервера, и задержка, и удаление.
        {
            let mut seen = std::collections::HashSet::new();
            let mut repaired = false;
            for node in &mut nodes {
                if !seen.insert(node.id.clone()) {
                    node.id = uuid::Uuid::new_v4().to_string();
                    seen.insert(node.id.clone());
                    repaired = true;
                }
            }
            // Сразу на диск: иначе каждый запуск раздавал бы дубликатам новые
            // случайные id, и выбранный сервер переезжал бы вместе с ними.
            if repaired {
                let _ = store.save("servers", &nodes);
            }
        }
        let subs: Vec<Subscription> = store.load("subscriptions");
        let split: SplitConfig = store.load("split");
        let ui: UiState = store.load("ui");
        let engine_overrides: HashMap<String, String> = store.load("engines");

        // A core surviving a previous crash still owns the virtual adapter, and
        // a crash in system-proxy mode leaves the machine pointed at a listener
        // that no longer exists. Clean up both before doing anything else.
        // On Android neither exists: the service dies with the process, and
        // there is no system proxy to restore.
        #[cfg(not(target_os = "android"))]
        {
            crate::core::process::kill_orphan(&paths.pid_file, &core_exe);
            crate::sys::sysproxy::init(paths.config_dir.join("sysproxy-backup.json"));
            crate::sys::sysproxy::restore_after_crash(settings.mixed_port);
        }

        let status = Status {
            tunnel_mode: settings.tunnel_mode,
            active_id: ui.active_id.clone(),
            elevated: elevate::is_elevated(),
            // Means "this app turned the system proxy on", not "a proxy is set".
            // Seeding it from the OS would make the first teardown clobber a
            // proxy the user configured themselves.
            system_proxy: false,
            ..Default::default()
        };

        Ok(Self {
            #[cfg(not(target_os = "android"))]
            core: Mutex::new(CoreSupervisor::new(
                Engine::SingBox,
                core_exe,
                paths.work_dir.clone(),
            )),
            #[cfg(target_os = "android")]
            core: Mutex::new(AndroidEngine::new(app, paths.log_file.clone())),
            #[cfg(not(target_os = "android"))]
            xray: Mutex::new(xray_exe.map(|exe| {
                CoreSupervisor::new(Engine::Xray, exe, paths.work_dir.clone())
            })),
            paths,
            store,
            secret: uuid::Uuid::new_v4().to_string(),
            settings: RwLock::new(settings),
            nodes: RwLock::new(nodes),
            subs: RwLock::new(subs),
            split: RwLock::new(split),
            active_id: RwLock::new(ui.active_id),
            latency: RwLock::new(HashMap::new()),
            tags: RwLock::new(HashMap::new()),
            engine_overrides: RwLock::new(engine_overrides),
            xray_ports: RwLock::new(HashMap::new()),
            clash: RwLock::new(None),
            status: RwLock::new(status),
            traffic: RwLock::new(Traffic::default()),
            session: AtomicU64::new(0),
        })
    }

    pub fn save_settings(&self) -> Result<()> {
        self.store.save("settings", &*self.settings.read())
    }

    pub fn save_nodes(&self) -> Result<()> {
        self.store.save("servers", &*self.nodes.read())
    }

    pub fn save_subs(&self) -> Result<()> {
        self.store.save("subscriptions", &*self.subs.read())
    }

    pub fn save_split(&self) -> Result<()> {
        self.store.save("split", &*self.split.read())
    }

    pub fn save_ui(&self) -> Result<()> {
        self.store.save(
            "ui",
            &UiState {
                active_id: self.active_id.read().clone(),
            },
        )
    }

    /// The node the tunnel should use: the pinned one, or the first available
    /// when the pin points at something that no longer exists.
    pub fn resolve_active_id(&self) -> String {
        let nodes = self.nodes.read();
        let current = self.active_id.read().clone();
        if nodes.iter().any(|n| n.id == current) {
            return current;
        }
        nodes.first().map(|n| n.id.clone()).unwrap_or_default()
    }
}
