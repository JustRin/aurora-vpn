use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum TunnelMode {
    /// Virtual adapter captures everything system-wide. Needs administrator
    /// rights; this is the only mode where per-application rules work.
    #[default]
    Tun,
    /// SOCKS/HTTP listener registered as the Windows system proxy. No elevation,
    /// but only proxy-aware apps are covered.
    SystemProxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TunStack {
    /// gVisor for TCP + kernel for UDP: the best throughput/compatibility trade-off.
    #[default]
    Mixed,
    System,
    Gvisor,
}

impl TunStack {
    pub fn as_str(self) -> &'static str {
        match self {
            TunStack::Mixed => "mixed",
            TunStack::System => "system",
            TunStack::Gvisor => "gvisor",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub tunnel_mode: TunnelMode,
    pub mixed_port: u16,
    pub clash_port: u16,
    pub allow_lan: bool,

    pub tun_stack: TunStack,
    pub tun_mtu: u32,
    pub strict_route: bool,
    pub ipv6: bool,

    pub log_level: String,

    pub dns_remote: String,
    pub dns_direct: String,
    pub dns_strategy: String,
    pub fake_ip: bool,

    pub auto_connect: bool,
    pub start_minimized: bool,
    pub close_to_tray: bool,

    /// `system`, `ru` or `en`. The frontend resolves `system` from the browser
    /// locale; Rust resolves it via `sys-locale` for the tray menu.
    pub language: String,

    /// Palette id, or `system`. Autostart is deliberately *not* stored here: the
    /// OS is its only source of truth, since the user can revoke it outside the
    /// app.
    pub theme: String,
    /// Resolved appearance of `theme`, mirrored from the frontend so the window
    /// can be painted before the WebView has loaded and can tell us itself.
    pub theme_dark: bool,
    pub theme_background: String,
    pub latency_url: String,
    /// Кто выбирает сервер: пользователь или балансировщик (core/balancer.rs).
    pub balancer: Balancer,
    /// Период полного обхода серверов балансировщиком, минуты.
    pub balancer_interval_min: u32,
    /// «Самый быстрый»: на сколько миллисекунд другой сервер должен быть
    /// быстрее, чтобы на него перейти.
    pub balancer_tolerance_ms: u32,
    /// Прежний тумблер «выбирать самый быстрый». Читается только ради переезда
    /// в `balancer` (`migrate`) и обратно не записывается.
    #[serde(skip_serializing)]
    pub auto_select: bool,
    /// Minutes between automatic subscription refreshes; 0 disables it.
    pub sub_auto_update_min: u32,
}

/// Кто выбирает сервер. Стратегии описаны в core/balancer.rs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum Balancer {
    /// Работает выбранный сервер; само ничего не переключается.
    #[default]
    Manual,
    /// Выбранный сервер основной: упал — лучший из живых, ожил — обратно.
    Failover,
    /// Самый быстрый по обходам, с допуском и без метаний.
    Fastest,
    /// Каждый обход — следующий живой по списку.
    Rotate,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            tunnel_mode: TunnelMode::Tun,
            mixed_port: 2080,
            clash_port: 9191,
            allow_lan: false,

            tun_stack: TunStack::Mixed,
            tun_mtu: 9000,
            strict_route: true,
            ipv6: false,

            log_level: "info".into(),

            dns_remote: "1.1.1.1".into(),
            dns_direct: "77.88.8.8".into(),
            dns_strategy: "prefer_ipv4".into(),
            fake_ip: false,

            auto_connect: false,
            start_minimized: false,
            close_to_tray: true,

            language: "system".into(),

            theme: "dark".into(),
            theme_dark: true,
            theme_background: "#0a0c12".into(),
            latency_url: "https://www.gstatic.com/generate_204".into(),
            balancer: Balancer::Manual,
            balancer_interval_min: 3,
            balancer_tolerance_ms: 100,
            auto_select: false,
            // Refresh once a day out of the box: a silently stale server list is
            // the most common way one of these clients stops working.
            sub_auto_update_min: 1440,
        }
    }
}

impl Settings {
    /// Whether switching from `self` to `next` changes the running tunnel —
    /// that is, any field the generated core document is built from. UI-only
    /// preferences (theme, language, tray behaviour…) must not bounce a live
    /// connection.
    ///
    /// The destructuring is exhaustive on purpose: a new field refuses to
    /// compile until it is filed into one of the two groups.
    pub fn tunnel_changed(&self, next: &Settings) -> bool {
        let Settings {
            tunnel_mode,
            mixed_port,
            clash_port,
            allow_lan,
            tun_stack,
            tun_mtu,
            strict_route,
            ipv6,
            log_level,
            dns_remote,
            dns_direct,
            dns_strategy,
            fake_ip,
            // Baked into the `urltest` outbound of the generated document.
            latency_url,
            // Живут в приложении, а не в документе: балансировщик
            // перенастраивается на ходу, без перезапуска ядра.
            balancer: _,
            balancer_interval_min: _,
            balancer_tolerance_ms: _,
            auto_select: _,
            // UI-only: never part of the generated document.
            auto_connect: _,
            start_minimized: _,
            close_to_tray: _,
            language: _,
            theme: _,
            theme_dark: _,
            theme_background: _,
            sub_auto_update_min: _,
        } = self;

        *tunnel_mode != next.tunnel_mode
            || *mixed_port != next.mixed_port
            || *clash_port != next.clash_port
            || *allow_lan != next.allow_lan
            || *tun_stack != next.tun_stack
            || *tun_mtu != next.tun_mtu
            || *strict_route != next.strict_route
            || *ipv6 != next.ipv6
            || *log_level != next.log_level
            || *dns_remote != next.dns_remote
            || *dns_direct != next.dns_direct
            || *dns_strategy != next.dns_strategy
            || *fake_ip != next.fake_ip
            || *latency_url != next.latency_url
    }

    /// Переменилось ли что-то для балансировщика. Ядро при этом не трогают:
    /// стратегия живёт в приложении и переустанавливается на ходу.
    pub fn balancer_changed(&self, next: &Settings) -> bool {
        self.balancer != next.balancer
            || self.balancer_interval_min != next.balancer_interval_min
            || self.balancer_tolerance_ms != next.balancer_tolerance_ms
    }

    /// Переезд с тумблера «выбирать самый быстрый» на стратегии. Возвращает,
    /// изменилось ли что-то — тогда файл стоит перезаписать.
    pub fn migrate(&mut self) -> bool {
        if !self.auto_select {
            return false;
        }
        self.auto_select = false;
        if self.balancer == Balancer::Manual {
            self.balancer = Balancer::Fastest;
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum SplitMode {
    /// Every application goes through the tunnel.
    #[default]
    Off,
    /// Only the listed applications are tunnelled; everything else stays direct.
    Include,
    /// The listed applications bypass the tunnel; everything else is tunnelled.
    Exclude,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppRule {
    pub id: String,
    /// Executable file name, e.g. `chrome.exe`.
    pub name: String,
    /// Full path when the user picked a specific binary; empty means match by name.
    pub path: String,
    pub enabled: bool,
}

impl Default for AppRule {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            path: String::new(),
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SplitConfig {
    pub mode: SplitMode,
    pub apps: Vec<AppRule>,

    pub direct_domains: Vec<String>,
    pub direct_ips: Vec<String>,
    pub proxy_domains: Vec<String>,
    pub proxy_ips: Vec<String>,
    pub block_domains: Vec<String>,

    /// Keep LAN/loopback traffic off the tunnel. Turning this off usually breaks
    /// printers, NAS and router admin pages.
    pub bypass_private: bool,
    pub bypass_ru: bool,
    pub bypass_cn: bool,
    pub block_ads: bool,
}

impl Default for SplitConfig {
    fn default() -> Self {
        Self {
            mode: SplitMode::Off,
            apps: Vec::new(),
            direct_domains: Vec::new(),
            direct_ips: Vec::new(),
            proxy_domains: Vec::new(),
            proxy_ips: Vec::new(),
            block_domains: Vec::new(),
            bypass_private: true,
            bypass_ru: false,
            bypass_cn: false,
            block_ads: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Balancer, Settings};

    #[test]
    fn ui_preferences_do_not_touch_the_tunnel() {
        let base = Settings::default();
        let ui = Settings {
            theme: "crimson".into(),
            theme_dark: false,
            theme_background: "#ffffff".into(),
            language: "en".into(),
            close_to_tray: false,
            auto_connect: true,
            start_minimized: true,
            sub_auto_update_min: 0,
            ..base.clone()
        };
        assert!(!base.tunnel_changed(&ui));
    }

    #[test]
    fn config_inputs_do_touch_the_tunnel() {
        let base = Settings::default();
        assert!(base.tunnel_changed(&Settings { dns_remote: "9.9.9.9".into(), ..base.clone() }));
        assert!(base.tunnel_changed(&Settings { mixed_port: 1080, ..base.clone() }));
    }

    #[test]
    fn the_balancer_is_reconfigured_live_rather_than_by_a_restart() {
        let base = Settings::default();
        let next = Settings { balancer: Balancer::Fastest, balancer_tolerance_ms: 200, ..base.clone() };
        assert!(!base.tunnel_changed(&next));
        assert!(base.balancer_changed(&next));
        assert!(!base.balancer_changed(&base.clone()));
    }

    #[test]
    fn the_old_fastest_toggle_becomes_the_fastest_strategy() {
        let mut settings: Settings = serde_json::from_str(r#"{"autoSelect": true}"#).unwrap();
        assert!(settings.migrate());
        assert_eq!(settings.balancer, Balancer::Fastest);
        // И не записывается обратно: следующий запуск ничего не переедет заново.
        assert!(!serde_json::to_string(&settings).unwrap().contains("autoSelect"));

        let mut explicit: Settings =
            serde_json::from_str(r#"{"autoSelect": true, "balancer": "failover"}"#).unwrap();
        assert!(explicit.migrate());
        assert_eq!(explicit.balancer, Balancer::Failover);

        let mut untouched = Settings::default();
        assert!(!untouched.migrate());
    }
}

impl SplitConfig {
    /// Enabled rules that match by executable name.
    pub fn active_names(&self) -> Vec<String> {
        self.apps
            .iter()
            .filter(|a| a.enabled && a.path.is_empty() && !a.name.is_empty())
            .map(|a| a.name.clone())
            .collect()
    }

    /// Enabled rules that match by full executable path.
    pub fn active_paths(&self) -> Vec<String> {
        self.apps
            .iter()
            .filter(|a| a.enabled && !a.path.is_empty())
            .map(|a| a.path.clone())
            .collect()
    }

    pub fn has_active_apps(&self) -> bool {
        !self.active_names().is_empty() || !self.active_paths().is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    /// RFC3339 timestamp of the last successful refresh.
    pub last_updated: String,
    pub node_count: usize,
    pub last_error: String,

    // ---- plan status, reported by the panel in `subscription-userinfo` ----
    pub upload: u64,
    pub download: u64,
    /// Traffic allowance in bytes; 0 means unlimited.
    pub total: u64,
    /// Unix seconds when the plan lapses; 0 means it never does.
    pub expire: i64,
    /// Refresh cadence the provider suggests, in hours; 0 when not advertised.
    pub update_interval_hours: u32,
    /// True once the panel actually reported a quota, so the UI can tell
    /// "unlimited" apart from "never asked".
    pub has_usage: bool,
}

impl Default for Subscription {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            url: String::new(),
            enabled: true,
            last_updated: String::new(),
            node_count: 0,
            last_error: String::new(),
            upload: 0,
            download: 0,
            total: 0,
            expire: 0,
            update_interval_hours: 0,
            has_usage: false,
        }
    }
}
