//! Правила маршрутизации и DNS в порядке, заданном `core/config.rs` приложения.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::common::Target;
use crate::config::{RouteOpts, RuleOpts};
use crate::procinfo;
use crate::ruleset::RuleSet;

/// Всё, что известно о соединении. Процесс ищется лениво: большинству правил он
/// не нужен, а поиск — самая дорогая часть решения.
#[derive(Default)]
pub struct Meta {
    pub network: &'static str,
    pub source: Option<std::net::SocketAddr>,
    pub destination: Option<Target>,
    pub domain: Option<String>,
    pub protocol: Option<&'static str>,
    pub query_type: Option<u16>,
    /// Итог шага `resolve`: адрес для IP-правил. Назначение остаётся именем.
    pub resolved_ip: Option<IpAddr>,
    pub process: Option<Option<procinfo::Process>>,
}

impl Meta {
    pub fn dest_ip(&self) -> Option<IpAddr> {
        self.destination.as_ref().and_then(Target::ip).or(self.resolved_ip)
    }

    async fn process(&mut self) -> Option<&procinfo::Process> {
        if self.process.is_none() {
            let found = match self.source {
                Some(src) => procinfo::lookup(self.network, src).await,
                None => None,
            };
            self.process = Some(found);
        }
        self.process.as_ref().and_then(Option::as_ref)
    }
}

#[derive(Clone, Copy)]
struct Cidr {
    addr: u128,
    mask: u128,
    v4: bool,
}

impl Cidr {
    fn parse(text: &str) -> Option<Self> {
        let (ip, bits) = match text.split_once('/') {
            Some((ip, bits)) => (ip, Some(bits.parse::<u32>().ok()?)),
            None => (text, None),
        };
        match ip.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) => {
                let bits = bits.unwrap_or(32).min(32);
                let mask = if bits == 0 { 0 } else { u128::from(u32::MAX << (32 - bits)) };
                Some(Self { addr: u128::from(u32::from(v4)) & mask, mask, v4: true })
            }
            IpAddr::V6(v6) => {
                let bits = bits.unwrap_or(128).min(128);
                let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                Some(Self { addr: u128::from(v6) & mask, mask, v4: false })
            }
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.v4 && u128::from(u32::from(v4)) & self.mask == self.addr,
            IpAddr::V6(v6) => !self.v4 && u128::from(v6) & self.mask == self.addr,
        }
    }
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                // CGNAT (100.64/10) и бенчмарк-сеть не ходят через туннель.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Поиск по доменным суффиксам: имя проверяется от полного к родителям, одна
/// проба — один поиск в хэше. Не зависит от длины списка, в отличие от перебора.
#[derive(Default)]
struct SuffixSet(HashSet<String>);

impl SuffixSet {
    fn new(list: &[String]) -> Self {
        Self(list.iter().map(|s| s.trim_start_matches('.').to_ascii_lowercase()).collect())
    }

    fn matches(&self, domain: &str) -> bool {
        let mut rest = domain;
        loop {
            if self.0.contains(rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, tail)) => rest = tail,
                None => return false,
            }
        }
    }
}

struct Matcher {
    process_name: HashSet<String>,
    process_path: HashSet<String>,
    domain: HashSet<String>,
    suffix: SuffixSet,
    keyword: Vec<String>,
    cidr: Vec<Cidr>,
    rule_sets: Vec<Arc<RuleSet>>,
    ip_is_private: bool,
    protocols: Vec<String>,
    query_types: Vec<u16>,
    clash_mode: Option<String>,
    /// Правило ссылается на набор, которого нет: не срабатывает никогда.
    broken: bool,
}

fn query_type(name: &str) -> Option<u16> {
    match name.to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "AAAA" => Some(28),
        "CNAME" => Some(5),
        "MX" => Some(15),
        "TXT" => Some(16),
        "HTTPS" => Some(65),
        "SVCB" => Some(64),
        other => other.parse().ok(),
    }
}

impl Matcher {
    fn new(rule: &RuleOpts, sets: &HashMap<String, Arc<RuleSet>>) -> Self {
        let lower = |list: &[String]| -> HashSet<String> { list.iter().map(|s| s.to_ascii_lowercase()).collect() };
        let mut broken = false;
        let rule_sets = rule
            .rule_set
            .iter()
            .filter_map(|tag| {
                let set = sets.get(tag).cloned();
                broken |= set.is_none();
                set
            })
            .collect();
        let protocols = match &rule.protocol {
            serde_json::Value::String(s) => vec![s.clone()],
            serde_json::Value::Array(list) => list.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            _ => Vec::new(),
        };
        Self {
            process_name: lower(&rule.process_name),
            process_path: lower(&rule.process_path),
            domain: lower(&rule.domain),
            suffix: SuffixSet::new(&rule.domain_suffix),
            keyword: rule.domain_keyword.iter().map(|k| k.to_ascii_lowercase()).collect(),
            cidr: rule.ip_cidr.iter().filter_map(|c| Cidr::parse(c)).collect(),
            rule_sets,
            ip_is_private: rule.ip_is_private,
            protocols,
            query_types: rule.query_type.iter().filter_map(|q| query_type(q)).collect(),
            clash_mode: (!rule.clash_mode.is_empty()).then(|| rule.clash_mode.clone()),
            broken,
        }
    }

    async fn matches(&self, meta: &mut Meta, mode: &str) -> bool {
        if self.broken {
            return false;
        }
        if let Some(wanted) = &self.clash_mode {
            if !wanted.eq_ignore_ascii_case(mode) {
                return false;
            }
        }
        if !self.protocols.is_empty()
            && !meta.protocol.is_some_and(|p| self.protocols.iter().any(|w| w == p))
        {
            return false;
        }
        if !self.query_types.is_empty() && !meta.query_type.is_some_and(|q| self.query_types.contains(&q)) {
            return false;
        }

        // Адресные условия объединены по ИЛИ между собой, как у sing-box.
        let domain = meta.domain.as_deref();
        let ip = meta.dest_ip();
        let has_address_items = !self.domain.is_empty()
            || !self.suffix.0.is_empty()
            || !self.keyword.is_empty()
            || !self.cidr.is_empty()
            || !self.rule_sets.is_empty()
            || self.ip_is_private;
        if has_address_items {
            let mut hit = false;
            if let Some(d) = domain {
                hit = self.domain.contains(d)
                    || self.suffix.matches(d)
                    || self.keyword.iter().any(|k| d.contains(k.as_str()));
            }
            if !hit {
                if let Some(ip) = ip {
                    hit = self.cidr.iter().any(|c| c.contains(ip)) || (self.ip_is_private && is_private(ip));
                }
            }
            if !hit {
                hit = self.rule_sets.iter().any(|set| set.matches(domain, ip));
            }
            if !hit {
                return false;
            }
        }

        if !self.process_name.is_empty() || !self.process_path.is_empty() {
            let Some(process) = meta.process().await else { return false };
            let name_hit = self.process_name.contains(&process.name_lower);
            let path_hit = self.process_path.contains(&process.path_lower);
            if !(name_hit || path_hit) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Sniff,
    Resolve,
    HijackDns,
    Reject,
    Route(String),
}

/// Что делать с соединением: шаг выполняет движок, потом разбор идёт дальше.
pub enum Decision {
    Step(Action, usize),
    Final(String),
}

struct Rule {
    matcher: Matcher,
    action: Action,
}

pub struct Router {
    rules: Vec<Rule>,
    final_outbound: String,
    mode: Arc<RwLock<String>>,
}

pub fn load_rule_sets(route: &RouteOpts) -> HashMap<String, Arc<RuleSet>> {
    let mut sets = HashMap::new();
    for rs in &route.rule_set {
        match RuleSet::load(Path::new(&rs.path)) {
            Ok(set) => {
                sets.insert(rs.tag.clone(), Arc::new(set));
            }
            // Правила набора выключатся, туннель останется: набор — не повод падать.
            Err(e) => crate::warn!("router", "набор {}: {e}; его правила выключены", rs.tag),
        }
    }
    sets
}

impl Router {
    pub fn new(route: &RouteOpts, sets: &HashMap<String, Arc<RuleSet>>, mode: Arc<RwLock<String>>) -> Self {
        let rules = route
            .rules
            .iter()
            .map(|r| Rule {
                matcher: Matcher::new(r, sets),
                action: match r.action.as_str() {
                    "sniff" => Action::Sniff,
                    "resolve" => Action::Resolve,
                    "hijack-dns" => Action::HijackDns,
                    "reject" => Action::Reject,
                    _ => Action::Route(r.outbound.clone()),
                },
            })
            .collect();
        let final_outbound = if route.final_outbound.is_empty() { "direct".to_string() } else { route.final_outbound.clone() };
        Self { rules, final_outbound, mode }
    }

    /// Первое совпавшее правило начиная с `from`.
    pub async fn next(&self, meta: &mut Meta, from: usize) -> Decision {
        let mode = self.mode.read().clone();
        for (i, rule) in self.rules.iter().enumerate().skip(from) {
            if rule.matcher.matches(meta, &mode).await {
                return Decision::Step(rule.action.clone(), i + 1);
            }
        }
        Decision::Final(self.final_outbound.clone())
    }
}

pub enum DnsAction {
    Server(String),
    Reject,
    Final,
}

struct DnsRule {
    matcher: Matcher,
    reject: bool,
    server: String,
}

pub struct DnsRules {
    rules: Vec<DnsRule>,
    mode: Arc<RwLock<String>>,
}

impl DnsRules {
    pub fn new(list: &[RuleOpts], sets: &HashMap<String, Arc<RuleSet>>, mode: Arc<RwLock<String>>) -> Self {
        let rules = list
            .iter()
            .map(|r| DnsRule {
                matcher: Matcher::new(r, sets),
                reject: r.action == "reject",
                server: r.server.clone(),
            })
            .collect();
        Self { rules, mode }
    }

    pub async fn evaluate(&self, meta: &mut Meta) -> DnsAction {
        let mode = self.mode.read().clone();
        for rule in &self.rules {
            if rule.matcher.matches(meta, &mode).await {
                return if rule.reject { DnsAction::Reject } else { DnsAction::Server(rule.server.clone()) };
            }
        }
        DnsAction::Final
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(json: &str) -> RuleOpts {
        serde_json::from_str(json).unwrap()
    }

    fn router(rules: &str, final_out: &str, mode: &str) -> Router {
        let route: RouteOpts =
            serde_json::from_str(&format!(r#"{{"rules":{rules},"final":"{final_out}"}}"#)).unwrap();
        Router::new(&route, &HashMap::new(), Arc::new(RwLock::new(mode.to_string())))
    }

    fn meta_domain(domain: &str) -> Meta {
        Meta {
            network: "tcp",
            domain: Some(domain.to_string()),
            destination: Some(Target::new(domain, 443)),
            ..Default::default()
        }
    }

    fn meta_ip(ip: &str) -> Meta {
        Meta { network: "tcp", destination: Some(Target::new(ip, 443)), ..Default::default() }
    }

    async fn route(r: &Router, mut meta: Meta) -> String {
        let mut from = 0;
        loop {
            match r.next(&mut meta, from).await {
                Decision::Step(Action::Route(tag), _) => return tag,
                Decision::Step(Action::Reject, _) => return "REJECT".to_string(),
                Decision::Step(_, next) => from = next,
                Decision::Final(tag) => return tag,
            }
        }
    }

    #[tokio::test]
    async fn first_match_wins_and_final_catches_the_rest() {
        let r = router(
            r#"[{"domain_suffix":["blocked.ru"],"outbound":"proxy"},{"domain_suffix":["ru"],"outbound":"direct"}]"#,
            "proxy",
            "Rule",
        );
        assert_eq!(route(&r, meta_domain("a.blocked.ru")).await, "proxy");
        assert_eq!(route(&r, meta_domain("yandex.ru")).await, "direct");
        assert_eq!(route(&r, meta_domain("example.com")).await, "proxy");
    }

    #[tokio::test]
    async fn suffix_requires_a_label_boundary() {
        let r = router(r#"[{"domain_suffix":["vk.com"],"outbound":"direct"}]"#, "proxy", "Rule");
        assert_eq!(route(&r, meta_domain("vk.com")).await, "direct");
        assert_eq!(route(&r, meta_domain("m.vk.com")).await, "direct");
        assert_eq!(route(&r, meta_domain("notvk.com")).await, "proxy");
    }

    #[tokio::test]
    async fn cidr_and_private() {
        let r = router(
            r#"[{"ip_is_private":true,"outbound":"direct"},{"ip_cidr":["1.2.3.0/24"],"outbound":"block"}]"#,
            "proxy",
            "Rule",
        );
        assert_eq!(route(&r, meta_ip("192.168.1.1")).await, "direct");
        assert_eq!(route(&r, meta_ip("1.2.3.200")).await, "block");
        assert_eq!(route(&r, meta_ip("1.2.4.1")).await, "proxy");
    }

    #[tokio::test]
    async fn clash_mode_switches_without_rebuilding_rules() {
        let mode = Arc::new(RwLock::new("Rule".to_string()));
        let route_opts: RouteOpts = serde_json::from_str(
            r#"{"rules":[{"clash_mode":"Global","outbound":"proxy"}],"final":"direct"}"#,
        )
        .unwrap();
        let r = Router::new(&route_opts, &HashMap::new(), mode.clone());
        assert_eq!(route(&r, meta_ip("8.8.8.8")).await, "direct");
        *mode.write() = "Global".to_string();
        assert_eq!(route(&r, meta_ip("8.8.8.8")).await, "proxy");
    }

    #[tokio::test]
    async fn rule_with_a_missing_set_never_fires() {
        let r = router(r#"[{"rule_set":["absent"],"outbound":"block"}]"#, "proxy", "Rule");
        assert_eq!(route(&r, meta_domain("example.com")).await, "proxy");
    }

    #[tokio::test]
    async fn process_rule_does_not_fire_without_a_process() {
        let r = router(r#"[{"process_name":["chrome.exe"],"outbound":"proxy"}]"#, "direct", "Rule");
        assert_eq!(route(&r, meta_ip("8.8.8.8")).await, "direct");
    }

    #[tokio::test]
    async fn process_rule_compares_case_insensitively() {
        let matcher = Matcher::new(&rule(r#"{"process_name":["Chrome.EXE"]}"#), &HashMap::new());
        let mut meta = Meta {
            network: "tcp",
            process: Some(Some(procinfo::Process {
                name_lower: "chrome.exe".into(),
                path_lower: r"c:\x\chrome.exe".into(),
                path: r"C:\x\chrome.exe".into(),
            })),
            ..Default::default()
        };
        assert!(matcher.matches(&mut meta, "Rule").await);
    }

    #[tokio::test]
    async fn dns_protocol_rule_needs_the_sniff_result() {
        let r = router(
            r#"[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"}]"#,
            "proxy",
            "Rule",
        );
        let mut meta = meta_ip("1.1.1.1");
        let Decision::Step(Action::Sniff, next) = r.next(&mut meta, 0).await else { panic!() };
        assert!(matches!(r.next(&mut meta, next).await, Decision::Final(_)));
        meta.protocol = Some("dns");
        assert!(matches!(r.next(&mut meta, next).await, Decision::Step(Action::HijackDns, _)));
    }

    #[test]
    fn private_ranges() {
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.0.1", "127.0.0.1", "169.254.0.1", "fe80::1", "fd00::1", "::1"] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "2001:db8::1", "1.1.1.1"] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }
}
