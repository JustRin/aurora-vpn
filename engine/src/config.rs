//! Подмножество конфига sing-box, которое строит `core/config.rs` приложения.
//!
//! Намеренно нестрогий разбор: неизвестное поле игнорируется, неподдержанный
//! протокол превращается в заглушку (см. `outbound::build`). sing-box отвергал
//! весь документ из-за одного поля, и приложению приходилось выбрасывать узлы
//! заранее, чтобы не потерять остальные.

use std::collections::HashMap;

use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// `"x"` или `["x", "y"]` — sing-box принимает обе формы.
fn listable<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<OneOrMany>::deserialize(d)? {
        Some(OneOrMany::One(s)) => vec![s],
        Some(OneOrMany::Many(v)) => v,
        None => Vec::new(),
    })
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub log: LogOpts,
    pub dns: DnsOpts,
    pub inbounds: Vec<InboundOpts>,
    pub outbounds: Vec<OutboundOpts>,
    pub endpoints: Vec<Value>,
    pub route: RouteOpts,
    pub experimental: Experimental,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct LogOpts {
    pub level: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DnsOpts {
    pub servers: Vec<DnsServerOpts>,
    pub rules: Vec<RuleOpts>,
    #[serde(rename = "final")]
    pub final_server: String,
    pub strategy: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct DnsServerOpts {
    #[serde(rename = "type")]
    pub kind: String,
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub path: String,
    pub detour: String,
    pub domain_resolver: String,
    pub inet4_range: String,
    pub inet6_range: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct InboundOpts {
    #[serde(rename = "type")]
    pub kind: String,
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
    #[serde(deserialize_with = "listable")]
    pub address: Vec<String>,
    pub mtu: u32,
    pub auto_route: bool,
    pub strict_route: bool,
    pub stack: String,
    /// `mixed`: логин и пароль. На Android 127.0.0.1 общий для всех приложений,
    /// и открытый прокси нашёл бы любой сканер VPN.
    pub users: Vec<UserOpts>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct UserOpts {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct OutboundOpts {
    #[serde(rename = "type")]
    pub kind: String,
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub uuid: String,
    pub password: String,
    pub method: String,
    pub flow: String,
    pub security: String,
    pub alter_id: u32,
    pub packet_encoding: String,
    pub username: String,
    pub version: String,
    /// Veil: путь туннеля на сайте.
    pub path: String,
    pub tls: Option<TlsOpts>,
    pub transport: Option<TransportOpts>,
    pub multiplex: Option<Value>,
    pub obfs: Option<ObfsOpts>,
    #[serde(deserialize_with = "listable")]
    pub server_ports: Vec<String>,
    // Группы
    pub outbounds: Vec<String>,
    pub default: String,
    pub url: String,
    pub interval: String,
    pub tolerance: u32,
    pub idle_timeout: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ObfsOpts {
    #[serde(rename = "type")]
    pub kind: String,
    pub password: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct TlsOpts {
    pub enabled: bool,
    pub server_name: String,
    pub insecure: bool,
    #[serde(deserialize_with = "listable")]
    pub alpn: Vec<String>,
    pub utls: Option<UtlsOpts>,
    pub reality: Option<RealityOpts>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct UtlsOpts {
    pub enabled: bool,
    pub fingerprint: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct RealityOpts {
    pub enabled: bool,
    pub public_key: String,
    pub short_id: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct TransportOpts {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: String,
    pub headers: HashMap<String, Value>,
    pub host: Value,
    pub service_name: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RouteOpts {
    pub rules: Vec<RuleOpts>,
    pub rule_set: Vec<RuleSetOpts>,
    #[serde(rename = "final")]
    pub final_outbound: String,
    pub auto_detect_interface: bool,
    pub default_domain_resolver: Value,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct RuleSetOpts {
    #[serde(rename = "type")]
    pub kind: String,
    pub tag: String,
    pub format: String,
    pub path: String,
}

/// Правило маршрутизации или DNS: у sing-box это один и тот же плоский объект.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct RuleOpts {
    pub action: String,
    pub outbound: String,
    pub server: String,
    pub strategy: String,
    pub protocol: Value,
    pub clash_mode: String,
    pub ip_is_private: bool,
    #[serde(deserialize_with = "listable")]
    pub process_name: Vec<String>,
    #[serde(deserialize_with = "listable")]
    pub process_path: Vec<String>,
    #[serde(deserialize_with = "listable")]
    pub domain: Vec<String>,
    #[serde(deserialize_with = "listable")]
    pub domain_suffix: Vec<String>,
    #[serde(deserialize_with = "listable")]
    pub domain_keyword: Vec<String>,
    #[serde(deserialize_with = "listable")]
    pub ip_cidr: Vec<String>,
    #[serde(deserialize_with = "listable")]
    pub rule_set: Vec<String>,
    #[serde(deserialize_with = "listable")]
    pub query_type: Vec<String>,
    /// Тег входа, как у sing-box: на Android сайдкар Veil так привязывает
    /// каждый loopback-порт к своему узлу.
    #[serde(deserialize_with = "listable")]
    pub inbound: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Experimental {
    pub clash_api: ClashApiOpts,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ClashApiOpts {
    pub external_controller: String,
    pub secret: String,
    pub default_mode: String,
}

impl Config {
    /// Программы, которые конфиг целиком отправляет напрямую, указав их путь:
    /// сайдкар Xray и приложения, исключённые пользователем из VPN. Строгий
    /// режим TUN не должен отрезать им выход мимо туннеля — Xray, например, сам
    /// дозванивается до сервера, а из РФ тот доступен только по IPv6.
    pub fn direct_process_paths(&self) -> Vec<String> {
        let direct: Vec<&str> =
            self.outbounds.iter().filter(|o| o.kind == "direct").map(|o| o.tag.as_str()).collect();
        let mut paths: Vec<String> = Vec::new();
        for rule in &self.route.rules {
            let routes_direct =
                matches!(rule.action.as_str(), "" | "route") && direct.contains(&rule.outbound.as_str());
            if !routes_direct || !rule.only_matches_process() {
                continue;
            }
            for path in &rule.process_path {
                if !paths.contains(path) {
                    paths.push(path.clone());
                }
            }
        }
        paths
    }
}

impl RuleOpts {
    /// Условие правила — только путь к программе: под него подпадает весь её
    /// трафик, а не часть.
    fn only_matches_process(&self) -> bool {
        !self.process_path.is_empty()
            && self.protocol.is_null()
            && self.clash_mode.is_empty()
            && !self.ip_is_private
            && self.process_name.is_empty()
            && self.domain.is_empty()
            && self.domain_suffix.is_empty()
            && self.domain_keyword.is_empty()
            && self.ip_cidr.is_empty()
            && self.rule_set.is_empty()
            && self.query_type.is_empty()
            && self.inbound.is_empty()
    }
}

pub fn load(path: &std::path::Path) -> Result<Config, String> {
    let raw = std::fs::read(path).map_err(|e| format!("чтение {}: {e}", path.display()))?;
    serde_json::from_slice(&raw).map_err(|e| format!("разбор {}: {e}", path.display()))
}

/// `"3m"`, `"30s"`, `"1h"` → секунды; пустое и непонятное — `fallback`.
pub fn seconds(text: &str, fallback: u64) -> u64 {
    let text = text.trim();
    let split = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
    let Ok(n) = text[..split].parse::<u64>() else {
        return fallback;
    };
    match &text[split..] {
        "h" => n * 3600,
        "m" => n * 60,
        "s" | "" => n,
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(seconds("3m", 0), 180);
        assert_eq!(seconds("30s", 0), 30);
        assert_eq!(seconds("", 7), 7);
        assert_eq!(seconds("oops", 7), 7);
    }

    #[test]
    fn listable_accepts_both_forms() {
        let rule: RuleOpts =
            serde_json::from_str(r#"{"domain":"a.com","ip_cidr":["1.1.1.1/32","2.2.2.2/32"]}"#).unwrap();
        assert_eq!(rule.domain, vec!["a.com"]);
        assert_eq!(rule.ip_cidr.len(), 2);
    }

    #[test]
    fn programs_sent_direct_by_path_are_listed() {
        let cfg: Config = serde_json::from_str(
            r#"{
                "outbounds":[{"type":"selector","tag":"proxy"},{"type":"direct","tag":"direct"}],
                "route":{"rules":[
                    {"action":"sniff"},
                    {"process_path":["C:\\app\\xray.exe"],"outbound":"direct"},
                    {"process_name":["xray.exe"],"outbound":"direct"},
                    {"process_path":["C:\\app\\xray.exe"],"outbound":"direct"},
                    {"process_path":["C:\\Games\\game.exe"],"action":"route","outbound":"direct"},
                    {"process_path":["C:\\chrome.exe"],"outbound":"proxy"},
                    {"process_path":["C:\\part.exe"],"domain_suffix":["ru"],"outbound":"direct"}
                ]}
            }"#,
        )
        .unwrap();
        assert_eq!(cfg.direct_process_paths(), vec![r"C:\app\xray.exe".to_string(), r"C:\Games\game.exe".to_string()]);
    }

    #[test]
    fn unknown_fields_do_not_reject_the_document() {
        let cfg: Config = serde_json::from_str(
            r#"{"new_section":{},"outbounds":[{"type":"direct","tag":"d","future_field":1}]}"#,
        )
        .unwrap();
        assert_eq!(cfg.outbounds[0].tag, "d");
    }
}
