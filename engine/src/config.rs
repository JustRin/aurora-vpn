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
    fn unknown_fields_do_not_reject_the_document() {
        let cfg: Config = serde_json::from_str(
            r#"{"new_section":{},"outbounds":[{"type":"direct","tag":"d","future_field":1}]}"#,
        )
        .unwrap();
        assert_eq!(cfg.outbounds[0].tag, "d");
    }
}
