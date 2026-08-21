use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
    Tuic,
}

impl Protocol {
    pub fn as_singbox(self) -> &'static str {
        match self {
            Protocol::Vless => "vless",
            Protocol::Vmess => "vmess",
            Protocol::Trojan => "trojan",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::Hysteria2 => "hysteria2",
            Protocol::Tuic => "tuic",
        }
    }
}

/// Transport layer, named after the `network` field 3x-ui writes into share links.
///
/// `Xhttp` exists only in Xray; a node using it is routed through the Xray
/// engine rather than handled by sing-box directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Tcp,
    Ws,
    Grpc,
    Http,
    Httpupgrade,
    Xhttp,
}

impl Network {
    #[cfg_attr(target_os = "android", allow(dead_code))]
    pub fn as_xray(self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Ws => "ws",
            Network::Grpc => "grpc",
            Network::Http => "http",
            Network::Httpupgrade => "httpupgrade",
            Network::Xhttp => "xhttp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    #[default]
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerNode {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,

    // ---- credentials (only some apply per protocol) ----
    pub uuid: String,
    pub password: String,
    /// shadowsocks cipher
    pub method: String,
    /// vmess legacy field, kept because old 3x-ui inbounds still emit it
    pub alter_id: u16,
    /// vmess `scy`
    pub vmess_security: String,

    // ---- transport ----
    pub network: Network,
    pub path: String,
    pub host: String,
    pub service_name: String,

    // ---- security ----
    pub security: Security,
    pub sni: String,
    pub alpn: Vec<String>,
    /// uTLS fingerprint (chrome, firefox, safari, randomized, ...)
    pub fingerprint: String,
    /// REALITY public key (`pbk`)
    pub public_key: String,
    /// REALITY short id (`sid`)
    pub short_id: String,
    pub allow_insecure: bool,
    /// `xtls-rprx-vision` and friends
    pub flow: String,
    /// REALITY `spx`, used only by Xray.
    pub spider_x: String,
    /// VLESS Encryption (`mlkem768x25519plus…`). Empty or `none` for the classic
    /// behaviour. Only Xray implements the non-trivial values.
    pub encryption: String,

    pub mux: bool,

    /// Set when the node came from a subscription, so refreshes can replace it.
    pub subscription_id: Option<String>,
    pub raw_link: String,
}

impl Default for ServerNode {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            protocol: Protocol::default(),
            address: String::new(),
            port: 443,
            uuid: String::new(),
            password: String::new(),
            method: String::new(),
            alter_id: 0,
            vmess_security: String::new(),
            network: Network::default(),
            path: String::new(),
            host: String::new(),
            service_name: String::new(),
            security: Security::default(),
            sni: String::new(),
            alpn: Vec::new(),
            fingerprint: String::new(),
            public_key: String::new(),
            short_id: String::new(),
            allow_insecure: false,
            flow: String::new(),
            spider_x: String::new(),
            encryption: String::new(),
            mux: false,
            subscription_id: None,
            raw_link: String::new(),
        }
    }
}

impl ServerNode {
    /// Whether this node can only be carried by the Xray engine.
    ///
    /// Two features force it: VLESS Encryption, which sing-box does not
    /// implement at all, and the XHTTP transport, which is Xray-only. Such a
    /// node is dialled by Xray and handed to sing-box over a loopback SOCKS
    /// hop, so routing and split tunnelling keep working unchanged.
    pub fn needs_xray(&self) -> bool {
        let encrypted = !self.encryption.is_empty()
            && !self.encryption.eq_ignore_ascii_case("none");
        (self.protocol == Protocol::Vless && encrypted) || self.network == Network::Xhttp
    }

    /// Whether the Xray-only part of this node is negotiable.
    ///
    /// VLESS Encryption is an optional layer bolted onto classic VLESS — a
    /// server that has not enabled it still speaks the classic protocol, so
    /// the node can be retried on the sing-box engine with the layer dropped.
    /// An XHTTP transport has no such degraded form: without it there is no
    /// connection at all.
    pub fn can_fall_back_to_singbox(&self) -> bool {
        self.needs_xray() && self.network != Network::Xhttp
    }

    /// Stable identity of a node as advertised by the server, used to keep
    /// user edits (and latency history) attached across subscription refreshes.
    pub fn fingerprint_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.protocol.as_singbox(),
            self.address,
            self.port,
            if self.uuid.is_empty() { &self.password } else { &self.uuid },
            self.path
        )
    }

    /// The hostname TLS should be validated against, falling back the same way
    /// Xray does: explicit SNI → transport Host header → connect address.
    fn effective_sni(&self) -> String {
        if !self.sni.is_empty() {
            self.sni.clone()
        } else if !self.host.is_empty() {
            // `Host` may carry a comma-separated list; TLS only wants one name.
            self.host.split(',').next().unwrap_or("").trim().to_string()
        } else {
            self.address.clone()
        }
    }

    fn tls_block(&self) -> Option<Value> {
        // hysteria2/tuic are QUIC-based and always need a TLS block, even when
        // the share link omits `security=tls`.
        let forced = matches!(self.protocol, Protocol::Hysteria2 | Protocol::Tuic);
        if self.security == Security::None && !forced {
            return None;
        }

        let mut tls = Map::new();
        tls.insert("enabled".into(), json!(true));

        let sni = self.effective_sni();
        if !sni.is_empty() {
            tls.insert("server_name".into(), json!(sni));
        }
        if self.allow_insecure {
            tls.insert("insecure".into(), json!(true));
        }
        if !self.alpn.is_empty() {
            tls.insert("alpn".into(), json!(self.alpn));
        }
        if !self.fingerprint.is_empty() {
            tls.insert(
                "utls".into(),
                json!({ "enabled": true, "fingerprint": self.fingerprint }),
            );
        }
        if self.security == Security::Reality && !self.public_key.is_empty() {
            // REALITY forges a real TLS handshake, so uTLS is mandatory; default
            // to chrome when the link did not pin a fingerprint.
            if !tls.contains_key("utls") {
                tls.insert(
                    "utls".into(),
                    json!({ "enabled": true, "fingerprint": "chrome" }),
                );
            }
            let mut reality = Map::new();
            reality.insert("enabled".into(), json!(true));
            reality.insert("public_key".into(), json!(self.public_key));
            if !self.short_id.is_empty() {
                reality.insert("short_id".into(), json!(self.short_id));
            }
            tls.insert("reality".into(), Value::Object(reality));
            // REALITY pins its own certificate chain; `insecure` would be a no-op
            // that only weakens the fallback path.
            tls.remove("insecure");
        }

        Some(Value::Object(tls))
    }

    fn transport_block(&self) -> Option<Value> {
        match self.network {
            Network::Tcp => None,
            Network::Ws => {
                let mut t = Map::new();
                t.insert("type".into(), json!("ws"));

                // v2rayN/3x-ui encode WebSocket early-data as `?ed=<bytes>` glued
                // onto the path. sing-box wants it as separate options.
                let (path, early) = split_early_data(&self.path);
                t.insert(
                    "path".into(),
                    json!(if path.is_empty() { "/".to_string() } else { path }),
                );
                if !self.host.is_empty() {
                    t.insert("headers".into(), json!({ "Host": self.host }));
                }
                if let Some(bytes) = early {
                    t.insert("max_early_data".into(), json!(bytes));
                    t.insert(
                        "early_data_header_name".into(),
                        json!("Sec-WebSocket-Protocol"),
                    );
                }
                Some(Value::Object(t))
            }
            Network::Grpc => {
                let name = if self.service_name.is_empty() {
                    self.path.trim_start_matches('/').to_string()
                } else {
                    self.service_name.clone()
                };
                Some(json!({ "type": "grpc", "service_name": name }))
            }
            Network::Http => {
                let mut t = Map::new();
                t.insert("type".into(), json!("http"));
                t.insert(
                    "path".into(),
                    json!(if self.path.is_empty() { "/".to_string() } else { self.path.clone() }),
                );
                if !self.host.is_empty() {
                    let hosts: Vec<String> = self
                        .host
                        .split(',')
                        .map(|h| h.trim().to_string())
                        .filter(|h| !h.is_empty())
                        .collect();
                    if !hosts.is_empty() {
                        t.insert("host".into(), json!(hosts));
                    }
                }
                Some(Value::Object(t))
            }
            // Never reached in practice: `needs_xray` diverts these nodes to the
            // Xray engine before a sing-box outbound is ever built for them.
            Network::Xhttp => None,
            Network::Httpupgrade => {
                let mut t = Map::new();
                t.insert("type".into(), json!("httpupgrade"));
                t.insert(
                    "path".into(),
                    json!(if self.path.is_empty() { "/".to_string() } else { self.path.clone() }),
                );
                if !self.host.is_empty() {
                    t.insert("host".into(), json!(self.host));
                }
                Some(Value::Object(t))
            }
        }
    }

    /// Render this node as a sing-box outbound.
    ///
    /// `domain_resolver` is pinned to the direct DNS server: without it the core
    /// would try to resolve the proxy's own hostname through the proxy itself.
    pub fn to_outbound(&self, tag: &str, domain_resolver: &str) -> Value {
        let mut o = Map::new();
        o.insert("type".into(), json!(self.protocol.as_singbox()));
        o.insert("tag".into(), json!(tag));
        o.insert("server".into(), json!(self.address));
        o.insert("server_port".into(), json!(self.port));

        match self.protocol {
            Protocol::Vless => {
                o.insert("uuid".into(), json!(self.uuid));
                // `flow` is only meaningful over a real TLS/REALITY handshake.
                if !self.flow.is_empty() && self.security != Security::None {
                    o.insert("flow".into(), json!(self.flow));
                }
                o.insert("packet_encoding".into(), json!("xudp"));
            }
            Protocol::Vmess => {
                o.insert("uuid".into(), json!(self.uuid));
                o.insert("alter_id".into(), json!(self.alter_id));
                let sec = if self.vmess_security.is_empty() {
                    "auto".to_string()
                } else {
                    self.vmess_security.clone()
                };
                o.insert("security".into(), json!(sec));
                o.insert("packet_encoding".into(), json!("xudp"));
            }
            Protocol::Trojan => {
                o.insert("password".into(), json!(self.password));
            }
            Protocol::Shadowsocks => {
                o.insert("method".into(), json!(self.method));
                o.insert("password".into(), json!(self.password));
            }
            Protocol::Hysteria2 => {
                o.insert("password".into(), json!(self.password));
            }
            Protocol::Tuic => {
                o.insert("uuid".into(), json!(self.uuid));
                o.insert("password".into(), json!(self.password));
                o.insert("congestion_control".into(), json!("bbr"));
            }
        }

        if let Some(tls) = self.tls_block() {
            o.insert("tls".into(), tls);
        }

        // QUIC-based protocols carry their own framing and reject a transport block.
        if !matches!(self.protocol, Protocol::Hysteria2 | Protocol::Tuic) {
            if let Some(t) = self.transport_block() {
                o.insert("transport".into(), t);
            }
        }

        // XTLS Vision multiplexes inside the TLS stream already; stacking smux on
        // top of it breaks the flow, so the two are mutually exclusive.
        if self.mux && !self.flow.contains("vision") {
            o.insert(
                "multiplex".into(),
                json!({
                    "enabled": true,
                    "protocol": "smux",
                    "max_streams": 8,
                    "padding": true
                }),
            );
        }

        if !domain_resolver.is_empty() {
            o.insert("domain_resolver".into(), json!(domain_resolver));
        }

        Value::Object(o)
    }
}

/// `"/path?ed=2048"` → `("/path", Some(2048))`.
fn split_early_data(path: &str) -> (String, Option<u32>) {
    let Some((base, query)) = path.split_once('?') else {
        return (path.to_string(), None);
    };
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("ed=") {
            if let Ok(bytes) = value.parse::<u32>() {
                return (base.to_string(), Some(bytes));
            }
        }
    }
    (path.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_data_is_lifted_out_of_the_path() {
        assert_eq!(split_early_data("/ray?ed=2048"), ("/ray".into(), Some(2048)));
        assert_eq!(split_early_data("/ray"), ("/ray".into(), None));
        // A query string without `ed` must survive untouched.
        assert_eq!(split_early_data("/ray?x=1"), ("/ray?x=1".into(), None));
    }

    #[test]
    fn reality_outbound_always_carries_utls() {
        let node = ServerNode {
            protocol: Protocol::Vless,
            security: Security::Reality,
            public_key: "pbk".into(),
            short_id: "sid".into(),
            address: "example.com".into(),
            ..Default::default()
        };
        let out = node.to_outbound("t", "dns-direct");
        let tls = &out["tls"];
        assert_eq!(tls["reality"]["enabled"], json!(true));
        assert_eq!(tls["utls"]["fingerprint"], json!("chrome"));
    }

    #[test]
    fn vision_flow_suppresses_multiplex() {
        let node = ServerNode {
            security: Security::Reality,
            public_key: "pbk".into(),
            flow: "xtls-rprx-vision".into(),
            mux: true,
            ..Default::default()
        };
        assert!(node.to_outbound("t", "").get("multiplex").is_none());
    }

    #[test]
    fn only_the_encryption_layer_is_negotiable() {
        // Encryption can be dropped: the server still speaks classic VLESS.
        let encrypted = ServerNode {
            protocol: Protocol::Vless,
            encryption: "mlkem768x25519plus.native.0rtt.KEY".into(),
            ..Default::default()
        };
        assert!(encrypted.can_fall_back_to_singbox());

        // XHTTP is the transport itself; there is nothing to fall back to.
        let xhttp = ServerNode {
            protocol: Protocol::Vless,
            network: Network::Xhttp,
            ..Default::default()
        };
        assert!(!xhttp.can_fall_back_to_singbox());

        // A plain node never needed Xray in the first place.
        assert!(!ServerNode::default().can_fall_back_to_singbox());
    }

    #[test]
    fn plain_vless_drops_flow() {
        let node = ServerNode {
            security: Security::None,
            flow: "xtls-rprx-vision".into(),
            ..Default::default()
        };
        assert!(node.to_outbound("t", "").get("flow").is_none());
    }
}
