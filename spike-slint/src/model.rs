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
    /// WireGuard, and with it Cloudflare WARP. Unlike every other protocol here
    /// it is not an outbound but an *endpoint* — see [`ServerNode::is_endpoint`].
    Wireguard,
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
            Protocol::Wireguard => "wireguard",
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

    // ---- hysteria2 ----
    /// QUIC-обфускация; пусто — без неё. Единственный тип — «salamander».
    pub obfs: String,
    pub obfs_password: String,
    /// Диапазоны прыжковых портов в форме sing-box («20000:50000»); основной
    /// порт остаётся в `port`.
    pub hop_ports: Vec<String>,

    // ---- wireguard / WARP ----
    /// Our own x25519 secret, base64. The peer lives in `address`/`port`.
    pub private_key: String,
    pub peer_public_key: String,
    /// Addresses of the virtual interface, bare (`172.16.0.2`); the prefix
    /// length is implied — a WireGuard client owns exactly its own address.
    pub local_v4: String,
    pub local_v6: String,
    /// WARP tags every packet with three bytes derived from the account's
    /// `client_id`; a plain WireGuard peer leaves this empty.
    pub reserved: Vec<u8>,
    pub mtu: u16,
    /// Seconds between keepalives; 0 leaves it off.
    pub keepalive: u16,

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
            obfs: String::new(),
            obfs_password: String::new(),
            hop_ports: Vec::new(),
            private_key: String::new(),
            peer_public_key: String::new(),
            local_v4: String::new(),
            local_v6: String::new(),
            reserved: Vec::new(),
            // WARP's own client advertises 1280: the tunnel rides inside UDP that
            // itself crosses networks of unknown MTU, and 1420 fragments there.
            mtu: 1280,
            keepalive: 30,
            subscription_id: None,
            raw_link: String::new(),
        }
    }
}

/// Отпечатки uTLS, которые понимает ядро.
///
/// Список фильтруется не для красоты: на незнакомом отпечатке sing-box
/// отвергает не узел, а весь конфиг целиком — «initialize outbound[6]: unknown
/// uTLS fingerprint», и подключения нет вообще. А приносят подписки что
/// угодно: `unsafe`, `random_hello`, пустые строки. Незнакомое просто
/// выбрасывается: ядро подставит своё, и узел останется рабочим.
const KNOWN_FINGERPRINTS: [&str; 11] = [
    "chrome",
    "firefox",
    "edge",
    "safari",
    "360",
    "qq",
    "ios",
    "android",
    "random",
    "randomized",
    "randomizednoalpn",
];

impl ServerNode {
    /// Whether this node can only be carried by the Xray engine.
    ///
    /// Two features force it: VLESS Encryption, which sing-box does not
    /// implement at all, and the XHTTP transport, which is Xray-only. Such a
    /// node is dialled by Xray and handed to sing-box over a loopback SOCKS
    /// hop, so routing and split tunnelling keep working unchanged.
    pub fn needs_xray(&self) -> bool {
        // An endpoint has no transport and no TLS layer, so neither of the two
        // Xray-only features below can apply — whatever a hand-edited file says.
        if self.is_endpoint() {
            return false;
        }
        let encrypted = !self.encryption.is_empty()
            && !self.encryption.eq_ignore_ascii_case("none");
        (self.protocol == Protocol::Vless && encrypted) || self.network == Network::Xhttp
    }

    /// Whether the node renders into `endpoints` rather than `outbounds`.
    ///
    /// sing-box dropped the `wireguard` outbound in 1.13; the protocol lives on
    /// as an endpoint — a thing with both inbound and outbound behaviour. It is
    /// still addressed by tag everywhere else, so selectors, the Clash API and
    /// the latency probes cannot tell the difference.
    pub fn is_endpoint(&self) -> bool {
        self.protocol == Protocol::Wireguard
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
        if KNOWN_FINGERPRINTS.contains(&self.fingerprint.as_str()) {
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
                if !self.obfs.is_empty() {
                    o.insert(
                        "obfs".into(),
                        json!({ "type": self.obfs, "password": self.obfs_password }),
                    );
                }
                if !self.hop_ports.is_empty() {
                    // `server_port` остаётся: первый удар идёт по основному
                    // порту, диапазоны — для прыжков.
                    o.insert("server_ports".into(), json!(self.hop_ports));
                }
            }
            Protocol::Tuic => {
                o.insert("uuid".into(), json!(self.uuid));
                o.insert("password".into(), json!(self.password));
                o.insert("congestion_control".into(), json!("bbr"));
            }
            // Never reached: `is_endpoint` sends these nodes to `to_endpoint`
            // before an outbound is ever built for them.
            Protocol::Wireguard => {}
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

    /// Render this node as a sing-box WireGuard endpoint.
    ///
    /// `detour` chains the endpoint on top of another outbound: this is what
    /// carries the WARP layer, where the tunnel's own UDP travels through the
    /// user's proxy instead of leaving the machine directly.
    pub fn to_endpoint(&self, tag: &str, domain_resolver: &str, detour: Option<&str>) -> Value {
        let mut e = Map::new();
        e.insert("type".into(), json!("wireguard"));
        e.insert("tag".into(), json!(tag));
        e.insert("mtu".into(), json!(self.mtu));

        // A WireGuard client owns exactly the addresses it was handed, so each
        // one is a host route rather than a subnet.
        let mut addresses: Vec<String> = Vec::new();
        if !self.local_v4.is_empty() {
            addresses.push(with_prefix(&self.local_v4, 32));
        }
        if !self.local_v6.is_empty() {
            addresses.push(with_prefix(&self.local_v6, 128));
        }
        e.insert("address".into(), json!(addresses));
        e.insert("private_key".into(), json!(self.private_key));

        let mut peer = Map::new();
        peer.insert("address".into(), json!(self.address));
        peer.insert("port".into(), json!(self.port));
        peer.insert("public_key".into(), json!(self.peer_public_key));
        // Everything goes through the tunnel: this endpoint is either the exit
        // itself or the layer wrapped around one.
        peer.insert("allowed_ips".into(), json!(["0.0.0.0/0", "::/0"]));
        if !self.reserved.is_empty() {
            peer.insert("reserved".into(), json!(self.reserved));
        }
        if self.keepalive > 0 {
            peer.insert("persistent_keepalive_interval".into(), json!(self.keepalive));
        }
        e.insert("peers".into(), json!([Value::Object(peer)]));

        if let Some(tag) = detour {
            e.insert("detour".into(), json!(tag));
        }
        if !domain_resolver.is_empty() {
            e.insert("domain_resolver".into(), json!(domain_resolver));
        }

        Value::Object(e)
    }
}

/// `172.16.0.2` → `172.16.0.2/32`, leaving an address that already carries a
/// prefix alone.
fn with_prefix(address: &str, bits: u8) -> String {
    if address.contains('/') {
        address.to_string()
    } else {
        format!("{address}/{bits}")
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
    fn hysteria2_outbound_carries_obfs_and_hop_ports() {
        let node = ServerNode {
            protocol: Protocol::Hysteria2,
            address: "1.2.3.4".into(),
            port: 443,
            password: "p".into(),
            obfs: "salamander".into(),
            obfs_password: "rain".into(),
            hop_ports: vec!["20000:50000".into()],
            ..Default::default()
        };
        let out = node.to_outbound("t", "dns-direct");
        assert_eq!(out["obfs"]["type"], json!("salamander"));
        assert_eq!(out["obfs"]["password"], json!("rain"));
        assert_eq!(out["server_ports"], json!(["20000:50000"]));
        // Основной порт не теряется — по нему идёт первое подключение.
        assert_eq!(out["server_port"], json!(443));
        // QUIC сам себе рамка: TLS обязателен, transport-блока нет.
        assert_eq!(out["tls"]["enabled"], json!(true));
        assert!(out.get("transport").is_none());
    }

    #[test]
    fn hysteria2_without_extras_stays_minimal() {
        let node = ServerNode {
            protocol: Protocol::Hysteria2,
            address: "1.2.3.4".into(),
            port: 443,
            password: "p".into(),
            ..Default::default()
        };
        let out = node.to_outbound("t", "");
        assert!(out.get("obfs").is_none());
        assert!(out.get("server_ports").is_none());
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

    #[test]
    fn a_wireguard_endpoint_carries_host_routes_and_the_warp_tag() {
        let node = ServerNode {
            protocol: Protocol::Wireguard,
            address: "162.159.192.1".into(),
            port: 2408,
            private_key: "priv".into(),
            peer_public_key: "peer".into(),
            local_v4: "172.16.0.2".into(),
            local_v6: "2606:4700:110::2".into(),
            reserved: vec![189, 239, 196],
            ..Default::default()
        };
        let out = node.to_endpoint("warp", "dns-direct", None);

        assert_eq!(out["type"], json!("wireguard"));
        // Клиент владеет ровно выданными адресами — это /32 и /128, не подсети.
        assert_eq!(out["address"], json!(["172.16.0.2/32", "2606:4700:110::2/128"]));
        let peer = &out["peers"][0];
        assert_eq!(peer["address"], json!("162.159.192.1"));
        assert_eq!(peer["port"], json!(2408));
        assert_eq!(peer["allowed_ips"], json!(["0.0.0.0/0", "::/0"]));
        assert_eq!(peer["reserved"], json!([189, 239, 196]));
        assert_eq!(out["domain_resolver"], json!("dns-direct"));
        assert!(out.get("detour").is_none());
    }

    #[test]
    fn a_detour_turns_the_endpoint_into_a_layer() {
        let node = ServerNode {
            protocol: Protocol::Wireguard,
            local_v4: "172.16.0.2".into(),
            ..Default::default()
        };
        let out = node.to_endpoint("warp-layer", "", Some("proxy"));
        assert_eq!(out["detour"], json!("proxy"));
        // Пустой resolver не выдумывает ключ: у sing-box отсутствие поля само
        // означает «как обычно».
        assert!(out.get("domain_resolver").is_none());
    }

    #[test]
    fn a_plain_wireguard_peer_carries_no_reserved_bytes() {
        // Пустой `reserved` пропускается: WARP-метка есть не у всякого пира, а
        // массив неверной длины ядро отвергает вместе со всем документом.
        let node = ServerNode {
            protocol: Protocol::Wireguard,
            local_v4: "10.0.0.2".into(),
            keepalive: 0,
            ..Default::default()
        };
        let out = node.to_endpoint("wg", "", None);
        assert!(out["peers"][0].get("reserved").is_none());
        assert!(out["peers"][0].get("persistent_keepalive_interval").is_none());
    }

    #[test]
    fn an_address_that_already_has_a_prefix_is_left_alone() {
        assert_eq!(with_prefix("172.16.0.2", 32), "172.16.0.2/32");
        assert_eq!(with_prefix("172.16.0.2/30", 32), "172.16.0.2/30");
    }

    #[test]
    fn an_endpoint_never_goes_to_the_second_engine() {
        // У endpoint нет ни транспорта, ни TLS-слоя, так что ни одна причина
        // уйти в Xray к нему не относится — что бы ни лежало в файле.
        let node = ServerNode {
            protocol: Protocol::Wireguard,
            network: Network::Xhttp,
            encryption: "mlkem768x25519plus.native.0rtt.KEY".into(),
            ..Default::default()
        };
        assert!(node.is_endpoint());
        assert!(!node.needs_xray());
    }
}
