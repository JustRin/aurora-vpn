//! Xray-core as a secondary engine.
//!
//! sing-box keeps everything it is good at — TUN, routing, per-application split
//! tunnelling, DNS, the control API. Nodes it cannot speak (VLESS Encryption,
//! XHTTP) are dialled by Xray instead and handed back over a loopback SOCKS hop,
//! one listener per node. To sing-box each of them is an ordinary `socks`
//! outbound, so the selector, urltest and latency probes keep working.

use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::error::{AppError, Result};
use crate::model::{Network, Protocol, Security, ServerNode};

/// First loopback port of the per-node SOCKS listeners.
pub const DEFAULT_BASE_PORT: u16 = 24_150;

pub struct BuiltXray {
    pub json: Value,
    /// node id → the loopback SOCKS port that reaches it.
    pub ports: HashMap<String, u16>,
}

fn stream_settings(node: &ServerNode) -> Value {
    let mut stream = Map::new();
    stream.insert("network".into(), json!(node.network.as_xray()));

    let security = match node.security {
        Security::None => "none",
        Security::Tls => "tls",
        Security::Reality => "reality",
    };
    stream.insert("security".into(), json!(security));

    // TLS validates against explicit SNI → transport Host → connect address,
    // matching how Xray itself resolves it.
    let sni = if !node.sni.is_empty() {
        node.sni.clone()
    } else if !node.host.is_empty() {
        node.host.split(',').next().unwrap_or("").trim().to_string()
    } else {
        node.address.clone()
    };

    match node.security {
        Security::Tls => {
            let mut tls = Map::new();
            tls.insert("serverName".into(), json!(sni));
            if !node.fingerprint.is_empty() {
                tls.insert("fingerprint".into(), json!(node.fingerprint));
            }
            if node.allow_insecure {
                tls.insert("allowInsecure".into(), json!(true));
            }
            if !node.alpn.is_empty() {
                tls.insert("alpn".into(), json!(node.alpn));
            }
            stream.insert("tlsSettings".into(), Value::Object(tls));
        }
        Security::Reality => {
            let mut reality = Map::new();
            reality.insert("serverName".into(), json!(sni));
            reality.insert(
                "fingerprint".into(),
                json!(if node.fingerprint.is_empty() {
                    "chrome"
                } else {
                    &node.fingerprint
                }),
            );
            reality.insert("publicKey".into(), json!(node.public_key));
            reality.insert("shortId".into(), json!(node.short_id));
            reality.insert("spiderX".into(), json!(node.spider_x));
            stream.insert("realitySettings".into(), Value::Object(reality));
        }
        Security::None => {}
    }

    let path = if node.path.is_empty() { "/" } else { &node.path };
    match node.network {
        Network::Tcp => {}
        Network::Ws => {
            let mut ws = Map::new();
            ws.insert("path".into(), json!(path));
            if !node.host.is_empty() {
                ws.insert("host".into(), json!(node.host));
            }
            stream.insert("wsSettings".into(), Value::Object(ws));
        }
        Network::Grpc => {
            let name = if node.service_name.is_empty() {
                node.path.trim_start_matches('/').to_string()
            } else {
                node.service_name.clone()
            };
            stream.insert("grpcSettings".into(), json!({ "serviceName": name }));
        }
        Network::Http => {
            let hosts: Vec<String> = node
                .host
                .split(',')
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .collect();
            stream.insert(
                "httpSettings".into(),
                json!({ "path": path, "host": hosts }),
            );
        }
        Network::Httpupgrade => {
            stream.insert(
                "httpupgradeSettings".into(),
                json!({ "path": path, "host": node.host }),
            );
        }
        Network::Xhttp => {
            let mut xhttp = Map::new();
            xhttp.insert("path".into(), json!(path));
            if !node.host.is_empty() {
                xhttp.insert("host".into(), json!(node.host));
            }
            stream.insert("xhttpSettings".into(), Value::Object(xhttp));
        }
    }

    Value::Object(stream)
}

fn outbound(node: &ServerNode, tag: &str) -> Result<Value> {
    let mut settings = Map::new();

    match node.protocol {
        Protocol::Vless => {
            let mut user = Map::new();
            user.insert("id".into(), json!(node.uuid));
            // Xray insists on the field being present; `none` is the classic value.
            user.insert(
                "encryption".into(),
                json!(if node.encryption.is_empty() {
                    "none"
                } else {
                    &node.encryption
                }),
            );
            if !node.flow.is_empty() && node.security != Security::None {
                user.insert("flow".into(), json!(node.flow));
            }
            settings.insert(
                "vnext".into(),
                json!([{
                    "address": node.address,
                    "port": node.port,
                    "users": [Value::Object(user)]
                }]),
            );
        }
        Protocol::Vmess => {
            settings.insert(
                "vnext".into(),
                json!([{
                    "address": node.address,
                    "port": node.port,
                    "users": [{
                        "id": node.uuid,
                        "alterId": node.alter_id,
                        "security": if node.vmess_security.is_empty() {
                            "auto"
                        } else {
                            &node.vmess_security
                        }
                    }]
                }]),
            );
        }
        Protocol::Trojan => {
            settings.insert(
                "servers".into(),
                json!([{
                    "address": node.address,
                    "port": node.port,
                    "password": node.password
                }]),
            );
        }
        other => {
            return Err(AppError::msg(format!(
                "протокол «{}» не поддерживается движком Xray",
                other.as_singbox()
            )))
        }
    }

    Ok(json!({
        "tag": tag,
        "protocol": node.protocol.as_singbox(),
        "settings": Value::Object(settings),
        "streamSettings": stream_settings(node)
    }))
}

/// Build the Xray document for the nodes that need it.
///
/// Returns `None` when no node does, so the second process is never started
/// for a configuration that does not need it.
pub fn build(nodes: &[ServerNode], base_port: u16, log_level: &str) -> Result<Option<BuiltXray>> {
    let needing: Vec<&ServerNode> = nodes.iter().filter(|n| n.needs_xray()).collect();
    if needing.is_empty() {
        return Ok(None);
    }

    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut rules = Vec::new();
    let mut ports = HashMap::new();

    for (index, node) in needing.iter().enumerate() {
        let port = base_port
            .checked_add(u16::try_from(index).unwrap_or(u16::MAX))
            .ok_or_else(|| AppError::msg("слишком много узлов для движка Xray"))?;
        let in_tag = format!("in-{index}");
        let out_tag = format!("out-{index}");

        inbounds.push(json!({
            "tag": in_tag,
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": port,
            "settings": { "auth": "noauth", "udp": true }
        }));
        outbounds.push(outbound(node, &out_tag)?);
        // Pin each listener to its own node: without this rule Xray would send
        // everything to the first outbound and every server would behave alike.
        rules.push(json!({
            "type": "field",
            "inboundTag": [in_tag],
            "outboundTag": out_tag
        }));

        ports.insert(node.id.clone(), port);
    }

    let json = json!({
        "log": { "loglevel": log_level },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": { "rules": rules }
    });

    Ok(Some(BuiltXray { json, ports }))
}

/// Xray's log levels differ from sing-box's; map ours onto the nearest.
pub fn log_level(level: &str) -> &'static str {
    match level {
        "trace" | "debug" => "debug",
        "info" => "info",
        "error" => "error",
        _ => "warning",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypted_node(id: &str) -> ServerNode {
        ServerNode {
            id: id.into(),
            name: format!("node {id}"),
            protocol: Protocol::Vless,
            address: "1.2.3.4".into(),
            port: 47182,
            uuid: "9deed72d-8f4a-42f8-8c22-ee0d5f6ed6c2".into(),
            security: Security::Reality,
            public_key: "PBK".into(),
            short_id: "79a1".into(),
            spider_x: "/spider".into(),
            fingerprint: "chrome".into(),
            sni: "www.icloud.com".into(),
            flow: "xtls-rprx-vision".into(),
            encryption: "mlkem768x25519plus.native.0rtt.KEY".into(),
            ..Default::default()
        }
    }

    #[test]
    fn plain_nodes_do_not_start_the_second_engine() {
        let plain = ServerNode {
            protocol: Protocol::Vless,
            encryption: "none".into(),
            ..Default::default()
        };
        assert!(!plain.needs_xray());
        assert!(build(&[plain], 24150, "warning").unwrap().is_none());
    }

    #[test]
    fn vless_encryption_and_xhttp_both_route_through_xray() {
        assert!(encrypted_node("a").needs_xray());

        let xhttp = ServerNode {
            protocol: Protocol::Vless,
            network: Network::Xhttp,
            ..Default::default()
        };
        assert!(xhttp.needs_xray());
    }

    #[test]
    fn each_node_gets_its_own_listener_and_routing_rule() {
        let nodes = vec![encrypted_node("a"), encrypted_node("b")];
        let built = build(&nodes, 24150, "warning").unwrap().unwrap();

        assert_eq!(built.ports["a"], 24150);
        assert_eq!(built.ports["b"], 24151);

        let rules = built.json["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        // A shared outbound would make every server behave like the first.
        assert_eq!(rules[0]["inboundTag"], json!(["in-0"]));
        assert_eq!(rules[0]["outboundTag"], json!("out-0"));
        assert_eq!(rules[1]["outboundTag"], json!("out-1"));
    }

    #[test]
    fn reality_and_encryption_reach_the_outbound_verbatim() {
        let built = build(&[encrypted_node("a")], 24150, "warning").unwrap().unwrap();
        let out = &built.json["outbounds"][0];
        let user = &out["settings"]["vnext"][0]["users"][0];

        assert_eq!(user["encryption"], json!("mlkem768x25519plus.native.0rtt.KEY"));
        assert_eq!(user["flow"], json!("xtls-rprx-vision"));

        let reality = &out["streamSettings"]["realitySettings"];
        assert_eq!(reality["publicKey"], json!("PBK"));
        assert_eq!(reality["shortId"], json!("79a1"));
        assert_eq!(reality["spiderX"], json!("/spider"));
        assert_eq!(reality["serverName"], json!("www.icloud.com"));
    }

    #[test]
    fn hysteria2_is_rejected_rather_than_mangled() {
        // Only sing-box speaks it; silently emitting a broken Xray outbound
        // would be worse than refusing.
        let node = ServerNode {
            protocol: Protocol::Hysteria2,
            network: Network::Xhttp,
            ..Default::default()
        };
        assert!(build(&[node], 24150, "warning").is_err());
    }
}
