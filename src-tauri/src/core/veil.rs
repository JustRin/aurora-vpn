//! Veil там, где ядро — sing-box (Linux, macOS) или libbox (Android).
//!
//! Ни то ни другое не знает Veil, поэтому его узлы везёт aura-engine внутри
//! этого же процесса, а sing-box видит их как loopback-SOCKS — тот же приём,
//! что Xray на ПК. Свой дозвон движка до сервера sing-box выпускает мимо
//! туннеля по адресу сервера (правила для узлов из `xray_ports` в config.rs).
//! На Android к этому три отличия, и все про то, что на телефоне 127.0.0.1
//! общий для всех приложений:
//! - у каждого входа пароль (секрет сессии): иначе любое приложение, в том
//!   числе российское, исключённое из туннеля, пустило бы запрос через сервер
//!   и увидело его IP;
//! - сокеты движка выводятся из VPN через `VpnService.protect`, иначе дозвон до
//!   сервера Veil ушёл бы в собственный туннель и замкнулся;
//! - имя сервера движок резолвит сам через DNS «напрямую» из настроек, тоже по
//!   защищённым сокетам: системный резолвер внутри VPN отдал бы fake-ip.

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::model::ServerNode;

/// Первый порт входов. Порты зависят только от порядка узлов: документ,
/// собранный заново, совпадает с работающим.
pub const BASE_PORT: u16 = 24_250;
/// Логин входов; пароль — секрет сессии, тот же, что у панели ядра.
pub const PROXY_USER: &str = "aurora";
const DNS_TAG: &str = "veil-dns";

/// Документ движка и порт каждого узла Veil. `None` — таких узлов нет.
pub fn sidecar_config(
    nodes: &[ServerNode],
    password: &str,
    dns_direct: &str,
    log_level: &str,
) -> Option<(Value, HashMap<String, u16>)> {
    let veil: Vec<&ServerNode> = nodes.iter().filter(|n| n.needs_aura()).collect();
    if veil.is_empty() {
        return None;
    }
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut rules = Vec::new();
    let mut ports = HashMap::new();
    for (index, node) in veil.iter().enumerate() {
        let Some(port) = BASE_PORT.checked_add(index as u16) else { break };
        let (inbound, outbound) = (format!("in-{index}"), format!("out-{index}"));
        inbounds.push(json!({
            "type": "mixed",
            "tag": inbound,
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{ "username": PROXY_USER, "password": password }]
        }));
        outbounds.push(node.to_outbound(&outbound, DNS_TAG));
        // Каждый вход — только к своему узлу: без правила все шли бы в первый.
        rules.push(json!({ "inbound": [inbound], "outbound": outbound }));
        ports.insert(node.id.clone(), port);
    }
    outbounds.push(json!({ "type": "block", "tag": "block" }));
    // `local` здесь нельзя: системный резолвер внутри VPN спросил бы sing-box.
    let dns = if dns_direct.trim().eq_ignore_ascii_case("local") { "77.88.8.8" } else { dns_direct };
    let (server, _) = super::config::dns_server(DNS_TAG, dns, None);
    let level = match log_level {
        "trace" | "debug" => "debug",
        "info" => "info",
        "error" => "error",
        _ => "warn",
    };
    let doc = json!({
        "log": { "level": level },
        "dns": { "servers": [server], "final": DNS_TAG },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": { "rules": rules, "final": "block" }
    });
    Some((doc, ports))
}

pub use engine::{start, stop};

mod engine {
    use std::collections::HashMap;

    use tauri::{AppHandle, Emitter, Manager};

    use crate::core::log::LogLine;
    use crate::error::{AppError, Result};
    use crate::model::ServerNode;
    use crate::state::AppState;

    /// Поднять движок под узлы Veil из `nodes` и вернуть их порты. Прежний
    /// движок снимается в любом случае.
    pub fn start(app: &AppHandle, nodes: &[ServerNode]) -> Result<HashMap<String, u16>> {
        stop(app);
        let state = app.state::<AppState>();
        let (dns, level) = {
            let settings = state.settings.read();
            (settings.dns_direct.clone(), settings.log_level.clone())
        };
        let Some((doc, ports)) = super::sidecar_config(nodes, &state.secret, &dns, &level) else {
            return Ok(HashMap::new());
        };
        let path = state.paths.work_dir.join("veil.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&doc)?)?;

        // Android: сокеты движка выводит из VPN сам VpnService.
        #[cfg(target_os = "android")]
        {
            let protect_app = app.clone();
            aura_engine::set_socket_protector(Some(std::sync::Arc::new(move |fd| {
                crate::core::android::protect(&protect_app, fd)
            })));
        }

        let log_app = app.clone();
        let sink = aura_engine::log_sink(move |level, text| {
            let _ = log_app.emit(
                crate::commands::EVT_LOG,
                LogLine { seq: 0, level: level.to_string(), text: format!("veil: {text}") },
            );
        });
        let engine = aura_engine::start(aura_engine::Options { config: path, wintun: None, log: Some(sink) })
            .map_err(|e| AppError::msg(format!("Veil: движок не запустился: {e}")))?;
        *state.veil.lock() = Some(engine);
        Ok(ports)
    }

    pub fn stop(app: &AppHandle) {
        let state = app.state::<AppState>();
        // Drop снимает рантайм движка и закрывает его входы.
        let engine = state.veil.lock().take();
        drop(engine);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;

    fn veil(id: &str) -> ServerNode {
        ServerNode {
            id: id.into(),
            name: id.into(),
            protocol: Protocol::Veil,
            address: "example.com".into(),
            port: 443,
            password: "pw".into(),
            path: "/api/v1/sync/x".into(),
            security: crate::model::Security::Tls,
            ..Default::default()
        }
    }

    #[test]
    fn each_veil_node_gets_its_own_locked_listener() {
        let plain = ServerNode { id: "v".into(), ..Default::default() };
        let (doc, ports) = sidecar_config(&[veil("a"), plain, veil("b")], "secret", "77.88.8.8", "info").unwrap();
        assert_eq!(ports.len(), 2, "VLESS сюда не попадает");
        assert_eq!(ports["a"], BASE_PORT);
        assert_eq!(ports["b"], BASE_PORT + 1);

        let inbounds = doc["inbounds"].as_array().unwrap();
        assert!(inbounds.iter().all(|i| i["listen"] == json!("127.0.0.1")
            && i["users"][0]["username"] == json!(PROXY_USER)
            && i["users"][0]["password"] == json!("secret")));
        let rules = doc["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[1], json!({ "inbound": ["in-1"], "outbound": "out-1" }));
        assert_eq!(doc["route"]["final"], json!("block"));
        let out = &doc["outbounds"][0];
        assert_eq!(out["type"], json!("veil"));
        assert_eq!(out["domain_resolver"], json!(DNS_TAG));
        assert_eq!(doc["dns"]["servers"][0]["tag"], json!(DNS_TAG));
    }

    #[test]
    fn no_veil_nodes_no_engine() {
        assert!(sidecar_config(&[ServerNode::default()], "s", "77.88.8.8", "info").is_none());
    }

    #[test]
    fn the_system_resolver_is_never_used() {
        let (doc, _) = sidecar_config(&[veil("a")], "s", "local", "info").unwrap();
        assert_ne!(doc["dns"]["servers"][0]["type"], json!("local"));
    }
}
