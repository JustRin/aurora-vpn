//! Turns the user-facing model (servers + settings + split rules) into a
//! sing-box configuration document.
//!
//! Rule ordering is the whole game here: sing-box takes the first match, so the
//! sequence below encodes the product's precedence promise, from most specific
//! to least:
//!
//! ```text
//! sniff → Xray bypass → DNS hijack → Clash mode override → blocklist
//!   → private IPs → user "always direct" → user "always proxy" → geo bypass
//!   → per-application rules → final
//! ```

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::error::{AppError, Result};
use crate::model::ServerNode;
use crate::settings::{Settings, SplitConfig, SplitMode, TunnelMode};

pub const TAG_PROXY: &str = "proxy";
pub const TAG_AUTO: &str = "auto";
pub const TAG_DIRECT: &str = "direct";
pub const TAG_DNS_REMOTE: &str = "dns-remote";
pub const TAG_DNS_DIRECT: &str = "dns-direct";
pub const TAG_DNS_FAKE: &str = "dns-fake";
pub const TAG_DNS_BOOTSTRAP: &str = "dns-bootstrap";

pub struct BuildInput<'a> {
    pub nodes: &'a [ServerNode],
    pub active_id: &'a str,
    pub settings: &'a Settings,
    pub split: &'a SplitConfig,
    pub clash_secret: &'a str,
    pub cache_path: &'a Path,
    /// node id → loopback SOCKS port served by the Xray engine. Those nodes
    /// become plain `socks` outbounds here, which keeps the selector, urltest
    /// and latency probes working exactly as for native ones.
    pub xray_ports: &'a HashMap<String, u16>,
    /// Path of the Xray binary we spawn, so its own dials can be routed around
    /// the tunnel. Without it those nodes connect and then carry nothing.
    pub xray_exe: Option<&'a Path>,
    /// Geo rule-sets already cached on disk. A set that is missing is omitted
    /// along with its rules — referencing it would make the core refuse to
    /// start, taking the whole tunnel down over an optional filter.
    pub rule_sets: &'a HashSet<String>,
    pub rule_set_dir: &'a Path,
    /// In-process libbox has no stdout the app could capture, so the config
    /// points its log output at a file the Rust side tails.
    #[cfg(target_os = "android")]
    pub log_file: &'a Path,
}

#[derive(Debug)]
pub struct BuiltConfig {
    pub json: Value,
    /// `(node id, sing-box outbound tag)` so the UI can drive the Clash API,
    /// which addresses proxies by tag rather than by our internal id.
    pub tags: Vec<(String, String)>,
}

/// Outbound tags end up in logs and in the Clash API URL path, so keep them
/// readable but free of characters that would need escaping.
fn sanitize_tag(name: &str, index: usize) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_matches('-').trim();
    let short: String = cleaned.chars().take(40).collect();
    if short.is_empty() {
        format!("node-{index}")
    } else {
        format!("{index}-{short}")
    }
}

/// Expand a DNS address into sing-box's typed server object.
///
/// Accepts a bare IP (`1.1.1.1`), an explicit scheme (`tls://`, `https://`,
/// `quic://`, `h3://`, `udp://`) or the literal `local` for the OS resolver.
fn dns_server(tag: &str, address: &str, detour: Option<&str>) -> (Value, bool) {
    let raw = address.trim();
    let mut server = Map::new();
    server.insert("tag".into(), json!(tag));

    let (scheme, rest) = match raw.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r.to_string()),
        None => (String::new(), raw.to_string()),
    };

    if raw.eq_ignore_ascii_case("local") || scheme == "local" {
        server.insert("type".into(), json!("local"));
        return (Value::Object(server), false);
    }

    // For DoH/DoH3 the remainder is `host[:port]/path`.
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h.to_string(), format!("/{p}")),
        None => (rest.clone(), String::new()),
    };

    let (host, port) = match hostport.rsplit_once(':') {
        // Guard against bare IPv6 literals being split on their own colons.
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => {
            (h.to_string(), p.parse::<u16>().ok())
        }
        _ => (hostport.clone(), None),
    };

    let kind = match scheme.as_str() {
        "tls" => "tls",
        "https" => "https",
        "quic" => "quic",
        "h3" => "h3",
        _ => "udp",
    };
    server.insert("type".into(), json!(kind));
    server.insert("server".into(), json!(host));
    if let Some(p) = port {
        server.insert("server_port".into(), json!(p));
    }
    if matches!(kind, "https" | "h3") && !path.is_empty() {
        server.insert("path".into(), json!(path));
    }
    if let Some(d) = detour {
        server.insert("detour".into(), json!(d));
    }

    // A hostname-based resolver has to be bootstrapped by something else.
    let needs_bootstrap = host.parse::<IpAddr>().is_err();
    (Value::Object(server), needs_bootstrap)
}

/// Emit one rule per matcher kind: within a single sing-box rule the fields are
/// ANDed, so name-matches and path-matches must live in separate rules to be ORed.
#[cfg(not(target_os = "android"))]
fn app_rules(split: &SplitConfig, extra: &[(&str, Value)]) -> Vec<Value> {
    let mut out = Vec::new();
    let names = split.active_names();
    let paths = split.active_paths();

    for (field, values) in [("process_name", names), ("process_path", paths)] {
        if values.is_empty() {
            continue;
        }
        let mut rule = Map::new();
        rule.insert(field.into(), json!(values));
        for (k, v) in extra {
            rule.insert((*k).into(), v.clone());
        }
        out.push(Value::Object(rule));
    }
    out
}

/// Keep the second engine's own connections out of the tunnel.
///
/// `auto_detect_interface` is what stops sing-box from dialling through its own
/// TUN, but it only covers sing-box: Xray is a separate process, and its packets
/// are captured like any other application's. They then fall through to
/// `final: proxy`, reach the selector, and arrive back at the very loopback SOCKS
/// listener they came from — Xray dialling itself, forever.
///
/// The failure is silent by construction: connecting to a local listener always
/// succeeds, so the core reports a healthy tunnel and the interface says
/// «Подключено» while not a byte reaches the server.
///
/// Two rules rather than one: fields inside a sing-box rule are ANDed, so the
/// path match and the name match have to be separate to be ORed.
fn engine_bypass_rules(exe: &Path, extra: &[(&str, Value)]) -> Vec<Value> {
    let path = exe.to_string_lossy().to_string();
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    [("process_path", path), ("process_name", name)]
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(field, value)| {
            let mut rule = Map::new();
            rule.insert(field.into(), json!([value]));
            for (k, v) in extra {
                rule.insert((*k).into(), v.clone());
            }
            Value::Object(rule)
        })
        .collect()
}

/// Local, never remote: the file is already on disk by the time we get here.
fn rule_set(tag: &str, dir: &Path) -> Value {
    json!({
        "type": "local",
        "tag": tag,
        "format": "binary",
        "path": crate::core::ruleset::path_for(dir, tag).to_string_lossy()
    })
}

pub fn build(input: &BuildInput) -> Result<BuiltConfig> {
    let BuildInput {
        nodes,
        active_id,
        settings,
        split,
        clash_secret,
        cache_path,
        xray_ports,
        xray_exe,
        rule_sets,
        rule_set_dir,
        #[cfg(target_os = "android")]
        log_file,
    } = input;

    // Android has exactly one tunnel: the VpnService TUN device. The persisted
    // preference may still say "system proxy" if the store travelled over from
    // a desktop install.
    #[cfg(target_os = "android")]
    let tunnel_mode = TunnelMode::Tun;
    #[cfg(not(target_os = "android"))]
    let tunnel_mode = settings.tunnel_mode;

    // Only worth emitting when the second engine is actually dialling something.
    let xray_bypass = match (xray_ports.is_empty(), *xray_exe) {
        (false, Some(exe)) => Some(exe),
        _ => None,
    };

    // The addresses the second engine dials, excluded by destination as well.
    // Process attribution alone is not enough: it races an engine switchover
    // (the old core keeps routing while the new one comes up), and the lookup
    // for a node's hostname is made by the system resolver, not by Xray, so no
    // process rule can ever claim it.
    let mut xray_server_ips: Vec<String> = Vec::new();
    let mut xray_server_domains: Vec<String> = Vec::new();
    for node in nodes.iter().filter(|n| xray_ports.contains_key(&n.id)) {
        let entry = match node.address.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => (format!("{ip}/32"), &mut xray_server_ips),
            Ok(IpAddr::V6(ip)) => (format!("{ip}/128"), &mut xray_server_ips),
            Err(_) => (node.address.clone(), &mut xray_server_domains),
        };
        if !entry.1.contains(&entry.0) {
            entry.1.push(entry.0);
        }
    }

    // A toggle whose data never arrived must not be silently half-applied.
    let has_set = |tag: &str| rule_sets.contains(tag);
    let block_ads = split.block_ads && has_set("geosite-ads");
    let bypass_ru = split.bypass_ru && has_set("geosite-ru") && has_set("geoip-ru");
    let bypass_cn = split.bypass_cn && has_set("geosite-cn") && has_set("geoip-cn");

    if nodes.is_empty() {
        return Err(AppError::msg("не добавлено ни одного сервера"));
    }

    // ---------------------------------------------------------------- outbounds
    let mut outbounds: Vec<Value> = Vec::new();
    let mut tags: Vec<(String, String)> = Vec::new();

    for (index, node) in nodes.iter().enumerate() {
        let tag = sanitize_tag(&node.name, index);
        let outbound = match xray_ports.get(&node.id) {
            Some(port) => json!({
                "type": "socks",
                "tag": tag,
                "server": "127.0.0.1",
                "server_port": port,
                "version": "5"
            }),
            None => node.to_outbound(&tag, TAG_DNS_DIRECT),
        };
        outbounds.push(outbound);
        tags.push((node.id.clone(), tag));
    }

    let node_tags: Vec<String> = tags.iter().map(|(_, t)| t.clone()).collect();

    // vmess+ws в авто-группу не включаются: в sing-box (вплоть до 1.14-rc)
    // неудачный дозвон до такого узла роняет весь процесс — паника typed-nil
    // в v2raywebsocket.Close (transport/v2raywebsocket/conn.go:49, приходит
    // из protocol/vmess/outbound.go:173). urltest — это принудительные
    // дозвоны до всех узлов на старте и каждые три минуты, включая мёртвые
    // из публичных подписок: с ними ядро жило секунды. Вручную такой узел
    // выбрать по-прежнему можно — разовый сбой ловит автоперезапуск, — а
    // узел, унесённый в Xray, безопасен и остаётся в группе: sing-box дозванивается
    // лишь до его loopback-порта.
    let auto_members: Vec<String> = nodes
        .iter()
        .zip(&node_tags)
        .filter(|(node, _)| {
            let ws_vmess = node.protocol == crate::model::Protocol::Vmess
                && node.network == crate::model::Network::Ws;
            !ws_vmess || xray_ports.contains_key(&node.id)
        })
        .map(|(_, tag)| tag.clone())
        .collect();
    // Список из одних vmess+ws оставляем как есть: пустую группу sing-box
    // отвергает, а без авто-группы не собирается селектор.
    let auto_members = if auto_members.is_empty() { node_tags.clone() } else { auto_members };

    outbounds.push(json!({
        "type": "urltest",
        "tag": TAG_AUTO,
        "outbounds": auto_members,
        "url": settings.latency_url,
        "interval": "3m",
        "tolerance": 50,
        "idle_timeout": "30m"
    }));

    let active_tag = tags
        .iter()
        .find(|(id, _)| id == active_id)
        .map(|(_, t)| t.clone())
        .unwrap_or_else(|| node_tags[0].clone());

    let default_tag = if settings.auto_select {
        TAG_AUTO.to_string()
    } else {
        active_tag
    };

    let mut selector_members = vec![TAG_AUTO.to_string()];
    selector_members.extend(node_tags.iter().cloned());

    outbounds.push(json!({
        "type": "selector",
        "tag": TAG_PROXY,
        "outbounds": selector_members,
        "default": default_tag,
        // Without this, switching servers leaves live sockets on the old node.
        "interrupt_exist_connections": true
    }));
    outbounds.push(json!({ "type": "direct", "tag": TAG_DIRECT }));

    // --------------------------------------------------------------------- dns
    let mut dns_servers: Vec<Value> = Vec::new();

    // No `detour` on the direct resolver: in sing-box an absent detour already
    // means "dial directly", and naming the plain `direct` outbound explicitly
    // is rejected at start-up with "detour to an empty direct outbound makes no
    // sense". `sing-box check` does not catch it — only running the core does.
    let (direct_server, direct_needs_bootstrap) =
        dns_server(TAG_DNS_DIRECT, &settings.dns_direct, None);
    let (remote_server, _) = dns_server(TAG_DNS_REMOTE, &settings.dns_remote, Some(TAG_PROXY));

    if direct_needs_bootstrap {
        dns_servers.push(json!({ "type": "local", "tag": TAG_DNS_BOOTSTRAP }));
    }

    let mut direct_server = direct_server;
    if direct_needs_bootstrap {
        direct_server["domain_resolver"] = json!(TAG_DNS_BOOTSTRAP);
    }
    dns_servers.push(direct_server);

    // The remote resolver lives behind the proxy, so its own hostname (if any)
    // must be resolved by the direct one first.
    let mut remote_server = remote_server;
    remote_server["domain_resolver"] = json!(TAG_DNS_DIRECT);
    dns_servers.push(remote_server);

    if settings.fake_ip {
        dns_servers.push(json!({
            "type": "fakeip",
            "tag": TAG_DNS_FAKE,
            "inet4_range": "198.18.0.0/15",
            "inet6_range": "fc00::/18"
        }));
    }

    let mut dns_rules: Vec<Value> = Vec::new();

    // First, and ahead of the blocklists: the hand-off leaks through DNS exactly
    // as it does through routing. A hijacked lookup for the node's own hostname
    // would be sent to the remote resolver, which sits behind the proxy — behind
    // Xray itself — and the name would never resolve.
    if let Some(exe) = xray_bypass {
        dns_rules.extend(engine_bypass_rules(exe, &[("server", json!(TAG_DNS_DIRECT))]));
    }
    // The hostname of an Xray-backed node is resolved by svchost on the
    // engine's behalf; sending that lookup to the proxied resolver would ask
    // the node to bootstrap through itself.
    if !xray_server_domains.is_empty() {
        dns_rules.push(json!({
            "domain": xray_server_domains,
            "server": TAG_DNS_DIRECT
        }));
    }

    if !split.block_domains.is_empty() {
        dns_rules.push(json!({
            "domain_suffix": split.block_domains,
            "action": "reject"
        }));
    }
    if block_ads {
        dns_rules.push(json!({ "rule_set": ["geosite-ads"], "action": "reject" }));
    }
    if !split.direct_domains.is_empty() {
        dns_rules.push(json!({
            "domain_suffix": split.direct_domains,
            "server": TAG_DNS_DIRECT
        }));
    }
    if !split.proxy_domains.is_empty() {
        dns_rules.push(json!({
            "domain_suffix": split.proxy_domains,
            "server": TAG_DNS_REMOTE
        }));
    }

    let mut geo_direct_sites: Vec<&str> = Vec::new();
    if bypass_ru {
        geo_direct_sites.push("geosite-ru");
    }
    if bypass_cn {
        geo_direct_sites.push("geosite-cn");
    }
    if !geo_direct_sites.is_empty() {
        dns_rules.push(json!({
            "rule_set": geo_direct_sites,
            "server": TAG_DNS_DIRECT
        }));
    }

    // Per-application DNS steering. Skipping this is exactly how split tunnelling
    // leaks: the traffic would take the right path but the lookup would not.
    let fake_ip_usable = settings.fake_ip;
    // On Android the TUN device itself keeps excluded apps out, DNS included —
    // whatever still reaches us follows the default path.
    #[cfg(target_os = "android")]
    let dns_final = {
        if fake_ip_usable {
            dns_rules.push(json!({
                "query_type": ["A", "AAAA"],
                "server": TAG_DNS_FAKE
            }));
        }
        TAG_DNS_REMOTE
    };
    #[cfg(not(target_os = "android"))]
    let dns_final = match split.mode {
        SplitMode::Include if split.has_active_apps() => {
            if fake_ip_usable {
                dns_rules.extend(app_rules(
                    split,
                    &[
                        ("query_type", json!(["A", "AAAA"])),
                        ("server", json!(TAG_DNS_FAKE)),
                    ],
                ));
            }
            dns_rules.extend(app_rules(split, &[("server", json!(TAG_DNS_REMOTE))]));
            TAG_DNS_DIRECT
        }
        SplitMode::Exclude if split.has_active_apps() => {
            dns_rules.extend(app_rules(split, &[("server", json!(TAG_DNS_DIRECT))]));
            if fake_ip_usable {
                dns_rules.push(json!({
                    "query_type": ["A", "AAAA"],
                    "server": TAG_DNS_FAKE
                }));
            }
            TAG_DNS_REMOTE
        }
        _ => {
            if fake_ip_usable {
                dns_rules.push(json!({
                    "query_type": ["A", "AAAA"],
                    "server": TAG_DNS_FAKE
                }));
            }
            TAG_DNS_REMOTE
        }
    };

    let strategy = if settings.ipv6 {
        settings.dns_strategy.clone()
    } else {
        // Handing out AAAA records the tunnel will not carry produces long
        // connection stalls while clients wait for IPv6 to time out.
        "ipv4_only".to_string()
    };

    let mut dns = Map::new();
    dns.insert("servers".into(), json!(dns_servers));
    if !dns_rules.is_empty() {
        dns.insert("rules".into(), json!(dns_rules));
    }
    dns.insert("final".into(), json!(dns_final));
    dns.insert("strategy".into(), json!(strategy));
    dns.insert("independent_cache".into(), json!(true));

    // ---------------------------------------------------------------- inbounds
    let mut inbounds: Vec<Value> = Vec::new();

    if tunnel_mode == TunnelMode::Tun {
        let mut address = vec!["172.19.0.1/30".to_string()];
        if settings.ipv6 {
            address.push("fdfe:dcba:9876::1/126".to_string());
        }
        #[allow(unused_mut)]
        let mut tun = json!({
            "type": "tun",
            "tag": "tun-in",
            "address": address,
            "mtu": settings.tun_mtu,
            "auto_route": true,
            "strict_route": settings.strict_route,
            "stack": settings.tun_stack.as_str()
        });
        // Per-app split tunnelling happens at the TUN device itself: libbox
        // passes these lists to VpnService.Builder, so excluded apps never
        // enter the tunnel at all. `AppRule.path` carries the package name.
        #[cfg(target_os = "android")]
        {
            let packages = split.active_paths();
            if !packages.is_empty() && split.has_active_apps() {
                let key = match split.mode {
                    SplitMode::Include => Some("include_package"),
                    SplitMode::Exclude => Some("exclude_package"),
                    SplitMode::Off => None,
                };
                if let Some(key) = key {
                    tun[key] = json!(packages);
                }
            }
        }
        inbounds.push(tun);
    }

    inbounds.push(json!({
        "type": "mixed",
        "tag": "mixed-in",
        "listen": if settings.allow_lan { "0.0.0.0" } else { "127.0.0.1" },
        "listen_port": settings.mixed_port
    }));

    // ------------------------------------------------------------------- route
    let mut rules: Vec<Value> = Vec::new();
    let mut used_rule_sets: Vec<Value> = Vec::new();

    // Sniffing recovers the hostname from the packet stream; without it, domain
    // rules can never match traffic arriving through TUN.
    rules.push(json!({ "action": "sniff" }));

    // Before the DNS hijack, and before the Clash mode override could force
    // everything through the proxy: nothing the second engine sends may be
    // allowed to re-enter the tunnel.
    if let Some(exe) = xray_bypass {
        rules.extend(engine_bypass_rules(exe, &[("outbound", json!(TAG_DIRECT))]));
    }
    // Belt to the process rules' braces: even when attribution fails, a
    // connection towards an Xray node's own server must never re-enter the
    // tunnel. Matching plain IPs needs no resolve step — the engine dials
    // literal addresses.
    if !xray_server_ips.is_empty() {
        rules.push(json!({ "ip_cidr": xray_server_ips, "outbound": TAG_DIRECT }));
    }
    if !xray_server_domains.is_empty() {
        rules.push(json!({ "domain": xray_server_domains, "outbound": TAG_DIRECT }));
    }

    if tunnel_mode == TunnelMode::Tun {
        rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
    }

    // The Clash-API mode switch, applied without restarting the core. The app's
    // own switch only offers Global (Direct is what disconnecting already does),
    // but the mode belongs to the API, and a Clash dashboard pointed at it can
    // still ask for either.
    rules.push(json!({ "clash_mode": "Direct", "outbound": TAG_DIRECT }));
    rules.push(json!({ "clash_mode": "Global", "outbound": TAG_PROXY }));

    if !split.block_domains.is_empty() {
        rules.push(json!({ "domain_suffix": split.block_domains, "action": "reject" }));
    }
    if block_ads {
        rules.push(json!({ "rule_set": ["geosite-ads"], "action": "reject" }));
        used_rule_sets.push(rule_set("geosite-ads", rule_set_dir));
    }

    if split.bypass_private {
        rules.push(json!({ "ip_is_private": true, "outbound": TAG_DIRECT }));
    }

    if !split.direct_domains.is_empty() {
        rules.push(json!({ "domain_suffix": split.direct_domains, "outbound": TAG_DIRECT }));
    }
    if !split.proxy_domains.is_empty() {
        rules.push(json!({ "domain_suffix": split.proxy_domains, "outbound": TAG_PROXY }));
    }

    if bypass_ru {
        rules.push(json!({ "rule_set": ["geosite-ru"], "outbound": TAG_DIRECT }));
        used_rule_sets.push(rule_set("geosite-ru", rule_set_dir));
    }
    if bypass_cn {
        rules.push(json!({ "rule_set": ["geosite-cn"], "outbound": TAG_DIRECT }));
        used_rule_sets.push(rule_set("geosite-cn", rule_set_dir));
    }

    // Everything below matches on IP, which only exists once the destination has
    // been resolved. Insert the resolve step lazily so domain-routed traffic can
    // still reach the proxy as a hostname.
    let ip_rules_present =
        !split.direct_ips.is_empty() || !split.proxy_ips.is_empty() || bypass_ru || bypass_cn;
    if ip_rules_present {
        rules.push(json!({ "action": "resolve", "strategy": strategy }));
    }

    if !split.direct_ips.is_empty() {
        rules.push(json!({ "ip_cidr": split.direct_ips, "outbound": TAG_DIRECT }));
    }
    if !split.proxy_ips.is_empty() {
        rules.push(json!({ "ip_cidr": split.proxy_ips, "outbound": TAG_PROXY }));
    }
    if bypass_ru {
        rules.push(json!({ "rule_set": ["geoip-ru"], "outbound": TAG_DIRECT }));
        used_rule_sets.push(rule_set("geoip-ru", rule_set_dir));
    }
    if bypass_cn {
        rules.push(json!({ "rule_set": ["geoip-cn"], "outbound": TAG_DIRECT }));
        used_rule_sets.push(rule_set("geoip-cn", rule_set_dir));
    }

    // On Android app selection is enforced by the TUN device itself (see the
    // include/exclude packages above): whatever still enters the tunnel goes
    // to the proxy, so process-attribution rules are neither possible nor needed.
    #[cfg(target_os = "android")]
    let route_final = TAG_PROXY;
    #[cfg(not(target_os = "android"))]
    let route_final = match split.mode {
        SplitMode::Include if split.has_active_apps() => {
            rules.extend(app_rules(split, &[("outbound", json!(TAG_PROXY))]));
            TAG_DIRECT
        }
        SplitMode::Exclude if split.has_active_apps() => {
            rules.extend(app_rules(split, &[("outbound", json!(TAG_DIRECT))]));
            TAG_PROXY
        }
        _ => TAG_PROXY,
    };

    let mut route = Map::new();
    route.insert("rules".into(), json!(rules));
    if !used_rule_sets.is_empty() {
        route.insert("rule_set".into(), json!(used_rule_sets));
    }
    route.insert("final".into(), json!(route_final));
    route.insert("auto_detect_interface".into(), json!(true));
    route.insert("default_domain_resolver".into(), json!(TAG_DNS_DIRECT));

    // ------------------------------------------------------------------ assemble
    // Desktop: no `output` key on purpose — logs stay on stdout so the
    // supervisor can stream them into the UI live. Android: libbox runs
    // in-process, so the file named here is the only place lines can go.
    #[cfg(not(target_os = "android"))]
    let log_section = json!({ "level": settings.log_level, "timestamp": true });
    #[cfg(target_os = "android")]
    let log_section = json!({
        "level": settings.log_level,
        "timestamp": true,
        "output": log_file.to_string_lossy()
    });

    let config = json!({
        "log": log_section,
        "experimental": {
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", settings.clash_port),
                "secret": clash_secret,
                "default_mode": "Rule"
            },
            "cache_file": {
                "enabled": true,
                "path": cache_path.to_string_lossy(),
                "store_fakeip": settings.fake_ip
            }
        },
        "dns": Value::Object(dns),
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": Value::Object(route)
    });

    Ok(BuiltConfig { json: config, tags })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Protocol, Security};
    use crate::settings::AppRule;
    use std::path::PathBuf;

    fn node(name: &str, id: &str) -> ServerNode {
        ServerNode {
            id: id.into(),
            name: name.into(),
            protocol: Protocol::Vless,
            address: "example.com".into(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            security: Security::Reality,
            public_key: "pbk".into(),
            ..Default::default()
        }
    }

    /// Every geo set cached and usable — the ordinary case.
    fn all_sets() -> HashSet<String> {
        ["geosite-ads", "geosite-ru", "geosite-cn", "geoip-ru", "geoip-cn"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn build_with(settings: Settings, split: SplitConfig) -> Value {
        build_full(settings, split, HashMap::new(), all_sets())
    }

    // A realistic absolute path for the host OS: `file_name()` only splits on
    // the platform's own separator, so a Windows path is one opaque component
    // on Unix and the derived `process_name` rule would never match.
    #[cfg(windows)]
    const XRAY_EXE: &str = r"C:\app\xray.exe";
    #[cfg(not(windows))]
    const XRAY_EXE: &str = "/app/xray.exe";

    fn build_with_xray(
        settings: Settings,
        split: SplitConfig,
        xray_ports: HashMap<String, u16>,
    ) -> Value {
        build_full(settings, split, xray_ports, all_sets())
    }

    fn build_full(
        settings: Settings,
        split: SplitConfig,
        xray_ports: HashMap<String, u16>,
        rule_sets: HashSet<String>,
    ) -> Value {
        let nodes = vec![node("Tokyo", "a"), node("Berlin", "b")];
        let cache = PathBuf::from("cache.db");
        let dir = PathBuf::from("rules");
        let xray_exe = PathBuf::from(XRAY_EXE);
        build(&BuildInput {
            nodes: &nodes,
            active_id: "b",
            settings: &settings,
            split: &split,
            clash_secret: "secret",
            cache_path: &cache,
            xray_ports: &xray_ports,
            xray_exe: Some(&xray_exe),
            rule_sets: &rule_sets,
            rule_set_dir: &dir,
        })
        .unwrap()
        .json
    }

    #[test]
    fn a_geo_set_that_could_not_be_cached_drops_its_rules_instead_of_the_tunnel() {
        // Referencing a missing set makes sing-box refuse to start, which would
        // trade the whole tunnel for an optional filter.
        let split = SplitConfig { bypass_ru: true, block_ads: true, ..Default::default() };
        let cfg = build_full(Settings::default(), split, HashMap::new(), HashSet::new());

        assert!(cfg["route"].get("rule_set").is_none());
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().all(|r| r.get("rule_set").is_none()));
        let dns = cfg["dns"]["rules"].as_array().map(|r| r.to_vec()).unwrap_or_default();
        assert!(dns.iter().all(|r| r.get("rule_set").is_none()));
    }

    #[test]
    fn a_partially_cached_geo_pair_is_not_half_applied() {
        // geosite present, geoip missing: applying only half would route by
        // domain but leak every direct-IP connection into the tunnel.
        let split = SplitConfig { bypass_ru: true, ..Default::default() };
        let only_site = HashSet::from(["geosite-ru".to_string()]);
        let cfg = build_full(Settings::default(), split, HashMap::new(), only_site);

        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().all(|r| r.get("rule_set").is_none()));
    }

    #[test]
    fn cached_sets_are_referenced_as_local_files() {
        let split = SplitConfig { block_ads: true, ..Default::default() };
        let cfg = build_with(Settings::default(), split);
        let set = &cfg["route"]["rule_set"].as_array().unwrap()[0];

        // `remote` would make the core fetch it at start-up and die if offline.
        assert_eq!(set["type"], json!("local"));
        assert!(set["path"].as_str().unwrap().ends_with("geosite-ads.srs"));
    }

    #[test]
    fn xray_backed_nodes_become_socks_outbounds_but_stay_in_the_selector() {
        let ports = HashMap::from([("a".to_string(), 24150u16)]);
        let cfg = build_with_xray(Settings::default(), SplitConfig::default(), ports);
        let outbounds = cfg["outbounds"].as_array().unwrap();

        let chained = outbounds.iter().find(|o| o["tag"] == json!("0-Tokyo")).unwrap();
        assert_eq!(chained["type"], json!("socks"));
        assert_eq!(chained["server"], json!("127.0.0.1"));
        assert_eq!(chained["server_port"], json!(24150));

        // The other node keeps its native outbound.
        let native = outbounds.iter().find(|o| o["tag"] == json!("1-Berlin")).unwrap();
        assert_eq!(native["type"], json!("vless"));

        // Both must still be selectable and measurable.
        let selector = outbounds.iter().find(|o| o["tag"] == json!(TAG_PROXY)).unwrap();
        let members = selector["outbounds"].as_array().unwrap();
        assert!(members.contains(&json!("0-Tokyo")));
        assert!(members.contains(&json!("1-Berlin")));
    }

    fn rule_index(rules: &[Value], predicate: impl Fn(&Value) -> bool) -> Option<usize> {
        rules.iter().position(predicate)
    }

    #[test]
    fn the_second_engine_dials_around_the_tunnel_it_feeds() {
        // Without this the node connects and carries nothing: Xray's packets to
        // the server are captured by the TUN and handed back to Xray.
        let ports = HashMap::from([("a".to_string(), 24150u16)]);
        let cfg = build_with_xray(Settings::default(), SplitConfig::default(), ports);
        let rules = cfg["route"]["rules"].as_array().unwrap();

        let by_path = rule_index(rules, |r| r["process_path"] == json!([XRAY_EXE])).unwrap();
        let by_name = rule_index(rules, |r| r["process_name"] == json!(["xray.exe"])).unwrap();
        assert_eq!(rules[by_path]["outbound"], json!(TAG_DIRECT));
        assert_eq!(rules[by_name]["outbound"], json!(TAG_DIRECT));

        // Both of these would feed the loop back if they matched first: the
        // hijack answers Xray's lookups from behind the proxy, and the Global
        // override forces every destination through it.
        let hijack = rule_index(rules, |r| r["action"] == json!("hijack-dns")).unwrap();
        let global = rule_index(rules, |r| r["clash_mode"] == json!("Global")).unwrap();
        assert!(by_path < hijack && by_name < hijack);
        assert!(by_path < global && by_name < global);

        // The lookup follows the traffic, as for any other per-application rule.
        let dns = cfg["dns"]["rules"].as_array().unwrap();
        let lookup = dns.iter().find(|r| r["process_path"] == json!([XRAY_EXE])).unwrap();
        assert_eq!(lookup["server"], json!(TAG_DNS_DIRECT));
    }

    #[test]
    fn xray_server_ips_bypass_the_tunnel_by_destination_too() {
        // Process attribution races an engine switchover; the destination
        // itself must be enough to keep the dial out of the tunnel.
        let mut nodes = vec![node("Tokyo", "a"), node("Berlin", "b")];
        nodes[0].address = "1.2.3.4".into();
        let ports = HashMap::from([("a".to_string(), 24150u16)]);
        let cfg = build_for_nodes(nodes, ports);

        let rules = cfg["route"]["rules"].as_array().unwrap();
        let ip = rule_index(rules, |r| r["ip_cidr"] == json!(["1.2.3.4/32"])).unwrap();
        assert_eq!(rules[ip]["outbound"], json!(TAG_DIRECT));

        // Ahead of the hijack and the Global override, like the process rules.
        let hijack = rule_index(rules, |r| r["action"] == json!("hijack-dns")).unwrap();
        let global = rule_index(rules, |r| r["clash_mode"] == json!("Global")).unwrap();
        assert!(ip < hijack && ip < global);

        // Berlin stays native, so its address must not leak into the bypass.
        assert!(rules.iter().all(|r| r["domain"] != json!(["example.com"])));
    }

    #[test]
    fn xray_server_domains_bypass_routing_and_dns() {
        // The hostname is resolved by svchost on Xray's behalf — a process
        // rule can never claim that lookup, so the domain itself must steer
        // both the route and the resolver around the tunnel.
        let nodes = vec![node("Tokyo", "a"), node("Berlin", "b")];
        let ports = HashMap::from([("a".to_string(), 24150u16)]);
        let cfg = build_for_nodes(nodes, ports);

        let rules = cfg["route"]["rules"].as_array().unwrap();
        let dom = rule_index(rules, |r| r["domain"] == json!(["example.com"])).unwrap();
        assert_eq!(rules[dom]["outbound"], json!(TAG_DIRECT));

        let dns = cfg["dns"]["rules"].as_array().unwrap();
        let lookup = dns.iter().find(|r| r["domain"] == json!(["example.com"])).unwrap();
        assert_eq!(lookup["server"], json!(TAG_DNS_DIRECT));
    }

    fn build_for_nodes(nodes: Vec<ServerNode>, xray_ports: HashMap<String, u16>) -> Value {
        let settings = Settings::default();
        let split = SplitConfig::default();
        let cache = PathBuf::from("cache.db");
        let dir = PathBuf::from("rules");
        let xray_exe = PathBuf::from(XRAY_EXE);
        let sets = all_sets();
        build(&BuildInput {
            nodes: &nodes,
            active_id: "a",
            settings: &settings,
            split: &split,
            clash_secret: "secret",
            cache_path: &cache,
            xray_ports: &xray_ports,
            xray_exe: Some(&xray_exe),
            rule_sets: &sets,
            rule_set_dir: &dir,
        })
        .unwrap()
        .json
    }

    #[test]
    fn no_bypass_when_the_second_engine_is_not_in_play() {
        let cfg = build_with(Settings::default(), SplitConfig::default());
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().all(|r| r.get("process_path").is_none()));

        let dns = cfg["dns"]["rules"].as_array().map(|r| r.to_vec()).unwrap_or_default();
        assert!(dns.iter().all(|r| r.get("process_path").is_none()));
    }

    #[test]
    fn vmess_ws_nodes_stay_out_of_the_urltest_group() {
        // Неудачный дозвон до vmess+ws роняет ядро паникой (typed-nil в
        // v2raywebsocket.Close), а urltest дозванивается до всех узлов на
        // старте и каждые три минуты — мёртвый узел из подписки убивал
        // туннель секундами после подключения.
        let mut nodes = vec![node("Tokyo", "a"), node("Junk", "b")];
        nodes[1].protocol = Protocol::Vmess;
        nodes[1].network = crate::model::Network::Ws;
        nodes[1].security = Security::None;
        nodes[1].public_key = String::new();
        let cfg = build_for_nodes(nodes, HashMap::new());

        let outbounds = cfg["outbounds"].as_array().unwrap();
        let auto = outbounds.iter().find(|o| o["tag"] == json!(TAG_AUTO)).unwrap();
        let members = auto["outbounds"].as_array().unwrap();
        assert!(members.contains(&json!("0-Tokyo")));
        assert!(!members.contains(&json!("1-Junk")), "{members:?}");

        // Из селектора узел не пропадает — вручную его выбрать можно.
        let selector = outbounds.iter().find(|o| o["tag"] == json!(TAG_PROXY)).unwrap();
        assert!(selector["outbounds"].as_array().unwrap().contains(&json!("1-Junk")));
    }

    #[test]
    fn all_vmess_ws_keeps_the_urltest_group_populated() {
        // Пустую группу ядро отвергает целиком — при списке из одних vmess+ws
        // фильтр отступает: лучше живой конфиг с риском, чем никакого.
        let mut nodes = vec![node("Only", "a")];
        nodes[0].protocol = Protocol::Vmess;
        nodes[0].network = crate::model::Network::Ws;
        nodes[0].security = Security::None;
        nodes[0].public_key = String::new();
        let cfg = build_for_nodes(nodes, HashMap::new());

        let outbounds = cfg["outbounds"].as_array().unwrap();
        let auto = outbounds.iter().find(|o| o["tag"] == json!(TAG_AUTO)).unwrap();
        assert_eq!(auto["outbounds"], json!(["0-Only"]));
    }

    #[test]
    fn xray_backed_vmess_ws_is_probed_normally() {
        // Узел, унесённый в Xray, для sing-box — loopback SOCKS: паника
        // недостижима, и мерить его авто-группой безопасно.
        let mut nodes = vec![node("Tokyo", "a"), node("WsNode", "b")];
        nodes[1].protocol = Protocol::Vmess;
        nodes[1].network = crate::model::Network::Ws;
        nodes[1].security = Security::None;
        nodes[1].public_key = String::new();
        let ports = HashMap::from([("b".to_string(), 24150u16)]);
        let cfg = build_for_nodes(nodes, ports);

        let outbounds = cfg["outbounds"].as_array().unwrap();
        let auto = outbounds.iter().find(|o| o["tag"] == json!(TAG_AUTO)).unwrap();
        assert!(auto["outbounds"].as_array().unwrap().contains(&json!("1-WsNode")));
    }

    #[test]
    fn selector_defaults_to_the_active_node() {
        let cfg = build_with(Settings::default(), SplitConfig::default());
        let selector = cfg["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == json!(TAG_PROXY))
            .unwrap();
        assert_eq!(selector["default"], json!("1-Berlin"));
    }

    #[test]
    fn auto_select_switches_the_default_to_urltest() {
        let settings = Settings { auto_select: true, ..Default::default() };
        let cfg = build_with(settings, SplitConfig::default());
        let selector = cfg["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == json!(TAG_PROXY))
            .unwrap();
        assert_eq!(selector["default"], json!(TAG_AUTO));
    }

    #[test]
    fn include_mode_tunnels_only_listed_apps() {
        let split = SplitConfig {
            mode: SplitMode::Include,
            apps: vec![AppRule { name: "chrome.exe".into(), ..Default::default() }],
            ..Default::default()
        };
        let cfg = build_with(Settings::default(), split);
        assert_eq!(cfg["route"]["final"], json!(TAG_DIRECT));

        let rules = cfg["route"]["rules"].as_array().unwrap();
        let app = rules.iter().find(|r| r["process_name"].is_array()).unwrap();
        assert_eq!(app["outbound"], json!(TAG_PROXY));

        // The lookup must follow the traffic, otherwise DNS leaks around the split.
        let dns = cfg["dns"]["rules"].as_array().unwrap();
        let dns_app = dns.iter().find(|r| r["process_name"].is_array()).unwrap();
        assert_eq!(dns_app["server"], json!(TAG_DNS_REMOTE));
        assert_eq!(cfg["dns"]["final"], json!(TAG_DNS_DIRECT));
    }

    #[test]
    fn exclude_mode_inverts_both_routing_and_dns() {
        let split = SplitConfig {
            mode: SplitMode::Exclude,
            apps: vec![AppRule { name: "steam.exe".into(), ..Default::default() }],
            ..Default::default()
        };
        let cfg = build_with(Settings::default(), split);
        assert_eq!(cfg["route"]["final"], json!(TAG_PROXY));

        let rules = cfg["route"]["rules"].as_array().unwrap();
        let app = rules.iter().find(|r| r["process_name"].is_array()).unwrap();
        assert_eq!(app["outbound"], json!(TAG_DIRECT));

        let dns = cfg["dns"]["rules"].as_array().unwrap();
        let dns_app = dns.iter().find(|r| r["process_name"].is_array()).unwrap();
        assert_eq!(dns_app["server"], json!(TAG_DNS_DIRECT));
        assert_eq!(cfg["dns"]["final"], json!(TAG_DNS_REMOTE));
    }

    #[test]
    fn name_and_path_rules_are_emitted_separately_so_they_or_together() {
        let split = SplitConfig {
            mode: SplitMode::Exclude,
            apps: vec![
                AppRule { name: "steam.exe".into(), ..Default::default() },
                AppRule { name: "game.exe".into(), path: r"C:\games\game.exe".into(), ..Default::default() },
            ],
            ..Default::default()
        };
        let cfg = build_with(Settings::default(), split);
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["process_name"].is_array()));
        assert!(rules.iter().any(|r| r["process_path"].is_array()));
    }

    #[test]
    fn split_mode_without_any_app_falls_back_to_full_tunnel() {
        let split = SplitConfig { mode: SplitMode::Include, ..Default::default() };
        let cfg = build_with(Settings::default(), split);
        // An empty Include list must not silently strand every application direct.
        assert_eq!(cfg["route"]["final"], json!(TAG_PROXY));
    }

    #[test]
    fn resolve_precedes_every_ip_based_rule() {
        let split = SplitConfig { bypass_ru: true, ..Default::default() };
        let cfg = build_with(Settings::default(), split);
        let rules = cfg["route"]["rules"].as_array().unwrap();

        let resolve = rule_index(rules, |r| r["action"] == json!("resolve")).unwrap();
        let geoip = rule_index(rules, |r| r["rule_set"] == json!(["geoip-ru"])).unwrap();
        assert!(resolve < geoip, "resolve must run before geoip matching");

        // Domain rules stay above resolve so hostnames survive to the proxy.
        let geosite = rule_index(rules, |r| r["rule_set"] == json!(["geosite-ru"])).unwrap();
        assert!(geosite < resolve);
    }

    #[test]
    fn user_proxy_rules_outrank_geo_bypass() {
        let split = SplitConfig {
            bypass_ru: true,
            proxy_domains: vec!["blocked.ru".into()],
            ..Default::default()
        };
        let cfg = build_with(Settings::default(), split);
        let rules = cfg["route"]["rules"].as_array().unwrap();
        let explicit = rule_index(rules, |r| r["domain_suffix"] == json!(["blocked.ru"])).unwrap();
        let geo = rule_index(rules, |r| r["rule_set"] == json!(["geosite-ru"])).unwrap();
        assert!(explicit < geo);
    }

    #[test]
    fn system_proxy_mode_drops_the_tun_inbound_and_dns_hijack() {
        let settings = Settings { tunnel_mode: TunnelMode::SystemProxy, ..Default::default() };
        let cfg = build_with(settings, SplitConfig::default());
        let inbounds = cfg["inbounds"].as_array().unwrap();
        assert!(inbounds.iter().all(|i| i["type"] != json!("tun")));
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().all(|r| r["action"] != json!("hijack-dns")));
    }

    #[test]
    fn ipv6_off_forces_an_ipv4_only_strategy() {
        let cfg = build_with(Settings::default(), SplitConfig::default());
        assert_eq!(cfg["dns"]["strategy"], json!("ipv4_only"));
        let tun = cfg["inbounds"].as_array().unwrap()[0].clone();
        assert_eq!(tun["address"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn only_referenced_rule_sets_are_downloaded() {
        let cfg = build_with(Settings::default(), SplitConfig::default());
        assert!(cfg["route"].get("rule_set").is_none());

        let split = SplitConfig { block_ads: true, ..Default::default() };
        let cfg = build_with(Settings::default(), split);
        let sets = cfg["route"]["rule_set"].as_array().unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0]["tag"], json!("geosite-ads"));
    }

    #[test]
    fn doh_resolver_gets_a_bootstrap_server() {
        let settings = Settings {
            dns_direct: "https://dns.google/dns-query".into(),
            ..Default::default()
        };
        let cfg = build_with(settings, SplitConfig::default());
        let servers = cfg["dns"]["servers"].as_array().unwrap();
        assert!(servers.iter().any(|s| s["tag"] == json!(TAG_DNS_BOOTSTRAP)));
        let direct = servers.iter().find(|s| s["tag"] == json!(TAG_DNS_DIRECT)).unwrap();
        assert_eq!(direct["type"], json!("https"));
        assert_eq!(direct["path"], json!("/dns-query"));
        assert_eq!(direct["domain_resolver"], json!(TAG_DNS_BOOTSTRAP));
    }

    #[test]
    fn direct_resolver_carries_no_detour() {
        // Regression: naming `direct` here is a fatal start-up error in sing-box,
        // and it slips past `sing-box check` — the core only rejects it on run.
        let cfg = build_with(Settings::default(), SplitConfig::default());
        let servers = cfg["dns"]["servers"].as_array().unwrap();
        let direct = servers.iter().find(|s| s["tag"] == json!(TAG_DNS_DIRECT)).unwrap();
        assert!(direct.get("detour").is_none(), "{direct}");

        // The proxied resolver, by contrast, genuinely needs its detour.
        let remote = servers.iter().find(|s| s["tag"] == json!(TAG_DNS_REMOTE)).unwrap();
        assert_eq!(remote["detour"], json!(TAG_PROXY));
    }

    #[test]
    fn plain_ip_resolver_needs_no_bootstrap() {
        let cfg = build_with(Settings::default(), SplitConfig::default());
        let servers = cfg["dns"]["servers"].as_array().unwrap();
        assert!(servers.iter().all(|s| s["tag"] != json!(TAG_DNS_BOOTSTRAP)));
    }

    #[test]
    fn building_without_servers_is_an_error_not_an_empty_tunnel() {
        let cache = PathBuf::from("c.db");
        let settings = Settings::default();
        let split = SplitConfig::default();
        let ports = HashMap::new();
        let sets = HashSet::new();
        let dir = PathBuf::from("rules");
        let err = build(&BuildInput {
            nodes: &[],
            active_id: "",
            settings: &settings,
            split: &split,
            clash_secret: "s",
            cache_path: &cache,
            xray_ports: &ports,
            xray_exe: None,
            rule_sets: &sets,
            rule_set_dir: &dir,
        })
        .unwrap_err();
        assert!(err.to_string().contains("сервер"));
    }
}
