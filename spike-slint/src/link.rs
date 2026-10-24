//! Parsing of share links produced by 3x-ui / Xray / v2rayN, plus subscription
//! payloads (a base64 blob or a plain newline-separated list of those links).

use std::collections::HashMap;

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;
use serde_json::Value;

use crate::error::{AppError, Result};
use crate::model::{Network, Protocol, Security, ServerNode};

/// Decode base64 that may be standard or URL-safe, padded or not.
pub fn b64_decode(input: &str) -> Option<Vec<u8>> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let trimmed = cleaned.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
        .ok()
}

fn pct(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().into_owned()
}

struct UriParts {
    userinfo: String,
    host: String,
    port: u16,
    query: HashMap<String, String>,
    fragment: String,
}

/// Split `user@host:port?query#fragment` — the shape every non-vmess share link uses.
fn split_uri(rest: &str) -> Result<UriParts> {
    let (before_fragment, fragment) = match rest.split_once('#') {
        Some((a, b)) => (a, pct(b)),
        None => (rest, String::new()),
    };

    let (authority, query_str) = match before_fragment.split_once('?') {
        Some((a, b)) => (a, b),
        None => (before_fragment, ""),
    };

    // Split on the LAST '@' so an un-encoded '@' inside a password cannot
    // swallow the host.
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (u.to_string(), h),
        None => (String::new(), authority),
    };

    let (host, port) = split_host_port(hostport)?;

    let mut query = HashMap::new();
    for pair in query_str.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(pct(k).to_lowercase(), pct(v));
    }

    Ok(UriParts {
        userinfo,
        host,
        port,
        query,
        fragment,
    })
}

fn split_host_port(hostport: &str) -> Result<(String, u16)> {
    // Bracketed IPv6 literal: [2001:db8::1]:443
    if let Some(close) = hostport.rfind(']') {
        if hostport.starts_with('[') {
            let host = hostport[1..close].to_string();
            let port = hostport[close + 1..]
                .trim_start_matches(':')
                .parse::<u16>()
                .map_err(|_| AppError::msg("не удалось разобрать порт"))?;
            return Ok((host, port));
        }
    }
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| AppError::msg("в ссылке нет порта"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| AppError::msg(format!("некорректный порт: {port}")))?;
    if host.is_empty() {
        return Err(AppError::msg("в ссылке нет адреса сервера"));
    }
    Ok((host.to_string(), port))
}

fn map_network(raw: &str) -> Result<Network> {
    match raw.trim().to_lowercase().as_str() {
        "" | "tcp" | "raw" => Ok(Network::Tcp),
        "ws" | "websocket" => Ok(Network::Ws),
        "grpc" | "gun" => Ok(Network::Grpc),
        "http" | "h2" | "h2c" => Ok(Network::Http),
        "httpupgrade" => Ok(Network::Httpupgrade),
        // Xray-only, and that is fine: such a node is dialled by the Xray engine
        // instead of sing-box.
        "xhttp" | "splithttp" => Ok(Network::Xhttp),
        other @ ("kcp" | "mkcp" | "quic") => Err(AppError::msg(format!(
            "транспорт «{other}» не поддерживается ядром sing-box"
        ))),
        other => Err(AppError::msg(format!("неизвестный транспорт «{other}»"))),
    }
}

fn map_security(raw: &str) -> Result<Security> {
    match raw.trim().to_lowercase().as_str() {
        "" | "none" => Ok(Security::None),
        "tls" => Ok(Security::Tls),
        "reality" => Ok(Security::Reality),
        "xtls" => Err(AppError::msg(
            "устаревший XTLS не поддерживается — на сервере нужен REALITY или TLS",
        )),
        other => Err(AppError::msg(format!("неизвестный security «{other}»"))),
    }
}

fn alpn_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn fallback_name(node: &ServerNode) -> String {
    format!("{}:{}", node.address, node.port)
}

/// Apply the query parameters that VLESS/trojan share links have in common.
fn apply_common_query(node: &mut ServerNode, q: &HashMap<String, String>) -> Result<()> {
    let get = |k: &str| q.get(k).map(String::as_str).unwrap_or("");

    node.network = map_network(get("type"))?;
    node.security = map_security(get("security"))?;

    // Xray obfuscates plain TCP with a fake HTTP header; sing-box dropped that
    // transport, so a node relying on it would silently fail to handshake.
    if node.network == Network::Tcp && get("headertype").eq_ignore_ascii_case("http") {
        return Err(AppError::msg(
            "obfs «headerType=http» поверх TCP не поддерживается ядром sing-box",
        ));
    }

    node.path = get("path").to_string();
    node.host = if !get("host").is_empty() {
        get("host").to_string()
    } else {
        get("sni").to_string()
    };
    node.service_name = get("servicename").to_string();
    node.sni = get("sni").to_string();
    node.fingerprint = get("fp").to_string();
    node.public_key = get("pbk").to_string();
    node.short_id = get("sid").to_string();
    node.flow = get("flow").to_string();
    node.spider_x = get("spx").to_string();
    // `encryption=none` is the historical placeholder; anything else is real
    // VLESS Encryption and forces the Xray engine.
    node.encryption = match get("encryption") {
        "" | "none" => String::new(),
        value => value.to_string(),
    };
    node.alpn = alpn_list(get("alpn"));
    node.allow_insecure = matches!(get("allowinsecure"), "1" | "true")
        || matches!(get("insecure"), "1" | "true");

    if node.security == Security::Reality && node.public_key.is_empty() {
        return Err(AppError::msg(
            "для REALITY в ссылке отсутствует публичный ключ (pbk)",
        ));
    }
    Ok(())
}

fn parse_vless(rest: &str) -> Result<ServerNode> {
    let p = split_uri(rest)?;
    if p.userinfo.is_empty() {
        return Err(AppError::msg("в ссылке vless:// отсутствует UUID"));
    }
    let mut node = ServerNode {
        id: new_id(),
        protocol: Protocol::Vless,
        address: p.host,
        port: p.port,
        uuid: pct(&p.userinfo),
        name: p.fragment,
        ..Default::default()
    };
    apply_common_query(&mut node, &p.query)?;
    if node.name.is_empty() {
        node.name = fallback_name(&node);
    }
    Ok(node)
}

fn parse_trojan(rest: &str) -> Result<ServerNode> {
    let p = split_uri(rest)?;
    if p.userinfo.is_empty() {
        return Err(AppError::msg("в ссылке trojan:// отсутствует пароль"));
    }
    let mut node = ServerNode {
        id: new_id(),
        protocol: Protocol::Trojan,
        address: p.host,
        port: p.port,
        password: pct(&p.userinfo),
        name: p.fragment,
        ..Default::default()
    };
    apply_common_query(&mut node, &p.query)?;
    // trojan is TLS-only by definition; links routinely omit `security=tls`.
    if node.security == Security::None {
        node.security = Security::Tls;
    }
    if node.name.is_empty() {
        node.name = fallback_name(&node);
    }
    Ok(node)
}

/// `mport=443,20000-50000` → `["443:443", "20000:50000"]` — форма sing-box.
fn parse_port_ranges(raw: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (a, b) = match part.split_once(['-', ':']) {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (part, part),
        };
        let range = match (a.parse::<u16>(), b.parse::<u16>()) {
            (Ok(a), Ok(b)) if a > 0 && a <= b => format!("{a}:{b}"),
            _ => {
                return Err(AppError::msg(format!(
                    "некорректный диапазон портов «{part}»"
                )))
            }
        };
        if !out.contains(&range) {
            out.push(range);
        }
    }
    Ok(out)
}

/// Официальный клиент Hysteria2 пишет прыжковые порты прямо в адресе:
/// `hysteria2://pass@host:443,20000-50000?…`. Общий разбор ссылок ждёт один
/// порт, поэтому список снимается заранее: в ссылке остаётся первый порт, а
/// диапазоны уходят в узел целиком.
fn split_hysteria2_ports(rest: &str) -> (String, Vec<String>) {
    let keep = (rest.to_string(), Vec::new());
    let cut = rest.find(['?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(cut);
    let after_at = authority.rfind('@').map(|i| i + 1).unwrap_or(0);
    let hostport = &authority[after_at..];
    let Some(colon) = hostport.rfind(':') else { return keep };
    // `]` после двоеточия — это IPv6-литерал без порта, не список.
    if hostport[colon..].contains(']') {
        return keep;
    }
    let spec = &hostport[colon + 1..];
    let looks_like_list = spec.contains([',', '-'])
        && !spec.is_empty()
        && spec.chars().all(|c| c.is_ascii_digit() || matches!(c, ',' | '-'));
    if !looks_like_list {
        return keep;
    }
    let Ok(ranges) = parse_port_ranges(spec) else { return keep };
    let Some(main) = spec.split([',', '-']).find(|s| !s.is_empty()) else {
        return keep;
    };
    let rewritten = format!(
        "{}{}:{main}{tail}",
        &authority[..after_at],
        &hostport[..colon]
    );
    (rewritten, ranges)
}

fn parse_hysteria2(rest: &str) -> Result<ServerNode> {
    let (rest, mut hop_ports) = split_hysteria2_ports(rest);
    let p = split_uri(&rest)?;
    let get = |k: &str| p.query.get(k).map(String::as_str).unwrap_or("");

    // Панели пишут диапазоны и в query: `mport` у v2rayN, `ports` у NekoBox.
    for key in ["mport", "ports"] {
        if !get(key).is_empty() {
            for range in parse_port_ranges(get(key))? {
                if !hop_ports.contains(&range) {
                    hop_ports.push(range);
                }
            }
        }
    }

    // Обфускацию нельзя молча выбросить: сервер с salamander просто не отвечает
    // клиенту без него, и туннель выглядит подключённым, но мёртв — каждое
    // соединение висит до таймаута. Другие типы ядро не умеет — честный отказ.
    let obfs_password = get("obfs-password").to_string();
    let obfs = match get("obfs").trim().to_lowercase().as_str() {
        // Пароль без типа — тоже salamander: других типов у Hysteria2 нет, а
        // некоторые панели пишут только obfs-password.
        "" | "none" => {
            if obfs_password.is_empty() {
                String::new()
            } else {
                "salamander".to_string()
            }
        }
        "salamander" => "salamander".to_string(),
        other => {
            return Err(AppError::msg(format!(
                "обфускация «{other}» не поддерживается — Hysteria2 умеет только salamander"
            )))
        }
    };
    if obfs == "salamander" && obfs_password.is_empty() {
        return Err(AppError::msg(
            "в ссылке hysteria2:// включён obfs, но не задан obfs-password",
        ));
    }

    let mut node = ServerNode {
        id: new_id(),
        protocol: Protocol::Hysteria2,
        address: p.host,
        port: p.port,
        password: pct(&p.userinfo),
        name: p.fragment,
        security: Security::Tls,
        sni: get("sni").to_string(),
        allow_insecure: matches!(get("insecure"), "1" | "true")
            || matches!(get("allowinsecure"), "1" | "true"),
        alpn: alpn_list(get("alpn")),
        obfs,
        obfs_password,
        hop_ports,
        ..Default::default()
    };
    if node.name.is_empty() {
        node.name = fallback_name(&node);
    }
    Ok(node)
}

fn parse_tuic(rest: &str) -> Result<ServerNode> {
    let p = split_uri(rest)?;
    let (uuid, password) = match p.userinfo.split_once(':') {
        Some((u, pw)) => (pct(u), pct(pw)),
        None => (pct(&p.userinfo), String::new()),
    };
    let get = |k: &str| p.query.get(k).map(String::as_str).unwrap_or("");
    let mut node = ServerNode {
        id: new_id(),
        protocol: Protocol::Tuic,
        address: p.host,
        port: p.port,
        uuid,
        password,
        name: p.fragment,
        security: Security::Tls,
        sni: get("sni").to_string(),
        allow_insecure: matches!(get("allow_insecure"), "1" | "true"),
        alpn: alpn_list(get("alpn")),
        ..Default::default()
    };
    if node.name.is_empty() {
        node.name = fallback_name(&node);
    }
    Ok(node)
}

/// Shadowsocks comes in two flavours: SIP002 (`base64(method:pass)@host:port`)
/// and the legacy fully-base64 form (`base64(method:pass@host:port)`).
fn parse_shadowsocks(rest: &str) -> Result<ServerNode> {
    let (before_fragment, name) = match rest.split_once('#') {
        Some((a, b)) => (a, pct(b)),
        None => (rest, String::new()),
    };
    let before_query = before_fragment.split('?').next().unwrap_or(before_fragment);

    let (method, password, host, port) = if before_query.contains('@') {
        let (userinfo, hostport) = before_query
            .rsplit_once('@')
            .ok_or_else(|| AppError::msg("некорректная ссылка ss://"))?;
        let decoded = b64_decode(userinfo).map(|b| String::from_utf8_lossy(&b).into_owned());
        let creds = decoded.unwrap_or_else(|| pct(userinfo));
        let (m, pw) = creds
            .split_once(':')
            .ok_or_else(|| AppError::msg("в ss:// не разобрать метод шифрования и пароль"))?;
        let (h, p) = split_host_port(hostport)?;
        (m.to_string(), pw.to_string(), h, p)
    } else {
        let decoded = b64_decode(before_query)
            .ok_or_else(|| AppError::msg("не удалось декодировать base64 в ss://"))?;
        let text = String::from_utf8_lossy(&decoded).into_owned();
        let (creds, hostport) = text
            .rsplit_once('@')
            .ok_or_else(|| AppError::msg("некорректная ссылка ss://"))?;
        let (m, pw) = creds
            .split_once(':')
            .ok_or_else(|| AppError::msg("в ss:// не разобрать метод шифрования и пароль"))?;
        let (h, p) = split_host_port(hostport)?;
        (m.to_string(), pw.to_string(), h, p)
    };

    let mut node = ServerNode {
        id: new_id(),
        protocol: Protocol::Shadowsocks,
        address: host,
        port,
        method,
        password,
        name,
        ..Default::default()
    };
    if node.name.is_empty() {
        node.name = fallback_name(&node);
    }
    Ok(node)
}

/// vmess:// is a base64-encoded JSON object whose fields are loosely typed —
/// ports and alterIds arrive as either strings or numbers depending on the panel.
fn parse_vmess(rest: &str) -> Result<ServerNode> {
    let payload = rest.split('#').next().unwrap_or(rest);
    let decoded = b64_decode(payload)
        .ok_or_else(|| AppError::msg("не удалось декодировать base64 в vmess://"))?;
    let v: Value = serde_json::from_slice(&decoded)
        .map_err(|e| AppError::msg(format!("vmess:// содержит некорректный JSON: {e}")))?;

    let s = |key: &str| -> String {
        match &v[key] {
            Value::String(text) => text.clone(),
            Value::Number(n) => n.to_string(),
            _ => String::new(),
        }
    };
    let num = |key: &str| -> u64 { s(key).parse().unwrap_or(0) };

    let port = u16::try_from(num("port"))
        .map_err(|_| AppError::msg("некорректный порт в vmess://"))?;

    let mut node = ServerNode {
        id: new_id(),
        protocol: Protocol::Vmess,
        address: s("add"),
        port,
        uuid: s("id"),
        alter_id: num("aid") as u16,
        vmess_security: s("scy"),
        name: s("ps"),
        network: map_network(&s("net"))?,
        security: map_security(&s("tls"))?,
        path: s("path"),
        host: s("host"),
        service_name: s("path"),
        sni: s("sni"),
        fingerprint: s("fp"),
        alpn: alpn_list(&s("alpn")),
        ..Default::default()
    };

    if node.network == Network::Tcp && s("type").eq_ignore_ascii_case("http") {
        return Err(AppError::msg(
            "obfs «type=http» поверх TCP не поддерживается ядром sing-box",
        ));
    }
    if node.address.is_empty() {
        return Err(AppError::msg("в vmess:// отсутствует адрес сервера"));
    }
    if node.name.is_empty() {
        node.name = fallback_name(&node);
    }
    Ok(node)
}

/// The port Cloudflare's own client dials when nothing else is said.
const WARP_DEFAULT_PORT: u16 = 2408;

/// Split `host[:port]`, defaulting the port — unlike [`split_host_port`], which
/// treats a missing one as a broken link.
fn split_host_optional_port(hostport: &str, default: u16) -> Result<(String, u16)> {
    if hostport.contains(':') || hostport.starts_with('[') {
        return split_host_port(hostport);
    }
    if hostport.is_empty() {
        return Err(AppError::msg("в ссылке нет адреса сервера"));
    }
    Ok((hostport.to_string(), default))
}

/// `warp://…` — a Cloudflare WARP node.
///
/// The credentials are deliberately not in the link: they belong to the account
/// the app registers, and the link says at most which entry point to dial. What
/// Hiddify writes into these links — an account label in the userinfo position,
/// its own obfuscation options (`ifp`, `ifps`, `ifpd`, `ifpm`) in the query — is
/// meaningful only to its own core, so it is dropped rather than refused.
fn parse_warp(rest: &str) -> Result<ServerNode> {
    let (before_fragment, fragment) = match rest.split_once('#') {
        Some((head, tail)) => (head, pct(tail)),
        None => (rest, String::new()),
    };
    let authority = before_fragment.split('?').next().unwrap_or("");
    // Split on the last '@' for the same reason every other parser does.
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let authority = authority.trim_end_matches('/');

    let mut node = ServerNode {
        id: new_id(),
        protocol: Protocol::Wireguard,
        ..Default::default()
    };

    // `warp://auto` — and a bare `warp://` — mean "wherever the account says".
    if !authority.is_empty() && !authority.eq_ignore_ascii_case("auto") {
        let (host, port) = split_host_optional_port(authority, WARP_DEFAULT_PORT)?;
        node.address = host;
        node.port = port;
    }

    node.name = if fragment.is_empty() { "WARP".into() } else { fragment };
    Ok(node)
}

/// `wireguard://<private key>@host:port?publickey=…&address=…` — a plain
/// WireGuard peer, credentials and all.
fn parse_wireguard(rest: &str) -> Result<ServerNode> {
    let parts = split_uri(rest)?;
    let q = &parts.query;
    let first = |keys: &[&str]| -> String {
        keys.iter()
            .find_map(|k| q.get(*k))
            .cloned()
            .unwrap_or_default()
    };

    let private_key = pct(&parts.userinfo);
    if private_key.is_empty() {
        return Err(AppError::msg("в ссылке нет приватного ключа"));
    }
    let peer_public_key = first(&["publickey", "public_key", "peer_public_key", "pbk"]);
    if peer_public_key.is_empty() {
        return Err(AppError::msg("в ссылке нет публичного ключа сервера"));
    }

    let mut node = ServerNode {
        id: new_id(),
        protocol: Protocol::Wireguard,
        address: parts.host,
        port: parts.port,
        private_key,
        peer_public_key,
        reserved: parse_reserved(&first(&["reserved"])),
        ..Default::default()
    };

    // `address=172.16.0.2/32,2606:4700:110::2/128`: the prefixes are implied by
    // the protocol, so only the addresses themselves are kept.
    for address in first(&["address", "ip", "addresses"]).split(',') {
        let address = address.trim().split('/').next().unwrap_or("").trim();
        if address.is_empty() {
            continue;
        }
        if address.contains(':') {
            node.local_v6 = address.to_string();
        } else {
            node.local_v4 = address.to_string();
        }
    }
    if node.local_v4.is_empty() && node.local_v6.is_empty() {
        return Err(AppError::msg("в ссылке нет адреса интерфейса (address)"));
    }

    if let Ok(mtu) = first(&["mtu"]).parse::<u16>() {
        node.mtu = mtu;
    }
    if let Ok(keepalive) = first(&["keepalive", "persistent_keepalive"]).parse::<u16>() {
        node.keepalive = keepalive;
    }

    node.name = if parts.fragment.is_empty() {
        fallback_name(&node)
    } else {
        parts.fragment
    };
    Ok(node)
}

/// `reserved` comes either as the three bytes themselves (`1,2,3`) or as the
/// base64 `client_id` they are derived from. Anything else is dropped: a
/// wrong-length value makes sing-box refuse the whole document, while an absent
/// one just means "no tag".
fn parse_reserved(raw: &str) -> Vec<u8> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    if raw.contains(',') {
        let bytes: Vec<u8> = raw
            .split(',')
            .filter_map(|part| part.trim().parse::<u8>().ok())
            .collect();
        return if bytes.len() == 3 { bytes } else { Vec::new() };
    }
    b64_decode(raw).filter(|bytes| bytes.len() == 3).unwrap_or_default()
}

/// Whether the text is a WireGuard-style `.conf` rather than a list of links.
fn is_wg_conf(text: &str) -> bool {
    text.lines().any(|line| line.trim().eq_ignore_ascii_case("[interface]"))
}

fn conf_number(key: &str, value: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .map_err(|_| AppError::msg(format!("некорректное значение {key} = {value}")))
}

/// `on`, `true`, `1` — wg-quick's spellings of a switch.
fn conf_flag(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "on" | "true" | "1" | "yes")
}

/// A WireGuard or AmneziaWG `.conf` — what `awg-quick`, the Amnezia apps and
/// 3x-ui hand out. The obfuscation keys decide which of the two it is: a file
/// without any is plain WireGuard and runs on the stock core.
///
/// The name comes from the first comment, where 3x-ui and the Amnezia apps put
/// the client's; it is left empty when there is none, for the caller to fill.
/// `DNS`, `AllowedIPs`, `ListenPort` and the hook scripts are dropped: the app
/// keeps its own resolvers and always routes the whole tunnel.
fn wg_conf_node(text: &str) -> Result<ServerNode> {
    #[derive(PartialEq)]
    enum Section {
        Preamble,
        Interface,
        Peer,
        Other,
    }

    let mut node = ServerNode {
        id: new_id(),
        protocol: Protocol::Wireguard,
        ..Default::default()
    };
    let mut section = Section::Preamble;
    let mut peers = 0;
    let mut endpoint = String::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#').or_else(|| line.strip_prefix(';')) {
            // A commented-out setting is not a name.
            let comment = comment.trim();
            if node.name.is_empty() && !comment.contains('=') {
                node.name = comment.to_string();
            }
            continue;
        }
        if line.starts_with('[') {
            section = match line.to_ascii_lowercase().as_str() {
                "[interface]" => Section::Interface,
                "[peer]" => {
                    peers += 1;
                    Section::Peer
                }
                _ => Section::Other,
            };
            continue;
        }
        // Split on the first '=': base64 keys end in padding of their own.
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let original_key = key.trim();
        let key = original_key.to_ascii_lowercase();
        let value = value.trim();
        let awg = &mut node.awg;

        match section {
            Section::Interface => match key.as_str() {
                "privatekey" => node.private_key = value.to_string(),
                "address" => {
                    for address in value.split(',') {
                        let address = address.trim().split('/').next().unwrap_or("").trim();
                        if address.contains(':') {
                            if node.local_v6.is_empty() {
                                node.local_v6 = address.to_string();
                            }
                        } else if !address.is_empty() && node.local_v4.is_empty() {
                            node.local_v4 = address.to_string();
                        }
                    }
                }
                "mtu" => node.mtu = conf_number(original_key, value)?,
                "jc" => awg.jc = conf_number(original_key, value)?,
                "jmin" => awg.jmin = conf_number(original_key, value)?,
                "jmax" => awg.jmax = conf_number(original_key, value)?,
                "s1" => awg.s1 = conf_number(original_key, value)?,
                "s2" => awg.s2 = conf_number(original_key, value)?,
                "s3" => awg.s3 = conf_number(original_key, value)?,
                "s4" => awg.s4 = conf_number(original_key, value)?,
                "h1" => awg.h1 = value.to_string(),
                "h2" => awg.h2 = value.to_string(),
                "h3" => awg.h3 = value.to_string(),
                "h4" => awg.h4 = value.to_string(),
                "i1" => awg.i1 = value.to_string(),
                "i2" => awg.i2 = value.to_string(),
                "i3" => awg.i3 = value.to_string(),
                "i4" => awg.i4 = value.to_string(),
                "i5" => awg.i5 = value.to_string(),
                "headerprotectionkey" => awg.header_protection_key = value.to_string(),
                "contentpaddingaddition" => awg.content_padding_addition = value.to_string(),
                "rekeyaftertime" => awg.rekey_after_time = value.to_string(),
                "rekeytimeout" => awg.rekey_timeout = value.to_string(),
                "rejectaftertime" => awg.reject_after_time = value.to_string(),
                "keepalivetimeout" => awg.keepalive_timeout = value.to_string(),
                "maxhandshakeattempts" => awg.max_handshake_attempts = value.to_string(),
                "randomtrailers" => awg.random_trailers = conf_flag(value),
                "disablecookies" => awg.disable_cookies = conf_flag(value),
                _ => {}
            },
            // A client tunnel has one peer; any further ones would be routes
            // the app does not model.
            Section::Peer if peers == 1 => match key.as_str() {
                "publickey" => node.peer_public_key = value.to_string(),
                "presharedkey" => node.pre_shared_key = value.to_string(),
                "endpoint" => endpoint = value.to_string(),
                "persistentkeepalive" => {
                    if value.eq_ignore_ascii_case("off") {
                        node.keepalive = 0;
                    } else if let Ok(seconds) = value.parse::<u16>() {
                        node.keepalive = seconds;
                    } else if value.contains('-') {
                        // AmneziaWG 3.x re-picks the interval from a range;
                        // its low end serves wherever one number is needed.
                        node.awg.keepalive_range = value.to_string();
                        let low = value.split('-').next().unwrap_or("").trim();
                        node.keepalive = low.parse().unwrap_or(0);
                    } else {
                        return Err(AppError::msg(format!(
                            "некорректное значение PersistentKeepalive = {value}"
                        )));
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    if node.private_key.is_empty() {
        return Err(AppError::msg("в конфигурации нет приватного ключа (PrivateKey)"));
    }
    if node.peer_public_key.is_empty() {
        return Err(AppError::msg("в конфигурации нет публичного ключа сервера (PublicKey)"));
    }
    if endpoint.is_empty() {
        return Err(AppError::msg("в конфигурации нет адреса сервера (Endpoint)"));
    }
    if node.local_v4.is_empty() && node.local_v6.is_empty() {
        return Err(AppError::msg("в конфигурации нет адреса интерфейса (Address)"));
    }
    let (host, port) = split_host_port(&endpoint)?;
    node.address = host;
    node.port = port;

    if !node.awg.is_empty() {
        node.protocol = Protocol::Amneziawg;
    }
    Ok(node)
}

/// Every `.conf` in the text, each starting at its own `[Interface]`.
fn parse_wg_confs(text: &str) -> ParseReport {
    let mut documents: Vec<String> = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let opens = line.trim().eq_ignore_ascii_case("[interface]");
        if opens && current.to_ascii_lowercase().contains("[interface]") {
            documents.push(std::mem::take(&mut current));
        }
        current.push_str(line);
        current.push('\n');
    }
    documents.push(current);

    let mut nodes = Vec::new();
    let mut errors = Vec::new();
    for document in documents {
        let document = document.trim();
        match wg_conf_node(document) {
            Ok(mut node) => {
                if node.name.is_empty() {
                    node.name = fallback_name(&node);
                }
                node.raw_link = document.to_string();
                nodes.push(node);
            }
            Err(e) => errors.push((truncate(document.lines().next().unwrap_or(""), 90), e.to_string())),
        }
    }
    ParseReport { nodes, errors }
}

/// Undo Qt's `qCompress`: a four-byte big-endian length, then a zlib stream.
fn q_uncompress(bytes: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let stream = bytes.get(4..)?;
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(stream).read_to_end(&mut out).ok()?;
    Some(out)
}

/// The `.conf` text inside an Amnezia profile, and the profile's own title.
///
/// The profile lists one container per protocol the server runs; the
/// AmneziaWG one (or plain WireGuard) keeps the client config as a JSON
/// string in `last_config`, whose `config` is the `.conf` text itself.
fn amnezia_profile_conf(profile: &Value) -> Result<(String, String)> {
    let title = profile["description"].as_str().unwrap_or("").trim().to_string();
    let containers = profile["containers"].as_array().cloned().unwrap_or_default();
    for container in &containers {
        for key in ["awg", "wireguard"] {
            let Some(last) = container[key]["last_config"].as_str() else {
                continue;
            };
            let Ok(last) = serde_json::from_str::<Value>(last) else {
                continue;
            };
            if let Some(conf) = last["config"].as_str().filter(|c| is_wg_conf(c)) {
                return Ok((conf.to_string(), title));
            }
        }
    }
    Err(AppError::msg(
        "в профиле Amnezia нет AmneziaWG — поддерживаются только AmneziaWG и WireGuard",
    ))
}

/// `vpn://…` — AmneziaWG as 3x-ui and the Amnezia apps share it.
///
/// Two payloads hide behind the one scheme: 3x-ui encodes the `.conf` text
/// itself, the Amnezia apps a Qt-compressed JSON profile that carries the same
/// text inside. Either way the `.conf` is what gets parsed.
fn parse_amnezia_link(rest: &str) -> Result<ServerNode> {
    let (payload, fragment) = match rest.split_once('#') {
        Some((head, tail)) => (head, pct(tail)),
        None => (rest, String::new()),
    };
    let bytes = b64_decode(payload.trim_end_matches('/'))
        .ok_or_else(|| AppError::msg("не удалось декодировать base64 в vpn://"))?;

    let text = String::from_utf8_lossy(&bytes);
    let (conf, title) = if is_wg_conf(&text) {
        (text.into_owned(), String::new())
    } else {
        let json = q_uncompress(&bytes).unwrap_or_else(|| bytes.clone());
        let profile: Value = serde_json::from_slice(&json).map_err(|_| {
            AppError::msg("в ссылке vpn:// нет ни конфигурации, ни профиля Amnezia")
        })?;
        amnezia_profile_conf(&profile)?
    };

    let mut node = wg_conf_node(&conf)?;
    if !fragment.is_empty() {
        node.name = fragment;
    } else if node.name.is_empty() {
        node.name = title;
    }
    if node.name.is_empty() {
        node.name = fallback_name(&node);
    }
    Ok(node)
}

/// A port written as a number or as a string, the way panels disagree on it.
fn json_port(value: &Value) -> Option<u16> {
    match value {
        Value::Number(n) => n.as_u64().and_then(|p| u16::try_from(p).ok()),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// `alpn` as Xray accepts it: a list, or one comma-separated string.
fn json_alpn(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Value::String(s) => alpn_list(s),
        _ => Vec::new(),
    }
}

/// An Xray `masque` outbound, as 3x-ui writes it into a JSON subscription:
///
/// ```text
/// { "protocol": "masque", "settings": { "address": …, "port": … },
///   "streamSettings": { "network": "masque", "security": "tls",
///     "tlsSettings": { "serverName": …, "alpn": ["h3"] },
///     "masqueSettings": { "path": …, "user": <email>, "pass": … } } }
/// ```
fn parse_masque_outbound(outbound: &Value, name: &str) -> Result<ServerNode> {
    let settings = &outbound["settings"];
    let address = settings["address"].as_str().unwrap_or("").trim().to_string();
    if address.is_empty() {
        return Err(AppError::msg("в outbound MASQUE нет адреса сервера"));
    }
    let port = json_port(&settings["port"])
        .ok_or_else(|| AppError::msg("в outbound MASQUE нет порта"))?;

    let stream = &outbound["streamSettings"];
    // Xray's docs name the selector `method`, 3x-ui writes `network`; the
    // transport is the protocol's own either way.
    let transport = stream["network"]
        .as_str()
        .or_else(|| stream["method"].as_str())
        .unwrap_or("masque");
    if !transport.eq_ignore_ascii_case("masque") {
        return Err(AppError::msg(format!(
            "MASQUE ходит только своим транспортом, а не «{transport}»"
        )));
    }
    if stream["security"].as_str() == Some("reality") {
        return Err(AppError::msg("MASQUE не работает поверх REALITY — только TLS"));
    }

    let tls = &stream["tlsSettings"];
    let masque = &stream["masqueSettings"];
    let text = |value: &Value| value.as_str().unwrap_or("").trim().to_string();

    let mut username = text(&masque["user"]);
    let mut password = text(&masque["pass"]);
    // The same credentials may come as a ready header instead.
    if username.is_empty() && password.is_empty() {
        let header = text(&masque["headers"]["Authorization"]);
        if let Some(encoded) = header.strip_prefix("Basic ") {
            if let Some(decoded) = b64_decode(encoded) {
                let decoded = String::from_utf8_lossy(&decoded).into_owned();
                if let Some((user, pass)) = decoded.split_once(':') {
                    username = user.to_string();
                    password = pass.to_string();
                }
            }
        }
    }

    let mut node = ServerNode {
        id: new_id(),
        name: name.trim().to_string(),
        protocol: Protocol::Masque,
        address,
        port,
        username,
        password,
        security: Security::Tls,
        sni: text(&tls["serverName"]),
        alpn: json_alpn(&tls["alpn"]),
        fingerprint: text(&tls["fingerprint"]),
        path: text(&masque["path"]),
        host: text(&masque["host"]),
        ..Default::default()
    };
    if node.name.is_empty() {
        node.name = fallback_name(&node);
    }
    // No share-link format exists for MASQUE; the outbound itself, wrapped as
    // a one-server config, is what pasting back into the app understands.
    node.raw_link = serde_json::json!({ "remarks": node.name, "outbounds": [outbound] }).to_string();
    Ok(node)
}

/// A JSON subscription: one complete Xray config per server, each with its
/// `remarks` — 3x-ui's `/json/` endpoint, which is the only way it hands out
/// MASQUE at all.
///
/// Only MASQUE is taken from it. Every other protocol 3x-ui has a share link
/// for, and its regular subscription already brings those; importing them
/// here as well would give each such server twice.
fn parse_xray_json(root: &Value) -> ParseReport {
    let configs: Vec<&Value> = match root {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };

    let mut nodes = Vec::new();
    let mut errors = Vec::new();
    let mut others: Vec<String> = Vec::new();

    for config in configs {
        let remarks = config["remarks"].as_str().unwrap_or("");
        let outbounds: Vec<&Value> = match &config["outbounds"] {
            Value::Array(list) => list.iter().collect(),
            // A bare outbound: what a MASQUE node keeps as its own link.
            _ if config.get("protocol").is_some() => vec![config],
            _ => Vec::new(),
        };
        for outbound in outbounds {
            match outbound["protocol"].as_str().unwrap_or("") {
                "masque" => match parse_masque_outbound(outbound, remarks) {
                    Ok(node) => nodes.push(node),
                    Err(e) => errors.push((format!("masque «{remarks}»"), e.to_string())),
                },
                // The plumbing every config carries next to its proxy.
                "" | "freedom" | "blackhole" | "dns" | "loopback" => {}
                other => {
                    if !others.iter().any(|o| o == other) {
                        others.push(other.to_string());
                    }
                }
            }
        }
    }

    // Silence would read as "the subscription is empty", which it is not.
    if nodes.is_empty() && errors.is_empty() {
        let reason = if others.is_empty() {
            "в JSON нет ни одного outbound сервера".to_string()
        } else {
            format!(
                "в JSON-подписке нет серверов MASQUE, а {} из неё не берутся — их приносит обычная подписка панели",
                others.join(", ")
            )
        };
        errors.push(("JSON".to_string(), reason));
    }
    ParseReport { nodes, errors }
}

/// Parse a single share link into a node.
pub fn parse_link(raw: &str) -> Result<ServerNode> {
    let link = raw.trim();
    let (scheme, rest) = link
        .split_once("://")
        .ok_or_else(|| AppError::msg("строка не похожа на ссылку (нет «://»)"))?;

    let mut node = match scheme.to_lowercase().as_str() {
        "vless" => parse_vless(rest),
        "vmess" => parse_vmess(rest),
        "trojan" => parse_trojan(rest),
        "ss" => parse_shadowsocks(rest),
        "hysteria2" | "hy2" => parse_hysteria2(rest),
        "tuic" => parse_tuic(rest),
        "warp" => parse_warp(rest),
        "wireguard" | "wg" => parse_wireguard(rest),
        "vpn" => parse_amnezia_link(rest),
        other => Err(AppError::msg(format!("протокол «{other}» не поддерживается"))),
    }?;

    node.raw_link = link.to_string();
    Ok(node)
}

/// Plan status advertised by the panel alongside the node list.
///
/// 3x-ui (and the wider v2board-style ecosystem) answers a subscription request
/// with a `subscription-userinfo` header:
///
/// ```text
/// subscription-userinfo: upload=0; download=1234; total=107374182400; expire=1767225600
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserInfo {
    pub upload: u64,
    pub download: u64,
    /// Bytes allowed; 0 means unlimited.
    pub total: u64,
    /// Unix seconds; 0 means the plan never expires.
    pub expire: i64,
}

pub fn parse_user_info(header: &str) -> UserInfo {
    let mut info = UserInfo::default();

    for part in header.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "upload" => info.upload = value.parse().unwrap_or(0),
            "download" => info.download = value.parse().unwrap_or(0),
            "total" => info.total = value.parse().unwrap_or(0),
            "expire" => {
                // A few panels report milliseconds. Anything past the year 5138
                // as seconds is really a millisecond timestamp.
                let raw: i64 = value.parse().unwrap_or(0);
                info.expire = if raw > 100_000_000_000 { raw / 1000 } else { raw.max(0) };
            }
            _ => {}
        }
    }
    info
}

/// `profile-title` is sent either verbatim or as `base64:<...>`.
pub fn parse_profile_title(header: &str) -> Option<String> {
    let raw = header.trim();
    let decoded = match raw.strip_prefix("base64:") {
        Some(encoded) => b64_decode(encoded)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default(),
        None => raw.to_string(),
    };
    let trimmed = decoded.trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

pub struct ParseReport {
    pub nodes: Vec<ServerNode>,
    /// `(source line, reason)` for everything that could not be imported.
    pub errors: Vec<(String, String)>,
}

/// Parse a subscription body or a user-pasted blob of links.
///
/// Subscription servers usually return the whole list base64-encoded; some return
/// it verbatim. Try to decode first and keep the result only if it actually looks
/// like a list of links.
///
/// Two whole-document formats are recognised first, since neither is a list of
/// links and splitting one into lines would report every line as broken: a
/// JSON subscription of Xray configs, and WireGuard/AmneziaWG `.conf` text.
pub fn parse_subscription(body: &str) -> ParseReport {
    let document = body.trim_start_matches('\u{feff}').trim();
    if document.starts_with(['{', '[']) {
        if let Ok(root) = serde_json::from_str::<Value>(document) {
            return parse_xray_json(&root);
        }
    }
    if is_wg_conf(document) {
        return parse_wg_confs(document);
    }

    let text = match b64_decode(body) {
        Some(bytes) => {
            let decoded = String::from_utf8_lossy(&bytes).into_owned();
            if decoded.contains("://") {
                decoded
            } else {
                body.to_string()
            }
        }
        None => body.to_string(),
    };

    let mut nodes = Vec::new();
    let mut errors = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains("://") {
            continue;
        }
        match parse_link(line) {
            Ok(node) => nodes.push(node),
            Err(e) => errors.push((truncate(line, 90), e.to_string())),
        }
    }

    ParseReport { nodes, errors }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let head: String = text.chars().take(max).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_reality_vless_link() {
        let link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
                    ?type=tcp&security=reality&pbk=PUBKEY&sid=ab12&fp=chrome\
                    &sni=www.microsoft.com&flow=xtls-rprx-vision#%D0%A2%D0%BE%D0%BA%D0%B8%D0%BE";
        let n = parse_link(link).unwrap();
        assert_eq!(n.protocol, Protocol::Vless);
        assert_eq!(n.address, "1.2.3.4");
        assert_eq!(n.port, 443);
        assert_eq!(n.security, Security::Reality);
        assert_eq!(n.public_key, "PUBKEY");
        assert_eq!(n.flow, "xtls-rprx-vision");
        assert_eq!(n.name, "Токио"); // fragment is percent-decoded
    }

    #[test]
    fn parses_a_websocket_vless_link() {
        let link = "vless://uuid-1@host.tld:8443?type=ws&security=tls&path=%2Fray%3Fed%3D2048\
                    &host=cdn.tld&sni=cdn.tld#WS";
        let n = parse_link(link).unwrap();
        assert_eq!(n.network, Network::Ws);
        assert_eq!(n.path, "/ray?ed=2048");
        assert_eq!(n.host, "cdn.tld");
    }

    #[test]
    fn xray_only_transports_are_imported_and_flagged_for_the_xray_engine() {
        let n = parse_link("vless://u@h:443?type=xhttp&security=tls#x").unwrap();
        assert_eq!(n.network, Network::Xhttp);
        assert!(n.needs_xray());
    }

    #[test]
    fn transports_no_engine_implements_are_still_rejected() {
        for kind in ["kcp", "quic"] {
            let err = parse_link(&format!("vless://u@h:443?type={kind}&security=tls#x"))
                .unwrap_err();
            assert!(err.to_string().contains("не поддерживается"), "{err}");
        }
    }

    #[test]
    fn accepts_the_legacy_encryption_none_marker() {
        // Every 3x-ui link carries this; it must not be mistaken for a real
        // encryption layer.
        let n = parse_link("vless://u@h:443?encryption=none&type=tcp&security=tls#x").unwrap();
        assert_eq!(n.protocol, Protocol::Vless);
    }

    #[test]
    fn post_quantum_vless_encryption_is_kept_and_routed_to_xray() {
        // Shape taken from a real 3x-ui inbound running Xray 26.x.
        let n = parse_link(
            "vless://9deed72d-8f4a-42f8-8c22-ee0d5f6ed6c2@1.2.3.4:47182\
             ?encryption=mlkem768x25519plus.native.0rtt.qC-yAYXnimt3ADJeuER9\
             &flow=xtls-rprx-vision&security=reality&pbk=KEY&sid=79a1\
             &spx=%2Fb2aa52cfbd7e55f&type=tcp#n",
        )
        .unwrap();
        assert!(n.encryption.starts_with("mlkem768x25519plus"));
        assert_eq!(n.spider_x, "/b2aa52cfbd7e55f");
        assert!(n.needs_xray());
    }

    #[test]
    fn rejects_reality_without_a_public_key() {
        let err = parse_link("vless://u@h:443?type=tcp&security=reality#x").unwrap_err();
        assert!(err.to_string().contains("pbk"), "{err}");
    }

    #[test]
    fn parses_ipv6_authority() {
        let n = parse_link("vless://u@[2001:db8::1]:443?type=tcp&security=none#v6").unwrap();
        assert_eq!(n.address, "2001:db8::1");
        assert_eq!(n.port, 443);
    }

    #[test]
    fn parses_vmess_json_with_stringly_typed_numbers() {
        let payload = serde_json::json!({
            "v": "2", "ps": "node", "add": "a.com", "port": "443",
            "id": "uuid-2", "aid": "0", "net": "ws", "path": "/p",
            "host": "a.com", "tls": "tls"
        })
        .to_string();
        let encoded = STANDARD_NO_PAD.encode(payload);
        let n = parse_link(&format!("vmess://{encoded}")).unwrap();
        assert_eq!(n.protocol, Protocol::Vmess);
        assert_eq!(n.port, 443);
        assert_eq!(n.network, Network::Ws);
    }

    #[test]
    fn parses_hysteria2_with_obfs() {
        let n = parse_link(
            "hysteria2://pass@1.2.3.4:33884?sni=example.com&insecure=1\
             &obfs=salamander&obfs-password=rain#hy",
        )
        .unwrap();
        assert_eq!(n.protocol, Protocol::Hysteria2);
        assert_eq!(n.obfs, "salamander");
        assert_eq!(n.obfs_password, "rain");
        assert!(n.allow_insecure);
    }

    #[test]
    fn hysteria2_obfs_password_alone_still_means_salamander() {
        // Единственный существующий тип; часть панелей тип не пишет вовсе.
        let n = parse_link("hysteria2://p@h:443?obfs-password=rain#x").unwrap();
        assert_eq!(n.obfs, "salamander");
        assert_eq!(n.obfs_password, "rain");
    }

    #[test]
    fn hysteria2_rejects_what_would_silently_break() {
        // Неизвестный тип обфускации ядро не умеет, а «выбросить и подключиться
        // без него» даёт мёртвый туннель — сервер молчит.
        let unknown = parse_link("hysteria2://p@h:443?obfs=faketls&obfs-password=x#a");
        assert!(unknown.unwrap_err().to_string().contains("salamander"));

        let missing = parse_link("hysteria2://p@h:443?obfs=salamander#a");
        assert!(missing.unwrap_err().to_string().contains("obfs-password"));

        let bad_ports = parse_link("hysteria2://p@h:443?mport=50000-20000#a");
        assert!(bad_ports.unwrap_err().to_string().contains("диапазон"));
    }

    #[test]
    fn hysteria2_mport_becomes_hop_ranges() {
        let n = parse_link("hysteria2://p@h:443?mport=443,20000-50000#x").unwrap();
        assert_eq!(n.port, 443);
        assert_eq!(n.hop_ports, vec!["443:443".to_string(), "20000:50000".to_string()]);
    }

    #[test]
    fn hysteria2_port_list_in_authority_is_supported() {
        // Форма официального клиента: диапазоны прямо в адресе.
        let n = parse_link("hysteria2://p@h.tld:443,20000-50000?sni=h.tld#x").unwrap();
        assert_eq!(n.port, 443);
        assert_eq!(n.hop_ports, vec!["443:443".to_string(), "20000:50000".to_string()]);

        // Обычная ссылка с одним портом через переписыватель не меняется.
        let plain = parse_link("hysteria2://p@h.tld:443?sni=h.tld#x").unwrap();
        assert_eq!(plain.port, 443);
        assert!(plain.hop_ports.is_empty());

        // IPv6-литерал не принимается за список портов.
        let v6 = parse_link("hysteria2://p@[2001:db8::1]:443#x").unwrap();
        assert_eq!(v6.address, "2001:db8::1");
        assert_eq!(v6.port, 443);
        assert!(v6.hop_ports.is_empty());
    }

    #[test]
    fn parses_sip002_shadowsocks() {
        let creds = URL_SAFE_NO_PAD.encode("aes-256-gcm:secret");
        let n = parse_link(&format!("ss://{creds}@1.2.3.4:8388#SS")).unwrap();
        assert_eq!(n.method, "aes-256-gcm");
        assert_eq!(n.password, "secret");
        assert_eq!(n.port, 8388);
    }

    #[test]
    fn subscription_accepts_both_base64_and_plaintext() {
        let plain = "vless://u@a.com:443?type=tcp&security=none#one\n\
                     vless://u@b.com:443?type=tcp&security=none#two";
        assert_eq!(parse_subscription(plain).nodes.len(), 2);

        let encoded = STANDARD_NO_PAD.encode(plain);
        assert_eq!(parse_subscription(&encoded).nodes.len(), 2);
    }

    #[test]
    fn subscription_reports_bad_lines_without_dropping_good_ones() {
        let body = "vless://u@a.com:443?type=tcp&security=none#ok\n\
                    vless://u@b.com:443?type=kcp&security=tls#bad";
        let report = parse_subscription(body);
        assert_eq!(report.nodes.len(), 1);
        assert_eq!(report.errors.len(), 1);
    }

    #[test]
    fn reads_the_plan_status_header() {
        let info = parse_user_info("upload=100; download=200; total=1000; expire=1767225600");
        assert_eq!(info.upload, 100);
        assert_eq!(info.download, 200);
        assert_eq!(info.total, 1000);
        assert_eq!(info.expire, 1_767_225_600);
    }

    #[test]
    fn plan_status_tolerates_partial_and_malformed_headers() {
        // Unlimited plans send zeros; some panels omit fields entirely.
        let info = parse_user_info("upload=0; download=0; total=0; expire=0");
        assert_eq!(info, UserInfo::default());

        let partial = parse_user_info("download=42");
        assert_eq!(partial.download, 42);
        assert_eq!(partial.total, 0);

        // Garbage must degrade to zeros rather than panic.
        let junk = parse_user_info("nonsense; total=abc; =; expire=-5");
        assert_eq!(junk.total, 0);
        assert_eq!(junk.expire, 0);
    }

    #[test]
    fn millisecond_expiry_is_normalised_to_seconds() {
        let info = parse_user_info("expire=1767225600000");
        assert_eq!(info.expire, 1_767_225_600);
    }

    #[test]
    fn profile_title_accepts_plain_and_base64_forms() {
        assert_eq!(parse_profile_title("Мой сервер").as_deref(), Some("Мой сервер"));
        let encoded = STANDARD_NO_PAD.encode("Мой сервер");
        assert_eq!(
            parse_profile_title(&format!("base64:{encoded}")).as_deref(),
            Some("Мой сервер")
        );
        assert_eq!(parse_profile_title("   "), None);
    }

    #[test]
    fn password_containing_an_at_sign_does_not_eat_the_host() {
        let n = parse_link("trojan://p@ss@real.host:443?security=tls#t").unwrap();
        assert_eq!(n.address, "real.host");
        assert_eq!(n.password, "p@ss");
    }

    #[test]
    fn a_warp_link_names_an_entry_point_and_nothing_else() {
        // Ключей в ссылке нет и быть не должно: они принадлежат аккаунту,
        // который приложение регистрирует само.
        let n = parse_link("warp://188.114.98.0:955#Мой WARP").unwrap();
        assert_eq!(n.protocol, Protocol::Wireguard);
        assert_eq!(n.address, "188.114.98.0");
        assert_eq!(n.port, 955);
        assert_eq!(n.name, "Мой WARP");
        assert!(n.private_key.is_empty());
    }

    #[test]
    fn warp_auto_leaves_the_entry_point_to_the_account() {
        for link in ["warp://auto", "warp://auto#WARP", "warp://AUTO/"] {
            let n = parse_link(link).unwrap();
            assert_eq!(n.protocol, Protocol::Wireguard);
            assert!(n.address.is_empty(), "{link}");
        }
    }

    #[test]
    fn a_warp_link_without_a_port_gets_cloudflares_own() {
        let n = parse_link("warp://162.159.192.1").unwrap();
        assert_eq!(n.address, "162.159.192.1");
        assert_eq!(n.port, 2408);
    }

    #[test]
    fn hiddify_warp_extras_are_dropped_rather_than_refused() {
        // `A1@` — метка аккаунта их ядра, `ifp*` — его же обфускация; sing-box
        // не знает ни того, ни другого, но точка входа в ссылке настоящая.
        let n = parse_link("warp://A1@188.114.97.170:894?ifp=40-80&ifpm=m4#m4").unwrap();
        assert_eq!(n.address, "188.114.97.170");
        assert_eq!(n.port, 894);
        assert_eq!(n.name, "m4");
    }

    #[test]
    fn parses_a_plain_wireguard_link() {
        let n = parse_link(
            "wireguard://cHJpdmF0ZQ==@10.0.0.1:51820?publickey=cHVibGlj&address=10.7.0.2/32,fd00::2/128&reserved=1,2,3&mtu=1420#WG",
        )
        .unwrap();
        assert_eq!(n.protocol, Protocol::Wireguard);
        assert_eq!(n.private_key, "cHJpdmF0ZQ==");
        assert_eq!(n.peer_public_key, "cHVibGlj");
        // Префиксы подразумеваются протоколом, в модели живут голые адреса.
        assert_eq!(n.local_v4, "10.7.0.2");
        assert_eq!(n.local_v6, "fd00::2");
        assert_eq!(n.reserved, vec![1, 2, 3]);
        assert_eq!(n.mtu, 1420);
        assert_eq!(n.name, "WG");
    }

    #[test]
    fn a_wireguard_link_missing_what_it_cannot_work_without_is_refused() {
        // Молча принять такую ссылку — значит завести сервер, который
        // подключается и не несёт ни байта.
        for link in [
            "wireguard://@10.0.0.1:51820?publickey=p&address=10.7.0.2",
            "wireguard://priv@10.0.0.1:51820?address=10.7.0.2",
            "wireguard://priv@10.0.0.1:51820?publickey=p",
        ] {
            assert!(parse_link(link).is_err(), "{link}");
        }
    }

    /// A client `.conf` exactly as 3x-ui v3.10 renders one for an AmneziaWG
    /// 3.1 inbound (docs/content/docs/en/config/amneziawg.mdx).
    const AWG_CONF: &str = "[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.1.2/32, fd42::2/128
DNS = 8.8.8.8, 8.8.4.4
MTU = 1376
Jc = 4
Jmin = 65
Jmax = 220
S1 = 87
S2 = 44
S3 = 21
S4 = 12
H1 = 463065432
H2 = 912345678
H3 = 1345678901-1345679901
H4 = 1987654321
I1 = <r 148>
HeaderProtectionKey = 8Iu83eHDA3fMKKSGaEsVW9Ycd2lYYzc0MYlk1jJTvE4=
ContentPaddingAddition = 17-49
RekeyAfterTime = 111-139
RekeyTimeout = 4-7
RejectAfterTime = 187-251
KeepaliveTimeout = 9-14
MaxHandshakeAttempts = 19-36
RandomTrailers = on
DisableCookies = on

# nl-awg - ivy
[Peer]
PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = nl.example.com:51820
PersistentKeepalive = 15-25
";

    #[test]
    fn an_amneziawg_conf_keeps_every_obfuscation_value_verbatim() {
        let report = parse_subscription(AWG_CONF);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        let n = &report.nodes[0];

        assert_eq!(n.protocol, Protocol::Amneziawg);
        assert_eq!(n.name, "nl-awg - ivy");
        assert_eq!(n.address, "nl.example.com");
        assert_eq!(n.port, 51820);
        assert_eq!(n.private_key, "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");
        assert_eq!(n.peer_public_key, "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=");
        assert_eq!(n.pre_shared_key, "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=");
        assert_eq!(n.local_v4, "10.8.1.2");
        assert_eq!(n.local_v6, "fd42::2");
        assert_eq!(n.mtu, 1376);

        let a = &n.awg;
        assert_eq!((a.jc, a.jmin, a.jmax), (4, 65, 220));
        assert_eq!((a.s1, a.s2, a.s3, a.s4), (87, 44, 21, 12));
        assert_eq!(a.h1, "463065432");
        // Диапазон не схлопывается в число: сервер ждёт ровно его.
        assert_eq!(a.h3, "1345678901-1345679901");
        assert_eq!(a.i1, "<r 148>");
        assert_eq!(a.header_protection_key, "8Iu83eHDA3fMKKSGaEsVW9Ycd2lYYzc0MYlk1jJTvE4=");
        assert_eq!(a.content_padding_addition, "17-49");
        assert_eq!(a.reject_after_time, "187-251");
        assert_eq!(a.max_handshake_attempts, "19-36");
        assert!(a.random_trailers && a.disable_cookies);
        // Диапазон keepalive живёт в AWG, нижняя граница — в обычном поле.
        assert_eq!(a.keepalive_range, "15-25");
        assert_eq!(n.keepalive, 15);
        // Ссылкой узла служит сам файл: его можно скопировать и вставить снова.
        assert!(n.raw_link.starts_with("[Interface]"));
    }

    #[test]
    fn a_conf_without_obfuscation_is_plain_wireguard() {
        let conf = "[Interface]\nPrivateKey = priv\nAddress = 10.7.0.2/32\n\n\
                    [Peer]\nPublicKey = pub\nEndpoint = [2001:db8::1]:51820\n";
        let n = &parse_subscription(conf).nodes[0];
        assert_eq!(n.protocol, Protocol::Wireguard);
        assert!(n.awg.is_empty());
        assert_eq!(n.address, "2001:db8::1");
        // Без комментария имя берётся из адреса, как у ссылок без фрагмента.
        assert_eq!(n.name, "2001:db8::1:51820");
    }

    #[test]
    fn a_conf_missing_what_the_tunnel_needs_is_refused() {
        for (missing, conf) in [
            ("Endpoint", "[Interface]\nPrivateKey = p\nAddress = 10.0.0.2\n[Peer]\nPublicKey = k\n"),
            ("PublicKey", "[Interface]\nPrivateKey = p\nAddress = 10.0.0.2\n[Peer]\nEndpoint = h:1\n"),
            ("Address", "[Interface]\nPrivateKey = p\n[Peer]\nPublicKey = k\nEndpoint = h:1\n"),
        ] {
            let report = parse_subscription(conf);
            assert!(report.nodes.is_empty(), "{missing}");
            assert!(report.errors[0].1.contains(missing), "{:?}", report.errors);
        }
        let bad = parse_subscription(&AWG_CONF.replace("Jc = 4", "Jc = four"));
        assert!(bad.errors[0].1.contains("Jc"), "{:?}", bad.errors);
    }

    #[test]
    fn several_confs_pasted_together_become_several_servers() {
        let second = AWG_CONF.replace("ivy", "joe").replace("yAnz5", "zBoa6");
        let report = parse_subscription(&format!("{AWG_CONF}\n{second}"));
        assert_eq!(report.nodes.len(), 2, "{:?}", report.errors);
        assert_eq!(report.nodes[1].name, "nl-awg - joe");
        assert_ne!(report.nodes[0].fingerprint_key(), report.nodes[1].fingerprint_key());
    }

    #[test]
    fn a_3x_ui_vpn_link_is_the_conf_in_base64url() {
        // Так 3x-ui кладёт AmneziaWG в обычную подписку (internal/sub/service.go).
        let link = format!("vpn://{}", URL_SAFE_NO_PAD.encode(AWG_CONF));
        let report = parse_subscription(&format!("vless://u@a.com:443?type=tcp#v\n{link}"));
        assert_eq!(report.nodes.len(), 2, "{:?}", report.errors);
        let n = &report.nodes[1];
        assert_eq!(n.protocol, Protocol::Amneziawg);
        assert_eq!(n.name, "nl-awg - ivy");
        assert_eq!(n.raw_link, link);
    }

    #[test]
    fn an_amnezia_app_vpn_link_carries_a_compressed_profile() {
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let last_config = serde_json::json!({ "config": AWG_CONF, "H1": "463065432" }).to_string();
        let profile = serde_json::json!({
            "description": "Amsterdam",
            "containers": [
                { "container": "amnezia-xray", "xray": { "last_config": "{}" } },
                { "container": "amnezia-awg", "awg": { "last_config": last_config } }
            ]
        })
        .to_string();
        // qCompress: длина несжатых данных big-endian, за ней поток zlib.
        let mut packed = (profile.len() as u32).to_be_bytes().to_vec();
        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(profile.as_bytes()).unwrap();
        packed.extend(encoder.finish().unwrap());

        let n = parse_link(&format!("vpn://{}", URL_SAFE_NO_PAD.encode(&packed))).unwrap();
        assert_eq!(n.protocol, Protocol::Amneziawg);
        assert_eq!(n.awg.h3, "1345678901-1345679901");
        // Комментарий в самом файле точнее названия профиля: он про клиента.
        assert_eq!(n.name, "nl-awg - ivy");

        let without_awg = serde_json::json!({ "containers": [{ "xray": {} }] }).to_string();
        let err = parse_link(&format!("vpn://{}", URL_SAFE_NO_PAD.encode(without_awg))).unwrap_err();
        assert!(err.to_string().contains("AmneziaWG"), "{err}");
    }

    /// A 3x-ui v3.10 JSON subscription: one config per inbound, MASQUE next to
    /// a VLESS one (shape of internal/sub/json_service.go `getConfig`).
    fn json_subscription() -> String {
        serde_json::json!([
            {
                "remarks": "nl-vless-ivy",
                "outbounds": [
                    { "protocol": "vless", "tag": "proxy", "settings": { "vnext": [] } },
                    { "protocol": "freedom", "tag": "direct" },
                    { "protocol": "blackhole", "tag": "block" }
                ]
            },
            {
                "remarks": "nl-masque-ivy",
                "outbounds": [
                    {
                        "protocol": "masque",
                        "tag": "proxy",
                        "settings": { "address": "203.0.113.9", "port": 8443 },
                        "streamSettings": {
                            "network": "masque",
                            "security": "tls",
                            "tlsSettings": {
                                "serverName": "masque.example.test",
                                "alpn": ["h2"],
                                "fingerprint": "chrome"
                            },
                            "masqueSettings": {
                                "path": "/.well-known/masque/ip/*/*/",
                                "user": "ivy@example.test",
                                "pass": "pw-ivy"
                            }
                        }
                    },
                    { "protocol": "freedom", "tag": "direct" }
                ]
            }
        ])
        .to_string()
    }

    #[test]
    fn a_json_subscription_brings_its_masque_servers() {
        let report = parse_subscription(&json_subscription());
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        // VLESS из JSON не берётся: его приносит обычная подписка, иначе
        // каждый такой сервер появился бы дважды.
        assert_eq!(report.nodes.len(), 1);

        let n = &report.nodes[0];
        assert_eq!(n.protocol, Protocol::Masque);
        assert_eq!(n.name, "nl-masque-ivy");
        assert_eq!(n.address, "203.0.113.9");
        assert_eq!(n.port, 8443);
        assert_eq!(n.sni, "masque.example.test");
        assert_eq!(n.alpn, vec!["h2".to_string()]);
        assert_eq!(n.username, "ivy@example.test");
        assert_eq!(n.password, "pw-ivy");
        assert_eq!(n.path, "/.well-known/masque/ip/*/*/");
        assert_eq!(n.security, Security::Tls);
        assert!(n.needs_xray());

        // Ссылка узла — он сам одним конфигом: вставка возвращает тот же сервер.
        let again = parse_subscription(&n.raw_link);
        assert_eq!(again.nodes.len(), 1, "{:?}", again.errors);
        assert_eq!(again.nodes[0].fingerprint_key(), n.fingerprint_key());
    }

    #[test]
    fn masque_credentials_may_come_as_a_basic_header() {
        let body = serde_json::json!({
            "outbounds": [{
                "protocol": "masque",
                "settings": { "address": "h.example", "port": "443" },
                "streamSettings": {
                    "method": "masque",
                    "masqueSettings": {
                        "headers": { "Authorization": format!("Basic {}", STANDARD_NO_PAD.encode("ivy:pw")) }
                    }
                }
            }]
        })
        .to_string();
        let n = &parse_subscription(&body).nodes[0];
        assert_eq!((n.username.as_str(), n.password.as_str()), ("ivy", "pw"));
        assert_eq!(n.port, 443);
        assert_eq!(n.name, "h.example:443");
    }

    #[test]
    fn a_json_subscription_without_masque_says_why_nothing_came() {
        let body = serde_json::json!([{
            "remarks": "v",
            "outbounds": [{ "protocol": "vless" }, { "protocol": "trojan" }, { "protocol": "freedom" }]
        }])
        .to_string();
        let report = parse_subscription(&body);
        assert!(report.nodes.is_empty());
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].1.contains("vless, trojan"), "{:?}", report.errors);
    }

    #[test]
    fn a_masque_outbound_over_reality_is_refused() {
        let body = json_subscription().replace("\"security\":\"tls\"", "\"security\":\"reality\"");
        let report = parse_subscription(&body);
        assert!(report.nodes.is_empty());
        assert!(report.errors[0].1.contains("REALITY"), "{:?}", report.errors);
    }

    #[test]
    fn reserved_is_taken_either_as_bytes_or_as_the_client_id_behind_them() {
        assert_eq!(parse_reserved("1,2,3"), vec![1, 2, 3]);
        assert_eq!(parse_reserved("ve/E"), vec![189, 239, 196]);
        // Неверная длина отбрасывается: массив не из трёх байт заставит ядро
        // отвергнуть весь документ, а пустой просто означает «без метки».
        assert!(parse_reserved("1,2").is_empty());
        assert!(parse_reserved("").is_empty());
    }
}
