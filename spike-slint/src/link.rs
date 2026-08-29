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
pub fn parse_subscription(body: &str) -> ParseReport {
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
}
