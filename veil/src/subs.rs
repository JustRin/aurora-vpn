//! Подписки 3x-ui с Veil внутри.
//!
//! 3x-ui про Veil не знает, поэтому veil-server встаёт посредником: забирает у
//! панели подписку клиента по его subId, дописывает в неё ссылку `veil://` и
//! отдаёт с теми же заголовками (трафик, срок, интервал обновления). Пароль
//! Veil выводится из subId и секрета сервера, так что вносить людей в конфиг
//! Veil не нужно. Источник правды — панель: отключили клиента или кончился
//! срок — 3x-ui перестаёт отдавать его подписку, и при следующей сверке доступ
//! к Veil снимается сам.
//!
//! К панели ходим обычным HTTP: сервер остаётся на чистом Rust. Если подписка
//! 3x-ui сама на TLS, мостом служит Caddy (см. deploy/).

use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Больше подписка не бывает; лишнее — повод не доверять ответу.
const MAX_BODY: usize = 2 * 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Заголовки панели, которые клиенту важны: трафик и срок, интервал, имя.
const PASS_HEADERS: [&str; 11] = [
    "content-type",
    "subscription-userinfo",
    "profile-update-interval",
    "profile-title",
    "profile-web-page-url",
    "support-url",
    "content-disposition",
    "routing-enable",
    "cache-control",
    "expires",
    "pragma",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SubConfig {
    /// Подписка 3x-ui по HTTP, без subId на конце: `http://127.0.0.1:2097/subs/`.
    pub upstream: String,
    /// Путь, по которому клиенты приходят за подпиской (через Caddy).
    pub prefix: String,
    /// Секрет, из которого выводятся пароли Veil. Сменить — отозвать всех.
    pub secret: String,
    /// Адрес сервера в ссылке `veil://`: домен сайта.
    pub host: String,
    pub port: u16,
    /// Имя узла в клиенте.
    pub remark: String,
    /// Где помнить subId, которым уже выдан Veil.
    pub state_file: String,
    /// Кому дописывать Veil: подстроки User-Agent. Сторонние клиенты (Happ,
    /// v2rayNG) не знают `veil://` и получают подписку панели как есть.
    /// Пусто — всем.
    pub clients: Vec<String>,
}

impl Default for SubConfig {
    fn default() -> Self {
        Self {
            upstream: "http://127.0.0.1:2097/subs/".to_string(),
            prefix: "/subs/".to_string(),
            secret: String::new(),
            host: String::new(),
            port: 443,
            remark: "Veil".to_string(),
            state_file: "/var/lib/veil/subs.json".to_string(),
            clients: vec!["Aurora-VPN".to_string()],
        }
    }
}

impl SubConfig {
    pub fn wants_veil(&self, user_agent: Option<&str>) -> bool {
        self.clients.is_empty() || user_agent.is_some_and(|ua| self.clients.iter().any(|c| ua.contains(c.as_str())))
    }
}

/// Пароль Veil клиента с этим subId.
pub fn password(secret: &str, sub_id: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC принимает любой ключ");
    mac.update(b"veil-sub:");
    mac.update(sub_id.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// subId из 3x-ui: буквы, цифры, `-` и `_`. Всё прочее — не к панели.
pub fn valid_sub_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn percent(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn link(cfg: &SubConfig, tunnel_path: &str, sub_id: &str) -> String {
    format!(
        "veil://{}@{}:{}?path={}&sni={}&fp=chrome#{}",
        password(&cfg.secret, sub_id),
        cfg.host,
        cfg.port,
        percent(tunnel_path),
        cfg.host,
        percent(&cfg.remark)
    )
}

/// Дописать ссылку в подписку, сохранив её вид: base64 остаётся base64.
pub fn merge(body: &[u8], link: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let decoded = STANDARD
        .decode(&compact)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(compact.trim_end_matches('=')))
        .ok()
        .and_then(|raw| String::from_utf8(raw).ok())
        .filter(|plain| plain.contains("://"));
    let (lines, encoded) = match decoded {
        Some(plain) => (plain, true),
        None => (text.into_owned(), false),
    };
    let mut out = lines.trim_end_matches(['\n', '\r']).to_string();
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(link);
    if encoded {
        STANDARD.encode(out).into_bytes()
    } else {
        out.into_bytes()
    }
}

pub struct Fetched {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Fetched {
    /// Панель признаёт этот subId: есть что отдать.
    pub fn alive(&self) -> bool {
        self.status == 200 && !self.body.iter().all(u8::is_ascii_whitespace)
    }
}

struct Target {
    host: String,
    port: u16,
    path: String,
}

fn parse_upstream(url: &str) -> io::Result<Target> {
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, format!("подписка: нужен http://хост:порт/путь/, а не {url}"));
    let rest = url.strip_prefix("http://").ok_or_else(bad)?;
    let (authority, path) = rest.split_once('/').map(|(a, p)| (a, format!("/{p}"))).unwrap_or((rest, "/".to_string()));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().map_err(|_| bad())?),
        None => (authority.to_string(), 80),
    };
    Ok(Target { host, port, path })
}

/// Забрать подписку subId у панели. `user_agent` передаём как есть: 3x-ui
/// выбирает формат ответа по нему.
pub async fn fetch(cfg: &SubConfig, sub_id: &str, user_agent: Option<&str>) -> io::Result<Fetched> {
    let target = parse_upstream(&cfg.upstream)?;
    let request = format!(
        "GET {}{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        target.path,
        sub_id,
        if cfg.host.is_empty() { &target.host } else { &cfg.host },
        user_agent.unwrap_or("veil-server")
    );
    let raw = timeout(FETCH_TIMEOUT, async {
        let mut tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
        tcp.write_all(request.as_bytes()).await?;
        let mut raw = Vec::with_capacity(4096);
        let mut limited = (&mut tcp).take(MAX_BODY as u64 + 64 * 1024);
        limited.read_to_end(&mut raw).await?;
        Ok::<_, io::Error>(raw)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "подписка: панель не ответила"))??;
    parse_response(&raw).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "подписка: ответ панели не разобрать"))
}

fn parse_response(raw: &[u8]) -> Option<Fetched> {
    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let mut headers = Vec::new();
    let mut chunked = false;
    let mut length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim().to_string());
        if name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
        if name == "content-length" {
            length = value.parse::<usize>().ok();
        }
        headers.push((name, value));
    }
    let rest = &raw[head_end + 4..];
    let body = if chunked {
        let mut body = Vec::new();
        let mut i = 0;
        loop {
            let line_end = i + rest.get(i..)?.windows(2).position(|w| w == b"\r\n")?;
            let size = usize::from_str_radix(std::str::from_utf8(&rest[i..line_end]).ok()?.split(';').next()?.trim(), 16).ok()?;
            i = line_end + 2;
            if size == 0 {
                break;
            }
            body.extend_from_slice(rest.get(i..i + size)?);
            i += size + 2;
        }
        body
    } else {
        match length {
            Some(n) => rest.get(..n)?.to_vec(),
            None => rest.to_vec(),
        }
    };
    if body.len() > MAX_BODY {
        return None;
    }
    Some(Fetched { status, headers, body })
}

/// Заголовки ответа клиенту: только то, что ему нужно, в нижнем регистре (h2).
pub fn passed_headers(fetched: &Fetched) -> impl Iterator<Item = &(String, String)> {
    fetched.headers.iter().filter(|(name, _)| PASS_HEADERS.contains(&name.as_str()))
}

#[derive(Default, Serialize, Deserialize)]
struct Stored {
    subs: BTreeSet<String>,
}

pub fn load_known(path: &str) -> BTreeSet<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Stored>(&text).ok())
        .map(|s| s.subs.into_iter().filter(|id| valid_sub_id(id)).collect())
        .unwrap_or_default()
}

pub fn save_known(path: &str, subs: &BTreeSet<String>) -> io::Result<()> {
    let text = serde_json::to_string_pretty(&Stored { subs: subs.clone() }).map_err(io::Error::other)?;
    if let Some(dir) = Path::new(path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_keeps_the_encoding() {
        let link = "veil://pw@example.com:443?path=%2Fx#Veil";
        let plain = b"vless://a@b:1#x\nhysteria2://c@d:2#y\n";
        let merged = merge(&STANDARD.encode(plain).into_bytes(), link);
        let back = String::from_utf8(STANDARD.decode(merged).unwrap()).unwrap();
        assert_eq!(back.lines().collect::<Vec<_>>(), ["vless://a@b:1#x", "hysteria2://c@d:2#y", link]);
        let merged = merge(plain, link);
        assert!(String::from_utf8(merged).unwrap().ends_with(&format!("hysteria2://c@d:2#y\n{link}")));
        assert_eq!(merge(b"", link), link.as_bytes());
    }

    #[test]
    fn passwords_are_stable_and_distinct() {
        assert_eq!(password("s", "abc"), password("s", "abc"));
        assert_ne!(password("s", "abc"), password("s", "abd"));
        assert_ne!(password("s", "abc"), password("t", "abc"));
    }

    #[test]
    fn sub_ids_are_checked() {
        assert!(valid_sub_id("k3x9q_A-1"));
        for bad in ["", "../etc", "a/b", "a b", &"x".repeat(65)] {
            assert!(!valid_sub_id(bad), "{bad}");
        }
    }

    #[test]
    fn responses_parse() {
        let raw = b"HTTP/1.1 200 OK\r\nSubscription-Userinfo: upload=1; download=2; total=0; expire=0\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let f = parse_response(raw).unwrap();
        assert_eq!(f.status, 200);
        assert_eq!(f.body, b"hello");
        assert!(passed_headers(&f).any(|(n, _)| n == "subscription-userinfo"));
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked).unwrap().body, b"abcde");
        let gone = parse_response(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert!(!gone.alive());
        assert_eq!(parse_upstream("http://127.0.0.1:2097/subs/").unwrap().port, 2097);
        assert!(parse_upstream("https://x/").is_err());
    }
}
