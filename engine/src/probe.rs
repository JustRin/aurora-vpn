//! Замер задержки узла: HTTP(S)-запрос через него, как `/proxies/<tag>/delay`.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{invalid, other, BoxStream, Target};
use crate::engine::Context;
use crate::tls::TlsConfig;

struct ProbeUrl {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> Option<ProbeUrl> {
    let (scheme, rest) = url.split_once("://")?;
    let https = match scheme.to_ascii_lowercase().as_str() {
        "https" => true,
        "http" => false,
        _ => return None,
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => (h, p.parse().ok()?),
        _ => (authority, if https { 443 } else { 80 }),
    };
    (!host.is_empty()).then(|| ProbeUrl { https, host: host.to_string(), port, path: path.to_string() })
}

async fn request(stream: &mut BoxStream, url: &ProbeUrl) -> io::Result<u16> {
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.path, url.host
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    let mut head = [0u8; 32];
    let mut filled = 0;
    while filled < 12 {
        let n = stream.read(&mut head[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    let text = String::from_utf8_lossy(&head[..filled]);
    text.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| invalid("замер: не HTTP-ответ"))
}

pub async fn delay(ctx: &Arc<Context>, tag: &str, url: &str, timeout_ms: u32) -> io::Result<u32> {
    let url = parse_url(url).ok_or_else(|| other("замер: неверный адрес"))?;
    let (leaf, _) = ctx.outbounds.leaf(tag).ok_or_else(|| other(format!("нет исходящего {tag}")))?;
    let target = Target::new(&url.host, url.port);
    let work = async {
        let stream = leaf.dial(&target).await?;
        // Секундомер — после дозвона, как у sing-box: рукопожатие с самим узлом в
        // число не входит. На этой шкале настроены пороги балансировщика.
        let started = Instant::now();
        let mut stream: BoxStream = if url.https {
            let cfg = TlsConfig {
                sni: url.host.clone(),
                alpn: vec!["http/1.1".to_string()],
                insecure: false,
                fingerprint: "chrome".to_string(),
                reality: None,
            };
            Box::new(crate::tls::handshake(stream, &cfg).await?)
        } else {
            stream
        };
        let status = request(&mut stream, &url).await?;
        if status >= 500 {
            return Err(other(format!("замер: HTTP {status}")));
        }
        Ok(started.elapsed().as_millis().max(1) as u32)
    };
    tokio::time::timeout(Duration::from_millis(u64::from(timeout_ms)), work)
        .await
        .map_err(|_| other("таймаут"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("https://www.gstatic.com/generate_204").unwrap();
        assert!(u.https);
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("www.gstatic.com", 443, "/generate_204"));
        let u = parse_url("http://example.com:8080").unwrap();
        assert!(!u.https);
        assert_eq!((u.port, u.path.as_str()), (8080, "/"));
        assert!(parse_url("ftp://x").is_none());
        assert!(parse_url("nonsense").is_none());
    }
}
