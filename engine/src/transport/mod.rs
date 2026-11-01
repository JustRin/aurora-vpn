//! Путь до сервера: TCP → TLS/REALITY → WebSocket или HTTP Upgrade.

pub mod ws;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::{other, tcp_connect, BoxStream};
use crate::config::{OutboundOpts, TlsOpts, TransportOpts};
use crate::tls::{self, retry_reason, RealityConfig, Retry, Tls13Stream, TlsConfig};

#[derive(Clone)]
pub enum Transport {
    Tcp,
    Ws(ws::WsOptions),
    HttpUpgrade(ws::WsOptions),
}

pub struct Upstream {
    pub server: String,
    pub port: u16,
    pub tls: Option<TlsConfig>,
    pub transport: Transport,
}

fn decode_public_key(text: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    let trimmed = text.trim().trim_end_matches('=');
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .ok()?;
    raw.try_into().ok()
}

fn decode_short_id(text: &str) -> Option<[u8; 8]> {
    let hex = text.trim();
    if hex.len() > 16 || hex.len() % 2 != 0 {
        return None;
    }
    let mut out = [0u8; 8];
    for i in 0..hex.len() / 2 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn tls_config(opts: &TlsOpts, server: &str, default_alpn: &[&str]) -> Result<TlsConfig, String> {
    let reality = match &opts.reality {
        Some(r) if r.enabled => Some(RealityConfig {
            public_key: decode_public_key(&r.public_key).ok_or("reality: неверный public_key")?,
            short_id: decode_short_id(&r.short_id).ok_or("reality: неверный short_id")?,
            post_quantum: Default::default(),
        }),
        _ => None,
    };
    let sni = if opts.server_name.is_empty() { server.to_string() } else { opts.server_name.clone() };
    let alpn = if opts.alpn.is_empty() {
        default_alpn.iter().map(|a| a.to_string()).collect()
    } else {
        opts.alpn.clone()
    };
    Ok(TlsConfig {
        sni,
        alpn,
        insecure: opts.insecure,
        fingerprint: opts.utls.as_ref().filter(|u| u.enabled).map(|u| u.fingerprint.clone()).unwrap_or_default(),
        reality,
    })
}

fn header_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(items) => items.iter().find_map(header_value),
        _ => None,
    }
}

fn parse_transport(opts: &TransportOpts) -> Result<Transport, String> {
    let mut headers = Vec::new();
    let mut host = header_value(&opts.host).unwrap_or_default();
    for (name, value) in &opts.headers {
        let Some(value) = header_value(value) else { continue };
        if name.eq_ignore_ascii_case("host") {
            host = value;
        } else {
            headers.push((name.clone(), value));
        }
    }
    let path = if opts.path.is_empty() { "/".to_string() } else { opts.path.clone() };
    let options = ws::WsOptions { path, host, headers };
    match opts.kind.as_str() {
        "ws" => Ok(Transport::Ws(options)),
        "httpupgrade" => Ok(Transport::HttpUpgrade(options)),
        other => Err(format!("транспорт {other} пока не поддержан")),
    }
}

impl Upstream {
    pub fn from_opts(o: &OutboundOpts) -> Result<Self, String> {
        let transport = match &o.transport {
            Some(t) => parse_transport(t)?,
            None => Transport::Tcp,
        };
        // Поверх TLS WebSocket обязан договориться о http/1.1: на h2 сервер не
        // ответит 101. Так же поступает sing-box.
        let default_alpn: &[&str] = match transport {
            Transport::Tcp => &[],
            _ => &["http/1.1"],
        };
        let tls = match &o.tls {
            Some(t) if t.enabled => Some(tls_config(t, &o.server, default_alpn)?),
            _ => None,
        };
        if o.multiplex.as_ref().is_some_and(|m| m["enabled"].as_bool().unwrap_or(false)) {
            return Err("multiplex пока не поддержан".to_string());
        }
        Ok(Self { server: o.server.clone(), port: o.server_port, tls, transport })
    }

    pub async fn addrs(&self) -> io::Result<Vec<SocketAddr>> {
        crate::dns::resolve_server(&self.server, self.port).await
    }

    async fn tcp(&self) -> io::Result<BoxStream> {
        let mut last = None;
        for addr in self.addrs().await?.into_iter().take(3) {
            match tcp_connect(addr).await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| other(format!("{}: нет адресов", self.server))))
    }

    /// TLS-слой с повторным дозвоном по двум известным поводам: отказ короткому
    /// hello у REALITY и сервер без TLS 1.3.
    async fn tls_layer(&self, cfg: &TlsConfig) -> io::Result<BoxStream> {
        let mut attempt = 0;
        loop {
            let tcp = self.tcp().await?;
            match tls::handshake(tcp, cfg).await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(e) => match retry_reason(&e) {
                    Some(Retry::RealityWantsPostQuantum) if attempt == 0 => {
                        crate::info!("tls", "{}: сервер требует X25519MLKEM768, повторяю с длинным hello", self.server);
                        attempt += 1;
                    }
                    Some(Retry::NeedTls12) if cfg.reality.is_none() => {
                        let tcp = self.tcp().await?;
                        return tls::connect_rustls(tcp, cfg).await;
                    }
                    _ => return Err(e),
                },
            }
        }
    }

    pub async fn open(&self) -> io::Result<BoxStream> {
        let base = match &self.tls {
            Some(cfg) => self.tls_layer(cfg).await?,
            None => self.tcp().await?,
        };
        match &self.transport {
            Transport::Tcp => Ok(base),
            Transport::Ws(options) => ws::connect(base, options, &self.server, false).await,
            Transport::HttpUpgrade(options) => ws::connect(base, options, &self.server, true).await,
        }
    }

    /// Для Vision: нужен наш поток с доступом к сырому сокету.
    pub async fn open_tls13(&self) -> io::Result<Tls13Stream> {
        let cfg = self.tls.as_ref().ok_or_else(|| other("vision требует TLS"))?;
        let mut attempt = 0;
        loop {
            let tcp = self.tcp().await?;
            match tls::handshake(tcp, cfg).await {
                Ok(stream) => return Ok(stream),
                Err(e) => match retry_reason(&e) {
                    Some(Retry::RealityWantsPostQuantum) if attempt == 0 => {
                        crate::info!("tls", "{}: сервер требует X25519MLKEM768, повторяю с длинным hello", self.server);
                        attempt += 1;
                    }
                    _ => return Err(e),
                },
            }
        }
    }
}

/// Откладывает `pending` до первой записи и отправляет их одним куском с данными:
/// заголовок протокола и начало полезной нагрузки идут в одной TLS-записи.
pub struct EarlyWrite<S> {
    pub io: S,
    pending: Vec<u8>,
    pos: usize,
}

impl<S> EarlyWrite<S> {
    pub fn new(io: S, head: Vec<u8>) -> Self {
        Self { io, pending: head, pos: 0 }
    }
}

impl<S: AsyncWrite + Unpin> EarlyWrite<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pos < self.pending.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.pending[self.pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pos += n;
        }
        if !self.pending.is_empty() {
            self.pending = Vec::new();
            self.pos = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for EarlyWrite<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // Сервер заговорит первым только после заголовка — нельзя ждать его молча.
        if !self.pending.is_empty() {
            if let Poll::Ready(Err(e)) = self.poll_drain(cx) {
                return Poll::Ready(Err(e));
            }
            if self.pending.is_empty() {
                ready!(Pin::new(&mut self.io).poll_flush(cx))?;
            }
        }
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EarlyWrite<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if !self.pending.is_empty() {
            // Приняли данные в тот же кусок: дальше их допишет сток.
            if self.pos == 0 {
                self.pending.extend_from_slice(data);
                if let Poll::Ready(Err(e)) = self.poll_drain(cx) {
                    return Poll::Ready(Err(e));
                }
                return Poll::Ready(Ok(data.len()));
            }
            ready!(self.poll_drain(cx))?;
        }
        Pin::new(&mut self.io).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Для `dial_udp`: половины потока, у каждой свой замок.
pub struct Halves {
    pub read: tokio::sync::Mutex<tokio::io::ReadHalf<BoxStream>>,
    pub write: tokio::sync::Mutex<tokio::io::WriteHalf<BoxStream>>,
}

impl Halves {
    pub fn new(stream: BoxStream) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self { read: tokio::sync::Mutex::new(read), write: tokio::sync::Mutex::new(write) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_keys() {
        assert!(decode_public_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_some());
        assert!(decode_public_key("short").is_none());
        assert_eq!(decode_short_id("ab").unwrap()[0], 0xab);
        assert_eq!(decode_short_id("").unwrap(), [0; 8]);
        assert!(decode_short_id("abc").is_none());
        assert!(decode_short_id("00112233445566778899").is_none());
    }
}
