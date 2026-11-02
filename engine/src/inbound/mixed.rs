//! Вход `mixed`: SOCKS5 и HTTP-прокси на одном порту. Системный прокси Windows и
//! приложения с явной настройкой приходят сюда.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::common::{invalid, BoxStream, Target};
use crate::config::{InboundOpts, UserOpts};
use crate::engine::Context;
use crate::router::Meta;

pub async fn serve(opts: &InboundOpts, ctx: Arc<Context>) -> io::Result<()> {
    let host = if opts.listen.is_empty() { "127.0.0.1" } else { &opts.listen };
    let listener = TcpListener::bind((host, opts.listen_port)).await?;
    crate::info!("inbound", "mixed слушает {host}:{}", opts.listen_port);
    let inbound = Arc::new(Inbound { tag: opts.tag.clone(), users: opts.users.clone() });
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else { continue };
            let ctx = ctx.clone();
            let inbound = inbound.clone();
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                if let Err(e) = handle(stream, peer, ctx, &inbound).await {
                    crate::debug!("inbound", "{peer}: {e}");
                }
            });
        }
    });
    Ok(())
}

/// Тег входа и его пользователи. Без пользователей вход открыт, как раньше.
struct Inbound {
    tag: String,
    users: Vec<UserOpts>,
}

impl Inbound {
    fn allows(&self, username: &[u8], password: &[u8]) -> bool {
        self.users.iter().any(|u| u.username.as_bytes() == username && u.password.as_bytes() == password)
    }

    /// `Proxy-Authorization: Basic base64(логин:пароль)`.
    fn allows_basic(&self, header: Option<&str>) -> bool {
        use base64::Engine;
        let Some(encoded) = header.and_then(|h| h.trim().strip_prefix("Basic ").or_else(|| h.trim().strip_prefix("basic "))) else {
            return false;
        };
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else { return false };
        let Some(colon) = raw.iter().position(|b| *b == b':') else { return false };
        self.allows(&raw[..colon], &raw[colon + 1..])
    }
}

async fn handle(stream: TcpStream, peer: SocketAddr, ctx: Arc<Context>, inbound: &Inbound) -> io::Result<()> {
    let mut first = [0u8; 1];
    stream.peek(&mut first).await?;
    if first[0] == 5 {
        socks5(stream, peer, ctx, inbound).await
    } else {
        http(stream, peer, ctx, inbound).await
    }
}

fn meta(peer: SocketAddr, target: Target, inbound: &str) -> Meta {
    Meta {
        network: "tcp",
        inbound: (!inbound.is_empty()).then(|| inbound.to_string()),
        source: Some(peer),
        domain: target.domain().map(str::to_string),
        destination: Some(target),
        ..Default::default()
    }
}

async fn socks5(mut stream: TcpStream, peer: SocketAddr, ctx: Arc<Context>, inbound: &Inbound) -> io::Result<()> {
    let tag = inbound.tag.as_str();
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    if inbound.users.is_empty() {
        stream.write_all(&[5, 0]).await?;
    } else {
        // RFC 1929: логин и пароль. Клиент без этого метода не пройдёт.
        if !methods.contains(&2) {
            stream.write_all(&[5, 0xff]).await?;
            return Err(invalid("socks: клиент не предлагает вход по паролю"));
        }
        stream.write_all(&[5, 2]).await?;
        let mut ver_len = [0u8; 2];
        stream.read_exact(&mut ver_len).await?;
        let mut username = vec![0u8; ver_len[1] as usize];
        stream.read_exact(&mut username).await?;
        let mut password = vec![0u8; stream.read_u8().await? as usize];
        stream.read_exact(&mut password).await?;
        if !inbound.allows(&username, &password) {
            stream.write_all(&[1, 1]).await?;
            return Err(invalid("socks: неверный логин или пароль"));
        }
        stream.write_all(&[1, 0]).await?;
    }

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    let target = read_socks_target(&mut stream, req[3]).await?;
    match req[1] {
        1 => {
            stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let client: BoxStream = Box::new(stream);
            ctx.handle_tcp(client, meta(peer, target, tag), false).await;
            Ok(())
        }
        3 => udp_associate(stream, peer, ctx, tag).await,
        _ => {
            stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            Ok(())
        }
    }
}

async fn read_socks_target(stream: &mut TcpStream, atyp: u8) -> io::Result<Target> {
    let mut raw = vec![atyp];
    match atyp {
        1 => raw.resize(1 + 4 + 2, 0),
        4 => raw.resize(1 + 16 + 2, 0),
        3 => {
            let len = stream.read_u8().await?;
            raw.push(len);
            raw.resize(2 + len as usize + 2, 0);
        }
        _ => return Err(invalid("socks: тип адреса")),
    }
    let start = if atyp == 3 { 2 } else { 1 };
    stream.read_exact(&mut raw[start..]).await?;
    Target::read_socks(&raw).map(|(t, _)| t).ok_or_else(|| invalid("socks: адрес"))
}

/// UDP ASSOCIATE: одна клиентская точка и по сессии на адрес назначения.
async fn udp_associate(mut control: TcpStream, peer: SocketAddr, ctx: Arc<Context>, tag: &str) -> io::Result<()> {
    let local = control.local_addr()?;
    let socket = Arc::new(UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await?);
    let bound = socket.local_addr()?;
    let mut reply = vec![5, 0, 0];
    Target::from_addr(bound).write_socks(&mut reply);
    control.write_all(&reply).await?;

    let relay = async {
        let mut sessions: std::collections::HashMap<Target, Arc<dyn crate::common::PacketConn>> = Default::default();
        let mut guards = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        // Порт ассоциации увидит любой процесс на этой машине: служим только
        // тому, кто написал первым, — это клиент, получивший ответ на TCP.
        let mut owner: Option<SocketAddr> = None;
        loop {
            let (n, client) = socket.recv_from(&mut buf).await?;
            if n < 4 || buf[2] != 0 || owner.is_some_and(|o| o != client) {
                continue;
            }
            owner = Some(client);
            let Some((target, used)) = Target::read_socks(&buf[3..n]) else { continue };
            let payload = &buf[3 + used..n];
            if let Some(conn) = sessions.get(&target) {
                let _ = conn.send(payload, &target).await;
                continue;
            }
            let mut m = meta(peer, target.clone(), tag);
            m.network = "udp";
            let crate::engine::UdpOpen::Session(route) = ctx.open_udp(payload, &mut m).await else { continue };
            let conn = route.conn.clone();
            guards.push(route.guard);
            let _ = conn.send(payload, &target).await;
            sessions.insert(target, conn.clone());
            let socket = socket.clone();
            tokio::spawn(async move {
                let mut down = vec![0u8; 64 * 1024];
                while let Ok((len, from)) = conn.recv(&mut down).await {
                    let mut packet = vec![0, 0, 0];
                    from.write_socks(&mut packet);
                    packet.extend_from_slice(&down[..len]);
                    if socket.send_to(&packet, client).await.is_err() {
                        break;
                    }
                }
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };

    // Ассоциация живёт, пока жив управляющий TCP (RFC 1928).
    let mut sink = [0u8; 1];
    tokio::select! {
        _ = control.read(&mut sink) => Ok(()),
        result = relay => result,
    }
}

async fn http(mut stream: TcpStream, peer: SocketAddr, ctx: Arc<Context>, inbound: &Inbound) -> io::Result<()> {
    let tag = inbound.tag.as_str();
    let mut buf = vec![0u8; 8192];
    let mut filled = 0;
    let head_end = loop {
        let n = stream.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Ok(());
        }
        filled += n;
        if let Some(pos) = buf[..filled].windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if filled == buf.len() {
            stream.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n").await?;
            return Ok(());
        }
    };

    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| invalid("http: заголовок не UTF-8"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let (method, uri, version) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or("HTTP/1.1"));
    if !inbound.users.is_empty() {
        let auth = head
            .split("\r\n")
            .find_map(|line| line.split_once(':').filter(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization")))
            .map(|(_, value)| value);
        if !inbound.allows_basic(auth) {
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = uri.rsplit_once(':') else {
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
            return Ok(());
        };
        let target = Target::new(host, port.parse().unwrap_or(443));
        stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
        let leftover = buf[head_end..filled].to_vec();
        let client: BoxStream = Box::new(Prefixed::new(stream, leftover));
        ctx.handle_tcp(client, meta(peer, target, tag), false).await;
        return Ok(());
    }

    // Обычный прокси-запрос: абсолютный URI превращаем в путь, хоп-заголовки убираем.
    let Some(rest) = uri.strip_prefix("http://") else {
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
        return Ok(());
    };
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => (h, p.parse().unwrap_or(80)),
        _ => (authority, 80),
    };
    let target = Target::new(host, port);

    let mut rewritten = format!("{method} {path} {version}\r\n");
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if line.is_empty() || lower.starts_with("proxy-connection:") || lower.starts_with("proxy-authorization:") {
            continue;
        }
        rewritten.push_str(line);
        rewritten.push_str("\r\n");
    }
    rewritten.push_str("\r\n");
    let mut prefix = rewritten.into_bytes();
    prefix.extend_from_slice(&buf[head_end..filled]);
    let client: BoxStream = Box::new(Prefixed::new(stream, prefix));
    ctx.handle_tcp(client, meta(peer, target, tag), false).await;
    Ok(())
}

/// Поток, которому «вернули» уже прочитанное. Чтение отдаёт `head` первым.
struct Prefixed {
    io: TcpStream,
    head: Vec<u8>,
    pos: usize,
}

impl Prefixed {
    fn new(io: TcpStream, head: Vec<u8>) -> Self {
        Self { io, head, pos: 0 }
    }
}

impl tokio::io::AsyncRead for Prefixed {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if self.pos < self.head.len() {
            let n = buf.remaining().min(self.head.len() - self.pos);
            let pos = self.pos;
            buf.put_slice(&self.head[pos..pos + n]);
            self.pos += n;
            if self.pos == self.head.len() {
                self.head = Vec::new();
                self.pos = 0;
            }
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Prefixed {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, data)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
