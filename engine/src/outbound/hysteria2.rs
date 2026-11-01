//! Hysteria2: QUIC, вход через HTTP/3, потоки на TCP и датаграммы на UDP.
//!
//! Одно QUIC-соединение на узел. Узел, через который ничего не идёт (его только
//! что померили), закрывается по простою: иначе keep-alive сотни померянных узлов
//! будил бы процесс непрерывно.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::Outbound;
use crate::common::{invalid, other, udp_std_socket, BoxStream, PacketConn, Target};
use crate::config::OutboundOpts;
use crate::tls::rustls_config;

const FRAME_TCP_REQUEST: u64 = 0x401;
const AUTH_OK: u16 = 233;
const IDLE_CLOSE: Duration = Duration::from_secs(60);
const UDP_BUFFER: usize = 4 * 1024 * 1024;

fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

fn read_varint_slice(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let len = 1usize << (first >> 6);
    let raw = data.get(..len)?;
    let mut v = u64::from(first & 0x3f);
    for b in &raw[1..] {
        v = (v << 8) | u64::from(*b);
    }
    Some((v, len))
}

/// Случайная набивка в служебных полях: у настоящего клиента она всегда есть.
fn padding(len: std::ops::Range<usize>) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n = rng.gen_range(len);
    (0..n).map(|_| rng.gen_range(b'a'..=b'z') as char).collect()
}

fn encode_tcp_request(target: &str) -> Vec<u8> {
    let pad = padding(64..512);
    let mut out = Vec::with_capacity(target.len() + pad.len() + 16);
    write_varint(&mut out, FRAME_TCP_REQUEST);
    write_varint(&mut out, target.len() as u64);
    out.extend_from_slice(target.as_bytes());
    write_varint(&mut out, pad.len() as u64);
    out.extend_from_slice(pad.as_bytes());
    out
}

type Sessions = Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>;

struct Live {
    conn: quinn::Connection,
    active: Arc<AtomicUsize>,
    sessions: Sessions,
    /// Закрытие отправителя завершило бы HTTP/3-сессию, а с ней и соединение.
    _http3: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    _endpoint: quinn::Endpoint,
}

pub struct Hysteria2 {
    tag: String,
    server: String,
    port: u16,
    password: String,
    sni: String,
    insecure: bool,
    alpn: Vec<String>,
    live: tokio::sync::Mutex<Option<Arc<Live>>>,
}

static NEXT_SESSION: AtomicU32 = AtomicU32::new(1);

impl Hysteria2 {
    pub fn new(o: &OutboundOpts) -> Result<Self, String> {
        if let Some(obfs) = &o.obfs {
            if !obfs.kind.is_empty() {
                return Err(format!("hysteria2: обфускация {} пока не поддержана", obfs.kind));
            }
        }
        let tls = o.tls.clone().unwrap_or_default();
        let sni = if tls.server_name.is_empty() { o.server.clone() } else { tls.server_name.clone() };
        let alpn = if tls.alpn.is_empty() { vec!["h3".to_string()] } else { tls.alpn.clone() };
        Ok(Self {
            tag: o.tag.clone(),
            server: o.server.clone(),
            port: o.server_port,
            password: o.password.clone(),
            sni,
            insecure: tls.insecure,
            alpn,
            live: tokio::sync::Mutex::new(None),
        })
    }

    async fn connect(&self) -> io::Result<Arc<Live>> {
        let addrs = crate::dns::resolve_server(&self.server, self.port).await?;
        let addr: SocketAddr = *addrs.first().ok_or_else(|| other("hysteria2: нет адреса"))?;

        let mut tls = rustls_config(self.insecure, &self.alpn).map_err(io::Error::other)?;
        tls.enable_early_data = false;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(io::Error::other)?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_idle_timeout(Some(Duration::from_secs(30).try_into().map_err(io::Error::other)?))
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .datagram_receive_buffer_size(Some(1 << 20))
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        client.transport_config(Arc::new(transport));

        let socket = udp_std_socket(addr.is_ipv6())?;
        // Системные 64 КБ переполняются уже на сотнях мегабит: потерянная датаграмма
        // для QUIC — сигнал затора, и скорость падает сама собой.
        let tuning = socket2::SockRef::from(&socket);
        let _ = tuning.set_recv_buffer_size(UDP_BUFFER);
        let _ = tuning.set_send_buffer_size(UDP_BUFFER);
        let runtime = quinn::default_runtime().ok_or_else(|| other("hysteria2: нет рантайма"))?;
        let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;
        let conn = tokio::time::timeout(
            crate::common::DIAL_TIMEOUT,
            endpoint.connect_with(client, addr, &self.sni).map_err(io::Error::other)?,
        )
        .await
        .map_err(|_| other("hysteria2: таймаут рукопожатия QUIC"))?
        .map_err(io::Error::other)?;

        let http3 = self.authenticate(&conn).await?;

        let sessions: Sessions = Default::default();
        let active = Arc::new(AtomicUsize::new(0));
        spawn_datagram_pump(conn.clone(), sessions.clone());
        spawn_idle_reaper(conn.clone(), active.clone());
        Ok(Arc::new(Live { conn, active, sessions, _http3: http3, _endpoint: endpoint }))
    }

    async fn authenticate(&self, conn: &quinn::Connection) -> io::Result<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>> {
        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(|e| other(format!("hysteria2: h3: {e}")))?;
        // Драйвер живёт вместе с соединением: он обслуживает служебные потоки HTTP/3.
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("hysteria-auth", self.password.as_str())
            .header("hysteria-cc-rx", "0")
            .header("hysteria-padding", padding(64..512))
            .body(())
            .map_err(io::Error::other)?;
        let mut stream = sender.send_request(request).await.map_err(|e| other(format!("hysteria2: запрос: {e}")))?;
        stream.finish().await.map_err(|e| other(format!("hysteria2: запрос: {e}")))?;
        let response = stream.recv_response().await.map_err(|e| other(format!("hysteria2: ответ: {e}")))?;
        if response.status().as_u16() != AUTH_OK {
            return Err(other(format!("hysteria2: сервер отказал во входе ({})", response.status())));
        }
        Ok(sender)
    }

    async fn live(&self) -> io::Result<Arc<Live>> {
        let mut slot = self.live.lock().await;
        if let Some(live) = &*slot {
            if live.conn.close_reason().is_none() {
                return Ok(live.clone());
            }
        }
        let live = self.connect().await?;
        *slot = Some(live.clone());
        Ok(live)
    }
}

fn spawn_idle_reaper(conn: quinn::Connection, active: Arc<AtomicUsize>) {
    tokio::spawn(async move {
        let mut idle = Duration::ZERO;
        const STEP: Duration = Duration::from_secs(15);
        loop {
            tokio::select! {
                _ = conn.closed() => return,
                _ = tokio::time::sleep(STEP) => {}
            }
            if active.load(Ordering::Relaxed) > 0 {
                idle = Duration::ZERO;
                continue;
            }
            idle += STEP;
            if idle >= IDLE_CLOSE {
                conn.close(0u32.into(), b"");
                return;
            }
        }
    });
}

fn spawn_datagram_pump(conn: quinn::Connection, sessions: Sessions) {
    tokio::spawn(async move {
        while let Ok(data) = conn.read_datagram().await {
            if data.len() < 8 {
                continue;
            }
            let id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let tx = sessions.lock().get(&id).cloned();
            if let Some(tx) = tx {
                let _ = tx.try_send(data);
            }
        }
    });
}

struct ActiveGuard(Arc<AtomicUsize>);

impl ActiveGuard {
    fn new(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter.clone())
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

struct Hy2Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// Начало ответа сервера, пока он не разобран целиком. `None` — разобран.
    head: Option<Vec<u8>>,
    /// Данные, пришедшие вместе с концом ответа.
    rest: Vec<u8>,
    rest_pos: usize,
    _guard: ActiveGuard,
}

/// Ответ на запрос: статус, сообщение, набивка. `Ok(None)` — пришёл не целиком.
fn parse_tcp_response(data: &[u8]) -> io::Result<Option<(u8, String, usize)>> {
    let Some(&status) = data.first() else { return Ok(None) };
    let Some((msg_len, used)) = read_varint_slice(&data[1..]) else { return Ok(None) };
    if msg_len > 4096 {
        return Err(invalid("hysteria2: длина сообщения"));
    }
    let msg_at = 1 + used;
    let Some(msg) = data.get(msg_at..msg_at + msg_len as usize) else { return Ok(None) };
    let pad_at = msg_at + msg_len as usize;
    let Some((pad_len, used)) = data.get(pad_at..).and_then(read_varint_slice) else { return Ok(None) };
    if pad_len > 8192 {
        return Err(invalid("hysteria2: длина набивки"));
    }
    let end = pad_at + used + pad_len as usize;
    if data.len() < end {
        return Ok(None);
    }
    Ok(Some((status, String::from_utf8_lossy(msg).into_owned(), end)))
}

impl AsyncRead for Hy2Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while let Some(head) = this.head.as_mut() {
            let mut chunk = [0u8; 1024];
            let mut read = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.recv).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            head.extend_from_slice(read.filled());
            if let Some((status, msg, end)) = parse_tcp_response(head)? {
                if status != 0 {
                    return Poll::Ready(Err(other(format!("hysteria2: {msg}"))));
                }
                this.rest = head[end..].to_vec();
                this.head = None;
            }
        }
        if this.rest_pos < this.rest.len() {
            let n = buf.remaining().min(this.rest.len() - this.rest_pos);
            buf.put_slice(&this.rest[this.rest_pos..this.rest_pos + n]);
            this.rest_pos += n;
            if this.rest_pos == this.rest.len() {
                this.rest = Vec::new();
                this.rest_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hy2Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, data).map_err(io::Error::from)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

#[async_trait]
impl Outbound for Hysteria2 {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "hysteria2"
    }

    async fn dial(&self, target: &Target) -> io::Result<BoxStream> {
        let live = self.live().await?;
        let guard = ActiveGuard::new(&live.active);
        let (mut send, recv) = live.conn.open_bi().await.map_err(io::Error::other)?;
        // Ответ не ждём: первые данные клиента идут следом за запросом, без лишнего
        // круга до сервера. Отказ сервера придёт при первом чтении.
        send.write_all(&encode_tcp_request(&target.to_string())).await?;
        Ok(Box::new(Hy2Stream { send, recv, head: Some(Vec::with_capacity(1024)), rest: Vec::new(), rest_pos: 0, _guard: guard }))
    }

    async fn dial_udp(&self, _: &Target) -> io::Result<Box<dyn PacketConn>> {
        let live = self.live().await?;
        let id = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(256);
        live.sessions.lock().insert(id, tx);
        let guard = ActiveGuard::new(&live.active);
        Ok(Box::new(Hy2Packet { live, id, rx: tokio::sync::Mutex::new(rx), packet_id: AtomicU32::new(0), _guard: guard }))
    }
}

struct Hy2Packet {
    live: Arc<Live>,
    id: u32,
    rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    packet_id: AtomicU32,
    _guard: ActiveGuard,
}

impl Drop for Hy2Packet {
    fn drop(&mut self) {
        self.live.sessions.lock().remove(&self.id);
    }
}

#[async_trait]
impl PacketConn for Hy2Packet {
    async fn send(&self, data: &[u8], to: &Target) -> io::Result<()> {
        let addr = to.to_string();
        let mut head = Vec::with_capacity(addr.len() + 16);
        head.extend_from_slice(&self.id.to_be_bytes());
        head.extend_from_slice(&[0, 0, 0, 1]); // id пакета, номер и число частей
        write_varint(&mut head, addr.len() as u64);
        head.extend_from_slice(addr.as_bytes());

        let max = self.live.conn.max_datagram_size().ok_or_else(|| other("hysteria2: сервер не принимает датаграммы"))?;
        if head.len() + data.len() <= max {
            let mut packet = head;
            packet.extend_from_slice(data);
            return self.live.conn.send_datagram(packet.into()).map_err(io::Error::other);
        }
        // Не лезет в датаграмму: режем (QUIC внутри QUIC упирается сюда регулярно).
        let room = max.saturating_sub(head.len());
        if room == 0 {
            return Err(other("hysteria2: адрес не помещается в датаграмму"));
        }
        let parts = data.len().div_ceil(room);
        if parts > 255 {
            return Err(other("hysteria2: пакет слишком велик"));
        }
        let packet_id = (self.packet_id.fetch_add(1, Ordering::Relaxed) % 0xffff + 1) as u16;
        for (i, part) in data.chunks(room).enumerate() {
            let mut packet = head.clone();
            packet[4..6].copy_from_slice(&packet_id.to_be_bytes());
            packet[6] = i as u8;
            packet[7] = parts as u8;
            packet.extend_from_slice(part);
            self.live.conn.send_datagram(packet.into()).map_err(io::Error::other)?;
        }
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let mut rx = self.rx.lock().await;
        // Сборка фрагментов: одна очередь, сервер шлёт их подряд.
        let mut assembling: Option<(u16, u8, Vec<Vec<u8>>, Target)> = None;
        loop {
            let data = rx.recv().await.ok_or(io::ErrorKind::UnexpectedEof)?;
            let packet_id = u16::from_be_bytes([data[4], data[5]]);
            let (index, count) = (data[6], data[7]);
            let Some((addr_len, used)) = read_varint_slice(&data[8..]) else { continue };
            let addr_at = 8 + used;
            let addr_end = addr_at + addr_len as usize;
            let Some(addr) = data.get(addr_at..addr_end).and_then(|a| std::str::from_utf8(a).ok()) else { continue };
            let Some((host, port)) = addr.rsplit_once(':') else { continue };
            let from = Target::new(host, port.parse().unwrap_or(0));
            let payload = &data[addr_end..];

            if count <= 1 {
                let n = payload.len().min(buf.len());
                buf[..n].copy_from_slice(&payload[..n]);
                return Ok((n, from));
            }
            let state = assembling.get_or_insert_with(|| (packet_id, count, vec![Vec::new(); count as usize], from.clone()));
            if state.0 != packet_id {
                *state = (packet_id, count, vec![Vec::new(); count as usize], from.clone());
            }
            if let Some(slot) = state.2.get_mut(index as usize) {
                *slot = payload.to_vec();
            }
            if state.2.iter().all(|p| !p.is_empty()) {
                let mut n = 0;
                for part in &state.2 {
                    let take = part.len().min(buf.len() - n);
                    buf[n..n + take].copy_from_slice(&part[..take]);
                    n += take;
                }
                return Ok((n, state.3.clone()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_roundtrip_on_every_width() {
        for v in [0u64, 63, 64, 16_383, 16_384, 1 << 29, 1 << 30, 1 << 40] {
            let mut out = Vec::new();
            write_varint(&mut out, v);
            assert_eq!(read_varint_slice(&out), Some((v, out.len())));
        }
        assert!(read_varint_slice(&[0x40]).is_none());
    }

    #[test]
    fn tcp_response_waits_for_all_its_parts() {
        let mut full = vec![0u8, 2];
        full.extend_from_slice(b"ok");
        full.push(3);
        full.extend_from_slice(b"pad");
        full.extend_from_slice(b"DATA");
        for cut in 0..full.len() - 4 {
            assert!(parse_tcp_response(&full[..cut]).unwrap().is_none(), "разрез {cut}");
        }
        let (status, msg, end) = parse_tcp_response(&full).unwrap().unwrap();
        assert_eq!((status, msg.as_str()), (0, "ok"));
        assert_eq!(&full[end..], b"DATA");
    }

    #[test]
    fn tcp_request_layout() {
        let req = encode_tcp_request("example.com:443");
        let (frame, used) = read_varint_slice(&req).unwrap();
        assert_eq!(frame, FRAME_TCP_REQUEST);
        let (len, n) = read_varint_slice(&req[used..]).unwrap();
        let at = used + n;
        assert_eq!(&req[at..at + len as usize], b"example.com:443");
    }
}
