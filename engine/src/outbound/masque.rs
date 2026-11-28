//! Исходящий MASQUE (RFC 9484 CONNECT-IP поверх HTTP/3 DATAGRAM и HTTP/2 Capsules).
//!
//! Совместим с сервером MASQUE в Xray-core:
//! - HTTP/3 Extended CONNECT (`:protocol = connect-ip`, `capsule-protocol: ?1`,
//!   QUIC DATAGRAM с четвертным ID потока и Context ID = 0);
//! - HTTP/2 Extended CONNECT (когда `tls.alpn` содержит `h2` и не содержит `h3`;
//!   IP-пакеты передаются в капсулах `DATAGRAM` типа 0);
//! - Basic Auth (`Authorization: Basic ...`) из `username`/`password`;
//! - обмен капсулами `ADDRESS_REQUEST` / `ADDRESS_ASSIGN` и клиентский TCP/UDP
//!   стек (`masque_tcp`) с разрешением имён через удалённый DNS внутри туннеля.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use http::{Method, Request};
use parking_lot::Mutex as SyncMutex;
use rand::Rng;
use tokio::sync::{mpsc, oneshot, Mutex};

use super::masque_tcp::{IpStack, MasqueUdpHandle};
use super::Outbound;
use crate::common::{invalid, other, udp_std_socket, BoxStream, PacketConn, Target};
use crate::config::OutboundOpts;
use crate::tls::{rustls_config, TlsConfig};
use crate::transport::{tls_config, Transport, Upstream};

pub const DEFAULT_PATH: &str = "/.well-known/masque/ip/*/*/";
const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

const CAPSULE_DATAGRAM: u64 = 0;
const CAPSULE_ADDRESS_ASSIGN: u64 = 1;
const CAPSULE_ADDRESS_REQUEST: u64 = 2;
const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 3;

const H3_FRAME_DATA: u64 = 0x00;
const H3_FRAME_HEADERS: u64 = 0x01;
const H3_FRAME_SETTINGS: u64 = 0x04;
const H3_SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const H3_SETTING_QPACK_BLOCKED_STREAMS: u64 = 0x07;
const H3_SETTING_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
const H3_SETTING_H3_DATAGRAM: u64 = 0x33;

const MIN_PACKET_SIZE: usize = 1280;
const UDP_BUFFER: usize = 8 * 1024 * 1024;
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

// ------------------------------------------------------------------ QUIC varint & капсулы RFC 9297 / 9484

fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v < (1 << 6) {
        out.push(v as u8);
    } else if v < (1 << 14) {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < (1 << 30) {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let len = 1usize << (first >> 6);
    let raw = data.get(..len)?;
    let mut v = u64::from(first & 0x3f);
    for &b in &raw[1..] {
        v = (v << 8) | u64::from(b);
    }
    Some((v, len))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Prefix {
    addr: IpAddr,
    bits: u8,
}

impl Prefix {
    fn is_rejected(&self) -> bool {
        self.bits == 0 && self.addr.is_unspecified()
    }

    fn host_addr(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(v4) => {
                if self.bits >= 32 {
                    IpAddr::V4(v4)
                } else {
                    let mask = if self.bits == 0 { 0 } else { !0u32 << (32 - self.bits) };
                    IpAddr::V4(Ipv4Addr::from((u32::from(v4) & mask).wrapping_add(1)))
                }
            }
            IpAddr::V6(v6) => {
                if self.bits >= 128 {
                    IpAddr::V6(v6)
                } else {
                    let mask = if self.bits == 0 { 0 } else { !0u128 << (128 - self.bits) };
                    IpAddr::V6(Ipv6Addr::from((u128::from(v6) & mask).wrapping_add(1)))
                }
            }
        }
    }
}

fn encode_address_request_capsule() -> Vec<u8> {
    let mut payload = Vec::with_capacity(32);
    // Request ID 1: 0.0.0.0/32
    write_varint(&mut payload, 1);
    payload.push(4);
    payload.extend_from_slice(&[0; 4]);
    payload.push(32);
    // Request ID 2: ::/128
    write_varint(&mut payload, 2);
    payload.push(6);
    payload.extend_from_slice(&[0; 16]);
    payload.push(128);

    let mut out = Vec::with_capacity(payload.len() + 4);
    write_varint(&mut out, CAPSULE_ADDRESS_REQUEST);
    write_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(&payload);
    out
}

fn encode_reject_address_assign(ids: &[(u64, bool)]) -> Vec<u8> {
    let mut payload = Vec::new();
    for &(req_id, is_v4) in ids {
        write_varint(&mut payload, req_id);
        if is_v4 {
            payload.push(4);
            payload.extend_from_slice(&[0; 4]);
            payload.push(0);
        } else {
            payload.push(6);
            payload.extend_from_slice(&[0; 16]);
            payload.push(0);
        }
    }
    let mut out = Vec::with_capacity(payload.len() + 4);
    write_varint(&mut out, CAPSULE_ADDRESS_ASSIGN);
    write_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(&payload);
    out
}

fn encode_datagram_capsule(ip_packet: &[u8]) -> Vec<u8> {
    let payload_len = 1 + ip_packet.len();
    let mut out = Vec::with_capacity(payload_len + 8);
    write_varint(&mut out, CAPSULE_DATAGRAM);
    write_varint(&mut out, payload_len as u64);
    out.push(0); // Context ID = 0
    out.extend_from_slice(ip_packet);
    out
}

fn parse_address_list(mut data: &[u8]) -> io::Result<Vec<(u64, Prefix)>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let (req_id, used) = read_varint(data).ok_or_else(|| invalid("masque: capsule request_id"))?;
        data = &data[used..];
        let &ver = data.first().ok_or_else(|| invalid("masque: capsule ip_version"))?;
        data = &data[1..];
        let (addr, need) = match ver {
            4 => {
                if data.len() < 5 {
                    return Err(invalid("masque: capsule ipv4"));
                }
                let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                (IpAddr::V4(ip), 4)
            }
            6 => {
                if data.len() < 17 {
                    return Err(invalid("masque: capsule ipv6"));
                }
                let arr: [u8; 16] = data[..16].try_into().unwrap();
                (IpAddr::V6(Ipv6Addr::from(arr)), 16)
            }
            _ => return Err(invalid(format!("masque: неизвестная версия IP {ver}"))),
        };
        let bits = data[need];
        data = &data[need + 1..];
        out.push((req_id, Prefix { addr, bits }));
    }
    Ok(out)
}

#[derive(Default)]
struct CapsuleDecoder {
    buf: Vec<u8>,
}

impl CapsuleDecoder {
    fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn next(&mut self) -> Option<(u64, Vec<u8>)> {
        let (ctype, u1) = read_varint(&self.buf)?;
        let (clen, u2) = read_varint(&self.buf[u1..])?;
        let head = u1 + u2;
        let clen = clen as usize;
        if self.buf.len() < head + clen {
            return None;
        }
        let payload = self.buf[head..head + clen].to_vec();
        self.buf.drain(..head + clen);
        Some((ctype, payload))
    }
}

/// Уменьшить TTL/Hop Limit перед отправкой в туннель CONNECT-IP (RFC 9484 §6).
fn prepare_outgoing_ip(mut pkt: Vec<u8>) -> Option<Vec<u8>> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 || pkt[8] <= 1 {
                return None;
            }
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            if ihl < 20 || ihl > pkt.len() {
                return None;
            }
            pkt[8] -= 1;
            pkt[10] = 0;
            pkt[11] = 0;
            let mut acc = 0u32;
            for pair in pkt[..ihl].chunks_exact(2) {
                acc += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
            }
            while acc >> 16 != 0 {
                acc = (acc & 0xffff) + (acc >> 16);
            }
            let csum = !(acc as u16);
            pkt[10..12].copy_from_slice(&csum.to_be_bytes());
            Some(pkt)
        }
        6 => {
            if pkt.len() < 40 || pkt[7] <= 1 {
                return None;
            }
            pkt[7] -= 1;
            Some(pkt)
        }
        _ => None,
    }
}

// ------------------------------------------------------------------ минимальный QPACK / HTTP/3 для CONNECT-IP

fn qpack_write_int(out: &mut Vec<u8>, prefix_bits: u8, prefix_mask: u8, mut val: usize) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if val < max_prefix {
        out.push(prefix_mask | (val as u8));
        return;
    }
    out.push(prefix_mask | (max_prefix as u8));
    val -= max_prefix;
    while val >= 128 {
        out.push(((val & 0x7f) as u8) | 0x80);
        val >>= 7;
    }
    out.push(val as u8);
}

fn qpack_encode_literal(out: &mut Vec<u8>, name: &str, value: &str) {
    // RFC 9204 §4.5.6: Literal Field Line With Literal Name: 001 | N(0) | H(0) | NameLen(3+)
    qpack_write_int(out, 3, 0x20, name.len());
    out.extend_from_slice(name.as_bytes());
    // Value: H(0) | ValueLen(7+)
    qpack_write_int(out, 7, 0x00, value.len());
    out.extend_from_slice(value.as_bytes());
}

fn encode_connect_ip_qpack(authority: &str, path: &str, auth_header: Option<&str>) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    // Required Insert Count = 0, Delta Base = 0
    out.extend_from_slice(&[0x00, 0x00]);
    qpack_encode_literal(&mut out, ":method", "CONNECT");
    qpack_encode_literal(&mut out, ":protocol", "connect-ip");
    qpack_encode_literal(&mut out, ":scheme", "https");
    qpack_encode_literal(&mut out, ":authority", authority);
    qpack_encode_literal(&mut out, ":path", path);
    qpack_encode_literal(&mut out, "capsule-protocol", "?1");
    qpack_encode_literal(&mut out, "user-agent", USER_AGENT);
    if let Some(auth) = auth_header {
        qpack_encode_literal(&mut out, "authorization", auth);
    }
    out
}

fn qpack_read_int(data: &[u8], prefix_bits: u8) -> Option<(usize, usize)> {
    let first = *data.first()?;
    let max_prefix = (1usize << prefix_bits) - 1;
    let mut val = usize::from(first) & max_prefix;
    if val < max_prefix {
        return Some((val, 1));
    }
    let mut m = 0usize;
    let mut pos = 1usize;
    loop {
        let b = *data.get(pos)?;
        pos += 1;
        val = val.checked_add(usize::from(b & 0x7f).checked_shl(m as u32)?)?;
        if b & 0x80 == 0 {
            return Some((val, pos));
        }
        m += 7;
        if m > 28 {
            return None;
        }
    }
}

fn static_status_code(idx: usize) -> Option<u16> {
    match idx {
        24 => Some(103),
        25 => Some(200),
        26 => Some(304),
        27 => Some(404),
        28 => Some(503),
        63 => Some(100),
        64 => Some(204),
        65 => Some(206),
        66 => Some(302),
        67 => Some(400),
        68 => Some(403),
        69 => Some(421),
        70 => Some(425),
        71 => Some(500),
        _ => None,
    }
}

/// Извлечь HTTP-статус `:status` из блока QPACK (без динамической таблицы).
fn decode_qpack_status(block: &[u8]) -> Option<u16> {
    let (_, u1) = qpack_read_int(block, 8)?;
    let (_, u2) = qpack_read_int(block.get(u1..)?, 7)?;
    let mut p = block.get(u1 + u2..)?;
    while !p.is_empty() {
        let b = p[0];
        if b & 0x80 != 0 {
            // Indexed field line: 1 | T | Index(6+)
            let is_static = b & 0x40 != 0;
            let (idx, u) = qpack_read_int(p, 6)?;
            p = &p[u..];
            if is_static {
                if let Some(code) = static_status_code(idx) {
                    return Some(code);
                }
            }
        } else if b & 0x40 != 0 {
            // Literal with name reference: 01 | N | T | NameIdx(4+)
            let is_static = b & 0x10 != 0;
            let (idx, u) = qpack_read_int(p, 4)?;
            p = &p[u..];
            let huff = p.first().copied()? & 0x80 != 0;
            let (vlen, vu) = qpack_read_int(p, 7)?;
            let val = p.get(vu..vu + vlen)?;
            p = &p[vu + vlen..];
            if is_static && matches!(idx, 24..=28 | 63..=71) && !huff {
                if let Ok(s) = std::str::from_utf8(val) {
                    if let Ok(code) = s.parse::<u16>() {
                        return Some(code);
                    }
                }
            }
        } else if b & 0x20 != 0 {
            // Literal with literal name: 001 | N | H | NameLen(3+)
            let nhuff = b & 0x08 != 0;
            let (nlen, nu) = qpack_read_int(p, 3)?;
            let name = p.get(nu..nu + nlen)?;
            p = &p[nu + nlen..];
            let vhuff = p.first().copied()? & 0x80 != 0;
            let (vlen, vu) = qpack_read_int(p, 7)?;
            let val = p.get(vu..vu + vlen)?;
            p = &p[vu + vlen..];
            if !nhuff && !vhuff && name == b":status" {
                if let Ok(s) = std::str::from_utf8(val) {
                    if let Ok(code) = s.parse::<u16>() {
                        return Some(code);
                    }
                }
            }
        } else {
            return None;
        }
    }
    None
}

async fn read_quic_varint(recv: &mut quinn::RecvStream) -> io::Result<u64> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, format!("h3 varint: {e}")))?;
    let len = 1usize << (first[0] >> 6);
    let mut v = u64::from(first[0] & 0x3f);
    if len > 1 {
        let mut rest = [0u8; 7];
        recv.read_exact(&mut rest[..len - 1])
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, format!("h3 varint: {e}")))?;
        for &b in &rest[..len - 1] {
            v = (v << 8) | u64::from(b);
        }
    }
    Ok(v)
}

fn h3_frame(ftype: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    write_varint(&mut out, ftype);
    write_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

// ------------------------------------------------------------------ живой туннель и исходящий Masque

struct LiveTunnel {
    stack: Arc<IpStack>,
    closed: Arc<AtomicBool>,
    gen: u64,
    dns_cache: SyncMutex<HashMap<String, (IpAddr, Instant)>>,
    remote_dns: Vec<IpAddr>,
    _keepalive: Box<dyn std::any::Any + Send + Sync>,
}

impl LiveTunnel {
    fn is_alive(&self, gen: u64) -> bool {
        !self.closed.load(Ordering::Relaxed) && self.gen == gen
    }

    async fn resolve_target(&self, target: &Target) -> io::Result<SocketAddr> {
        if let Some(ip) = target.ip() {
            return Ok(SocketAddr::new(ip, target.port));
        }
        let domain = target.domain().ok_or_else(|| invalid("masque: пустая цель"))?;
        if let Some((ip, exp)) = self.dns_cache.lock().get(domain).copied() {
            if Instant::now() < exp {
                return Ok(SocketAddr::new(ip, target.port));
            }
        }
        // Выбираем DNS-сервер того же семейства, которое выдано туннелю.
        let mut servers: Vec<IpAddr> = self
            .remote_dns
            .iter()
            .copied()
            .filter(|addr| self.stack.local_ip_for(*addr).is_some())
            .collect();
        if servers.is_empty() {
            servers = self.remote_dns.clone();
        }
        let prefer_v4 = self.stack.local_v4.is_some();
        let qtype: u16 = if prefer_v4 { 1 } else { 28 };
        let udp = self.stack.open_udp();
        let txid: u16 = rand::thread_rng().gen();
        let query = build_dns_query(txid, domain, qtype)?;

        for dns_ip in servers {
            let dns_addr = SocketAddr::new(dns_ip, 53);
            if udp.send(dns_addr, &query).await.is_err() {
                continue;
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                let rem = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout(rem, udp.recv()).await {
                    Ok(Ok((_, resp))) => {
                        if let Some(ip) = parse_dns_answer(&resp, txid) {
                            self.dns_cache
                                .lock()
                                .insert(domain.to_string(), (ip, Instant::now() + DNS_CACHE_TTL));
                            return Ok(SocketAddr::new(ip, target.port));
                        }
                    }
                    _ => break,
                }
            }
        }
        Err(other(format!("masque: не удалось разрешить {domain}")))
    }
}

pub struct Masque {
    tag: String,
    server: String,
    port: u16,
    path: String,
    host: String,
    auth_header: Option<String>,
    tls: TlsConfig,
    use_h2: bool,
    remote_dns: Vec<IpAddr>,
    live: Mutex<Option<Arc<LiveTunnel>>>,
}

impl Masque {
    pub fn new(o: &OutboundOpts) -> Result<Self, String> {
        if o.server.is_empty() {
            return Err("masque: не задан server".into());
        }
        let port = if o.server_port == 0 { 443 } else { o.server_port };
        let tls_opts = o.tls.clone().unwrap_or_else(|| crate::config::TlsOpts {
            enabled: true,
            server_name: o.server.clone(),
            ..Default::default()
        });
        let use_h2 = tls_opts.alpn.iter().any(|a| a.eq_ignore_ascii_case("h2"))
            && !tls_opts.alpn.iter().any(|a| a.eq_ignore_ascii_case("h3"));
        let default_alpn: &[&str] = if use_h2 { &["h2"] } else { &["h3"] };
        let mut tls = tls_config(&tls_opts, &o.server, default_alpn)?;
        if tls.reality.is_some() {
            return Err("masque: REALITY не поддерживается, нужен обычный TLS".into());
        }
        if use_h2 {
            tls.alpn = vec!["h2".into()];
        } else {
            tls.alpn = vec!["h3".into()];
        }

        let path = if o.path.trim().is_empty() {
            DEFAULT_PATH.to_string()
        } else {
            o.path.trim().to_string()
        };
        if !path.starts_with('/') {
            return Err(format!("masque: path должен начинаться с '/': {path}"));
        }

        let auth_header = if !o.username.is_empty() || !o.password.is_empty() {
            let raw = format!("{}:{}", o.username, o.password);
            let b64 = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
            Some(format!("Basic {b64}"))
        } else {
            None
        };

        let remote_dns: Vec<IpAddr> = if o.remote_dns.is_empty() {
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
                "2606:4700:4700::1111".parse().unwrap(),
                "2606:4700:4700::1001".parse().unwrap(),
            ]
        } else {
            o.remote_dns
                .iter()
                .map(|s| s.parse::<IpAddr>().map_err(|_| format!("masque: неверный remote_dns {s}")))
                .collect::<Result<Vec<_>, _>>()?
        };

        Ok(Self {
            tag: o.tag.clone(),
            server: o.server.clone(),
            port,
            path,
            host: o.host.trim().to_string(),
            auth_header,
            tls,
            use_h2,
            remote_dns,
            live: Mutex::new(None),
        })
    }

    fn authority(&self) -> String {
        if !self.host.is_empty() {
            return self.host.clone();
        }
        let h = self.tls.sni.trim().trim_start_matches('[').trim_end_matches(']');
        if self.port == 443 {
            if h.parse::<Ipv6Addr>().is_ok() {
                format!("[{h}]")
            } else {
                h.to_string()
            }
        } else if h.parse::<Ipv6Addr>().is_ok() {
            format!("[{h}]:{}", self.port)
        } else {
            format!("{h}:{}", self.port)
        }
    }

    async fn live(&self) -> io::Result<Arc<LiveTunnel>> {
        let mut slot = self.live.lock().await;
        let gen = crate::common::network_generation();
        if let Some(t) = slot.as_ref() {
            if t.is_alive(gen) {
                return Ok(t.clone());
            }
        }
        let tunnel = if self.use_h2 {
            self.establish_h2(gen).await?
        } else {
            self.establish_h3(gen).await?
        };
        *slot = Some(tunnel.clone());
        Ok(tunnel)
    }

    async fn establish_h2(&self, gen: u64) -> io::Result<Arc<LiveTunnel>> {
        let up = Upstream {
            server: self.server.clone(),
            port: self.port,
            tls: Some(self.tls.clone()),
            transport: Transport::Tcp,
            pq_rejected: Default::default(),
        };
        let io = up.open().await?;
        let (send, conn) = h2::client::Builder::new()
            .header_table_size(65536)
            .enable_push(false)
            .initial_window_size(6 * 1024 * 1024)
            .initial_connection_window_size(15 * 1024 * 1024)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(|e| other(format!("masque h2: {e}")))?;
        let closed = Arc::new(AtomicBool::new(false));
        let closed_drv = closed.clone();
        tokio::spawn(async move {
            let _ = conn.await;
            closed_drv.store(true, Ordering::Relaxed);
        });

        // Ждём SETTINGS от сервера с ENABLE_CONNECT_PROTOCOL.
        let deadline = Instant::now() + Duration::from_secs(3);
        while !send.is_extended_connect_protocol_enabled() && Instant::now() < deadline {
            if closed.load(Ordering::Relaxed) {
                return Err(other("masque h2: соединение закрыто до SETTINGS"));
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        if !send.is_extended_connect_protocol_enabled() {
            return Err(other("masque h2: сервер не включил Extended CONNECT"));
        }

        let authority = self.authority();
        let uri = format!("https://{authority}{}", self.path);
        let mut req_b = Request::builder()
            .method(Method::CONNECT)
            .uri(&uri)
            .header("capsule-protocol", "?1")
            .header("user-agent", USER_AGENT);
        if let Some(auth) = &self.auth_header {
            req_b = req_b.header("authorization", auth.as_str());
        }
        let mut req = req_b.body(()).map_err(|e| invalid(format!("masque h2: {e}")))?;
        req.extensions_mut().insert(h2::ext::Protocol::from_static("connect-ip"));

        let mut ready = send.clone().ready().await.map_err(|e| other(format!("masque h2: {e}")))?;
        let (resp_fut, mut h2_tx) = ready.send_request(req, false).map_err(|e| other(format!("masque h2: {e}")))?;
        let resp = tokio::time::timeout(crate::common::DIAL_TIMEOUT, resp_fut)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "masque h2: таймаут ответа"))?
            .map_err(|e| other(format!("masque h2: {e}")))?;
        if !resp.status().is_success() {
            return Err(other(format!("masque h2: сервер ответил {}", resp.status())));
        }

        let mut h2_rx = resp.into_body();
        // Шлём ADDRESS_REQUEST.
        let req_cap = encode_address_request_capsule();
        h2_send_chunk(&mut h2_tx, Bytes::from(req_cap)).await?;

        let mut decoder = CapsuleDecoder::default();
        let (v4, v6, early_dgrams) = tokio::time::timeout(
            crate::common::DIAL_TIMEOUT,
            wait_h2_address_assign(&mut h2_rx, &mut h2_tx, &mut decoder),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "masque h2: таймаут назначения IP"))??;

        let (tx_ip, mut rx_ip_out) = mpsc::channel::<Vec<u8>>(512);
        let (cap_tx, mut cap_rx) = mpsc::channel::<Vec<u8>>(64);
        let stack = IpStack::new(v4, v6, MIN_PACKET_SIZE, tx_ip);
        for d in early_dgrams {
            stack.ingest(&d);
        }

        // Задача записи капсул и датаграмм в H2-поток.
        let closed_w = closed.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(cap) = cap_rx.recv() => {
                        if h2_send_chunk(&mut h2_tx, Bytes::from(cap)).await.is_err() {
                            break;
                        }
                    }
                    pkt = rx_ip_out.recv() => {
                        let Some(pkt) = pkt else {
                            h2_tx.send_reset(h2::Reason::CANCEL);
                            break;
                        };
                        if let Some(pkt) = prepare_outgoing_ip(pkt) {
                            let cap = encode_datagram_capsule(&pkt);
                            if h2_send_chunk(&mut h2_tx, Bytes::from(cap)).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            closed_w.store(true, Ordering::Relaxed);
        });

        // Задача чтения капсул из H2-потока.
        let stack_r = stack.clone();
        let closed_r = closed.clone();
        tokio::spawn(async move {
            while let Some(Ok(chunk)) = h2_rx.data().await {
                let _ = h2_rx.flow_control().release_capacity(chunk.len());
                decoder.feed(&chunk);
                while let Some((ctype, payload)) = decoder.next() {
                    match ctype {
                        CAPSULE_DATAGRAM => {
                            if let Some((ctx_id, u)) = read_varint(&payload) {
                                if ctx_id == 0 {
                                    stack_r.ingest(&payload[u..]);
                                }
                            }
                        }
                        CAPSULE_ADDRESS_REQUEST => {
                            if let Ok(reqs) = parse_address_list(&payload) {
                                let rej: Vec<_> = reqs.iter().map(|(id, p)| (*id, p.addr.is_ipv4())).collect();
                                let _ = cap_tx.try_send(encode_reject_address_assign(&rej));
                            }
                        }
                        CAPSULE_ADDRESS_ASSIGN | CAPSULE_ROUTE_ADVERTISEMENT | _ => {}
                    }
                }
            }
            closed_r.store(true, Ordering::Relaxed);
        });

        crate::info!("masque", "HTTP/2 CONNECT-IP поднят: v4={v4:?} v6={v6:?}");
        Ok(Arc::new(LiveTunnel {
            stack,
            closed,
            gen,
            dns_cache: SyncMutex::new(HashMap::new()),
            remote_dns: self.remote_dns.clone(),
            _keepalive: Box::new(send),
        }))
    }

    async fn establish_h3(&self, gen: u64) -> io::Result<Arc<LiveTunnel>> {
        let addrs = crate::dns::resolve_server(&self.server, self.port).await?;
        if addrs.is_empty() {
            return Err(other(format!("masque: нет адреса для {}", self.server)));
        }
        let mut rtls = rustls_config(self.tls.insecure, &["h3".into()]).map_err(io::Error::other)?;
        rtls.enable_early_data = false;
        let crypto = Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(rtls).map_err(io::Error::other)?);
        let sni = self.tls.sni.clone();

        let (endpoint, conn) = crate::common::race(addrs, move |addr: SocketAddr| {
            let crypto = crypto.clone();
            let sni = sni.clone();
            async move {
                let socket = udp_std_socket(addr.is_ipv6())?;
                let tuning = socket2::SockRef::from(&socket);
                let _ = tuning.set_recv_buffer_size(UDP_BUFFER);
                let _ = tuning.set_send_buffer_size(UDP_BUFFER);

                let mut client = quinn::ClientConfig::new(crypto);
                let mut transport = quinn::TransportConfig::default();
                transport
                    .max_idle_timeout(Some(Duration::from_secs(30).try_into().map_err(io::Error::other)?))
                    .keep_alive_interval(Some(Duration::from_secs(10)))
                    .datagram_receive_buffer_size(Some(2 * 1024 * 1024))
                    .datagram_send_buffer_size(2 * 1024 * 1024)
                    .initial_mtu(1350);
                client.transport_config(Arc::new(transport));

                let runtime = quinn::default_runtime().ok_or_else(|| other("masque: нет рантайма QUIC"))?;
                let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;
                let conn = tokio::time::timeout(
                    crate::common::DIAL_TIMEOUT,
                    endpoint.connect_with(client, addr, &sni).map_err(io::Error::other)?,
                )
                .await
                .map_err(|_| other("masque: таймаут QUIC"))?
                .map_err(io::Error::other)?;
                Ok((endpoint, conn))
            }
        })
        .await?;

        // 1) Наш исходящий управляющий поток HTTP/3 (тип 0x00) + SETTINGS.
        let mut ctrl_tx = conn.open_uni().await.map_err(io::Error::other)?;
        let mut settings_payload = Vec::new();
        for (k, v) in [
            (H3_SETTING_QPACK_MAX_TABLE_CAPACITY, 0u64),
            (H3_SETTING_QPACK_BLOCKED_STREAMS, 0),
            (H3_SETTING_ENABLE_CONNECT_PROTOCOL, 1),
            (H3_SETTING_H3_DATAGRAM, 1),
        ] {
            write_varint(&mut settings_payload, k);
            write_varint(&mut settings_payload, v);
        }
        let mut ctrl_init = vec![0x00u8]; // Control Stream
        ctrl_init.extend_from_slice(&h3_frame(H3_FRAME_SETTINGS, &settings_payload));
        ctrl_tx.write_all(&ctrl_init).await.map_err(io::Error::other)?;

        // 2) Чтение серверного Control Stream и его SETTINGS.
        let (settings_tx, settings_rx) = oneshot::channel::<io::Result<()>>();
        let conn_uni = conn.clone();
        tokio::spawn(async move {
            let mut settings_tx = Some(settings_tx);
            while let Ok(mut uni) = conn_uni.accept_uni().await {
                let Ok(stype) = read_quic_varint(&mut uni).await else { continue };
                if stype == 0x00 {
                    let res = async {
                        let ftype = read_quic_varint(&mut uni).await?;
                        let flen = read_quic_varint(&mut uni).await? as usize;
                        if ftype != H3_FRAME_SETTINGS || flen > 65536 {
                            return Err(invalid("masque h3: ожидался SETTINGS"));
                        }
                        let mut buf = vec![0u8; flen];
                        uni.read_exact(&mut buf).await.map_err(io::Error::other)?;
                        let mut p = buf.as_slice();
                        let mut ext_connect = false;
                        let mut datagrams = false;
                        while !p.is_empty() {
                            let (id, u1) = read_varint(p).ok_or_else(|| invalid("h3 setting id"))?;
                            let (val, u2) = read_varint(&p[u1..]).ok_or_else(|| invalid("h3 setting val"))?;
                            p = &p[u1 + u2..];
                            if id == H3_SETTING_ENABLE_CONNECT_PROTOCOL && val == 1 {
                                ext_connect = true;
                            } else if id == H3_SETTING_H3_DATAGRAM && val == 1 {
                                datagrams = true;
                            }
                        }
                        if !ext_connect {
                            return Err(other("masque h3: сервер не поддерживает Extended CONNECT"));
                        }
                        if !datagrams {
                            return Err(other("masque h3: сервер не поддерживает H3_DATAGRAM"));
                        }
                        Ok(())
                    }
                    .await;
                    if let Some(tx) = settings_tx.take() {
                        let _ = tx.send(res);
                    }
                    // Держим поток открытым до закрытия QUIC.
                    let mut drain = [0u8; 256];
                    while let Ok(Some(_)) = uni.read(&mut drain).await {}
                    return;
                } else {
                    tokio::spawn(async move {
                        let mut drain = [0u8; 256];
                        while let Ok(Some(_)) = uni.read(&mut drain).await {}
                    });
                }
            }
        });

        match tokio::time::timeout(crate::common::DIAL_TIMEOUT, settings_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => return Err(e),
            _ => return Err(other("masque h3: таймаут SETTINGS")),
        }

        // 3) Extended CONNECT на двунаправленном потоке HTTP/3.
        let (mut req_tx, mut req_rx) = conn.open_bi().await.map_err(io::Error::other)?;
        let raw_stream_id: u64 = req_tx.id().into();
        let quarter_stream_id = raw_stream_id / 4;

        let qpack = encode_connect_ip_qpack(&self.authority(), &self.path, self.auth_header.as_deref());
        let hdr_frame = h3_frame(H3_FRAME_HEADERS, &qpack);
        req_tx.write_all(&hdr_frame).await.map_err(io::Error::other)?;

        // 4) Читаем ответный HEADERS и проверяем статус 2xx.
        let status = tokio::time::timeout(crate::common::DIAL_TIMEOUT, async {
            loop {
                let ftype = read_quic_varint(&mut req_rx).await?;
                let flen = read_quic_varint(&mut req_rx).await? as usize;
                if flen > 65536 {
                    return Err(invalid("masque h3: кадр заголовков слишком велик"));
                }
                let mut payload = vec![0u8; flen];
                req_rx.read_exact(&mut payload).await.map_err(io::Error::other)?;
                if ftype == H3_FRAME_HEADERS {
                    let code = decode_qpack_status(&payload).ok_or_else(|| invalid("masque h3: нет :status"))?;
                    return Ok(code);
                }
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "masque h3: таймаут ответа"))??;

        if !(200..=299).contains(&status) {
            return Err(other(format!("masque h3: сервер ответил HTTP {status}")));
        }

        // 5) Шлём ADDRESS_REQUEST капсулу в кадре H3 DATA и ждём ADDRESS_ASSIGN.
        let req_cap = encode_address_request_capsule();
        req_tx
            .write_all(&h3_frame(H3_FRAME_DATA, &req_cap))
            .await
            .map_err(io::Error::other)?;

        let mut decoder = CapsuleDecoder::default();
        let (v4, v6) = tokio::time::timeout(
            crate::common::DIAL_TIMEOUT,
            wait_h3_address_assign(&mut req_rx, &mut req_tx, &mut decoder),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "masque h3: таймаут назначения IP"))??;

        let mut dgram_prefix = Vec::with_capacity(4);
        write_varint(&mut dgram_prefix, quarter_stream_id);
        dgram_prefix.push(0); // Context ID = 0

        let max_dgram = conn.max_datagram_size().unwrap_or(MIN_PACKET_SIZE + dgram_prefix.len());
        let mtu = max_dgram.saturating_sub(dgram_prefix.len()).max(MIN_PACKET_SIZE);

        let closed = Arc::new(AtomicBool::new(false));
        let (tx_ip, mut rx_ip_out) = mpsc::channel::<Vec<u8>>(512);
        let stack = IpStack::new(v4, v6, mtu, tx_ip);

        // Запись исходящих IP-пакетов в QUIC DATAGRAM.
        let conn_w = conn.clone();
        let closed_w = closed.clone();
        tokio::spawn(async move {
            while let Some(pkt) = rx_ip_out.recv().await {
                if let Some(pkt) = prepare_outgoing_ip(pkt) {
                    let mut dg = Vec::with_capacity(dgram_prefix.len() + pkt.len());
                    dg.extend_from_slice(&dgram_prefix);
                    dg.extend_from_slice(&pkt);
                    if conn_w.send_datagram(Bytes::from(dg)).is_err() && conn_w.close_reason().is_some() {
                        break;
                    }
                }
            }
            closed_w.store(true, Ordering::Relaxed);
            conn_w.close(0u32.into(), b"closed");
        });

        // Чтение входящих QUIC DATAGRAM и передача в IpStack.
        let conn_r = conn.clone();
        let stack_r = stack.clone();
        let closed_r = closed.clone();
        tokio::spawn(async move {
            while let Ok(dg) = conn_r.read_datagram().await {
                let Some((qsid, u1)) = read_varint(&dg) else { continue };
                if qsid != quarter_stream_id {
                    continue;
                }
                let Some((ctx_id, u2)) = read_varint(&dg[u1..]) else { continue };
                if ctx_id != 0 {
                    continue;
                }
                stack_r.ingest(&dg[u1 + u2..]);
            }
            closed_r.store(true, Ordering::Relaxed);
        });

        // Фоновое обслуживание капсул на управляющем H3-потоке CONNECT-IP.
        let closed_cap = closed.clone();
        tokio::spawn(async move {
            let _hold_ctrl = ctrl_tx;
            while let Ok(ftype) = read_quic_varint(&mut req_rx).await {
                let Ok(flen) = read_quic_varint(&mut req_rx).await else { break };
                let flen = flen as usize;
                if flen > 256 * 1024 {
                    break;
                }
                let mut buf = vec![0u8; flen];
                if req_rx.read_exact(&mut buf).await.is_err() {
                    break;
                }
                if ftype == H3_FRAME_DATA {
                    decoder.feed(&buf);
                    while let Some((ctype, payload)) = decoder.next() {
                        if ctype == CAPSULE_ADDRESS_REQUEST {
                            if let Ok(reqs) = parse_address_list(&payload) {
                                let rej: Vec<_> = reqs.iter().map(|(id, p)| (*id, p.addr.is_ipv4())).collect();
                                let frame = h3_frame(H3_FRAME_DATA, &encode_reject_address_assign(&rej));
                                if req_tx.write_all(&frame).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            closed_cap.store(true, Ordering::Relaxed);
        });

        crate::info!("masque", "HTTP/3 CONNECT-IP поднят: v4={v4:?} v6={v6:?} mtu={mtu}");
        Ok(Arc::new(LiveTunnel {
            stack,
            closed,
            gen,
            dns_cache: SyncMutex::new(HashMap::new()),
            remote_dns: self.remote_dns.clone(),
            _keepalive: Box::new((endpoint, conn)),
        }))
    }
}

async fn h2_send_chunk(tx: &mut h2::SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        let want = data.len().min(16 * 1024);
        tx.reserve_capacity(want);
        let cap = std::future::poll_fn(|cx| tx.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "masque h2: поток закрыт"))?
            .map_err(|e| other(format!("masque h2: {e}")))?;
        let part = data.split_to(cap.min(data.len()));
        tx.send_data(part, false).map_err(|e| other(format!("masque h2: {e}")))?;
    }
    Ok(())
}

async fn wait_h2_address_assign(
    rx: &mut h2::RecvStream,
    tx: &mut h2::SendStream<Bytes>,
    decoder: &mut CapsuleDecoder,
) -> io::Result<(Option<Ipv4Addr>, Option<Ipv6Addr>, Vec<Vec<u8>>)> {
    let mut v4 = None;
    let mut v6 = None;
    let mut early = Vec::new();
    while v4.is_none() && v6.is_none() {
        let chunk = rx
            .data()
            .await
            .ok_or_else(|| other("masque h2: сервер закрыл поток до назначения IP"))?
            .map_err(|e| other(format!("masque h2: {e}")))?;
        let _ = rx.flow_control().release_capacity(chunk.len());
        decoder.feed(&chunk);
        while let Some((ctype, payload)) = decoder.next() {
            match ctype {
                CAPSULE_ADDRESS_ASSIGN => {
                    for (_, p) in parse_address_list(&payload)? {
                        if p.is_rejected() {
                            continue;
                        }
                        match p.host_addr() {
                            IpAddr::V4(ip) if v4.is_none() => v4 = Some(ip),
                            IpAddr::V6(ip) if v6.is_none() => v6 = Some(ip),
                            _ => {}
                        }
                    }
                }
                CAPSULE_ADDRESS_REQUEST => {
                    if let Ok(reqs) = parse_address_list(&payload) {
                        let rej: Vec<_> = reqs.iter().map(|(id, p)| (*id, p.addr.is_ipv4())).collect();
                        let _ = h2_send_chunk(tx, Bytes::from(encode_reject_address_assign(&rej))).await;
                    }
                }
                CAPSULE_DATAGRAM => {
                    if let Some((0, u)) = read_varint(&payload) {
                        early.push(payload[u..].to_vec());
                    }
                }
                _ => {}
            }
        }
    }
    Ok((v4, v6, early))
}

async fn wait_h3_address_assign(
    rx: &mut quinn::RecvStream,
    tx: &mut quinn::SendStream,
    decoder: &mut CapsuleDecoder,
) -> io::Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
    let mut v4 = None;
    let mut v6 = None;
    while v4.is_none() && v6.is_none() {
        let ftype = read_quic_varint(rx).await?;
        let flen = read_quic_varint(rx).await? as usize;
        if flen > 256 * 1024 {
            return Err(invalid("masque h3: капсула слишком велика"));
        }
        let mut buf = vec![0u8; flen];
        rx.read_exact(&mut buf).await.map_err(io::Error::other)?;
        if ftype != H3_FRAME_DATA {
            continue;
        }
        decoder.feed(&buf);
        while let Some((ctype, payload)) = decoder.next() {
            match ctype {
                CAPSULE_ADDRESS_ASSIGN => {
                    for (_, p) in parse_address_list(&payload)? {
                        if p.is_rejected() {
                            continue;
                        }
                        match p.host_addr() {
                            IpAddr::V4(ip) if v4.is_none() => v4 = Some(ip),
                            IpAddr::V6(ip) if v6.is_none() => v6 = Some(ip),
                            _ => {}
                        }
                    }
                }
                CAPSULE_ADDRESS_REQUEST => {
                    if let Ok(reqs) = parse_address_list(&payload) {
                        let rej: Vec<_> = reqs.iter().map(|(id, p)| (*id, p.addr.is_ipv4())).collect();
                        let frame = h3_frame(H3_FRAME_DATA, &encode_reject_address_assign(&rej));
                        let _ = tx.write_all(&frame).await;
                    }
                }
                _ => {}
            }
        }
    }
    Ok((v4, v6))
}

#[async_trait]
impl Outbound for Masque {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "masque"
    }

    async fn dial(&self, target: &Target) -> io::Result<BoxStream> {
        let tunnel = self.live().await?;
        let addr = tunnel.resolve_target(target).await?;
        tunnel.stack.dial_tcp(addr).await
    }

    async fn dial_udp(&self, _target: &Target) -> io::Result<Box<dyn PacketConn>> {
        let tunnel = self.live().await?;
        let handle = tunnel.stack.open_udp();
        Ok(Box::new(MasquePacketConn { tunnel, handle }))
    }
}

struct MasquePacketConn {
    tunnel: Arc<LiveTunnel>,
    handle: MasqueUdpHandle,
}

#[async_trait]
impl PacketConn for MasquePacketConn {
    async fn send(&self, data: &[u8], to: &Target) -> io::Result<()> {
        let addr = self.tunnel.resolve_target(to).await?;
        self.handle.send(addr, data).await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let (from, payload) = self.handle.recv().await?;
        let n = payload.len().min(buf.len());
        buf[..n].copy_from_slice(&payload[..n]);
        Ok((n, Target::from_addr(from)))
    }
}

// ------------------------------------------------------------------ минимальный DNS-клиент внутри туннеля

fn build_dns_query(txid: u16, domain: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&txid.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(invalid(format!("masque dns: неверное имя {domain}")));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(out)
}

fn skip_dns_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    loop {
        let len = *pkt.get(pos)?;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            return pkt.get(pos + 1).map(|_| pos + 2);
        }
        pos += 1 + usize::from(len);
        jumps += 1;
        if jumps > 128 || pos > pkt.len() {
            return None;
        }
    }
}

fn parse_dns_answer(pkt: &[u8], expected_txid: u16) -> Option<IpAddr> {
    if pkt.len() < 12 || u16::from_be_bytes([pkt[0], pkt[1]]) != expected_txid {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]);
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(pkt, pos)?;
        pos += 4;
    }
    for _ in 0..ancount {
        pos = skip_dns_name(pkt, pos)?;
        if pos + 10 > pkt.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let rdlen = usize::from(u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]));
        pos += 10;
        if pos + rdlen > pkt.len() {
            return None;
        }
        if rtype == 1 && rdlen == 4 {
            return Some(IpAddr::V4(Ipv4Addr::new(pkt[pos], pkt[pos + 1], pkt[pos + 2], pkt[pos + 3])));
        }
        if rtype == 28 && rdlen == 16 {
            let arr: [u8; 16] = pkt[pos..pos + 16].try_into().ok()?;
            return Some(IpAddr::V6(Ipv6Addr::from(arr)));
        }
        pos += rdlen;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsules_roundtrip_and_handle_partial_chunks() {
        let req = encode_address_request_capsule();
        let dg = encode_datagram_capsule(b"\x45\x00\x00\x14test");
        let mut combined = Vec::new();
        combined.extend_from_slice(&req);
        combined.extend_from_slice(&dg);

        let mut dec = CapsuleDecoder::default();
        for b in &combined[..5] {
            dec.feed(&[*b]);
            assert!(dec.next().is_none());
        }
        dec.feed(&combined[5..]);

        let (t1, p1) = dec.next().unwrap();
        assert_eq!(t1, CAPSULE_ADDRESS_REQUEST);
        let addrs = parse_address_list(&p1).unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], (1, Prefix { addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED), bits: 32 }));
        assert_eq!(addrs[1], (2, Prefix { addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED), bits: 128 }));

        let (t2, p2) = dec.next().unwrap();
        assert_eq!(t2, CAPSULE_DATAGRAM);
        assert_eq!(p2[0], 0);
        assert_eq!(&p2[1..], b"\x45\x00\x00\x14test");
        assert!(dec.next().is_none());
    }

    #[test]
    fn qpack_connect_ip_and_status_decode() {
        let block = encode_connect_ip_qpack("masque.example.test:8443", DEFAULT_PATH, Some("Basic dTpw"));
        assert_eq!(&block[..2], &[0, 0]);
        assert!(block.windows(10).any(|w| w == b"connect-ip"));
        assert!(block.windows(10).any(|w| w == b"Basic dTpw"));

        // Статический :status = 200 (индекс 25 → 0xc0 | 25 = 0xd9).
        assert_eq!(decode_qpack_status(&[0x00, 0x00, 0xd9]), Some(200));
        // Литеральный :status = 200.
        let mut lit = vec![0x00, 0x00];
        qpack_encode_literal(&mut lit, ":status", "200");
        assert_eq!(decode_qpack_status(&lit), Some(200));
        // Статический :status = 403 (индекс 68 → 0x80 | 0x40 | 63, 5).
        assert_eq!(decode_qpack_status(&[0x00, 0x00, 0xff, 0x05]), Some(403));
    }

    #[test]
    fn masque_config_selects_h2_or_h3_and_basic_auth() {
        let mut opts = OutboundOpts {
            kind: "masque".into(),
            tag: "m".into(),
            server: "203.0.113.9".into(),
            server_port: 8443,
            username: "ivy@example.test".into(),
            password: "pw".into(),
            tls: Some(crate::config::TlsOpts {
                enabled: true,
                server_name: "masque.example.test".into(),
                alpn: vec!["h3".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let m_h3 = Masque::new(&opts).unwrap();
        assert!(!m_h3.use_h2);
        assert_eq!(m_h3.path, DEFAULT_PATH);
        assert_eq!(m_h3.authority(), "masque.example.test:8443");
        assert_eq!(
            m_h3.auth_header.as_deref(),
            Some("Basic aXZ5QGV4YW1wbGUudGVzdDpwdw==")
        );

        opts.tls.as_mut().unwrap().alpn = vec!["h2".into()];
        let m_h2 = Masque::new(&opts).unwrap();
        assert!(m_h2.use_h2);
    }

    #[tokio::test]
    async fn h2_connect_ip_end_to_end_address_assign_and_datagram_capsules() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let srv_task = tokio::spawn(async move {
            let mut h2_srv = h2::server::Builder::new()
                .enable_connect_protocol()
                .handshake(server_io)
                .await
                .unwrap();

            let mut handler = None;
            while let Some(res) = h2_srv.accept().await {
                let (req, mut respond) = res.unwrap();
                assert_eq!(req.method(), Method::CONNECT);
                assert_eq!(
                    req.extensions().get::<h2::ext::Protocol>().map(|p| p.as_str()),
                    Some("connect-ip")
                );
                assert_eq!(req.headers().get("capsule-protocol").unwrap(), "?1");
                assert_eq!(req.headers().get("authorization").unwrap(), "Basic dTpw");

                handler = Some(tokio::spawn(async move {
                    let mut rx = req.into_body();
                    let resp = http::Response::builder()
                        .status(200)
                        .header("capsule-protocol", "?1")
                        .body(())
                        .unwrap();
                    let mut tx = respond.send_response(resp, false).unwrap();

                    let mut dec = CapsuleDecoder::default();
                    let mut assigned = false;
                    while let Some(Ok(chunk)) = rx.data().await {
                        let _ = rx.flow_control().release_capacity(chunk.len());
                        dec.feed(&chunk);
                        while let Some((ctype, payload)) = dec.next() {
                            if ctype == CAPSULE_ADDRESS_REQUEST && !assigned {
                                assigned = true;
                                // Назначаем клиенту 10.77.0.2/32.
                                let mut ap = Vec::new();
                                write_varint(&mut ap, 1);
                                ap.push(4);
                                ap.extend_from_slice(&[10, 77, 0, 2]);
                                ap.push(32);
                                let mut cap = Vec::new();
                                write_varint(&mut cap, CAPSULE_ADDRESS_ASSIGN);
                                write_varint(&mut cap, ap.len() as u64);
                                cap.extend_from_slice(&ap);
                                tx.send_data(Bytes::from(cap), false).unwrap();
                            } else if ctype == CAPSULE_DATAGRAM {
                                assert_eq!(payload[0], 0);
                                let ip_pkt = &payload[1..];
                                let parsed = crate::inbound::tun::packet::parse(ip_pkt).unwrap();
                                assert_eq!(parsed.proto, crate::inbound::tun::packet::PROTO_UDP);
                                assert_eq!(parsed.src, IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)));
                                // TTL был уменьшен с 64 до 63 по RFC 9484 §6.
                                assert_eq!(ip_pkt[8], 63);
                                let udp_data = &ip_pkt[parsed.l4 + 8..parsed.total];
                                assert_eq!(udp_data, b"ping-masque");

                                // Собираем ответный UDP-пакет и шлём в DATAGRAM-капсуле.
                                let reply_payload = b"pong-masque";
                                let rlen = crate::inbound::tun::packet::udp_packet_len(parsed.dst, reply_payload.len());
                                let mut rpkt = vec![0u8; rlen];
                                crate::inbound::tun::packet::write_udp(
                                    &mut rpkt,
                                    parsed.dst,
                                    parsed.dport,
                                    parsed.src,
                                    parsed.sport,
                                    reply_payload,
                                );
                                let cap = encode_datagram_capsule(&rpkt);
                                tx.send_data(Bytes::from(cap), true).unwrap();
                                return;
                            }
                        }
                    }
                }));
            }
            if let Some(h) = handler {
                h.await.unwrap();
            }
        });

        let (send, conn) = h2::client::Builder::new()
            .enable_push(false)
            .handshake::<_, Bytes>(client_io)
            .await
            .unwrap();
        let closed = Arc::new(AtomicBool::new(false));
        let c_flag = closed.clone();
        tokio::spawn(async move {
            let _ = conn.await;
            c_flag.store(true, Ordering::Relaxed);
        });
        while !send.is_extended_connect_protocol_enabled() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://masque.test{DEFAULT_PATH}"))
            .header("capsule-protocol", "?1")
            .header("authorization", "Basic dTpw")
            .body(())
            .unwrap();
        req.extensions_mut().insert(h2::ext::Protocol::from_static("connect-ip"));

        let mut ready = send.clone().ready().await.unwrap();
        let (resp_fut, mut h2_tx) = ready.send_request(req, false).unwrap();
        let resp = resp_fut.await.unwrap();
        assert_eq!(resp.status(), 200);
        let mut h2_rx = resp.into_body();
        h2_send_chunk(&mut h2_tx, Bytes::from(encode_address_request_capsule())).await.unwrap();

        let mut dec = CapsuleDecoder::default();
        let (v4, v6, _) = wait_h2_address_assign(&mut h2_rx, &mut h2_tx, &mut dec).await.unwrap();
        assert_eq!(v4, Some(Ipv4Addr::new(10, 77, 0, 2)));
        assert_eq!(v6, None);

        let (tx_ip, mut rx_ip_out) = mpsc::channel::<Vec<u8>>(16);
        let stack = IpStack::new(v4, v6, MIN_PACKET_SIZE, tx_ip);
        tokio::spawn(async move {
            while let Some(pkt) = rx_ip_out.recv().await {
                if let Some(pkt) = prepare_outgoing_ip(pkt) {
                    if h2_send_chunk(&mut h2_tx, Bytes::from(encode_datagram_capsule(&pkt))).await.is_err() {
                        break;
                    }
                }
            }
        });
        let stack_r = stack.clone();
        tokio::spawn(async move {
            while let Some(Ok(chunk)) = h2_rx.data().await {
                let _ = h2_rx.flow_control().release_capacity(chunk.len());
                dec.feed(&chunk);
                while let Some((ctype, payload)) = dec.next() {
                    if ctype == CAPSULE_DATAGRAM {
                        if let Some((0, u)) = read_varint(&payload) {
                            stack_r.ingest(&payload[u..]);
                        }
                    }
                }
            }
        });

        let udp = stack.open_udp();
        let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
        udp.send(dst, b"ping-masque").await.unwrap();
        let (from, reply) = udp.recv().await.unwrap();
        assert_eq!(from, dst);
        assert_eq!(reply, b"pong-masque");
        drop(udp);
        drop(stack);
        drop(ready);
        drop(send);
        srv_task.await.unwrap();
    }
}
