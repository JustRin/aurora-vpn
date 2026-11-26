//! DNS: перехваченные запросы, правила, кэш и резолвинг для самого движка.
//!
//! - Положительный и отрицательный кэш (включая AAAA NODATA, HTTPS/65 и NXDOMAIN),
//!   чтобы каждый дозвон до сервера по имени не упирался в живой AAAA-запрос;
//! - Singleflight: пачка одинаковых одновременных запросов идёт в сеть один раз;
//! - RFC 7766 мультиплексирование для TCP/DoT: десятки параллельных запросов
//!   при открытии сайта едут в одном соединении вместо десятков рукопожатий;
//! - Keep-alive пул для DoH; автоматический сброс при смене прокси или сети.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::common::{
    invalid, network_generation, other, proxy_generation, tcp_connect_any, udp_socket, BoxStream, Target,
};
use crate::config::{DnsOpts, DnsServerOpts};
use crate::router::{DnsAction, DnsRules, Meta};

const QTYPE_A: u16 = 1;
const QTYPE_SOA: u16 = 6;
const QTYPE_AAAA: u16 = 28;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const MUX_REUSE_TIMEOUT: Duration = Duration::from_millis(1500);
const MUX_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
const HTTPS_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
const HTTPS_POOL_MAX: usize = 8;
const CACHE_MAX: usize = 4096;
const MIN_TTL: u32 = 10;
const MAX_TTL: u32 = 3600;
const NEG_DEFAULT_TTL: u32 = 60;
const NEG_MAX_TTL: u32 = 300;

/// Переменная длина из QUIC — здесь, потому что нужна и DNS-разбору QUIC-адресов,
/// и снифферу.
pub fn quic_varint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let len = 1usize << (first >> 6);
    let raw = data.get(..len)?;
    let mut v = u64::from(first & 0x3f);
    for b in &raw[1..] {
        v = (v << 8) | u64::from(*b);
    }
    Some((v, len))
}

/// Имя из вопроса: `Option`, потому что пакет чужой и может быть любым.
pub fn question_name(packet: &[u8]) -> Option<String> {
    parse_question(packet).map(|(name, _, _)| name)
}

/// `(имя в нижнем регистре, тип, конец вопроса)`.
fn parse_question(packet: &[u8]) -> Option<(String, u16, usize)> {
    let mut i = 12;
    let mut name = String::new();
    loop {
        let len = usize::from(*packet.get(i)?);
        i += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || name.len() + len > 253 {
            return None;
        }
        let label = packet.get(i..i + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        i += len;
    }
    let qtype = u16::from_be_bytes([*packet.get(i)?, *packet.get(i + 1)?]);
    Some((name, qtype, i + 4))
}

/// Пустой ответ на вопрос: `rcode` 0 (NOERROR) или 3 (NXDOMAIN).
fn empty_reply(query: &[u8], question_end: usize, rcode: u8) -> Vec<u8> {
    let mut out = query[..question_end.min(query.len())].to_vec();
    if out.len() >= 12 {
        out[2] = 0x81 | (query[2] & 0x01);
        out[3] = 0x80 | rcode;
        out[6..12].fill(0);
    }
    out
}

fn answer_with_ip(query: &[u8], question_end: usize, ip: IpAddr, ttl: u32) -> Vec<u8> {
    let mut out = empty_reply(query, question_end, 0);
    if out.len() < 12 {
        return out;
    }
    out[7] = 1;
    out.extend_from_slice(&[0xc0, 0x0c]);
    match ip {
        IpAddr::V4(v4) => {
            out.extend_from_slice(&QTYPE_A.to_be_bytes());
            out.extend_from_slice(&[0, 1]);
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&[0, 4]);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
            out.extend_from_slice(&[0, 1]);
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&[0, 16]);
            out.extend_from_slice(&v6.octets());
        }
    }
    out
}

/// Пропустить имя в сообщении, в том числе сжатое.
fn skip_name(packet: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *packet.get(i)?;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Some(i + 2);
        }
        i += 1 + usize::from(len);
    }
}

/// Адреса и наименьший TTL из ответа.
pub fn parse_answers(packet: &[u8]) -> Option<(Vec<IpAddr>, u32)> {
    let u16_at = |i: usize| -> Option<u16> { Some(u16::from_be_bytes([*packet.get(i)?, *packet.get(i + 1)?])) };
    let qd = u16_at(4)?;
    let an = u16_at(6)?;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(packet, i)? + 4;
    }
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..an {
        i = skip_name(packet, i)?;
        let kind = u16_at(i)?;
        let record_ttl = u32::from_be_bytes(packet.get(i + 4..i + 8)?.try_into().ok()?);
        let len = usize::from(u16_at(i + 8)?);
        let data = packet.get(i + 10..i + 10 + len)?;
        match (kind, len) {
            (QTYPE_A, 4) => {
                ips.push(IpAddr::from(<[u8; 4]>::try_from(data).ok()?));
                ttl = ttl.min(record_ttl);
            }
            (QTYPE_AAAA, 16) => {
                ips.push(IpAddr::from(<[u8; 16]>::try_from(data).ok()?));
                ttl = ttl.min(record_ttl);
            }
            _ => {}
        }
        i += 10 + len;
    }
    Some((ips, ttl))
}

/// TTL кэширования для любого корректного ответа: A, AAAA, HTTPS/65, CNAME,
/// а также пустых ответов (NODATA) и NXDOMAIN (RFC 2308).
fn cache_ttl(packet: &[u8]) -> Option<u32> {
    if packet.len() < 12 {
        return None;
    }
    // Обрезанный ответ (TC) или ошибка сервера (SERVFAIL/REFUSED/FORMERR) в кэш не идут.
    if packet[2] & 0x02 != 0 {
        return None;
    }
    let rcode = packet[3] & 0x0f;
    if rcode != 0 && rcode != 3 {
        return None;
    }
    let u16_at = |i: usize| -> Option<u16> { Some(u16::from_be_bytes([*packet.get(i)?, *packet.get(i + 1)?])) };
    let qd = u16_at(4)?;
    let an = u16_at(6)?;
    let ns = u16_at(8)?;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(packet, i)? + 4;
    }
    let mut min_ttl = u32::MAX;
    for _ in 0..an {
        i = skip_name(packet, i)?;
        let record_ttl = u32::from_be_bytes(packet.get(i + 4..i + 8)?.try_into().ok()?);
        let len = usize::from(u16_at(i + 8)?);
        packet.get(i + 10..i + 10 + len)?;
        min_ttl = min_ttl.min(record_ttl);
        i += 10 + len;
    }
    if an > 0 && min_ttl != u32::MAX {
        return Some(min_ttl.clamp(MIN_TTL, MAX_TTL));
    }
    // NODATA или NXDOMAIN: ищем SOA в секции authority (RFC 2308).
    let mut soa_ttl = None;
    for _ in 0..ns {
        let Some(next) = skip_name(packet, i) else { break };
        i = next;
        let Some(kind) = u16_at(i) else { break };
        let Some(record_ttl) = packet.get(i + 4..i + 8).and_then(|b| <[u8; 4]>::try_from(b).ok()).map(u32::from_be_bytes) else {
            break;
        };
        let Some(len) = u16_at(i + 8).map(usize::from) else { break };
        let Some(rdata) = packet.get(i + 10..i + 10 + len) else { break };
        if kind == QTYPE_SOA && rdata.len() >= 20 {
            let soa_min = u32::from_be_bytes(rdata[rdata.len() - 4..].try_into().unwrap());
            soa_ttl = Some(record_ttl.min(soa_min));
            break;
        }
        i += 10 + len;
    }
    Some(soa_ttl.unwrap_or(NEG_DEFAULT_TTL).clamp(MIN_TTL, NEG_MAX_TTL))
}

fn encode_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 18);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        let bytes = &label.as_bytes()[..label.len().min(63)];
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out
}

// --------------------------------------------------------------- серверы

enum Upstream {
    /// Обычный UDP мимо туннеля.
    Udp(SocketAddr),
    /// DNS-over-TCP (RFC 7766 мультиплексированный): прямо или через исходящий (`detour`).
    Tcp { target: Target, detour: Option<String> },
    Tls { target: Target, sni: String, detour: Option<String> },
    Https { target: Target, sni: String, path: String, detour: Option<String> },
    Local,
    FakeIp(FakeIp),
}

pub struct FakeIp {
    v4_base: u32,
    v4_size: u32,
    v6_base: u128,
    next: AtomicU32,
    /// Имя → адрес и обратно. Живёт в памяти: `store_fakeip` пока не поддержан.
    by_name: Mutex<HashMap<String, u32>>,
    by_index: Mutex<HashMap<u32, String>>,
}

impl FakeIp {
    fn new(opts: &DnsServerOpts) -> Result<Self, String> {
        let v4 = if opts.inet4_range.is_empty() { "198.18.0.0/15" } else { &opts.inet4_range };
        let (addr, bits) = v4.split_once('/').ok_or("fakeip: диапазон")?;
        let base = u32::from(addr.parse::<Ipv4Addr>().map_err(|e| e.to_string())?);
        let bits: u32 = bits.parse().map_err(|_| "fakeip: длина префикса")?;
        let v6 = if opts.inet6_range.is_empty() { "fc00::/18" } else { &opts.inet6_range };
        let v6_addr = v6.split('/').next().unwrap_or("fc00::");
        Ok(Self {
            v4_base: base,
            v4_size: 1u32 << (32 - bits.clamp(8, 30)),
            v6_base: u128::from(v6_addr.parse::<Ipv6Addr>().map_err(|e| e.to_string())?),
            next: AtomicU32::new(2),
            by_name: Mutex::new(HashMap::new()),
            by_index: Mutex::new(HashMap::new()),
        })
    }

    fn index_for(&self, name: &str) -> u32 {
        let mut by_name = self.by_name.lock();
        if let Some(index) = by_name.get(name) {
            return *index;
        }
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.v4_size.max(4);
        let mut by_index = self.by_index.lock();
        if let Some(old) = by_index.insert(index, name.to_string()) {
            by_name.remove(&old);
        }
        by_name.insert(name.to_string(), index);
        index
    }

    fn allocate(&self, name: &str, qtype: u16) -> IpAddr {
        let index = self.index_for(name);
        if qtype == QTYPE_AAAA {
            IpAddr::V6(Ipv6Addr::from(self.v6_base + u128::from(index)))
        } else {
            IpAddr::V4(Ipv4Addr::from(self.v4_base + index))
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let index = match ip {
            IpAddr::V4(v4) => {
                let v = u32::from(v4);
                if v < self.v4_base || v - self.v4_base >= self.v4_size {
                    return None;
                }
                v - self.v4_base
            }
            IpAddr::V6(v6) => {
                let v = u128::from(v6);
                if v < self.v6_base || v - self.v6_base >= u128::from(self.v4_size) {
                    return None;
                }
                (v - self.v6_base) as u32
            }
        };
        self.by_index.lock().get(&index).cloned()
    }
}

/// Одно живое мультиплексированное соединение RFC 7766 (TCP или DoT): принимает
/// десятки параллельных запросов с уникальными txid, склеивает пачки в одну запись
/// и закрывается само после простоя.
struct MuxReq {
    query: Vec<u8>,
    reply: oneshot::Sender<io::Result<Vec<u8>>>,
}

struct MuxClient {
    tx: mpsc::Sender<MuxReq>,
    alive: Arc<AtomicBool>,
    gen: (u64, u64),
}

impl MuxClient {
    fn spawn(stream: BoxStream, gen: (u64, u64)) -> Arc<Self> {
        let (mut read, mut write) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::channel::<MuxReq>(256);
        let alive = Arc::new(AtomicBool::new(true));
        let pending: Arc<Mutex<HashMap<u16, oneshot::Sender<io::Result<Vec<u8>>>>>> = Default::default();

        let alive_r = alive.clone();
        let pending_r = pending.clone();
        let reader = tokio::spawn(async move {
            let err = loop {
                let len = match read.read_u16().await {
                    Ok(len) => usize::from(len),
                    Err(e) => break e,
                };
                if len < 2 {
                    break invalid("dns: слишком короткий ответ");
                }
                let mut reply = vec![0u8; len];
                if let Err(e) = read.read_exact(&mut reply).await {
                    break e;
                }
                let wire_id = u16::from_be_bytes([reply[0], reply[1]]);
                if let Some(waiter) = pending_r.lock().remove(&wire_id) {
                    let _ = waiter.send(Ok(reply));
                }
            };
            alive_r.store(false, Ordering::Release);
            let msg = err.to_string();
            for (_, waiter) in pending_r.lock().drain() {
                let _ = waiter.send(Err(other(msg.clone())));
            }
        });

        let alive_w = alive.clone();
        let pending_w = pending;
        tokio::spawn(async move {
            let mut next_id: u16 = 1;
            let mut batch = Vec::with_capacity(4096);
            let mut queue_one = |req: MuxReq, batch: &mut Vec<u8>| {
                if req.query.len() < 2 || req.query.len() > usize::from(u16::MAX) {
                    let _ = req.reply.send(Err(invalid("dns: длина запроса")));
                    return;
                }
                let mut map = pending_w.lock();
                let mut wire_id = None;
                for _ in 0..64 {
                    let id = next_id;
                    next_id = next_id.wrapping_add(1).max(1);
                    if !map.contains_key(&id) {
                        wire_id = Some(id);
                        break;
                    }
                }
                let Some(wire_id) = wire_id else {
                    drop(map);
                    let _ = req.reply.send(Err(other("dns: очередь переполнена")));
                    return;
                };
                map.insert(wire_id, req.reply);
                drop(map);
                let len = req.query.len() as u16;
                batch.extend_from_slice(&len.to_be_bytes());
                batch.extend_from_slice(&wire_id.to_be_bytes());
                batch.extend_from_slice(&req.query[2..]);
            };

            loop {
                let first = match tokio::time::timeout(MUX_IDLE_TIMEOUT, rx.recv()).await {
                    Ok(Some(req)) => req,
                    Ok(None) => break,
                    Err(_) => {
                        if pending_w.lock().is_empty() {
                            break;
                        }
                        continue;
                    }
                };
                if !alive_w.load(Ordering::Acquire) {
                    let _ = first.reply.send(Err(other("dns: соединение закрыто")));
                    break;
                }
                batch.clear();
                queue_one(first, &mut batch);
                // Сразу подхватываем уже ждущие в канале запросы — уходят одной записью.
                for _ in 0..31 {
                    match rx.try_recv() {
                        Ok(req) => queue_one(req, &mut batch),
                        Err(_) => break,
                    }
                }
                if !batch.is_empty() {
                    if write.write_all(&batch).await.is_err() || write.flush().await.is_err() {
                        break;
                    }
                }
            }
            alive_w.store(false, Ordering::Release);
            reader.abort();
            for (_, waiter) in pending_w.lock().drain() {
                let _ = waiter.send(Err(other("dns: соединение закрыто")));
            }
        });

        Arc::new(Self { tx, alive, gen })
    }

    fn usable(&self, gen: (u64, u64)) -> bool {
        self.gen == gen && self.alive.load(Ordering::Acquire) && !self.tx.is_closed()
    }

    fn kill(&self) {
        self.alive.store(false, Ordering::Release);
    }

    async fn query(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(MuxReq { query: query.to_vec(), reply: tx })
            .await
            .map_err(|_| other("dns: соединение закрыто"))?;
        let mut reply = rx.await.map_err(|_| other("dns: соединение закрыто"))??;
        if reply.len() >= 2 && query.len() >= 2 {
            reply[..2].copy_from_slice(&query[..2]);
        }
        Ok(reply)
    }
}

type InflightTx = broadcast::Sender<Result<Vec<u8>, String>>;

struct HttpsConn {
    stream: BoxStream,
    used_at: Instant,
    gen: (u64, u64),
}

struct Server {
    tag: String,
    upstream: Upstream,
    /// Активное мультиплексированное TCP/DoT-соединение.
    mux: Mutex<Option<Arc<MuxClient>>>,
    /// Один дозвон на сервер: пачка стартовых запросов ждёт общее соединение.
    dial_lock: tokio::sync::Mutex<()>,
    /// Keep-alive пул для DoH.
    https_pool: Mutex<Vec<HttpsConn>>,
    cache: Mutex<HashMap<(String, u16), (Vec<u8>, Instant)>>,
    /// Одинаковые запросы в полёте (singleflight).
    inflight: Mutex<HashMap<(String, u16), Arc<InflightTx>>>,
}

fn current_gen(has_detour: bool) -> (u64, u64) {
    (network_generation(), if has_detour { proxy_generation() } else { 0 })
}

struct InflightGuard<'a> {
    map: &'a Mutex<HashMap<(String, u16), Arc<InflightTx>>>,
    key: (String, u16),
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.map.lock().remove(&self.key);
    }
}

fn host_port(raw: &str, port: u16, default_port: u16) -> Target {
    Target::new(raw, if port == 0 { default_port } else { port })
}

fn build_server(o: &DnsServerOpts) -> Result<Upstream, String> {
    let detour = (!o.detour.is_empty()).then(|| o.detour.clone());
    Ok(match o.kind.as_str() {
        "local" => Upstream::Local,
        "fakeip" => Upstream::FakeIp(FakeIp::new(o)?),
        "tcp" => Upstream::Tcp { target: host_port(&o.server, o.server_port, 53), detour },
        // Через прокси UDP-DNS идёт по мультиплексированному TCP: один поток на все запросы.
        "udp" | "" => {
            let target = host_port(&o.server, o.server_port, 53);
            match (detour, target.ip()) {
                (None, Some(ip)) => Upstream::Udp(SocketAddr::new(ip, target.port)),
                (detour, _) => Upstream::Tcp { target, detour },
            }
        }
        // QUIC-варианты сведены к их TCP-родне: те же серверы их тоже слушают.
        "tls" | "quic" => {
            Upstream::Tls { target: host_port(&o.server, o.server_port, 853), sni: o.server.clone(), detour }
        }
        "https" | "h3" => Upstream::Https {
            target: host_port(&o.server, o.server_port, 443),
            sni: o.server.clone(),
            path: if o.path.is_empty() { "/dns-query".to_string() } else { o.path.clone() },
            detour,
        },
        other => return Err(format!("DNS-сервер типа {other} не поддержан")),
    })
}

pub struct Dns {
    servers: HashMap<String, Arc<Server>>,
    rules: DnsRules,
    final_server: String,
    ipv4_only: bool,
    prefer_ipv4: bool,
    next_id: AtomicU16,
    default_resolver: String,
}

static GLOBAL: RwLock<Option<Arc<Dns>>> = parking_lot::const_rwlock(None);

pub fn set_global(dns: Option<Arc<Dns>>) {
    *GLOBAL.write() = dns;
}

fn global() -> io::Result<Arc<Dns>> {
    GLOBAL.read().clone().ok_or_else(|| other("dns: не инициализирован"))
}

/// Адрес самого сервера: всегда через прямой резолвер, иначе петля.
pub async fn resolve_server(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let dns = global()?;
    let ips = dns.lookup_server(host).await?;
    Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
}

pub async fn resolve_direct(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let dns = global()?;
    let ips = dns.lookup_via(&dns.default_resolver, host).await?;
    Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
}

impl Dns {
    pub fn new(opts: &DnsOpts, default_resolver: &str, rules: DnsRules) -> Result<Self, String> {
        let mut servers = HashMap::with_capacity(opts.servers.len() + 1);
        for s in &opts.servers {
            let upstream = build_server(s).map_err(|e| format!("{}: {e}", s.tag))?;
            servers.insert(
                s.tag.clone(),
                Arc::new(Server {
                    tag: s.tag.clone(),
                    upstream,
                    mux: Default::default(),
                    dial_lock: Default::default(),
                    https_pool: Default::default(),
                    cache: Default::default(),
                    inflight: Default::default(),
                }),
            );
        }
        if servers.is_empty() {
            servers.insert(
                "local".to_string(),
                Arc::new(Server {
                    tag: "local".to_string(),
                    upstream: Upstream::Local,
                    mux: Default::default(),
                    dial_lock: Default::default(),
                    https_pool: Default::default(),
                    cache: Default::default(),
                    inflight: Default::default(),
                }),
            );
        }
        let pick = |tag: &str| -> String {
            if servers.contains_key(tag) {
                tag.to_string()
            } else {
                opts.servers.first().map(|s| s.tag.clone()).unwrap_or_else(|| "local".to_string())
            }
        };
        Ok(Self {
            final_server: pick(&opts.final_server),
            default_resolver: pick(default_resolver),
            servers,
            rules,
            ipv4_only: opts.strategy == "ipv4_only",
            prefer_ipv4: opts.strategy != "prefer_ipv6",
            next_id: AtomicU16::new(1),
        })
    }

    /// Ответить на перехваченный запрос. Ошибка сети становится SERVFAIL: клиент
    /// должен получить хоть что-то, иначе он повиснет на собственном таймауте.
    pub async fn handle_query(&self, query: &[u8], meta: &mut Meta) -> Vec<u8> {
        let Some((name, qtype, question_end)) = parse_question(query) else {
            return empty_reply(query, query.len().min(12), 1);
        };
        meta.domain = Some(name.clone());
        meta.query_type = Some(qtype);

        if self.ipv4_only && qtype == QTYPE_AAAA {
            return empty_reply(query, question_end, 0);
        }

        let server = match self.rules.evaluate(meta).await {
            DnsAction::Reject => return empty_reply(query, question_end, 3),
            DnsAction::Server(tag) => tag,
            DnsAction::Final => self.final_server.clone(),
        };
        let Some(server) = self.servers.get(&server).cloned() else {
            return empty_reply(query, question_end, 2);
        };

        if let Upstream::FakeIp(fake) = &server.upstream {
            if qtype == QTYPE_A || qtype == QTYPE_AAAA {
                let ip = fake.allocate(&name, qtype);
                return answer_with_ip(query, question_end, ip, 1);
            }
            return empty_reply(query, question_end, 0);
        }

        match self.exchange_cached(&server, query, &name, qtype).await {
            Ok(reply) => reply,
            Err(e) => {
                crate::debug!("dns", "{name}: {} — {e}", server.tag);
                empty_reply(query, question_end, 2)
            }
        }
    }

    /// Обратный поиск по fakeip: `None`, если fakeip не используется.
    pub fn fake_lookup(&self, ip: IpAddr) -> Option<String> {
        self.servers.values().find_map(|s| match &s.upstream {
            Upstream::FakeIp(fake) => fake.lookup(ip),
            _ => None,
        })
    }

    async fn exchange_cached(&self, server: &Arc<Server>, query: &[u8], name: &str, qtype: u16) -> io::Result<Vec<u8>> {
        let key = (name.to_string(), qtype);
        if let Some((cached, until)) = server.cache.lock().get(&key) {
            if *until > Instant::now() {
                let mut reply = cached.clone();
                if reply.len() >= 2 && query.len() >= 2 {
                    reply[..2].copy_from_slice(&query[..2]);
                }
                return Ok(reply);
            }
        }

        // Singleflight: если тот же запрос уже в пути, ждём его ответ вместо дубля.
        let tx = loop {
            enum Slot {
                Wait(broadcast::Receiver<Result<Vec<u8>, String>>),
                Leader(Arc<broadcast::Sender<Result<Vec<u8>, String>>>),
            }
            let slot = {
                let mut map = server.inflight.lock();
                if let Some(existing) = map.get(&key) {
                    Slot::Wait(existing.subscribe())
                } else {
                    let (tx, _) = broadcast::channel(1);
                    let tx = Arc::new(tx);
                    map.insert(key.clone(), tx.clone());
                    Slot::Leader(tx)
                }
            };
            match slot {
                Slot::Leader(tx) => break tx,
                Slot::Wait(mut rx) => {
                    if let Ok(result) = rx.recv().await {
                        return match result {
                            Ok(mut reply) => {
                                if reply.len() >= 2 && query.len() >= 2 {
                                    reply[..2].copy_from_slice(&query[..2]);
                                }
                                Ok(reply)
                            }
                            Err(msg) => Err(other(msg)),
                        };
                    }
                }
            }
        };
        let _guard = InflightGuard { map: &server.inflight, key: key.clone() };

        let result = self.exchange(server, query).await;
        match result {
            Ok(reply) => {
                if let Some(ttl_secs) = cache_ttl(&reply) {
                    let mut cache = server.cache.lock();
                    if cache.len() >= CACHE_MAX {
                        let now = Instant::now();
                        cache.retain(|_, (_, until)| *until > now);
                        if cache.len() >= CACHE_MAX {
                            cache.clear();
                        }
                    }
                    cache.insert(key, (reply.clone(), Instant::now() + Duration::from_secs(u64::from(ttl_secs))));
                }
                let _ = tx.send(Ok(reply.clone()));
                Ok(reply)
            }
            Err(e) => {
                let _ = tx.send(Err(e.to_string()));
                Err(e)
            }
        }
    }

    /// Адреса имени через конкретный сервер: для дозвона самого движка.
    pub async fn lookup_via(&self, tag: &str, name: &str) -> io::Result<Vec<IpAddr>> {
        self.lookup(tag, name, self.ipv4_only).await
    }

    /// Адреса нашего сервера — обеих семей даже при `ipv4_only`: тот запрет про
    /// туннель, а к серверу идём мимо него. IPv4 сервера в РФ режут поадресно,
    /// IPv6 того же сервера при этом живёт; дозвон IPv4 всё равно пробует первым.
    pub async fn lookup_server(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        self.lookup(&self.default_resolver, name, false).await
    }

    async fn lookup(&self, tag: &str, name: &str, ipv4_only: bool) -> io::Result<Vec<IpAddr>> {
        let server = self.servers.get(tag).ok_or_else(|| other(format!("dns: сервера {tag} нет")))?.clone();
        if matches!(server.upstream, Upstream::Local) {
            let addrs = tokio::net::lookup_host((name, 0u16)).await?;
            return Ok(addrs.map(|a| a.ip()).collect());
        }
        let ask = |qtype| {
            let server = &server;
            async move {
                let query = encode_query(name, qtype, self.next_id.fetch_add(1, Ordering::Relaxed));
                self.exchange_cached(server, &query, name, qtype).await
            }
        };
        let replies = if ipv4_only {
            vec![ask(QTYPE_A).await]
        } else {
            let (a, aaaa) = tokio::join!(ask(QTYPE_A), ask(QTYPE_AAAA));
            vec![a, aaaa]
        };
        let mut out = Vec::new();
        let mut last = None;
        for reply in replies {
            match reply {
                Ok(reply) => {
                    if let Some((ips, _)) = parse_answers(&reply) {
                        out.extend(ips);
                    }
                }
                Err(e) => last = Some(e),
            }
        }
        if out.is_empty() {
            return Err(last.unwrap_or_else(|| other(format!("dns: {name} не разрешилось"))));
        }
        if self.prefer_ipv4 {
            out.sort_by_key(|ip| !ip.is_ipv4());
        }
        Ok(out)
    }

    async fn exchange(&self, server: &Arc<Server>, query: &[u8]) -> io::Result<Vec<u8>> {
        tokio::time::timeout(QUERY_TIMEOUT, async {
            match &server.upstream {
                Upstream::Udp(addr) => exchange_udp(*addr, query).await,
                Upstream::Tcp { target, detour } => {
                    self.exchange_mux(server, target, None, detour.as_deref(), query).await
                }
                Upstream::Tls { target, sni, detour } => {
                    self.exchange_mux(server, target, Some(sni), detour.as_deref(), query).await
                }
                Upstream::Https { target, sni, path, detour } => {
                    self.exchange_https(server, target, sni, path, detour.as_deref(), query).await
                }
                Upstream::Local => Err(other("dns: локальный резолвер не отвечает на сырые запросы")),
                Upstream::FakeIp(_) => Err(other("dns: fakeip не пересылает запросы")),
            }
        })
        .await
        .map_err(|_| other("dns: таймаут"))?
    }

    async fn open(&self, target: &Target, detour: Option<&str>) -> io::Result<BoxStream> {
        if let Some(tag) = detour {
            let ctx = crate::engine::try_global().ok_or_else(|| other("dns: движок не запущен"))?;
            let (leaf, _) = ctx.outbounds.leaf(tag).ok_or_else(|| other(format!("dns: нет исходящего {tag}")))?;
            return leaf.dial(target).await;
        }
        let addrs = match &target.host {
            crate::common::Host::Ip(ip) => vec![SocketAddr::new(*ip, target.port)],
            // Box: сервер, заданный именем, разрешается через другой сервер — это рекурсия.
            crate::common::Host::Domain(d) => Box::pin(resolve_direct(d, target.port)).await?,
        };
        Ok(Box::new(tcp_connect_any(addrs).await?))
    }

    async fn open_mux(
        &self,
        server: &Arc<Server>,
        target: &Target,
        sni: Option<&String>,
        detour: Option<&str>,
    ) -> io::Result<Arc<MuxClient>> {
        let gen = current_gen(detour.is_some());
        if let Some(existing) = server.mux.lock().as_ref().filter(|m| m.usable(gen)).cloned() {
            return Ok(existing);
        }
        let _guard = server.dial_lock.lock().await;
        let gen = current_gen(detour.is_some());
        if let Some(existing) = server.mux.lock().as_ref().filter(|m| m.usable(gen)).cloned() {
            return Ok(existing);
        }
        let mut stream = self.open(target, detour).await?;
        if let Some(sni) = sni {
            let cfg = crate::tls::TlsConfig {
                sni: sni.clone(),
                alpn: vec!["dot".to_string()],
                insecure: false,
                fingerprint: "chrome".to_string(),
                reality: None,
                pq_advertise: false,
            };
            stream = Box::new(crate::tls::handshake(stream, &cfg).await?);
        }
        let mux = MuxClient::spawn(stream, gen);
        *server.mux.lock() = Some(mux.clone());
        Ok(mux)
    }

    async fn exchange_mux(
        &self,
        server: &Arc<Server>,
        target: &Target,
        sni: Option<&String>,
        detour: Option<&str>,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let gen = current_gen(detour.is_some());
        let existing = server.mux.lock().as_ref().filter(|m| m.usable(gen)).cloned();
        if let Some(mux) = existing {
            // Застарелое соединение, тихо сброшенное сервером, не должно сжигать весь
            // 5-секундный таймаут: короткий предел и немедленный перезвон.
            if let Ok(Ok(reply)) = tokio::time::timeout(MUX_REUSE_TIMEOUT, mux.query(query)).await {
                return Ok(reply);
            }
            mux.kill();
            let mut slot = server.mux.lock();
            if slot.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, &mux)) {
                *slot = None;
            }
        }

        let mux = self.open_mux(server, target, sni, detour).await?;
        match mux.query(query).await {
            Ok(reply) => Ok(reply),
            Err(e) => {
                mux.kill();
                let mut slot = server.mux.lock();
                if slot.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, &mux)) {
                    *slot = None;
                }
                Err(e)
            }
        }
    }

    async fn exchange_https(
        &self,
        server: &Arc<Server>,
        target: &Target,
        sni: &str,
        path: &str,
        detour: Option<&str>,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let gen = current_gen(detour.is_some());
        let pooled = {
            let mut pool = server.https_pool.lock();
            let now = Instant::now();
            pool.retain(|c| c.gen == gen && now.duration_since(c.used_at) < HTTPS_IDLE_TIMEOUT);
            pool.pop()
        };

        if let Some(mut conn) = pooled {
            if let Ok(Ok((body, keep_alive))) =
                tokio::time::timeout(MUX_REUSE_TIMEOUT, https_roundtrip(&mut conn.stream, sni, path, query)).await
            {
                if keep_alive {
                    let mut pool = server.https_pool.lock();
                    if pool.len() < HTTPS_POOL_MAX {
                        pool.push(HttpsConn { stream: conn.stream, used_at: Instant::now(), gen });
                    }
                }
                return Ok(body);
            }
        }

        let stream = self.open(target, detour).await?;
        let cfg = crate::tls::TlsConfig {
            sni: sni.to_string(),
            alpn: vec!["http/1.1".to_string()],
            insecure: false,
            fingerprint: "chrome".to_string(),
            reality: None,
            pq_advertise: false,
        };
        let mut stream: BoxStream = Box::new(crate::tls::handshake(stream, &cfg).await?);
        let (body, keep_alive) = https_roundtrip(&mut stream, sni, path, query).await?;
        if keep_alive {
            let mut pool = server.https_pool.lock();
            if pool.len() < HTTPS_POOL_MAX {
                pool.push(HttpsConn { stream, used_at: Instant::now(), gen });
            }
        }
        Ok(body)
    }
}

async fn https_roundtrip(stream: &mut BoxStream, sni: &str, path: &str, query: &[u8]) -> io::Result<(Vec<u8>, bool)> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {sni}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        query.len()
    );
    let mut req = Vec::with_capacity(head.len() + query.len());
    req.extend_from_slice(head.as_bytes());
    req.extend_from_slice(query);
    stream.write_all(&req).await?;
    stream.flush().await?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let split = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 16 * 1024 {
            return Err(invalid("doh: слишком длинные заголовки"));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "doh: соединение закрыто"));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head_str = String::from_utf8_lossy(&buf[..split]);
    if head_str.split_whitespace().nth(1) != Some("200") {
        return Err(invalid(format!("doh: {}", head_str.lines().next().unwrap_or(""))));
    }

    let mut content_len: Option<usize> = None;
    let mut chunked = false;
    let mut close = false;
    for line in head_str.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_len = value.parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        } else if name.eq_ignore_ascii_case("connection") && value.eq_ignore_ascii_case("close") {
            close = true;
        }
    }

    let body_start = split + 4;
    if let Some(len) = content_len {
        if len > 65_535 {
            return Err(invalid("doh: ответ слишком велик"));
        }
        while buf.len() < body_start + len {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "doh: ответ обрезан"));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        return Ok((buf[body_start..body_start + len].to_vec(), !close));
    }

    if chunked {
        let mut raw = buf[body_start..].to_vec();
        let mut out = Vec::new();
        let mut pos = 0;
        loop {
            let crlf = loop {
                if let Some(rel) = raw[pos..].windows(2).position(|w| w == b"\r\n") {
                    break pos + rel;
                }
                if raw.len() > 65_535 {
                    return Err(invalid("doh: ответ слишком велик"));
                }
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "doh: ответ обрезан"));
                }
                raw.extend_from_slice(&chunk[..n]);
            };
            let size_str = std::str::from_utf8(&raw[pos..crlf]).unwrap_or("").split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_str, 16).map_err(|_| invalid("doh: размер чанка"))?;
            pos = crlf + 2;
            if size == 0 {
                return Ok((out, !close));
            }
            while raw.len() < pos + size + 2 {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "doh: ответ обрезан"));
                }
                raw.extend_from_slice(&chunk[..n]);
            }
            out.extend_from_slice(&raw[pos..pos + size]);
            pos += size + 2;
        }
    }

    let mut rest = buf[body_start..].to_vec();
    stream.read_to_end(&mut rest).await?;
    Ok((rest, false))
}

async fn tcp_roundtrip(stream: &mut BoxStream, frame: &[u8]) -> io::Result<Vec<u8>> {
    stream.write_all(frame).await?;
    stream.flush().await?;
    let len = stream.read_u16().await? as usize;
    let mut reply = vec![0u8; len];
    stream.read_exact(&mut reply).await?;
    Ok(reply)
}

async fn exchange_udp(addr: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let socket = udp_socket(addr.is_ipv6())?;
    socket.connect(addr).await?;
    let mut buf = vec![0u8; 4096];
    // Быстрый первый повтор (800 мс), второй — запасной (1500 мс): потерянный
    // UDP-пакет не должен подвешивать открытие страницы на полторы секунды.
    for wait in [Duration::from_millis(800), Duration::from_millis(1500)] {
        socket.send(query).await?;
        match tokio::time::timeout(wait, socket.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                buf.truncate(n);
                // Обрезанный ответ (TC): добираем по TCP.
                if buf.get(2).is_some_and(|f| f & 0x02 != 0) {
                    let mut stream: BoxStream = Box::new(tcp_connect_any(vec![addr]).await?);
                    let mut frame = Vec::with_capacity(query.len() + 2);
                    frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
                    frame.extend_from_slice(query);
                    return tcp_roundtrip(&mut stream, &frame).await;
                }
                return Ok(buf);
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => continue,
        }
    }
    Err(other(format!("dns: {addr} не ответил")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip() {
        let q = encode_query("Example.COM", QTYPE_A, 7);
        let (name, qtype, end) = parse_question(&q).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(qtype, QTYPE_A);
        assert_eq!(end, q.len());
    }

    #[test]
    fn empty_reply_keeps_question_and_id() {
        let q = encode_query("a.b", QTYPE_AAAA, 0x1234);
        let (_, _, end) = parse_question(&q).unwrap();
        let reply = empty_reply(&q, end, 0);
        assert_eq!(&reply[..2], &[0x12, 0x34]);
        assert_eq!(reply[2] & 0x80, 0x80);
        assert_eq!(&reply[6..12], &[0; 6]);
        assert!(parse_answers(&reply).unwrap().0.is_empty());
    }

    #[test]
    fn answers_are_parsed_with_compression() {
        let q = encode_query("a.b", QTYPE_A, 1);
        let (_, _, end) = parse_question(&q).unwrap();
        let reply = answer_with_ip(&q, end, "1.2.3.4".parse().unwrap(), 300);
        let (ips, ttl) = parse_answers(&reply).unwrap();
        assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(ttl, 300);
    }

    #[test]
    fn cache_ttl_covers_nodata_nxdomain_and_non_address_records() {
        // Пустой AAAA (NODATA) и NXDOMAIN должны кэшироваться, SERVFAIL — нет.
        let q = encode_query("vpn.example", QTYPE_AAAA, 1);
        let (_, _, end) = parse_question(&q).unwrap();
        assert_eq!(cache_ttl(&empty_reply(&q, end, 0)), Some(NEG_DEFAULT_TTL));
        assert_eq!(cache_ttl(&empty_reply(&q, end, 3)), Some(NEG_DEFAULT_TTL));
        assert_eq!(cache_ttl(&empty_reply(&q, end, 2)), None);

        // HTTPS (65) запись в ответе тоже должна кэшироваться по своему TTL.
        let q = encode_query("example.com", 65, 2);
        let (_, _, end) = parse_question(&q).unwrap();
        let mut https = empty_reply(&q, end, 0);
        https[7] = 1;
        https.extend_from_slice(&[0xc0, 0x0c, 0, 65, 0, 1]);
        https.extend_from_slice(&120u32.to_be_bytes());
        https.extend_from_slice(&[0, 3, 0, 1, 0]);
        assert_eq!(cache_ttl(&https), Some(120));
    }

    #[test]
    fn hostile_packets_do_not_panic() {
        for packet in [&[][..], &[0; 11][..], &[0xff; 40][..]] {
            let _ = parse_question(packet);
            let _ = parse_answers(packet);
            let _ = cache_ttl(packet);
        }
        // Метка длиннее пакета и указатель вместо метки.
        let mut bad = vec![0u8; 12];
        bad.extend_from_slice(&[60, 1, 2]);
        assert!(parse_question(&bad).is_none());
        let mut ptr = vec![0u8; 12];
        ptr.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert!(parse_question(&ptr).is_none());
    }

    /// При `ipv4_only` (IPv6 туннеля выключен) адрес нашего сервера всё равно
    /// приходит обеих семей, IPv4 первым; чужие имена — только IPv4.
    #[tokio::test]
    async fn server_address_comes_in_both_families_under_ipv4_only() {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = upstream.recv_from(&mut buf).await {
                let Some((_, qtype, end)) = parse_question(&buf[..n]) else { continue };
                let ip: IpAddr = if qtype == QTYPE_AAAA { "::1".parse().unwrap() } else { "192.0.2.1".parse().unwrap() };
                let _ = upstream.send_to(&answer_with_ip(&buf[..n], end, ip, 60), from).await;
            }
        });
        let opts = DnsOpts {
            servers: vec![DnsServerOpts {
                kind: "udp".into(),
                tag: "direct".into(),
                server: upstream_addr.ip().to_string(),
                server_port: upstream_addr.port(),
                ..Default::default()
            }],
            strategy: "ipv4_only".into(),
            ..Default::default()
        };
        let rules = DnsRules::new(&[], &HashMap::new(), Arc::new(RwLock::new(String::new())));
        let dns = Dns::new(&opts, "direct", rules).unwrap();

        assert_eq!(dns.lookup_via("direct", "veil.test").await.unwrap(), ["192.0.2.1".parse::<IpAddr>().unwrap()]);
        let ips = dns.lookup_server("veil.test").await.unwrap();
        assert_eq!(ips, ["192.0.2.1".parse::<IpAddr>().unwrap(), "::1".parse().unwrap()]);
    }

    #[test]
    fn fake_ip_is_stable_and_reversible() {
        let fake = FakeIp::new(&DnsServerOpts::default()).unwrap();
        let a = fake.allocate("a.example", QTYPE_A);
        assert_eq!(a, fake.allocate("a.example", QTYPE_A));
        assert_ne!(a, fake.allocate("b.example", QTYPE_A));
        assert_eq!(fake.lookup(a).as_deref(), Some("a.example"));
        assert_eq!(fake.lookup("8.8.8.8".parse().unwrap()), None);
    }
}
