//! DNS: перехваченные запросы, правила, кэш и резолвинг для самого движка.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{invalid, other, tcp_connect, udp_socket, BoxStream, Target};
use crate::config::{DnsOpts, DnsServerOpts};
use crate::router::{DnsAction, DnsRules, Meta};

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_MAX: usize = 4096;
const MIN_TTL: u32 = 10;
const MAX_TTL: u32 = 3600;

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
    /// DNS-over-TCP: прямо или через исходящий (`detour`). Через прокси DNS идёт
    /// именно так: по TCP соединение переживает несколько запросов, а UDP через
    /// большинство протоколов — лишнее рукопожатие на каждый.
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

struct Server {
    tag: String,
    upstream: Upstream,
    /// Живое соединение для TCP/TLS: DNS — короткие и частые запросы.
    pool: tokio::sync::Mutex<Option<BoxStream>>,
    cache: Mutex<HashMap<(String, u16), (Vec<u8>, Instant)>>,
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
        // Через прокси UDP-DNS не имеет смысла, см. `Upstream::Tcp`.
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
    resolve_direct(host, port).await
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
                    pool: Default::default(),
                    cache: Default::default(),
                }),
            );
        }
        if servers.is_empty() {
            servers.insert(
                "local".to_string(),
                Arc::new(Server {
                    tag: "local".to_string(),
                    upstream: Upstream::Local,
                    pool: Default::default(),
                    cache: Default::default(),
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
                reply[..2].copy_from_slice(&query[..2]);
                return Ok(reply);
            }
        }
        let reply = self.exchange(server, query).await?;
        if let Some((_, ttl)) = parse_answers(&reply) {
            if ttl != u32::MAX && reply.get(3).is_some_and(|rc| rc & 0x0f == 0) {
                let mut cache = server.cache.lock();
                if cache.len() >= CACHE_MAX {
                    let now = Instant::now();
                    cache.retain(|_, (_, until)| *until > now);
                    if cache.len() >= CACHE_MAX {
                        cache.clear();
                    }
                }
                let ttl = Duration::from_secs(u64::from(ttl.clamp(MIN_TTL, MAX_TTL)));
                cache.insert(key, (reply.clone(), Instant::now() + ttl));
            }
        }
        Ok(reply)
    }

    /// Адреса имени через конкретный сервер: для дозвона самого движка.
    pub async fn lookup_via(&self, tag: &str, name: &str) -> io::Result<Vec<IpAddr>> {
        let server = self.servers.get(tag).ok_or_else(|| other(format!("dns: сервера {tag} нет")))?.clone();
        if matches!(server.upstream, Upstream::Local) {
            let addrs = tokio::net::lookup_host((name, 0u16)).await?;
            return Ok(addrs.map(|a| a.ip()).collect());
        }
        let mut out = Vec::new();
        let types: &[u16] = if self.ipv4_only { &[QTYPE_A] } else { &[QTYPE_A, QTYPE_AAAA] };
        let mut last = None;
        for &qtype in types {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let query = encode_query(name, qtype, id);
            match self.exchange_cached(&server, &query, name, qtype).await {
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
                    self.exchange_stream(server, target, None, detour.as_deref(), query).await
                }
                Upstream::Tls { target, sni, detour } => {
                    self.exchange_stream(server, target, Some(sni), detour.as_deref(), query).await
                }
                Upstream::Https { target, sni, path, detour } => {
                    self.exchange_https(target, sni, path, detour.as_deref(), query).await
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
        let addr = *addrs.first().ok_or_else(|| other("dns: нет адреса сервера"))?;
        Ok(Box::new(tcp_connect(addr).await?))
    }

    async fn exchange_stream(
        &self,
        server: &Arc<Server>,
        target: &Target,
        sni: Option<&String>,
        detour: Option<&str>,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        // Сначала живое соединение из пула; упало — один раз дозваниваемся заново.
        let pooled = server.pool.lock().await.take();
        let mut frame = Vec::with_capacity(query.len() + 2);
        frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
        frame.extend_from_slice(query);

        if let Some(mut stream) = pooled {
            if let Ok(reply) = tcp_roundtrip(&mut stream, &frame).await {
                *server.pool.lock().await = Some(stream);
                return Ok(reply);
            }
        }

        let mut stream = self.open(target, detour).await?;
        if let Some(sni) = sni {
            let cfg = crate::tls::TlsConfig {
                sni: sni.clone(),
                alpn: vec!["dot".to_string()],
                insecure: false,
                fingerprint: "chrome".to_string(),
                reality: None,
            };
            stream = Box::new(crate::tls::handshake(stream, &cfg).await?);
        }
        let reply = tcp_roundtrip(&mut stream, &frame).await?;
        *server.pool.lock().await = Some(stream);
        Ok(reply)
    }

    async fn exchange_https(
        &self,
        target: &Target,
        sni: &str,
        path: &str,
        detour: Option<&str>,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let stream = self.open(target, detour).await?;
        let cfg = crate::tls::TlsConfig {
            sni: sni.to_string(),
            alpn: vec!["http/1.1".to_string()],
            insecure: false,
            fingerprint: "chrome".to_string(),
            reality: None,
        };
        let mut stream = crate::tls::handshake(stream, &cfg).await?;
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: {sni}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            query.len()
        );
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(query).await?;
        stream.flush().await?;
        let mut reply = Vec::with_capacity(1024);
        stream.read_to_end(&mut reply).await?;
        let split = reply.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| invalid("doh: нет конца заголовков"))?;
        let head = String::from_utf8_lossy(&reply[..split]);
        if head.split_whitespace().nth(1) != Some("200") {
            return Err(invalid(format!("doh: {}", head.lines().next().unwrap_or(""))));
        }
        Ok(reply[split + 4..].to_vec())
    }
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
    // Один повтор: UDP теряется, а клиент ждать не должен.
    for _ in 0..2 {
        socket.send(query).await?;
        match tokio::time::timeout(Duration::from_millis(1500), socket.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                buf.truncate(n);
                // Обрезанный ответ (TC): добираем по TCP.
                if buf.get(2).is_some_and(|f| f & 0x02 != 0) {
                    let mut stream: BoxStream = Box::new(tcp_connect(addr).await?);
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
    fn hostile_packets_do_not_panic() {
        for packet in [&[][..], &[0; 11][..], &[0xff; 40][..]] {
            let _ = parse_question(packet);
            let _ = parse_answers(packet);
        }
        // Метка длиннее пакета и указатель вместо метки.
        let mut bad = vec![0u8; 12];
        bad.extend_from_slice(&[60, 1, 2]);
        assert!(parse_question(&bad).is_none());
        let mut ptr = vec![0u8; 12];
        ptr.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert!(parse_question(&ptr).is_none());
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
