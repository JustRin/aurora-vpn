//! Общие типы: адрес назначения, потоки, дозвон мимо собственного туннеля.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type BoxStream = Box<dyn AsyncStream>;

pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl Target {
    pub fn new(host: &str, port: u16) -> Self {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let host = match bare.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(bare.to_ascii_lowercase()),
        };
        Self { host, port }
    }

    pub fn from_addr(addr: SocketAddr) -> Self {
        Self { host: Host::Ip(addr.ip()), port: addr.port() }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self.host {
            Host::Ip(ip) => Some(ip),
            Host::Domain(_) => None,
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match &self.host {
            Host::Ip(_) => None,
            Host::Domain(d) => Some(d),
        }
    }

    /// Формат адреса SOCKS5 (и Trojan, и Shadowsocks): atyp 1/3/4, адрес, порт.
    pub fn write_socks(&self, out: &mut Vec<u8>) {
        match &self.host {
            Host::Ip(IpAddr::V4(ip)) => {
                out.push(1);
                out.extend_from_slice(&ip.octets());
            }
            Host::Ip(IpAddr::V6(ip)) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
            }
            Host::Domain(d) => {
                out.push(3);
                out.push(d.len().min(255) as u8);
                out.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
    }

    /// Разбор формата SOCKS5 из начала `data`: цель и сколько байт она заняла.
    pub fn read_socks(data: &[u8]) -> Option<(Target, usize)> {
        let atyp = *data.first()?;
        let (host, used) = match atyp {
            1 => {
                let o: [u8; 4] = data.get(1..5)?.try_into().ok()?;
                (Host::Ip(IpAddr::from(o)), 5)
            }
            4 => {
                let o: [u8; 16] = data.get(1..17)?.try_into().ok()?;
                (Host::Ip(IpAddr::from(o)), 17)
            }
            3 => {
                let len = *data.get(1)? as usize;
                let name = std::str::from_utf8(data.get(2..2 + len)?).ok()?;
                (Host::Domain(name.to_ascii_lowercase()), 2 + len)
            }
            _ => return None,
        };
        let port = u16::from_be_bytes(data.get(used..used + 2)?.try_into().ok()?);
        Some((Target { host, port }, used + 2))
    }

    /// Порядок VMess/VLESS/XUDP: порт, затем atyp 1/2/3 и адрес.
    pub fn write_vless(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.port.to_be_bytes());
        match &self.host {
            Host::Ip(IpAddr::V4(ip)) => {
                out.push(1);
                out.extend_from_slice(&ip.octets());
            }
            Host::Domain(d) => {
                out.push(2);
                out.push(d.len().min(255) as u8);
                out.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
            }
            Host::Ip(IpAddr::V6(ip)) => {
                out.push(3);
                out.extend_from_slice(&ip.octets());
            }
        }
    }

    pub fn read_vless(data: &[u8]) -> Option<(Target, usize)> {
        let port = u16::from_be_bytes(data.get(..2)?.try_into().ok()?);
        let (host, used) = match *data.get(2)? {
            1 => {
                let o: [u8; 4] = data.get(3..7)?.try_into().ok()?;
                (Host::Ip(IpAddr::from(o)), 7)
            }
            2 => {
                let len = *data.get(3)? as usize;
                let name = std::str::from_utf8(data.get(4..4 + len)?).ok()?;
                (Host::Domain(name.to_string()), 4 + len)
            }
            3 => {
                let o: [u8; 16] = data.get(3..19)?.try_into().ok()?;
                (Host::Ip(IpAddr::from(o)), 19)
            }
            _ => return None,
        };
        Some((Target { host, port }, used))
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            Host::Ip(ip) => write!(f, "{ip}:{}", self.port),
            Host::Domain(d) => write!(f, "{d}:{}", self.port),
        }
    }
}

/// UDP-сессия через исходящий. Обе половины — от `&self`: отправка и приём живут
/// в разных задачах.
#[async_trait]
pub trait PacketConn: Send + Sync {
    async fn send(&self, data: &[u8], to: &Target) -> io::Result<()>;
    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Target)>;
}

// ------------------------------------------------------------- мимо туннеля

/// Индекс физического интерфейса; 0 — привязка не нужна (туннеля нет).
static BYPASS_IF_V4: AtomicU32 = AtomicU32::new(0);
static BYPASS_IF_V6: AtomicU32 = AtomicU32::new(0);

pub fn set_bypass_interface(v4: u32, v6: u32) {
    BYPASS_IF_V4.store(v4, Ordering::Relaxed);
    BYPASS_IF_V6.store(v6, Ordering::Relaxed);
}

/// Прибить сокет к физическому интерфейсу, иначе дозвон уйдёт в наш же TUN.
#[cfg(windows)]
fn bind_bypass(raw: std::os::windows::io::RawSocket, v6: bool) -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF};
    let index = if v6 { BYPASS_IF_V6.load(Ordering::Relaxed) } else { BYPASS_IF_V4.load(Ordering::Relaxed) };
    if index == 0 {
        return Ok(());
    }
    // У v4 индекс в сетевом порядке, у v6 — в родном: так описано в MSDN.
    let (level, name, value) = if v6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    } else {
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    };
    let rc = unsafe {
        setsockopt(raw as usize, level, name, &value as *const u32 as *const u8, std::mem::size_of::<u32>() as i32)
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Android: сокет движка выводит из VPN сам VpnService (`protect`), иначе дозвон
/// до сервера уйдёт в собственный туннель и замкнётся в петлю. Хук ставит
/// приложение; без него (ПК, стенд) ничего не происходит. Ошибка хука срывает
/// дозвон: лучше отказ, чем петля.
#[cfg(unix)]
pub type Protector = std::sync::Arc<dyn Fn(i32) -> io::Result<()> + Send + Sync>;

#[cfg(unix)]
static PROTECTOR: std::sync::RwLock<Option<Protector>> = std::sync::RwLock::new(None);

#[cfg(unix)]
pub fn set_socket_protector(protector: Option<Protector>) {
    *PROTECTOR.write().unwrap_or_else(|e| e.into_inner()) = protector;
}

#[cfg(unix)]
fn protector() -> Option<Protector> {
    PROTECTOR.read().unwrap_or_else(|e| e.into_inner()).clone()
}

pub async fn tcp_connect(addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        // Петля живёт сама по себе: привязка к физическому интерфейсу её сломает.
        if !addr.ip().is_loopback() {
            bind_bypass(socket.as_raw_socket(), addr.is_ipv6())?;
        }
    }
    #[cfg(unix)]
    if let Some(protect) = protector().filter(|_| !addr.ip().is_loopback()) {
        use std::os::fd::AsRawFd;
        // Хук ходит в Kotlin и ждёт ответа: не на потоке рантайма.
        let fd = socket.as_raw_fd();
        tokio::task::spawn_blocking(move || protect(fd)).await.map_err(io::Error::other)??;
    }
    let stream = tokio::time::timeout(DIAL_TIMEOUT, socket.connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("дозвон до {addr}: таймаут")))??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Через сколько стартует дозвон по следующему адресу, пока предыдущий молчит.
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Дозвон по списку адресов «счастливыми глазами» (RFC 8305): следующий адрес
/// стартует, если предыдущие молчат 250 мс или уже отказали, побеждает первый
/// ответивший. IPv4 сервера в РФ режут поадресно — SYN пропадает молча, и
/// поочерёдный дозвон ждал бы весь `DIAL_TIMEOUT`, хотя IPv6 того же сервера жив.
pub async fn tcp_connect_any(addrs: Vec<SocketAddr>) -> io::Result<TcpStream> {
    race(addrs, tcp_connect).await
}

async fn race<T, F, Fut>(addrs: Vec<SocketAddr>, dial: F) -> io::Result<T>
where
    T: Send + 'static,
    F: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<T>> + Send + 'static,
{
    let mut queue = interleave(addrs).into_iter().take(4);
    let mut attempts = tokio::task::JoinSet::new();
    let mut last = None;
    loop {
        if attempts.is_empty() {
            match queue.next() {
                Some(addr) => {
                    attempts.spawn(dial(addr));
                }
                None => return Err(last.unwrap_or_else(|| other("нет адресов для дозвона"))),
            }
        }
        tokio::select! {
            done = attempts.join_next() => match done {
                Some(Ok(Ok(stream))) => return Ok(stream),
                Some(Ok(Err(e))) => {
                    last = Some(e);
                    if let Some(addr) = queue.next() {
                        attempts.spawn(dial(addr));
                    }
                }
                Some(Err(e)) => last = Some(io::Error::other(e)),
                None => {}
            },
            _ = tokio::time::sleep(ATTEMPT_DELAY) => {
                if let Some(addr) = queue.next() {
                    attempts.spawn(dial(addr));
                }
            }
        }
    }
}

/// Семьи вперемешку, начиная с семьи первого адреса: два IPv4 подряд не должны
/// оттянуть IPv6.
fn interleave(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let first_v6 = addrs.first().is_some_and(SocketAddr::is_ipv6);
    let (mut same, mut other): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv6() == first_v6);
    same.reverse();
    other.reverse();
    let mut out = Vec::with_capacity(same.len() + other.len());
    while !same.is_empty() || !other.is_empty() {
        out.extend(same.pop());
        out.extend(other.pop());
    }
    out
}

pub fn udp_std_socket(v6: bool) -> io::Result<std::net::UdpSocket> {
    let domain = if v6 { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        bind_bypass(socket.as_raw_socket(), v6)?;
    }
    #[cfg(unix)]
    if let Some(protect) = protector() {
        use std::os::fd::AsRawFd;
        protect(socket.as_raw_fd())?;
    }
    let any: SocketAddr = if v6 { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    socket.bind(&any.into())?;
    Ok(socket.into())
}

pub fn udp_socket(v6: bool) -> io::Result<UdpSocket> {
    UdpSocket::from_std(udp_std_socket(v6)?)
}

pub fn other(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

pub fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// UUID в 16 байт; нестандартную строку xray/sing-box превращают в UUIDv5 от
/// нулевого пространства имён (`sha1(0…0 + текст)`).
pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() == 32 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 16];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        return Some(out);
    }
    if text.is_empty() || text.len() > 30 {
        return None;
    }
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(&[0u8; 16]);
    ctx.update(text.as_bytes());
    let digest = ctx.finish();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_ref()[..16]);
    out[6] = (out[6] & 0x0f) | 0x50;
    out[8] = (out[8] & 0x3f) | 0x80;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_address_roundtrip() {
        for t in [Target::new("1.2.3.4", 80), Target::new("example.com", 443), Target::new("::1", 53)] {
            let mut out = Vec::new();
            t.write_socks(&mut out);
            let (back, used) = Target::read_socks(&out).unwrap();
            assert_eq!(back, t);
            assert_eq!(used, out.len());
        }
    }

    #[test]
    fn vless_address_roundtrip() {
        for t in [Target::new("1.2.3.4", 80), Target::new("example.com", 443), Target::new("::1", 53)] {
            let mut out = Vec::new();
            t.write_vless(&mut out);
            let (back, used) = Target::read_vless(&out).unwrap();
            assert_eq!(back, t);
            assert_eq!(used, out.len());
        }
    }

    #[test]
    fn truncated_addresses_do_not_panic() {
        for data in [&[][..], &[1, 2][..], &[3, 200, 1][..], &[9, 9, 9][..]] {
            assert!(Target::read_socks(data).is_none());
        }
    }

    #[test]
    fn families_are_interleaved() {
        let a: Vec<SocketAddr> = ["1.1.1.1:1", "2.2.2.2:1", "[::1]:1", "[::2]:1", "3.3.3.3:1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let got: Vec<String> = interleave(a).iter().map(ToString::to_string).collect();
        assert_eq!(got, ["1.1.1.1:1", "[::1]:1", "2.2.2.2:1", "[::2]:1", "3.3.3.3:1"]);
    }

    /// IPv4 молчит (как SYN на перекрытый адрес), IPv6 отвечает: дозвон не ждёт
    /// таймаута первого. Дозвон подменён: под живым TUN на машине любой адрес
    /// «отвечает» сразу.
    #[tokio::test]
    async fn silent_address_does_not_stall_the_dial() {
        let silent: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let live: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let dial = move |addr: SocketAddr| async move {
            if addr == silent {
                std::future::pending::<()>().await;
            }
            Ok(addr)
        };
        let started = std::time::Instant::now();
        assert_eq!(race(vec![silent, live], dial).await.unwrap(), live);
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());

        // Отказ — следующий адрес сразу, без задержки.
        let refuse = |addr: SocketAddr| async move {
            if addr.is_ipv4() {
                return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
            }
            Ok(addr)
        };
        let started = std::time::Instant::now();
        assert_eq!(race(vec![silent, live], refuse).await.unwrap(), live);
        assert!(started.elapsed() < ATTEMPT_DELAY, "{:?}", started.elapsed());

        let error = race(vec![silent], refuse).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert!(tcp_connect_any(Vec::new()).await.is_err());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        assert_eq!(tcp_connect_any(vec![local]).await.unwrap().peer_addr().unwrap(), local);
    }

    #[test]
    fn uuid_parsing() {
        let u = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        assert_eq!(u[0], 0xb8);
        assert_eq!(u[15], 0x11);
        // Строка вместо UUID: версия 5, вариант RFC 4122.
        let v = parse_uuid("hello").unwrap();
        assert_eq!(v[6] >> 4, 5);
        assert_eq!(v[8] >> 6, 2);
    }
}
