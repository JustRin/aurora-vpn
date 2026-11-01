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
    let stream = tokio::time::timeout(DIAL_TIMEOUT, socket.connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("дозвон до {addr}: таймаут")))??;
    stream.set_nodelay(true)?;
    Ok(stream)
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
