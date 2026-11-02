//! Адрес назначения в формате SOCKS5: atyp 1/3/4, адрес, порт.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addr {
    pub host: Host,
    pub port: u16,
}

impl Addr {
    pub fn from_socket(addr: SocketAddr) -> Self {
        // IPv4 в обёртке IPv6 возвращаем как IPv4: клиент слал на IPv4.
        let ip = match addr.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        Self { host: Host::Ip(ip), port: addr.port() }
    }

    pub fn write(&self, out: &mut Vec<u8>) {
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
                let len = d.len().min(255);
                out.push(3);
                out.push(len as u8);
                out.extend_from_slice(&d.as_bytes()[..len]);
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
    }

    /// Адрес из начала `data` и сколько байт он занял.
    pub fn read(data: &[u8]) -> Option<(Addr, usize)> {
        let (host, used) = match *data.first()? {
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
                if name.is_empty() {
                    return None;
                }
                (Host::Domain(name.to_ascii_lowercase()), 2 + len)
            }
            _ => return None,
        };
        let port = u16::from_be_bytes(data.get(used..used + 2)?.try_into().ok()?);
        Some((Addr { host, port }, used + 2))
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            Host::Ip(ip) => write!(f, "{ip}:{}", self.port),
            Host::Domain(d) => write!(f, "{d}:{}", self.port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for a in [
            Addr { host: Host::Ip("1.2.3.4".parse().unwrap()), port: 443 },
            Addr { host: Host::Ip("::1".parse().unwrap()), port: 53 },
            Addr { host: Host::Domain("example.com".into()), port: 80 },
        ] {
            let mut out = Vec::new();
            a.write(&mut out);
            out.extend_from_slice(b"tail");
            let (back, used) = Addr::read(&out).unwrap();
            assert_eq!(back, a);
            assert_eq!(&out[used..], b"tail");
        }
        assert!(Addr::read(&[3, 0, 0, 80]).is_none());
        assert!(Addr::read(&[9]).is_none());
    }
}
