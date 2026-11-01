//! Клиент SOCKS5. Главная роль — передача узлов в локальный Xray.

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::Outbound;
use crate::common::{invalid, other, tcp_connect, udp_socket, BoxStream, PacketConn, Target};
use crate::config::OutboundOpts;

pub struct Socks {
    tag: String,
    server: String,
    port: u16,
    username: String,
    password: String,
}

impl Socks {
    pub fn new(o: &OutboundOpts) -> Self {
        Self {
            tag: o.tag.clone(),
            server: o.server.clone(),
            port: o.server_port,
            username: o.username.clone(),
            password: o.password.clone(),
        }
    }

    async fn connect(&self) -> io::Result<TcpStream> {
        let addrs = crate::dns::resolve_server(&self.server, self.port).await?;
        let addr = *addrs.first().ok_or_else(|| other("socks: нет адреса"))?;
        tcp_connect(addr).await
    }

    async fn greet(&self, stream: &mut TcpStream) -> io::Result<()> {
        if self.username.is_empty() {
            stream.write_all(&[5, 1, 0]).await?;
        } else {
            stream.write_all(&[5, 2, 0, 2]).await?;
        }
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        if reply[0] != 5 {
            return Err(invalid("socks: не SOCKS5"));
        }
        match reply[1] {
            0 => Ok(()),
            2 => {
                let mut auth = vec![1, self.username.len() as u8];
                auth.extend_from_slice(self.username.as_bytes());
                auth.push(self.password.len() as u8);
                auth.extend_from_slice(self.password.as_bytes());
                stream.write_all(&auth).await?;
                stream.read_exact(&mut reply).await?;
                if reply[1] != 0 {
                    return Err(other("socks: неверный логин или пароль"));
                }
                Ok(())
            }
            _ => Err(other("socks: сервер не принял ни один способ входа")),
        }
    }

    async fn request(&self, stream: &mut TcpStream, cmd: u8, target: &Target) -> io::Result<Target> {
        let mut req = vec![5, cmd, 0];
        target.write_socks(&mut req);
        stream.write_all(&req).await?;
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        if head[1] != 0 {
            return Err(other(format!("socks: отказ {}", head[1])));
        }
        let mut addr = vec![head[3]];
        match head[3] {
            1 => addr.resize(1 + 4 + 2, 0),
            4 => addr.resize(1 + 16 + 2, 0),
            3 => {
                let len = stream.read_u8().await? as usize;
                addr.push(len as u8);
                addr.resize(2 + len + 2, 0);
                let start = 2;
                stream.read_exact(&mut addr[start..]).await?;
                return Target::read_socks(&addr).map(|(t, _)| t).ok_or_else(|| invalid("socks: адрес в ответе"));
            }
            _ => return Err(invalid("socks: тип адреса в ответе")),
        }
        stream.read_exact(&mut addr[1..]).await?;
        Target::read_socks(&addr).map(|(t, _)| t).ok_or_else(|| invalid("socks: адрес в ответе"))
    }
}

#[async_trait]
impl Outbound for Socks {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "socks"
    }

    async fn dial(&self, target: &Target) -> io::Result<BoxStream> {
        let mut stream = self.connect().await?;
        self.greet(&mut stream).await?;
        self.request(&mut stream, 1, target).await?;
        Ok(Box::new(stream))
    }

    async fn dial_udp(&self, target: &Target) -> io::Result<Box<dyn PacketConn>> {
        let mut control = self.connect().await?;
        self.greet(&mut control).await?;
        let bound = self.request(&mut control, 3, &Target::new("0.0.0.0", 0)).await?;
        let relay = match bound.ip() {
            Some(ip) if !ip.is_unspecified() => SocketAddr::new(ip, bound.port),
            _ => SocketAddr::new(control.peer_addr()?.ip(), bound.port),
        };
        let _ = target;
        // Петля живёт сама по себе: привязка к физическому интерфейсу её сломает.
        let socket = if relay.ip().is_loopback() {
            UdpSocket::bind(SocketAddr::new(relay.ip(), 0)).await?
        } else {
            udp_socket(relay.is_ipv6())?
        };
        Ok(Box::new(SocksPacket { socket, relay, _control: control }))
    }
}

struct SocksPacket {
    socket: UdpSocket,
    relay: SocketAddr,
    /// Живёт, пока живёт сессия: закрытие TCP завершает ассоциацию (RFC 1928).
    _control: TcpStream,
}

#[async_trait]
impl PacketConn for SocksPacket {
    async fn send(&self, data: &[u8], to: &Target) -> io::Result<()> {
        let mut packet = Vec::with_capacity(data.len() + 32);
        packet.extend_from_slice(&[0, 0, 0]);
        to.write_socks(&mut packet);
        packet.extend_from_slice(data);
        self.socket.send_to(&packet, self.relay).await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        loop {
            let n = self.socket.recv(buf).await?;
            if n < 4 || buf[2] != 0 {
                continue; // фрагментация SOCKS5 никем не используется
            }
            let Some((from, used)) = Target::read_socks(&buf[3..n]) else { continue };
            let start = 3 + used;
            buf.copy_within(start..n, 0);
            return Ok((n - start, from));
        }
    }
}
