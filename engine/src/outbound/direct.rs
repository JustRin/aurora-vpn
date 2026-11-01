//! `direct` и `block`.

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use super::Outbound;
use crate::common::{other, tcp_connect, udp_socket, BoxStream, Host, PacketConn, Target};

pub struct Direct {
    tag: String,
}

impl Direct {
    pub fn new(tag: &str) -> Self {
        Self { tag: tag.to_string() }
    }
}

async fn resolve(target: &Target) -> io::Result<Vec<SocketAddr>> {
    match &target.host {
        Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, target.port)]),
        Host::Domain(name) => crate::dns::resolve_direct(name, target.port).await,
    }
}

#[async_trait]
impl Outbound for Direct {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "direct"
    }

    async fn dial(&self, target: &Target) -> io::Result<BoxStream> {
        let mut last = None;
        for addr in resolve(target).await?.into_iter().take(3) {
            match tcp_connect(addr).await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| other(format!("{target}: нет адресов"))))
    }

    async fn dial_udp(&self, target: &Target) -> io::Result<Box<dyn PacketConn>> {
        let v6 = resolve(target).await?.first().is_some_and(SocketAddr::is_ipv6);
        Ok(Box::new(DirectPacket { socket: udp_socket(v6)? }))
    }
}

struct DirectPacket {
    socket: UdpSocket,
}

#[async_trait]
impl PacketConn for DirectPacket {
    async fn send(&self, data: &[u8], to: &Target) -> io::Result<()> {
        let addr = *resolve(to).await?.first().ok_or_else(|| other("нет адреса"))?;
        self.socket.send_to(data, addr).await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let (n, from) = self.socket.recv_from(buf).await?;
        Ok((n, Target::from_addr(from)))
    }
}

pub struct Block {
    tag: String,
}

impl Block {
    pub fn new(tag: &str) -> Self {
        Self { tag: tag.to_string() }
    }
}

#[async_trait]
impl Outbound for Block {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "block"
    }
    async fn dial(&self, _: &Target) -> io::Result<BoxStream> {
        Err(other("заблокировано"))
    }
}
