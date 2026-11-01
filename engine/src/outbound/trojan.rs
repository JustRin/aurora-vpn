//! Trojan: hex(sha224(пароль)) CRLF команда адрес CRLF, дальше чистый поток.

use std::io;

use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::Outbound;
use crate::common::{invalid, BoxStream, PacketConn, Target};
use crate::config::OutboundOpts;
use crate::transport::{EarlyWrite, Halves, Upstream};

pub struct Trojan {
    tag: String,
    key: [u8; 56],
    upstream: Upstream,
}

impl Trojan {
    pub fn new(o: &OutboundOpts) -> Result<Self, String> {
        let digest = Sha224::digest(o.password.as_bytes());
        let mut key = [0u8; 56];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, byte) in digest.iter().enumerate() {
            key[i * 2] = HEX[(byte >> 4) as usize];
            key[i * 2 + 1] = HEX[(byte & 15) as usize];
        }
        Ok(Self { tag: o.tag.clone(), key, upstream: Upstream::from_opts(o)? })
    }

    fn header(&self, cmd: u8, target: &Target) -> Vec<u8> {
        let mut out = Vec::with_capacity(56 + 2 + 1 + 262 + 2);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(b"\r\n");
        out.push(cmd);
        target.write_socks(&mut out);
        out.extend_from_slice(b"\r\n");
        out
    }
}

#[async_trait]
impl Outbound for Trojan {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "trojan"
    }

    async fn dial(&self, target: &Target) -> io::Result<BoxStream> {
        let stream = self.upstream.open().await?;
        Ok(Box::new(EarlyWrite::new(stream, self.header(1, target))))
    }

    async fn dial_udp(&self, target: &Target) -> io::Result<Box<dyn PacketConn>> {
        let mut stream = self.upstream.open().await?;
        stream.write_all(&self.header(3, target)).await?;
        Ok(Box::new(TrojanPacket(Halves::new(stream))))
    }
}

/// Кадр UDP: адрес, длина, CRLF, данные.
struct TrojanPacket(Halves);

#[async_trait]
impl PacketConn for TrojanPacket {
    async fn send(&self, data: &[u8], to: &Target) -> io::Result<()> {
        let mut frame = Vec::with_capacity(data.len() + 32);
        to.write_socks(&mut frame);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(data);
        let mut write = self.0.write.lock().await;
        write.write_all(&frame).await?;
        write.flush().await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let mut read = self.0.read.lock().await;
        let atyp = read.read_u8().await?;
        let mut raw = vec![atyp];
        match atyp {
            1 => raw.resize(1 + 4 + 2, 0),
            4 => raw.resize(1 + 16 + 2, 0),
            3 => {
                let len = read.read_u8().await?;
                raw.push(len);
                raw.resize(2 + len as usize + 2, 0);
            }
            _ => return Err(invalid("trojan: тип адреса")),
        }
        let start = if atyp == 3 { 2 } else { 1 };
        read.read_exact(&mut raw[start..]).await?;
        let (from, _) = Target::read_socks(&raw).ok_or_else(|| invalid("trojan: адрес"))?;
        let len = read.read_u16().await? as usize;
        let mut crlf = [0u8; 2];
        read.read_exact(&mut crlf).await?;
        if len > buf.len() {
            return Err(invalid("trojan: пакет больше буфера"));
        }
        read.read_exact(&mut buf[..len]).await?;
        Ok((len, from))
    }
}
