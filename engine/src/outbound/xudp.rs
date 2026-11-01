//! XUDP: UDP-поверх-потока у VLESS и VMess (кадры Mux.Cool с одной сессией).

use std::io;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{invalid, BoxStream, PacketConn, Target};
use crate::transport::Halves;

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const OPTION_DATA: u8 = 1;
const NETWORK_UDP: u8 = 2;

pub struct XudpConn {
    halves: Halves,
    started: std::sync::atomic::AtomicBool,
}

impl XudpConn {
    pub fn new(stream: BoxStream) -> Self {
        Self { halves: Halves::new(stream), started: false.into() }
    }
}

/// Кадр на отправку. `first` — первый пакет сессии: статус New и глобальный ID.
pub fn encode(first: bool, data: &[u8], to: &Target) -> Vec<u8> {
    let mut meta = Vec::with_capacity(32);
    meta.extend_from_slice(&[0, 0]); // id сессии
    meta.push(if first { STATUS_NEW } else { STATUS_KEEP });
    meta.push(OPTION_DATA);
    meta.push(NETWORK_UDP);
    to.write_vless(&mut meta);
    if first {
        meta.extend_from_slice(&[0u8; 8]); // global id: нулевой, как у sing-box
    }
    let mut frame = Vec::with_capacity(meta.len() + data.len() + 4);
    frame.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    frame.extend_from_slice(&meta);
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

/// Метаданные входящего кадра: `(статус, есть данные, адрес)`.
pub fn parse_meta(meta: &[u8]) -> Option<(u8, bool, Option<Target>)> {
    let status = *meta.get(2)?;
    let option = *meta.get(3)?;
    let from = if meta.len() > 5 && meta[4] == NETWORK_UDP {
        Target::read_vless(&meta[5..]).map(|(t, _)| t)
    } else {
        None
    };
    Some((status, option & OPTION_DATA != 0, from))
}

#[async_trait]
impl PacketConn for XudpConn {
    async fn send(&self, data: &[u8], to: &Target) -> io::Result<()> {
        let first = !self.started.swap(true, std::sync::atomic::Ordering::AcqRel);
        let frame = encode(first, data, to);
        let mut write = self.halves.write.lock().await;
        write.write_all(&frame).await?;
        write.flush().await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let mut read = self.halves.read.lock().await;
        let mut last_from = Target::new("0.0.0.0", 0);
        loop {
            let meta_len = read.read_u16().await? as usize;
            if !(4..=512).contains(&meta_len) {
                return Err(invalid(format!("xudp: длина метаданных {meta_len}")));
            }
            let mut meta = [0u8; 512];
            read.read_exact(&mut meta[..meta_len]).await?;
            let (status, has_data, from) =
                parse_meta(&meta[..meta_len]).ok_or_else(|| invalid("xudp: метаданные"))?;
            if let Some(from) = from {
                last_from = from;
            }
            if has_data {
                let len = read.read_u16().await? as usize;
                if len > buf.len() {
                    return Err(invalid("xudp: пакет больше буфера"));
                }
                read.read_exact(&mut buf[..len]).await?;
                if status != STATUS_END {
                    return Ok((len, last_from));
                }
            }
            if status == STATUS_END {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_frame_has_global_id_and_later_ones_do_not() {
        let to = Target::new("1.2.3.4", 53);
        let first = encode(true, b"abc", &to);
        let next = encode(false, b"abc", &to);
        assert_eq!(first.len(), next.len() + 8);
        assert_eq!(first[4], STATUS_NEW);
        assert_eq!(next[4], STATUS_KEEP);
        let meta_len = u16::from_be_bytes([first[0], first[1]]) as usize;
        assert_eq!(&first[2 + meta_len..2 + meta_len + 2], &[0, 3]);
        assert_eq!(&first[first.len() - 3..], b"abc");
    }

    #[test]
    fn inbound_metadata() {
        let (status, data, from) = parse_meta(&[0, 0, 2, 1, 2, 0, 53, 1, 8, 8, 8, 8]).unwrap();
        assert_eq!((status, data), (2, true));
        assert_eq!(from.unwrap(), Target::new("8.8.8.8", 53));
        assert!(parse_meta(&[0, 0]).is_none());
    }
}
