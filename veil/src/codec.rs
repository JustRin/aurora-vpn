//! Записи туннеля: длина, затем ChaCha20-Poly1305 над типом, данными и набивкой.

use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use rand::Rng;

pub const KIND_HEADER: u8 = 1;
pub const KIND_DATA: u8 = 2;

const TAG_LEN: usize = 16;
/// Длина, тип, длина данных и тег.
pub const OVERHEAD: usize = 2 + 1 + 2 + TAG_LEN;
/// Больше за одну запись поток не кладёт: получатель не ждёт хвоста долго.
pub const MAX_CHUNK: usize = 16 * 1024;

/// Первые записи потока набиваются до случайной длины. Рукопожатие TLS внутри
/// туннеля (hello ≈ 517 Б, ответ сервера 3–6 КБ) иначе узнаётся снаружи по
/// размерам записей — так ловят «TLS в TLS». Тот же приём у XTLS Vision.
const SHAPED_RECORDS: u8 = 8;
const SHAPE_MIN: usize = 900;
const SHAPE_MAX: usize = 1400;

/// Предел данных одной записи: длина шифротекста — u16, и набивке нужно место.
pub const MAX_RECORD_DATA: usize = u16::MAX as usize - OVERHEAD - SHAPE_MAX;

fn nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    *Nonce::from_slice(&n)
}

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("veil: {what}"))
}

pub struct Sealer {
    aead: ChaCha20Poly1305,
    counter: u64,
    shaped: u8,
}

impl Sealer {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { aead: ChaCha20Poly1305::new(Key::from_slice(key)), counter: 0, shaped: 0 }
    }

    fn padding(&mut self, len: usize) -> usize {
        if self.shaped >= SHAPED_RECORDS {
            return 0;
        }
        self.shaped += 1;
        let mut rng = rand::thread_rng();
        let target = rng.gen_range(SHAPE_MIN..SHAPE_MAX);
        if len < target {
            target - len
        } else {
            rng.gen_range(0..64)
        }
    }

    /// Дописать запись в `out`. `data` не длиннее [`MAX_RECORD_DATA`].
    pub fn seal(&mut self, kind: u8, data: &[u8], out: &mut BytesMut) {
        assert!(data.len() <= MAX_RECORD_DATA, "veil: запись длиннее предела");
        let pad = self.padding(data.len());
        let sealed = 1 + 2 + data.len() + pad + TAG_LEN;
        out.reserve(2 + sealed);
        out.put_u16(sealed as u16);
        let start = out.len();
        out.put_u8(kind);
        out.put_u16(data.len() as u16);
        out.put_slice(data);
        out.put_bytes(0, pad);
        let tag = self
            .aead
            .encrypt_in_place_detached(&nonce(self.counter), &[], &mut out[start..])
            .expect("ChaCha20-Poly1305 шифрует любую длину записи");
        out.put_slice(&tag);
        self.counter += 1;
    }
}

pub struct Opener {
    aead: ChaCha20Poly1305,
    counter: u64,
    buf: BytesMut,
}

impl Opener {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { aead: ChaCha20Poly1305::new(Key::from_slice(key)), counter: 0, buf: BytesMut::new() }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Остался недочитанный хвост записи.
    pub fn has_partial(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Следующая целая запись: тип и данные без набивки.
    pub fn next(&mut self) -> io::Result<Option<(u8, Bytes)>> {
        if self.buf.len() < 2 {
            return Ok(None);
        }
        let sealed = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
        if sealed < 1 + 2 + TAG_LEN {
            return Err(bad("слишком короткая запись"));
        }
        if self.buf.len() < 2 + sealed {
            return Ok(None);
        }
        self.buf.advance(2);
        let mut rec = self.buf.split_to(sealed);
        let tag = Tag::clone_from_slice(&rec[sealed - TAG_LEN..]);
        rec.truncate(sealed - TAG_LEN);
        self.aead
            .decrypt_in_place_detached(&nonce(self.counter), &[], &mut rec, &tag)
            .map_err(|_| bad("запись не прошла проверку подлинности"))?;
        self.counter += 1;
        let kind = rec[0];
        let len = u16::from_be_bytes([rec[1], rec[2]]) as usize;
        if 3 + len > rec.len() {
            return Err(bad("длина данных больше записи"));
        }
        Ok(Some((kind, rec.freeze().slice(3..3 + len))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_shaping() {
        let key = [7u8; 32];
        let mut sealer = Sealer::new(&key);
        let mut opener = Opener::new(&key);
        let mut wire = BytesMut::new();
        let messages: Vec<Vec<u8>> = (0..20).map(|i| vec![i as u8; i * 300]).collect();
        let mut sizes = Vec::new();
        for m in &messages {
            let before = wire.len();
            sealer.seal(KIND_DATA, m, &mut wire);
            sizes.push(wire.len() - before);
        }
        // Первые записи не короче нижней границы набивки, какими бы ни были данные.
        assert!(sizes[..8].iter().all(|&s| s >= SHAPE_MIN));
        // Подаём по кусочку, как придут кадры h2.
        let mut got = Vec::new();
        for chunk in wire.chunks(777) {
            opener.push(chunk);
            while let Some((kind, data)) = opener.next().unwrap() {
                assert_eq!(kind, KIND_DATA);
                got.push(data.to_vec());
            }
        }
        assert_eq!(got, messages);
        assert!(!opener.has_partial());
    }

    #[test]
    fn tampering_detected() {
        let key = [1u8; 32];
        let mut wire = BytesMut::new();
        Sealer::new(&key).seal(KIND_HEADER, b"hello", &mut wire);
        let last = wire.len() - 1;
        wire[last] ^= 1;
        let mut opener = Opener::new(&key);
        opener.push(&wire);
        assert!(opener.next().is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let mut wire = BytesMut::new();
        Sealer::new(&[1; 32]).seal(KIND_DATA, b"x", &mut wire);
        let mut opener = Opener::new(&[2; 32]);
        opener.push(&wire);
        assert!(opener.next().is_err());
    }
}
