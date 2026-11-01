//! VMess AEAD: заголовок с AuthID и тело кусками с маской длины.
//!
//! Устаревший MD5-заголовок (alter_id > 0) не поддерживается: Xray убрал его
//! сам, а sing-box шлёт AEAD и для таких узлов.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockEncrypt, KeyInit};
use async_trait::async_trait;
use md5::{Digest as _, Md5};
use rand::{Rng, RngCore};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::digest;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128Reader};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::xudp::XudpConn;
use super::Outbound;
use crate::common::{invalid, parse_uuid, BoxStream, PacketConn, Target};
use crate::config::OutboundOpts;
use crate::transport::Upstream;

const CMD_TCP: u8 = 1;
const CMD_MUX: u8 = 3;
const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const SEC_AES128_GCM: u8 = 3;
const SEC_CHACHA20: u8 = 4;
const TAG: usize = 16;
const MAX_CHUNK: usize = 16 * 1024 - TAG;

/// Вложенный HMAC-SHA256 из vmess AEAD: у каждого пути хэш — предыдущий HMAC.
fn chain(keys: &[&[u8]], msg: &[u8]) -> [u8; 32] {
    let Some((key, parents)) = keys.split_last() else {
        let hash = digest::digest(&digest::SHA256, msg);
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_ref());
        return out;
    };
    let mut pad = [0u8; 64];
    if key.len() > 64 {
        pad[..32].copy_from_slice(&chain(parents, key));
    } else {
        pad[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend(pad.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let inner_hash = chain(parents, &inner);
    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend(pad.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    chain(parents, &outer)
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = Vec::with_capacity(path.len() + 1);
    keys.push(b"VMess AEAD KDF");
    keys.extend_from_slice(path);
    chain(&keys, key)
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&kdf(key, path)[..16]);
    out
}

fn gcm(key: &[u8]) -> io::Result<LessSafeKey> {
    let alg = if key.len() == 16 { &aead::AES_128_GCM } else { &aead::CHACHA20_POLY1305 };
    Ok(LessSafeKey::new(UnboundKey::new(alg, key).map_err(|_| invalid("vmess: ключ"))?))
}

fn seal_with(key: &LessSafeKey, nonce: &[u8], aad: &[u8], plain: &[u8]) -> io::Result<Vec<u8>> {
    let mut n = [0u8; 12];
    n.copy_from_slice(&nonce[..12]);
    let mut out = plain.to_vec();
    let tag = key
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(n), Aad::from(aad), &mut out)
        .map_err(|_| invalid("vmess: шифрование"))?;
    out.extend_from_slice(tag.as_ref());
    Ok(out)
}

fn auth_id(cmd_key: &[u8; 16], now: u64) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&now.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut block[8..12]);
    let crc = crc32fast::hash(&block[..12]);
    block[12..].copy_from_slice(&crc.to_be_bytes());

    let key = kdf16(cmd_key, &[b"AES Auth ID Encryption"]);
    let aes = aes::Aes128::new((&key).into());
    let mut b = aes::Block::from(block);
    aes.encrypt_block(&mut b);
    b.into()
}

/// Запечатанный заголовок запроса: AuthID, длина, nonce, тело.
fn seal_header(cmd_key: &[u8; 16], header: &[u8], now: u64) -> io::Result<Vec<u8>> {
    let id = auth_id(cmd_key, now);
    let mut conn_nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut conn_nonce);

    let len_key = kdf16(cmd_key, &[b"VMess Header AEAD Key_Length", &id, &conn_nonce]);
    let len_nonce = kdf(cmd_key, &[b"VMess Header AEAD Nonce_Length", &id, &conn_nonce]);
    let sealed_len = seal_with(&gcm(&len_key)?, &len_nonce, &id, &(header.len() as u16).to_be_bytes())?;

    let body_key = kdf16(cmd_key, &[b"VMess Header AEAD Key", &id, &conn_nonce]);
    let body_nonce = kdf(cmd_key, &[b"VMess Header AEAD Nonce", &id, &conn_nonce]);
    let sealed_body = seal_with(&gcm(&body_key)?, &body_nonce, &id, header)?;

    let mut out = Vec::with_capacity(16 + sealed_len.len() + 8 + sealed_body.len());
    out.extend_from_slice(&id);
    out.extend_from_slice(&sealed_len);
    out.extend_from_slice(&conn_nonce);
    out.extend_from_slice(&sealed_body);
    Ok(out)
}

fn fnv1a(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in data {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// Ключ чанков: у ChaCha он растянут из MD5, у AES берётся как есть.
fn body_key(security: u8, key: &[u8; 16]) -> io::Result<LessSafeKey> {
    if security == SEC_CHACHA20 {
        let first = Md5::digest(key);
        let second = Md5::digest(first);
        let mut k = [0u8; 32];
        k[..16].copy_from_slice(&first);
        k[16..].copy_from_slice(&second);
        gcm(&k)
    } else {
        gcm(key)
    }
}

fn shake(iv: &[u8; 16]) -> Shake128Reader {
    let mut hasher = Shake128::default();
    hasher.update(iv);
    hasher.finalize_xof()
}

fn sha256_16(data: &[u8; 16]) -> [u8; 16] {
    let hash = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash.as_ref()[..16]);
    out
}

pub struct Vmess {
    tag: String,
    cmd_key: [u8; 16],
    security: u8,
    upstream: Upstream,
}

impl Vmess {
    pub fn new(o: &OutboundOpts) -> Result<Self, String> {
        let uuid = parse_uuid(&o.uuid).ok_or("vmess: неверный uuid")?;
        let mut hasher = Md5::new();
        md5::Digest::update(&mut hasher, uuid);
        md5::Digest::update(&mut hasher, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let mut cmd_key = [0u8; 16];
        cmd_key.copy_from_slice(&hasher.finalize());
        let security = match o.security.as_str() {
            "" | "auto" | "aes-128-gcm" => SEC_AES128_GCM,
            "chacha20-poly1305" => SEC_CHACHA20,
            other => return Err(format!("vmess: шифр {other} не поддержан")),
        };
        Ok(Self { tag: o.tag.clone(), cmd_key, security, upstream: Upstream::from_opts(o)? })
    }

    async fn open(&self, cmd: u8, target: Option<&Target>) -> io::Result<BoxStream> {
        let io = self.upstream.open().await?;
        let (mut key, mut iv) = ([0u8; 16], [0u8; 16]);
        let (resp_v, padding): (u8, usize);
        {
            let mut rng = rand::thread_rng();
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut iv);
            resp_v = rng.gen();
            padding = rng.gen_range(0..16);
        }

        let mut header = Vec::with_capacity(64);
        header.push(1);
        header.extend_from_slice(&iv);
        header.extend_from_slice(&key);
        header.push(resp_v);
        header.push(OPT_CHUNK_STREAM | OPT_CHUNK_MASKING);
        header.push(((padding as u8) << 4) | self.security);
        header.push(0);
        header.push(cmd);
        if let Some(target) = target {
            target.write_vless(&mut header);
        }
        let start = header.len();
        header.resize(start + padding, 0);
        rand::thread_rng().fill_bytes(&mut header[start..]);
        let check = fnv1a(&header);
        header.extend_from_slice(&check.to_be_bytes());

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let sealed = seal_header(&self.cmd_key, &header, now)?;

        let resp_key = sha256_16(&key);
        let resp_iv = sha256_16(&iv);
        Ok(Box::new(VmessStream {
            io,
            write_key: body_key(self.security, &key)?,
            write_iv: iv,
            write_count: 0,
            write_mask: shake(&iv),
            wbuf: sealed,
            wpos: 0,
            read_key: body_key(self.security, &resp_key)?,
            read_iv: resp_iv,
            read_count: 0,
            read_mask: shake(&resp_iv),
            resp_key,
            resp_iv,
            resp_v,
            header_len: None,
            header_done: false,
            rbuf: vec![0u8; 32 * 1024],
            rpos: 0,
            rend: 0,
            chunk_len: None,
            plain: (0, 0),
            eof: false,
        }))
    }
}

#[async_trait]
impl Outbound for Vmess {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "vmess"
    }

    async fn dial(&self, target: &Target) -> io::Result<BoxStream> {
        self.open(CMD_TCP, Some(target)).await
    }

    async fn dial_udp(&self, _: &Target) -> io::Result<Box<dyn PacketConn>> {
        Ok(Box::new(XudpConn::new(self.open(CMD_MUX, None).await?)))
    }
}

struct VmessStream {
    io: BoxStream,
    write_key: LessSafeKey,
    write_iv: [u8; 16],
    write_count: u16,
    write_mask: Shake128Reader,
    wbuf: Vec<u8>,
    wpos: usize,
    read_key: LessSafeKey,
    read_iv: [u8; 16],
    read_count: u16,
    read_mask: Shake128Reader,
    resp_key: [u8; 16],
    resp_iv: [u8; 16],
    resp_v: u8,
    header_len: Option<usize>,
    header_done: bool,
    rbuf: Vec<u8>,
    rpos: usize,
    rend: usize,
    chunk_len: Option<usize>,
    plain: (usize, usize),
    eof: bool,
}

fn chunk_nonce(count: u16, iv: &[u8; 16]) -> Nonce {
    let mut n = [0u8; 12];
    n[..2].copy_from_slice(&count.to_be_bytes());
    n[2..].copy_from_slice(&iv[2..12]);
    Nonce::assume_unique_for_key(n)
}

impl VmessStream {
    fn seal_chunk(&mut self, plain: &[u8]) -> io::Result<()> {
        let mut mask = [0u8; 2];
        self.write_mask.read(&mut mask);
        let len = (plain.len() + TAG) as u16;
        self.wbuf.extend_from_slice(&(len ^ u16::from_be_bytes(mask)).to_be_bytes());
        let body = self.wbuf.len();
        self.wbuf.extend_from_slice(plain);
        let nonce = chunk_nonce(self.write_count, &self.write_iv);
        self.write_count = self.write_count.wrapping_add(1);
        let tag = self
            .write_key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut self.wbuf[body..])
            .map_err(|_| invalid("vmess: шифрование куска"))?;
        self.wbuf.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }

    /// Разобрать то, что лежит в `rbuf`. `Ok(true)` — есть прогресс.
    fn advance(&mut self) -> io::Result<bool> {
        let avail = self.rend - self.rpos;
        if !self.header_done {
            match self.header_len {
                None => {
                    if avail < 18 {
                        return Ok(false);
                    }
                    let key = kdf16(&self.resp_key, &[b"AEAD Resp Header Len Key"]);
                    let nonce = kdf(&self.resp_iv, &[b"AEAD Resp Header Len IV"]);
                    let mut n = [0u8; 12];
                    n.copy_from_slice(&nonce[..12]);
                    let start = self.rpos;
                    let plain = gcm(&key)?
                        .open_in_place(Nonce::assume_unique_for_key(n), Aad::empty(), &mut self.rbuf[start..start + 18])
                        .map_err(|_| invalid("vmess: длина ответа не прошла проверку (неверный uuid?)"))?;
                    self.header_len = Some(usize::from(plain[0]) << 8 | usize::from(plain[1]));
                    self.rpos += 18;
                }
                Some(len) => {
                    if avail < len + TAG {
                        return Ok(false);
                    }
                    let key = kdf16(&self.resp_key, &[b"AEAD Resp Header Key"]);
                    let nonce = kdf(&self.resp_iv, &[b"AEAD Resp Header IV"]);
                    let mut n = [0u8; 12];
                    n.copy_from_slice(&nonce[..12]);
                    let start = self.rpos;
                    let plain = gcm(&key)?
                        .open_in_place(Nonce::assume_unique_for_key(n), Aad::empty(), &mut self.rbuf[start..start + len + TAG])
                        .map_err(|_| invalid("vmess: заголовок ответа не прошёл проверку"))?;
                    if plain.first() != Some(&self.resp_v) {
                        return Err(invalid("vmess: чужой ответ"));
                    }
                    self.rpos += len + TAG;
                    self.header_done = true;
                }
            }
            return Ok(true);
        }
        match self.chunk_len {
            None => {
                if avail < 2 {
                    return Ok(false);
                }
                let mut mask = [0u8; 2];
                self.read_mask.read(&mut mask);
                let raw = u16::from_be_bytes([self.rbuf[self.rpos], self.rbuf[self.rpos + 1]]);
                let len = (raw ^ u16::from_be_bytes(mask)) as usize;
                self.rpos += 2;
                if len < TAG {
                    return Err(invalid("vmess: длина куска"));
                }
                self.chunk_len = Some(len);
                Ok(true)
            }
            Some(len) => {
                if avail < len {
                    return Ok(false);
                }
                let start = self.rpos;
                let nonce = chunk_nonce(self.read_count, &self.read_iv);
                self.read_count = self.read_count.wrapping_add(1);
                let plain_len = self
                    .read_key
                    .open_in_place(nonce, Aad::empty(), &mut self.rbuf[start..start + len])
                    .map_err(|_| invalid("vmess: кусок не прошёл проверку"))?
                    .len();
                self.rpos += len;
                self.chunk_len = None;
                if plain_len == 0 {
                    self.eof = true; // пустой кусок — конец потока
                } else {
                    self.plain = (start, start + plain_len);
                }
                Ok(true)
            }
        }
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Заголовок запроса уходит независимо от того, кто заговорит первым.
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        loop {
            if this.plain.0 < this.plain.1 {
                let n = buf.remaining().min(this.plain.1 - this.plain.0);
                buf.put_slice(&this.rbuf[this.plain.0..this.plain.0 + n]);
                this.plain.0 += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if this.advance()? {
                continue;
            }
            if this.rpos > 0 {
                this.rbuf.copy_within(this.rpos..this.rend, 0);
                this.rend -= this.rpos;
                this.rpos = 0;
            }
            let rend = this.rend;
            let mut read = ReadBuf::new(&mut this.rbuf[rend..]);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut read))?;
            let n = read.filled().len();
            if n == 0 {
                return Poll::Ready(Ok(()));
            }
            this.rend += n;
        }
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // Заголовок и первый кусок сливаем в один сегмент: первый слив не ждём.
        if this.write_count != 0 {
            ready!(this.poll_drain(cx))?;
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(MAX_CHUNK);
        this.seal_chunk(&data[..n])?;
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_vectors() {
        assert_eq!(fnv1a(b""), 0x811c_9dc5);
        assert_eq!(fnv1a(b"a"), 0xe40c_292c);
    }

    #[test]
    fn nested_hmac_with_no_paths_is_plain_hmac_sha256() {
        // RFC 4231, тест 2.
        let out = chain(&[b"Jefe"], b"what do ya want for nothing?");
        assert_eq!(out[..4], [0x5b, 0xdc, 0xc1, 0x46]);
    }

    #[test]
    fn auth_id_carries_a_valid_crc_after_decryption() {
        use aes::cipher::BlockDecrypt;
        let cmd_key = [9u8; 16];
        let id = auth_id(&cmd_key, 1_700_000_000);
        let key = kdf16(&cmd_key, &[b"AES Auth ID Encryption"]);
        let aes = aes::Aes128::new((&key).into());
        let mut block = aes::Block::from(id);
        aes.decrypt_block(&mut block);
        let crc = crc32fast::hash(&block[..12]);
        assert_eq!(block[12..], crc.to_be_bytes());
        assert_eq!(block[..8], 1_700_000_000u64.to_be_bytes());
    }
}
