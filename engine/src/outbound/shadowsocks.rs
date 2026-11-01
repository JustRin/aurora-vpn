//! Shadowsocks AEAD: chacha20-ietf-poly1305, aes-128-gcm, aes-256-gcm.
//!
//! Потоковые шифры (aes-*-cfb, chacha20-ietf) — без аутентификации и взломанные —
//! сюда не попали намеренно; такие узлы становятся заглушками. Семейство 2022 —
//! отдельная задача: в списках пользователя сейчас его нет.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use md5::{Digest, Md5};
use rand::RngCore;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hmac;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;

use super::Outbound;
use crate::common::{invalid, other, tcp_connect, udp_socket, BoxStream, PacketConn, Target};
use crate::config::OutboundOpts;

const TAG: usize = 16;
const MAX_CHUNK: usize = 0x3fff;

#[derive(Clone, Copy)]
struct Cipher {
    alg: &'static aead::Algorithm,
    key_len: usize,
}

fn cipher_for(method: &str) -> Option<Cipher> {
    Some(match method {
        "chacha20-ietf-poly1305" | "chacha20-poly1305" => Cipher { alg: &aead::CHACHA20_POLY1305, key_len: 32 },
        "aes-256-gcm" => Cipher { alg: &aead::AES_256_GCM, key_len: 32 },
        "aes-128-gcm" => Cipher { alg: &aead::AES_128_GCM, key_len: 16 },
        _ => return None,
    })
}

/// EVP_BytesToKey(MD5) — историческая форма ключа Shadowsocks.
fn derive_key(password: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < len {
        let mut hasher = Md5::new();
        hasher.update(&prev);
        hasher.update(password.as_bytes());
        prev = hasher.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(len);
    out
}

fn subkey(cipher: Cipher, master: &[u8], salt: &[u8]) -> io::Result<LessSafeKey> {
    let prk = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt), master);
    let expander = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, prk.as_ref());
    let mut okm = Vec::with_capacity(cipher.key_len + 20);
    let mut block: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while okm.len() < cipher.key_len {
        let mut ctx = hmac::Context::with_key(&expander);
        ctx.update(&block);
        ctx.update(b"ss-subkey");
        ctx.update(&[counter]);
        block = ctx.sign().as_ref().to_vec();
        okm.extend_from_slice(&block);
        counter += 1;
    }
    okm.truncate(cipher.key_len);
    let key = UnboundKey::new(cipher.alg, &okm).map_err(|_| invalid("shadowsocks: ключ"))?;
    Ok(LessSafeKey::new(key))
}

struct Sealer {
    key: LessSafeKey,
    nonce: u64,
}

impl Sealer {
    fn next(&mut self) -> Nonce {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.nonce.to_le_bytes());
        self.nonce += 1;
        Nonce::assume_unique_for_key(n)
    }

    fn seal_chunk(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let err = |_| invalid("shadowsocks: шифрование");
        let start = out.len();
        out.extend_from_slice(&(plain.len() as u16).to_be_bytes());
        let nonce = self.next();
        let tag = self.key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut out[start..start + 2]).map_err(err)?;
        out.extend_from_slice(tag.as_ref());
        let body = out.len();
        out.extend_from_slice(plain);
        let nonce = self.next();
        let tag = self.key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut out[body..]).map_err(err)?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }
}

pub struct Shadowsocks {
    tag: String,
    server: String,
    port: u16,
    cipher: Cipher,
    master: Vec<u8>,
}

impl Shadowsocks {
    pub fn new(o: &OutboundOpts) -> Result<Self, String> {
        let cipher = cipher_for(&o.method).ok_or_else(|| format!("shadowsocks: метод {} не поддержан", o.method))?;
        Ok(Self {
            tag: o.tag.clone(),
            server: o.server.clone(),
            port: o.server_port,
            cipher,
            master: derive_key(&o.password, cipher.key_len),
        })
    }

    async fn addr(&self) -> io::Result<SocketAddr> {
        let addrs = crate::dns::resolve_server(&self.server, self.port).await?;
        addrs.first().copied().ok_or_else(|| other("shadowsocks: нет адреса"))
    }
}

#[async_trait]
impl Outbound for Shadowsocks {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "shadowsocks"
    }

    async fn dial(&self, target: &Target) -> io::Result<BoxStream> {
        let stream = tcp_connect(self.addr().await?).await?;
        let mut salt = vec![0u8; self.cipher.key_len];
        rand::thread_rng().fill_bytes(&mut salt);
        let sealer = Sealer { key: subkey(self.cipher, &self.master, &salt)?, nonce: 0 };

        let mut address = Vec::with_capacity(32);
        target.write_socks(&mut address);

        Ok(Box::new(SsStream {
            io: Box::new(stream),
            cipher: self.cipher,
            master: self.master.clone(),
            sealer,
            salt_out: Some(salt),
            address: Some(address),
            wbuf: Vec::new(),
            wpos: 0,
            opener: None,
            rbuf: vec![0u8; 32 * 1024],
            rpos: 0,
            rend: 0,
            need_payload: None,
            plain: (0, 0),
        }))
    }

    async fn dial_udp(&self, _: &Target) -> io::Result<Box<dyn PacketConn>> {
        let server = self.addr().await?;
        Ok(Box::new(SsPacket {
            socket: udp_socket(server.is_ipv6())?,
            server,
            cipher: self.cipher,
            master: self.master.clone(),
        }))
    }
}

struct SsStream {
    io: BoxStream,
    cipher: Cipher,
    master: Vec<u8>,
    sealer: Sealer,
    salt_out: Option<Vec<u8>>,
    address: Option<Vec<u8>>,
    wbuf: Vec<u8>,
    wpos: usize,
    opener: Option<Sealer>,
    rbuf: Vec<u8>,
    rpos: usize,
    rend: usize,
    need_payload: Option<usize>,
    /// Открытый текст текущего куска внутри `rbuf`.
    plain: (usize, usize),
}

impl SsStream {
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

    /// Заголовок с адресом обязан уйти, даже если клиент ждёт, что сервер заговорит первым.
    fn prepare_first(&mut self, data: &[u8]) -> io::Result<usize> {
        let Some(address) = self.address.take() else {
            return Ok(0);
        };
        if let Some(salt) = self.salt_out.take() {
            self.wbuf.extend_from_slice(&salt);
        }
        let room = MAX_CHUNK - address.len();
        let n = data.len().min(room);
        let mut first = address;
        first.extend_from_slice(&data[..n]);
        self.sealer.seal_chunk(&first, &mut self.wbuf)?;
        Ok(n)
    }
}

impl AsyncRead for SsStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.address.is_some() {
            this.prepare_first(&[])?;
        }
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

            let avail = this.rend - this.rpos;
            let needed = if this.opener.is_none() {
                this.cipher.key_len
            } else if let Some(len) = this.need_payload {
                len + TAG
            } else {
                2 + TAG
            };
            if avail >= needed {
                let start = this.rpos;
                match (&mut this.opener, this.need_payload) {
                    (None, _) => {
                        let salt = this.rbuf[start..start + needed].to_vec();
                        this.opener = Some(Sealer { key: subkey(this.cipher, &this.master, &salt)?, nonce: 0 });
                        this.rpos += needed;
                    }
                    (Some(opener), None) => {
                        let nonce = opener.next();
                        let plain = opener
                            .key
                            .open_in_place(nonce, Aad::empty(), &mut this.rbuf[start..start + needed])
                            .map_err(|_| invalid("shadowsocks: длина не прошла проверку (неверный пароль?)"))?;
                        let len = (usize::from(plain[0]) << 8 | usize::from(plain[1])) & MAX_CHUNK;
                        this.need_payload = Some(len);
                        this.rpos += needed;
                    }
                    (Some(opener), Some(len)) => {
                        let nonce = opener.next();
                        opener
                            .key
                            .open_in_place(nonce, Aad::empty(), &mut this.rbuf[start..start + needed])
                            .map_err(|_| invalid("shadowsocks: данные не прошли проверку"))?;
                        this.need_payload = None;
                        this.plain = (start, start + len);
                        this.rpos += needed;
                    }
                }
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

impl AsyncWrite for SsStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = if this.address.is_some() {
            this.prepare_first(data)?
        } else {
            let n = data.len().min(MAX_CHUNK);
            this.sealer.seal_chunk(&data[..n], &mut this.wbuf)?;
            n
        };
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

struct SsPacket {
    socket: UdpSocket,
    server: SocketAddr,
    cipher: Cipher,
    master: Vec<u8>,
}

fn zero_nonce() -> Nonce {
    Nonce::assume_unique_for_key([0u8; 12])
}

#[async_trait]
impl PacketConn for SsPacket {
    async fn send(&self, data: &[u8], to: &Target) -> io::Result<()> {
        let mut packet = vec![0u8; self.cipher.key_len];
        rand::thread_rng().fill_bytes(&mut packet);
        let key = subkey(self.cipher, &self.master, &packet)?;
        let start = packet.len();
        to.write_socks(&mut packet);
        packet.extend_from_slice(data);
        let tag = key
            .seal_in_place_separate_tag(zero_nonce(), Aad::empty(), &mut packet[start..])
            .map_err(|_| invalid("shadowsocks: шифрование пакета"))?;
        packet.extend_from_slice(tag.as_ref());
        self.socket.send_to(&packet, self.server).await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        loop {
            let n = self.socket.recv(buf).await?;
            let salt_len = self.cipher.key_len;
            if n <= salt_len + TAG {
                continue;
            }
            let Ok(key) = subkey(self.cipher, &self.master, &buf[..salt_len]) else { continue };
            let Ok(plain) = key.open_in_place(zero_nonce(), Aad::empty(), &mut buf[salt_len..n]) else {
                continue; // чужой пакет на нашем порту
            };
            let Some((from, used)) = Target::read_socks(plain) else { continue };
            let len = plain.len() - used;
            let start = salt_len + used;
            buf.copy_within(start..start + len, 0);
            return Ok((len, from));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_derivation_matches_evp_bytes_to_key() {
        // Известный вектор из реализации shadowsocks-libev для пароля "foobar".
        let key = derive_key("foobar", 32);
        assert_eq!(key[..4], [0x38, 0x58, 0xf6, 0x22]);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn legacy_stream_ciphers_are_refused() {
        assert!(cipher_for("aes-256-cfb").is_none());
        assert!(cipher_for("chacha20-ietf").is_none());
        assert!(cipher_for("2022-blake3-aes-128-gcm").is_none());
    }

    #[test]
    fn chunks_open_with_the_same_key() {
        let cipher = cipher_for("chacha20-ietf-poly1305").unwrap();
        let master = derive_key("pw", 32);
        let salt = [1u8; 32];
        let mut tx = Sealer { key: subkey(cipher, &master, &salt).unwrap(), nonce: 0 };
        let mut rx = Sealer { key: subkey(cipher, &master, &salt).unwrap(), nonce: 0 };
        let mut wire = Vec::new();
        tx.seal_chunk(b"hello", &mut wire).unwrap();
        let (len_part, body) = wire.split_at_mut(2 + TAG);
        let nonce = rx.next();
        let len = rx.key.open_in_place(nonce, Aad::empty(), len_part).unwrap();
        assert_eq!(len, [0, 5]);
        let nonce = rx.next();
        assert_eq!(rx.key.open_in_place(nonce, Aad::empty(), body).unwrap(), b"hello");
    }
}
