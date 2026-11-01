//! Клиент TLS 1.3: рукопожатие, REALITY и поток записей.
//!
//! RFC 8446 в минимальном объёме: один проход без HRR и без PSK. Поток умеет то,
//! чего нет ни у одной библиотеки и что нужно Vision: переключиться на сырой сокет
//! и отдать всё, что успело накопиться в буферах (`set_direct_*`).

use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{ready, Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::{digest, hmac};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{PublicKey, StaticSecret};

use super::hello::{self, HelloParams, Profile, X25519, X25519_MLKEM768};
use super::{Retry, TlsConfig};
use crate::common::{invalid, BoxStream};

const REC_HANDSHAKE: u8 = 22;
const REC_APP: u8 = 23;
const REC_CCS: u8 = 20;
const REC_ALERT: u8 = 21;
const MAX_PLAIN: usize = 16 * 1024;
const RBUF: usize = MAX_PLAIN + 2048;

/// SHA-256 от "HelloRetryRequest": признак HRR в поле random у ServerHello.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11,
    0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Suite {
    Aes128,
    Aes256,
    Chacha,
}

impl Suite {
    fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Suite::Aes128),
            0x1302 => Some(Suite::Aes256),
            0x1303 => Some(Suite::Chacha),
            _ => None,
        }
    }

    fn hash(self) -> &'static digest::Algorithm {
        if self == Suite::Aes256 {
            &digest::SHA384
        } else {
            &digest::SHA256
        }
    }

    fn hmac(self) -> hmac::Algorithm {
        if self == Suite::Aes256 {
            hmac::HMAC_SHA384
        } else {
            hmac::HMAC_SHA256
        }
    }

    fn aead(self) -> &'static aead::Algorithm {
        match self {
            Suite::Aes128 => &aead::AES_128_GCM,
            Suite::Aes256 => &aead::AES_256_GCM,
            Suite::Chacha => &aead::CHACHA20_POLY1305,
        }
    }

    fn hash_len(self) -> usize {
        self.hash().output_len()
    }
}

fn hkdf_extract(suite: Suite, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let zero = vec![0u8; suite.hash_len()];
    let key = hmac::Key::new(suite.hmac(), if salt.is_empty() { &zero } else { salt });
    hmac::sign(&key, ikm).as_ref().to_vec()
}

fn expand_label(suite: Suite, secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(4 + 6 + label.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let key = hmac::Key::new(suite.hmac(), secret);
    let mut out = Vec::with_capacity(len);
    let mut block: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&block);
        ctx.update(&info);
        ctx.update(&[counter]);
        block = ctx.sign().as_ref().to_vec();
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(len);
    out
}

struct RecordKey {
    key: LessSafeKey,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKey {
    fn new(suite: Suite, secret: &[u8]) -> io::Result<Self> {
        let alg = suite.aead();
        let key = expand_label(suite, secret, "key", b"", alg.key_len());
        let iv = expand_label(suite, secret, "iv", b"", 12);
        let unbound = UnboundKey::new(alg, &key).map_err(|_| invalid("tls: ключ записи"))?;
        let mut fixed = [0u8; 12];
        fixed.copy_from_slice(&iv);
        Ok(Self { key: LessSafeKey::new(unbound), iv: fixed, seq: 0 })
    }

    fn nonce(&mut self) -> Nonce {
        let mut n = self.iv;
        for (slot, byte) in n[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *slot ^= byte;
        }
        self.seq += 1;
        Nonce::assume_unique_for_key(n)
    }

    /// Запечатать запись и дописать её в `out`.
    fn seal(&mut self, kind: u8, plain: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let start = out.len();
        let len = plain.len() + 1 + 16;
        out.reserve(len + 5);
        out.extend_from_slice(&[REC_APP, 3, 3]);
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(plain);
        out.push(kind);
        let mut header = [0u8; 5];
        header.copy_from_slice(&out[start..start + 5]);
        let nonce = self.nonce();
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(header), &mut out[start + 5..])
            .map_err(|_| invalid("tls: шифрование записи"))?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    /// Вскрыть запись на месте: `(тип, длина открытого текста)`.
    fn open(&mut self, header: [u8; 5], body: &mut [u8]) -> io::Result<(u8, usize)> {
        let nonce = self.nonce();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(header), body)
            .map_err(|_| invalid("tls: запись не прошла проверку"))?;
        // Внутренний тип — последний ненулевой байт, за ним только паддинг.
        let end = plain.iter().rposition(|b| *b != 0).ok_or_else(|| invalid("tls: пустая запись"))?;
        Ok((plain[end], end))
    }
}

/// Открытый ключ и подпись сертификата — ровно то, что сверяет REALITY.
fn cert_ed25519(der: &[u8]) -> Option<(&[u8], &[u8])> {
    fn tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let tag = *data.first()?;
        let first = *data.get(1)?;
        let (len, head) = if first < 0x80 {
            (first as usize, 2)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return None;
            }
            let mut v = 0usize;
            for b in data.get(2..2 + n)? {
                v = (v << 8) | *b as usize;
            }
            (v, 2 + n)
        };
        let body = data.get(head..head + len)?;
        Some((tag, body, &data[head + len..]))
    }
    let (_, cert, _) = tlv(der)?;
    let (_, mut tbs, rest) = tlv(cert)?;
    let (_, _, rest) = tlv(rest)?; // signatureAlgorithm
    let (_, sig_bits, _) = tlv(rest)?;
    let signature = sig_bits.get(1..)?;

    // tbsCertificate: [0] version, serial, sigAlg, issuer, validity, subject, spki.
    let (tag, _, next) = tlv(tbs)?;
    if tag == 0xa0 {
        tbs = next;
    }
    for _ in 0..5 {
        let (_, _, next) = tlv(tbs)?;
        tbs = next;
    }
    let (_, spki, _) = tlv(tbs)?;
    let (_, alg, rest) = tlv(spki)?;
    // 1.3.101.112 = Ed25519
    if alg.get(2..5)? != [0x2b, 0x65, 0x70] {
        return None;
    }
    let (_, key_bits, _) = tlv(rest)?;
    let key = key_bits.get(1..)?;
    (key.len() == 32).then_some((key, signature))
}

struct KeyShares {
    x25519: StaticSecret,
    mlkem: Option<(ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>, Vec<u8>)>,
}

fn mlkem_pair() -> (ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>, Vec<u8>) {
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
    let (dk, ek) = MlKem768::generate(&mut rand::rngs::OsRng);
    (dk, ek.as_bytes().to_vec())
}

fn shared_secret(shares: KeyShares, group: u16, peer: &[u8]) -> io::Result<Vec<u8>> {
    match group {
        X25519 => {
            let key: [u8; 32] = peer.try_into().map_err(|_| invalid("tls: длина ключа X25519"))?;
            Ok(shares.x25519.diffie_hellman(&PublicKey::from(key)).as_bytes().to_vec())
        }
        X25519_MLKEM768 => {
            use ml_kem::kem::Decapsulate;
            let (dk, _) = shares.mlkem.ok_or_else(|| invalid("tls: сервер выбрал ML-KEM без запроса"))?;
            if peer.len() != 1088 + 32 {
                return Err(invalid("tls: длина ключа ML-KEM"));
            }
            let ct = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(&peer[..1088])
                .map_err(|_| invalid("tls: шифртекст ML-KEM"))?;
            let ss = dk.decapsulate(&ct).map_err(|_| invalid("tls: декапсуляция ML-KEM"))?;
            let key: [u8; 32] = peer[1088..].try_into().unwrap();
            let classic = shares.x25519.diffie_hellman(&PublicKey::from(key));
            let mut out = Vec::with_capacity(64);
            out.extend_from_slice(ss.as_slice());
            out.extend_from_slice(classic.as_bytes());
            Ok(out)
        }
        other => Err(invalid(format!("tls: группа {other:#x} не предлагалась"))),
    }
}

/// Прочитать одну TLS-запись открытым текстом (заголовок и тело).
async fn read_record(io: &mut BoxStream, carry: &mut Vec<u8>) -> io::Result<([u8; 5], Vec<u8>)> {
    let need = |carry: &Vec<u8>| -> Option<usize> {
        (carry.len() >= 5).then(|| 5 + u16::from_be_bytes([carry[3], carry[4]]) as usize)
    };
    loop {
        if let Some(total) = need(carry) {
            if total > RBUF {
                return Err(invalid("tls: запись слишком велика"));
            }
            if carry.len() >= total {
                let mut header = [0u8; 5];
                header.copy_from_slice(&carry[..5]);
                let body = carry[5..total].to_vec();
                carry.drain(..total);
                return Ok((header, body));
            }
        }
        let mut chunk = [0u8; 4096];
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tls: сервер закрыл соединение в рукопожатии"));
        }
        carry.extend_from_slice(&chunk[..n]);
    }
}

fn certificate_verify_message(transcript_hash: &[u8]) -> Vec<u8> {
    let mut out = vec![0x20u8; 64];
    out.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    out.extend_from_slice(transcript_hash);
    out
}

fn signature_algorithm(scheme: u16) -> Option<&'static dyn rustls::pki_types::SignatureVerificationAlgorithm> {
    use webpki::ring as alg;
    Some(match scheme {
        0x0403 => alg::ECDSA_P256_SHA256,
        0x0503 => alg::ECDSA_P384_SHA384,
        0x0804 | 0x0809 => alg::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        0x0805 | 0x080a => alg::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        0x0806 | 0x080b => alg::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        0x0807 => alg::ED25519,
        _ => return None,
    })
}

fn verify_chain(certs: &[Vec<u8>], sni: &str, scheme: u16, signature: &[u8], message: &[u8]) -> io::Result<()> {
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    let end = certs.first().ok_or_else(|| invalid("tls: сервер не прислал сертификат"))?;
    let end_der = CertificateDer::from(end.as_slice());
    let cert = webpki::EndEntityCert::try_from(&end_der).map_err(|e| invalid(format!("tls: сертификат: {e}")))?;
    let intermediates: Vec<CertificateDer<'_>> =
        certs[1..].iter().map(|c| CertificateDer::from(c.as_slice())).collect();
    let now = UnixTime::since_unix_epoch(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default());
    let algs = webpki::ALL_VERIFICATION_ALGS;
    cert.verify_for_usage(
        algs,
        webpki_roots::TLS_SERVER_ROOTS,
        &intermediates,
        now,
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|e| invalid(format!("tls: цепочка сертификатов: {e}")))?;
    let name = ServerName::try_from(sni).map_err(|e| invalid(format!("tls: имя сервера: {e}")))?;
    cert.verify_is_valid_for_subject_name(&name)
        .map_err(|e| invalid(format!("tls: сертификат выдан не на {sni}: {e}")))?;
    let alg = signature_algorithm(scheme).ok_or_else(|| invalid(format!("tls: схема подписи {scheme:#x}")))?;
    cert.verify_signature(alg, message, signature)
        .map_err(|e| invalid(format!("tls: подпись сервера: {e}")))
}

fn decompress_cert(alg: u16, data: &[u8], expected: usize) -> io::Result<Vec<u8>> {
    use std::io::Read;
    if expected > 1 << 20 {
        return Err(invalid("tls: сжатый сертификат слишком велик"));
    }
    let mut out = Vec::with_capacity(expected);
    match alg {
        1 => {
            flate2::read::ZlibDecoder::new(data).read_to_end(&mut out)?;
        }
        2 => {
            brotli_decompressor::Decompressor::new(data, 4096).read_to_end(&mut out)?;
        }
        _ => return Err(invalid(format!("tls: сжатие сертификата {alg}"))),
    }
    if out.len() != expected {
        return Err(invalid("tls: длина распакованного сертификата"));
    }
    Ok(out)
}

fn parse_certificate(msg: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let bad = || invalid("tls: разбор Certificate");
    let ctx = *msg.first().ok_or_else(bad)? as usize;
    let mut i = 1 + ctx;
    let total = {
        let b = msg.get(i..i + 3).ok_or_else(bad)?;
        u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize
    };
    i += 3;
    let end = i + total;
    if end > msg.len() {
        return Err(bad());
    }
    let mut certs = Vec::new();
    while i < end {
        let b = msg.get(i..i + 3).ok_or_else(bad)?;
        let len = u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize;
        i += 3;
        certs.push(msg.get(i..i + len).ok_or_else(bad)?.to_vec());
        i += len;
        let b = msg.get(i..i + 2).ok_or_else(bad)?;
        i += 2 + u16::from_be_bytes([b[0], b[1]]) as usize;
    }
    Ok(certs)
}

struct ServerHello {
    suite: Suite,
    group: u16,
    key: Vec<u8>,
}

fn parse_server_hello(msg: &[u8]) -> io::Result<ServerHello> {
    let bad = || invalid("tls: разбор ServerHello");
    if msg.get(2..34).ok_or_else(bad)? == HRR_RANDOM {
        return Err(invalid("tls: сервер запросил HelloRetryRequest"));
    }
    let sid = *msg.get(34).ok_or_else(bad)? as usize;
    let mut i = 35 + sid;
    let cipher = u16::from_be_bytes(msg.get(i..i + 2).ok_or_else(bad)?.try_into().unwrap());
    i += 3;
    let ext_len = u16::from_be_bytes(msg.get(i..i + 2).ok_or_else(bad)?.try_into().unwrap()) as usize;
    i += 2;
    let end = i + ext_len;
    let (mut tls13, mut share) = (false, None);
    while i + 4 <= end && end <= msg.len() {
        let id = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let len = u16::from_be_bytes([msg[i + 2], msg[i + 3]]) as usize;
        let body = msg.get(i + 4..i + 4 + len).ok_or_else(bad)?;
        match id {
            43 if body == [3, 4] => tls13 = true,
            51 if body.len() >= 4 => {
                let group = u16::from_be_bytes([body[0], body[1]]);
                let klen = u16::from_be_bytes([body[2], body[3]]) as usize;
                share = Some((group, body.get(4..4 + klen).ok_or_else(bad)?.to_vec()));
            }
            _ => {}
        }
        i += 4 + len;
    }
    if !tls13 {
        return Err(io::Error::other(Retry::NeedTls12));
    }
    let suite = Suite::from_id(cipher).ok_or_else(|| invalid(format!("tls: шифр {cipher:#x}")))?;
    let (group, key) = share.ok_or_else(|| invalid("tls: в ServerHello нет key_share"))?;
    Ok(ServerHello { suite, group, key })
}

pub async fn handshake(mut io: BoxStream, cfg: &TlsConfig) -> io::Result<Tls13Stream> {
    let profile = Profile::from_fingerprint(&cfg.fingerprint);
    let post_quantum = cfg.reality.as_ref().is_some_and(|r| r.post_quantum.load(Ordering::Relaxed));

    let x25519 = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let x25519_pub = *PublicKey::from(&x25519).as_bytes();
    let mlkem = post_quantum.then(mlkem_pair);
    let mlkem_share = mlkem.as_ref().map(|(_, ek)| {
        let mut key = Vec::with_capacity(ek.len() + 32);
        key.extend_from_slice(ek);
        key.extend_from_slice(&x25519_pub);
        key
    });

    let mut random = [0u8; 32];
    let mut session_id = [0u8; 32];
    {
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut random);
        rng.fill_bytes(&mut session_id);
    }

    // ALPN по умолчанию — браузерный: без него отпечаток выдаёт клиента сразу.
    let default_alpn = ["h2".to_string(), "http/1.1".to_string()];
    let alpn: &[String] = if cfg.alpn.is_empty() { &default_alpn } else { &cfg.alpn };
    let sni_is_name = cfg.sni.parse::<std::net::IpAddr>().is_err() && !cfg.sni.is_empty();

    let mut client_hello = hello::build(&HelloParams {
        profile,
        sni: sni_is_name.then_some(cfg.sni.as_str()),
        alpn,
        random,
        session_id,
        x25519_pub,
        mlkem_pub: mlkem_share.as_deref(),
    });

    // REALITY прячет в session_id зашифрованную метку. AAD — весь hello с нулями
    // на месте session_id, поэтому пишем его после сборки, смещение фиксированное.
    let mut auth_key = None;
    if let Some(reality) = &cfg.reality {
        const SID_AT: usize = 39;
        client_hello[SID_AT..SID_AT + 32].fill(0);
        let secret = x25519.diffie_hellman(&PublicKey::from(reality.public_key));
        let salt = hmac::Key::new(hmac::HMAC_SHA256, &random[..20]);
        let prk = hmac::sign(&salt, secret.as_bytes());
        let expander = hmac::Key::new(hmac::HMAC_SHA256, prk.as_ref());
        let mut ctx = hmac::Context::with_key(&expander);
        ctx.update(b"REALITY");
        ctx.update(&[1]);
        let okm = ctx.sign();
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm.as_ref()[..32]);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as u32;
        let mut sid = [0u8; 32];
        sid[..4].copy_from_slice(&[26, 6, 27, 0]);
        sid[4..8].copy_from_slice(&now.to_be_bytes());
        sid[8..16].copy_from_slice(&reality.short_id);

        let sealing = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &key).map_err(|_| invalid("reality: ключ"))?);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&random[20..32]);
        let tag = sealing
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(client_hello.as_slice()),
                &mut sid[..16],
            )
            .map_err(|_| invalid("reality: шифрование session_id"))?;
        sid[16..32].copy_from_slice(tag.as_ref());
        client_hello[SID_AT..SID_AT + 32].copy_from_slice(&sid);
        auth_key = Some(key);
    }

    let mut first = Vec::with_capacity(client_hello.len() + 5);
    // Первая запись всегда 0x0301 — для совместимости, как у браузеров.
    first.extend_from_slice(&[REC_HANDSHAKE, 3, 1]);
    first.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
    first.extend_from_slice(&client_hello);
    io.write_all(&first).await?;
    io.flush().await?;

    let mut transcript = client_hello;
    let mut carry = Vec::with_capacity(4096);

    // ServerHello, возможно с пропущенным алертом вместо него.
    let (header, server_hello) = loop {
        let (header, body) = read_record(&mut io, &mut carry).await?;
        match header[0] {
            REC_HANDSHAKE => break (header, body),
            REC_ALERT => {
                return Err(invalid(format!(
                    "tls: алерт сервера {}",
                    body.get(1).copied().unwrap_or(0)
                )))
            }
            _ => continue,
        }
    };
    let _ = header;
    if server_hello.first() != Some(&2) || server_hello.len() < 4 {
        return Err(invalid("tls: ожидался ServerHello"));
    }
    let sh_len = u32::from_be_bytes([0, server_hello[1], server_hello[2], server_hello[3]]) as usize;
    let sh = parse_server_hello(server_hello.get(4..4 + sh_len).ok_or_else(|| invalid("tls: ServerHello обрезан"))?)?;
    transcript.extend_from_slice(&server_hello[..4 + sh_len]);

    let suite = sh.suite;
    let shared = shared_secret(KeyShares { x25519, mlkem }, sh.group, &sh.key)?;

    let empty_hash = digest::digest(suite.hash(), b"");
    let early = hkdf_extract(suite, b"", &vec![0u8; suite.hash_len()]);
    let derived = expand_label(suite, &early, "derived", empty_hash.as_ref(), suite.hash_len());
    let hs_secret = hkdf_extract(suite, &derived, &shared);
    let hello_hash = digest::digest(suite.hash(), &transcript);
    let c_hs = expand_label(suite, &hs_secret, "c hs traffic", hello_hash.as_ref(), suite.hash_len());
    let s_hs = expand_label(suite, &hs_secret, "s hs traffic", hello_hash.as_ref(), suite.hash_len());
    let mut hs_read = RecordKey::new(suite, &s_hs)?;
    let mut hs_write = RecordKey::new(suite, &c_hs)?;

    // Зашифрованная часть: сообщения рукопожатия могут лежать в записях как угодно.
    let mut hs_buf: Vec<u8> = Vec::with_capacity(8192);
    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut before_cv: Option<Vec<u8>> = None;
    let mut verified_reality = false;
    let mut landed = false;
    let mut cert_verify: Option<(u16, Vec<u8>)> = None;

    'handshake: loop {
        // Сначала разбираем то, что уже есть в буфере.
        while hs_buf.len() >= 4 {
            let len = u32::from_be_bytes([0, hs_buf[1], hs_buf[2], hs_buf[3]]) as usize;
            if hs_buf.len() < 4 + len {
                break;
            }
            let kind = hs_buf[0];
            let msg: Vec<u8> = hs_buf[..4 + len].to_vec();
            hs_buf.drain(..4 + len);
            let body = &msg[4..];
            match kind {
                8 => {} // EncryptedExtensions: ALPN выбран сервером, нам он не важен
                13 => return Err(invalid("tls: сервер требует клиентский сертификат")),
                11 | 25 => {
                    let plain;
                    let body_ref: &[u8] = if kind == 25 {
                        let alg = u16::from_be_bytes(body.get(..2).ok_or_else(|| invalid("tls: CompressedCertificate"))?.try_into().unwrap());
                        let b = body.get(2..5).ok_or_else(|| invalid("tls: CompressedCertificate"))?;
                        let expected = u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize;
                        let b = body.get(5..8).ok_or_else(|| invalid("tls: CompressedCertificate"))?;
                        let clen = u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize;
                        plain = decompress_cert(alg, body.get(8..8 + clen).ok_or_else(|| invalid("tls: CompressedCertificate"))?, expected)?;
                        &plain
                    } else {
                        body
                    };
                    certs = parse_certificate(body_ref)?;
                    if let Some(key) = &auth_key {
                        // Сертификат REALITY: ed25519, а подпись — HMAC от ключа.
                        let hit = certs.first().and_then(|c| cert_ed25519(c)).is_some_and(|(pk, sig)| {
                            let mac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, key), pk);
                            mac.as_ref() == sig
                        });
                        verified_reality = hit;
                        landed = !hit;
                    }
                }
                15 => {
                    let scheme = u16::from_be_bytes(body.get(..2).ok_or_else(|| invalid("tls: CertificateVerify"))?.try_into().unwrap());
                    let slen = u16::from_be_bytes(body.get(2..4).ok_or_else(|| invalid("tls: CertificateVerify"))?.try_into().unwrap()) as usize;
                    let sig = body.get(4..4 + slen).ok_or_else(|| invalid("tls: CertificateVerify"))?.to_vec();
                    cert_verify = Some((scheme, sig));
                    before_cv = Some(digest::digest(suite.hash(), &transcript).as_ref().to_vec());
                }
                20 => {
                    if auth_key.is_some() {
                        if !verified_reality {
                            return Err(reality_rejected(cfg, post_quantum, landed));
                        }
                    } else if !cfg.insecure {
                        let (scheme, sig) = cert_verify.as_ref().ok_or_else(|| invalid("tls: нет CertificateVerify"))?;
                        let hash = before_cv.as_ref().ok_or_else(|| invalid("tls: нет CertificateVerify"))?;
                        verify_chain(&certs, &cfg.sni, *scheme, sig, &certificate_verify_message(hash))?;
                    }
                    let finished_key = expand_label(suite, &s_hs, "finished", b"", suite.hash_len());
                    let hash = digest::digest(suite.hash(), &transcript);
                    let expected = hmac::sign(&hmac::Key::new(suite.hmac(), &finished_key), hash.as_ref());
                    if expected.as_ref() != body {
                        return Err(invalid("tls: Finished сервера не сошёлся"));
                    }
                    transcript.extend_from_slice(&msg);
                    break 'handshake;
                }
                other => return Err(invalid(format!("tls: неожиданное сообщение {other}"))),
            }
            transcript.extend_from_slice(&msg);
        }

        let (header, mut body) = read_record(&mut io, &mut carry).await?;
        match header[0] {
            REC_CCS => continue,
            REC_ALERT => {
                // Алерт открытым текстом от REALITY-маски — тоже отказ.
                if auth_key.is_some() && !post_quantum {
                    return Err(reality_rejected(cfg, post_quantum, true));
                }
                return Err(invalid(format!("tls: алерт сервера {}", body.get(1).copied().unwrap_or(0))));
            }
            REC_APP => {
                let (kind, len) = match hs_read.open(header, &mut body) {
                    Ok(v) => v,
                    Err(e) => return Err(e),
                };
                match kind {
                    REC_HANDSHAKE => hs_buf.extend_from_slice(&body[..len]),
                    REC_ALERT => {
                        if auth_key.is_some() && !post_quantum {
                            return Err(reality_rejected(cfg, post_quantum, true));
                        }
                        return Err(invalid(format!("tls: алерт сервера {}", body.get(1).copied().unwrap_or(0))));
                    }
                    _ => return Err(invalid("tls: данные до конца рукопожатия")),
                }
            }
            other => return Err(invalid(format!("tls: запись типа {other}"))),
        }
    }

    let finish_hash = digest::digest(suite.hash(), &transcript);
    let derived2 = expand_label(suite, &hs_secret, "derived", empty_hash.as_ref(), suite.hash_len());
    let master = hkdf_extract(suite, &derived2, &vec![0u8; suite.hash_len()]);
    let c_ap = expand_label(suite, &master, "c ap traffic", finish_hash.as_ref(), suite.hash_len());
    let s_ap = expand_label(suite, &master, "s ap traffic", finish_hash.as_ref(), suite.hash_len());

    let finished_key = expand_label(suite, &c_hs, "finished", b"", suite.hash_len());
    let verify = hmac::sign(&hmac::Key::new(suite.hmac(), &finished_key), finish_hash.as_ref());
    let mut msg = vec![20u8, 0, 0, verify.as_ref().len() as u8];
    msg.extend_from_slice(verify.as_ref());

    // CCS для совместимости со средними узлами: так делают браузеры и uTLS.
    let mut out = vec![REC_CCS, 3, 3, 0, 1, 1];
    hs_write.seal(REC_HANDSHAKE, &msg, &mut out)?;
    io.write_all(&out).await?;
    io.flush().await?;

    let mut rbuf = vec![0u8; RBUF];
    if carry.len() > rbuf.len() {
        return Err(invalid("tls: слишком много данных после рукопожатия"));
    }
    rbuf[..carry.len()].copy_from_slice(&carry);

    Ok(Tls13Stream {
        io,
        read: RecordKey::new(suite, &s_ap)?,
        write: RecordKey::new(suite, &c_ap)?,
        suite,
        read_secret: s_ap,
        write_secret: c_ap,
        rbuf,
        rpos: 0,
        rend: carry.len(),
        plain: (0, 0),
        wbuf: Vec::new(),
        wpos: 0,
        direct_read: false,
        direct_write: false,
        eof: false,
        close_sent: false,
    })
}

fn reality_rejected(cfg: &TlsConfig, post_quantum: bool, landed: bool) -> io::Error {
    if let Some(reality) = &cfg.reality {
        if !post_quantum && landed {
            reality.post_quantum.store(true, Ordering::Relaxed);
            return io::Error::other(Retry::RealityWantsPostQuantum);
        }
    }
    invalid("reality: сервер не подтвердил себя (неверный public_key или short_id?)")
}

pub struct Tls13Stream {
    io: BoxStream,
    read: RecordKey,
    write: RecordKey,
    suite: Suite,
    read_secret: Vec<u8>,
    write_secret: Vec<u8>,
    rbuf: Vec<u8>,
    rpos: usize,
    rend: usize,
    /// Открытый текст текущей записи: диапазон внутри `rbuf`.
    plain: (usize, usize),
    wbuf: Vec<u8>,
    wpos: usize,
    direct_read: bool,
    direct_write: bool,
    eof: bool,
    close_sent: bool,
}

impl Tls13Stream {
    /// Дальше запись идёт в сокет мимо TLS. Всё уже запечатанное уйдёт раньше:
    /// `poll_write` сперва сливает `wbuf`.
    pub fn set_direct_write(&mut self) {
        self.direct_write = true;
    }

    /// Дальше чтение идёт из сокета мимо TLS. Возвращает ещё не отданный открытый
    /// текст и сырые байты, которые успели прийти следом за последней записью.
    pub fn set_direct_read(&mut self) -> Vec<u8> {
        let mut rest = Vec::with_capacity(self.plain.1 - self.plain.0 + self.rend - self.rpos);
        rest.extend_from_slice(&self.rbuf[self.plain.0..self.plain.1]);
        rest.extend_from_slice(&self.rbuf[self.rpos..self.rend]);
        self.plain = (0, 0);
        self.rpos = 0;
        self.rend = 0;
        self.direct_read = true;
        // В прямом режиме буфер записи больше не нужен.
        self.rbuf = Vec::new();
        rest
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

    /// Вскрыть запись, лежащую целиком в `rbuf`, если она там есть.
    fn next_record(&mut self) -> io::Result<bool> {
        loop {
            let avail = self.rend - self.rpos;
            if avail < 5 {
                return Ok(false);
            }
            let start = self.rpos;
            let len = u16::from_be_bytes([self.rbuf[start + 3], self.rbuf[start + 4]]) as usize;
            if len + 5 > RBUF {
                return Err(invalid("tls: запись слишком велика"));
            }
            if avail < len + 5 {
                return Ok(false);
            }
            let mut header = [0u8; 5];
            header.copy_from_slice(&self.rbuf[start..start + 5]);
            self.rpos += 5 + len;
            if header[0] == REC_CCS {
                continue;
            }
            if header[0] != REC_APP {
                return Err(invalid(format!("tls: запись типа {}", header[0])));
            }
            let body = start + 5;
            let (kind, plain_len) = self.read.open(header, &mut self.rbuf[body..body + len])?;
            match kind {
                REC_APP => {
                    if plain_len == 0 {
                        continue;
                    }
                    self.plain = (body, body + plain_len);
                    return Ok(true);
                }
                REC_ALERT => {
                    self.eof = true;
                    return Ok(false);
                }
                REC_HANDSHAKE => {
                    // NewSessionTicket игнорируем; KeyUpdate обязаны поддержать,
                    // иначе долгое соединение умрёт на смене ключа.
                    let msg = &self.rbuf[body..body + plain_len];
                    if msg.first() == Some(&24) {
                        self.key_update(msg.get(4).copied().unwrap_or(0))?;
                    }
                }
                _ => return Err(invalid("tls: неизвестный внутренний тип записи")),
            }
        }
    }

    fn key_update(&mut self, requested: u8) -> io::Result<()> {
        let suite = self.suite;
        let next = expand_label(suite, &self.read_secret, "traffic upd", b"", suite.hash_len());
        self.read = RecordKey::new(suite, &next)?;
        self.read_secret = next;
        // Сервер просит сменить и наш ключ: ответ уходит ещё на старом, следующая
        // запись — уже на новом (RFC 8446, 4.6.3).
        if requested == 1 {
            self.write.seal(REC_HANDSHAKE, &[24, 0, 0, 1, 0], &mut self.wbuf)?;
            let next = expand_label(suite, &self.write_secret, "traffic upd", b"", suite.hash_len());
            self.write = RecordKey::new(suite, &next)?;
            self.write_secret = next;
        }
        Ok(())
    }
}

impl AsyncRead for Tls13Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.direct_read {
            return Pin::new(&mut this.io).poll_read(cx, buf);
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
            if this.next_record()? {
                continue;
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            // Сдвигаем хвост в начало: открытый текст уже отдан целиком.
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
                this.eof = true;
                return Poll::Ready(Ok(()));
            }
            this.rend += n;
        }
    }
}

impl AsyncWrite for Tls13Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if this.direct_write {
            return Pin::new(&mut this.io).poll_write(cx, data);
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(MAX_PLAIN);
        this.write.seal(REC_APP, &data[..n], &mut this.wbuf)?;
        // Данные уже приняты; если сокет занят, допишет следующий poll_write/flush.
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
        if !this.close_sent && !this.direct_write {
            this.close_sent = true;
            this.write.seal(REC_ALERT, &[1, 0], &mut this.wbuf)?;
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Вектор из RFC 8448 (раздел 3): early secret при нулевом PSK.
    #[test]
    fn key_schedule_matches_rfc8448() {
        let early = hkdf_extract(Suite::Aes128, b"", &[0u8; 32]);
        assert_eq!(
            early[..8],
            [0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b],
        );
        let empty = digest::digest(&digest::SHA256, b"");
        let derived = expand_label(Suite::Aes128, &early, "derived", empty.as_ref(), 32);
        assert_eq!(derived[..8], [0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5]);
    }

    #[test]
    fn records_roundtrip_with_padding_stripped() {
        let secret = [3u8; 32];
        let mut tx = RecordKey::new(Suite::Chacha, &secret).unwrap();
        let mut rx = RecordKey::new(Suite::Chacha, &secret).unwrap();
        let mut out = Vec::new();
        tx.seal(REC_APP, b"hello", &mut out).unwrap();
        let mut header = [0u8; 5];
        header.copy_from_slice(&out[..5]);
        let (kind, len) = rx.open(header, &mut out[5..]).unwrap();
        assert_eq!(kind, REC_APP);
        assert_eq!(&out[5..5 + len], b"hello");
    }

    #[test]
    fn broken_certificates_do_not_panic() {
        assert!(cert_ed25519(&[]).is_none());
        assert!(cert_ed25519(&[0x30, 0x82]).is_none());
        assert!(cert_ed25519(&[0x30, 0x03, 0x30, 0x7f, 0x00]).is_none());
        assert!(parse_certificate(&[]).is_err());
        assert!(parse_certificate(&[0, 0, 0, 9, 0]).is_err());
    }

    #[test]
    fn server_hello_without_tls13_asks_for_the_fallback() {
        let mut msg = vec![3, 3];
        msg.extend_from_slice(&[1u8; 32]);
        msg.push(0);
        msg.extend_from_slice(&[0xc0, 0x2f, 0]);
        msg.extend_from_slice(&[0, 0]);
        let err = parse_server_hello(&msg).err().unwrap();
        assert!(matches!(super::super::retry_reason(&err), Some(Retry::NeedTls12)));
    }
}
