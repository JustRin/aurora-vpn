//! Определение протокола и имени хоста по первым байтам.
//!
//! Без этого доменные правила не сработают на трафике из TUN: там есть только IP.
//! Весь разбор — по чужим байтам, поэтому без индексации на веру: любой выход за
//! границу превращается в «не распознано».

use ring::aead::quic as quic_hp;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hmac;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sniffed {
    pub protocol: &'static str,
    pub domain: Option<String>,
}

fn u16_at(d: &[u8], i: usize) -> Option<usize> {
    Some(usize::from(*d.get(i)?) << 8 | usize::from(*d.get(i + 1)?))
}

fn valid_host(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Имя из SNI в теле ClientHello (начиная с поля версии).
fn sni_in_hello(body: &[u8]) -> Option<String> {
    let mut i = 2 + 32;
    i += 1 + usize::from(*body.get(i)?); // session id
    i += 2 + u16_at(body, i)?; // шифры
    i += 1 + usize::from(*body.get(i)?); // сжатие
    let total = u16_at(body, i)?;
    i += 2;
    let end = (i + total).min(body.len());
    while i + 4 <= end {
        let kind = u16_at(body, i)?;
        let len = u16_at(body, i + 2)?;
        if kind == 0 {
            let list = body.get(i + 4..i + 4 + len)?;
            let name_len = u16_at(list, 3)?;
            let name = std::str::from_utf8(list.get(5..5 + name_len)?).ok()?.to_ascii_lowercase();
            return valid_host(&name).then_some(name);
        }
        i += 4 + len;
    }
    None
}

/// `None` — данных мало или это не TLS.
pub fn tls(data: &[u8]) -> Option<Sniffed> {
    if data.len() < 6 || data[0] != 22 || data[1] != 3 || data[5] != 1 {
        return None;
    }
    let domain = sni_in_hello(data.get(9..)?);
    Some(Sniffed { protocol: "tls", domain })
}

pub fn http(data: &[u8]) -> Option<Sniffed> {
    const METHODS: [&[u8]; 9] = [
        b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ",
    ];
    if !METHODS.iter().any(|m| data.starts_with(m)) {
        return None;
    }
    let text = std::str::from_utf8(&data[..data.len().min(4096)]).ok()?;
    let domain = text.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("host") {
            return None;
        }
        let host = value.trim();
        let host = host.rsplit_once(':').map_or(host, |(h, p)| if p.bytes().all(|b| b.is_ascii_digit()) { h } else { host });
        let host = host.to_ascii_lowercase();
        valid_host(&host).then_some(host)
    });
    Some(Sniffed { protocol: "http", domain })
}

/// DNS-запрос в UDP: минимальная проверка заголовка.
pub fn dns(data: &[u8]) -> Option<Sniffed> {
    if data.len() < 12 || data[2] & 0x80 != 0 {
        return None;
    }
    let qd = u16_at(data, 4)?;
    if qd == 0 || qd > 16 {
        return None;
    }
    Some(Sniffed { protocol: "dns", domain: crate::dns::question_name(data) })
}

fn hkdf_expand_label(secret: &[u8], label: &[u8], out_len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(4 + 6 + label.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(6 + label.len() as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(&info);
    ctx.update(&[1]);
    ctx.sign().as_ref()[..out_len].to_vec()
}

/// SNI из Initial-пакета QUIC v1: ключи выводятся из DCID и известны всем (RFC 9001).
pub fn quic(packet: &[u8]) -> Option<Sniffed> {
    const SALT_V1: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb,
        0x7f, 0x0a,
    ];
    let first = *packet.first()?;
    if first & 0xc0 != 0xc0 || first & 0x30 != 0 {
        return None;
    }
    if packet.get(1..5)? != [0, 0, 0, 1] {
        return None;
    }
    let dcid_len = usize::from(*packet.get(5)?);
    if dcid_len > 20 {
        return None;
    }
    let dcid = packet.get(6..6 + dcid_len)?;
    let mut i = 6 + dcid_len;
    i += 1 + usize::from(*packet.get(i)?); // scid
    let (token_len, used) = crate::dns::quic_varint(packet.get(i..)?)?;
    i += used + token_len as usize;
    let (length, used) = crate::dns::quic_varint(packet.get(i..)?)?;
    i += used;
    let pn_offset = i;
    let payload_end = pn_offset.checked_add(length as usize)?;
    if payload_end > packet.len() || length < 20 {
        return None;
    }

    let salt = hmac::Key::new(hmac::HMAC_SHA256, &SALT_V1);
    let initial = hmac::sign(&salt, dcid);
    let client = hkdf_expand_label(initial.as_ref(), b"client in", 32);
    let key = hkdf_expand_label(&client, b"quic key", 16);
    let iv = hkdf_expand_label(&client, b"quic iv", 12);
    let hp = hkdf_expand_label(&client, b"quic hp", 16);

    let hp_key = quic_hp::HeaderProtectionKey::new(&quic_hp::AES_128, &hp).ok()?;
    let sample = packet.get(pn_offset + 4..pn_offset + 20)?;
    let mask = hp_key.new_mask(sample).ok()?;

    let mut header = packet.get(..pn_offset + 4)?.to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(header[0] & 0x03) + 1;
    for k in 0..pn_len {
        header[pn_offset + k] ^= mask[1 + k];
    }
    let mut pn = 0u64;
    for b in &header[pn_offset..pn_offset + pn_len] {
        pn = (pn << 8) | u64::from(*b);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv);
    for (slot, byte) in nonce[4..].iter_mut().zip(pn.to_be_bytes()) {
        *slot ^= byte;
    }
    let mut body = packet.get(pn_offset + pn_len..payload_end)?.to_vec();
    let aad_bytes = &header[..pn_offset + pn_len];
    let sealing = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).ok()?);
    let plain = sealing.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad_bytes), &mut body).ok()?;

    Some(Sniffed { protocol: "quic", domain: sni_in_crypto(plain) })
}

/// Собрать кадры CRYPTO и найти SNI. Chrome режет hello и тасует кадры, поэтому
/// сборка идёт по смещениям, а не подряд.
fn sni_in_crypto(mut frames: &[u8]) -> Option<String> {
    let mut hello = vec![0u8; 0];
    while let Some(&kind) = frames.first() {
        match kind {
            0x00 | 0x01 => frames = &frames[1..],
            0x02 | 0x03 => {
                // ACK: разобрать поля, чтобы дойти до следующего кадра.
                let mut i = 1;
                let (_, n) = crate::dns::quic_varint(frames.get(i..)?)?;
                i += n;
                let (_, n) = crate::dns::quic_varint(frames.get(i..)?)?;
                i += n;
                let (ranges, n) = crate::dns::quic_varint(frames.get(i..)?)?;
                i += n;
                let (_, n) = crate::dns::quic_varint(frames.get(i..)?)?;
                i += n;
                for _ in 0..ranges.min(256) * 2 {
                    let (_, n) = crate::dns::quic_varint(frames.get(i..)?)?;
                    i += n;
                }
                if kind == 3 {
                    for _ in 0..3 {
                        let (_, n) = crate::dns::quic_varint(frames.get(i..)?)?;
                        i += n;
                    }
                }
                frames = frames.get(i..)?;
            }
            0x06 => {
                let mut i = 1;
                let (offset, n) = crate::dns::quic_varint(frames.get(i..)?)?;
                i += n;
                let (len, n) = crate::dns::quic_varint(frames.get(i..)?)?;
                i += n;
                let data = frames.get(i..i + len as usize)?;
                let end = offset as usize + data.len();
                if end > 64 * 1024 {
                    return None;
                }
                if hello.len() < end {
                    hello.resize(end, 0);
                }
                hello[offset as usize..end].copy_from_slice(data);
                frames = frames.get(i + len as usize..)?;
            }
            _ => break,
        }
    }
    if hello.first() != Some(&1) {
        return None;
    }
    sni_in_hello(hello.get(4..)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(name: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
        ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name.as_bytes());

        let mut body = vec![3, 3];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![1, 0];
        hs.extend_from_slice(&(body.len() as u16).to_be_bytes());
        hs.extend_from_slice(&body);
        let mut rec = vec![22, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn sni_from_tls() {
        let got = tls(&client_hello("Example.COM")).unwrap();
        assert_eq!(got.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn truncated_tls_never_panics() {
        let hello = client_hello("example.com");
        for cut in 0..hello.len() {
            let _ = tls(&hello[..cut]);
        }
    }

    #[test]
    fn host_from_http() {
        let got = http(b"GET / HTTP/1.1\r\nUser-Agent: x\r\nHost: Example.com:8080\r\n\r\n").unwrap();
        assert_eq!(got.domain.as_deref(), Some("example.com"));
        assert!(http(b"SSH-2.0-OpenSSH_9.6\r\n").is_none());
    }

    /// Пакет из RFC 9001, приложение A: клиентский Initial для example.com.
    #[test]
    fn quic_initial_from_the_rfc() {
        let hex = "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11\
                   d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399\
                   1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c\
                   8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212\
                   30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5\
                   457afd84d05dfffdb20392844ae81215468296b4cb9b8d6e8a1d7e4f3f7e2a4b";
        let bytes: Vec<u8> = (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()).collect();
        // Полный пакет в 1200 байт здесь обрезан: важно, что разбор не падает.
        assert!(quic(&bytes).is_none());
    }

    #[test]
    fn garbage_is_not_quic() {
        assert!(quic(&[]).is_none());
        assert!(quic(&[0xc0, 0, 0, 0, 1]).is_none());
        assert!(quic(&[0x40; 64]).is_none());
    }

    #[test]
    fn crypto_frames_are_reassembled_by_offset() {
        let hello_rec = client_hello("quic.example");
        let hs = &hello_rec[5..];
        let (a, b) = hs.split_at(20);
        // Второй кусок идёт первым: так тасует кадры Chrome.
        let mut frames = vec![0x06u8];
        frames.push(20); // offset
        frames.extend_from_slice(&[0x40 | ((b.len() >> 8) as u8), b.len() as u8]);
        frames.extend_from_slice(b);
        frames.push(0x01); // PING между кусками
        frames.push(0x06);
        frames.push(0);
        frames.push(a.len() as u8);
        frames.extend_from_slice(a);
        assert_eq!(sni_in_crypto(&frames).as_deref(), Some("quic.example"));
    }
}
