//! ClientHello под отпечаток браузера: то, ради чего в Go живёт uTLS.
//!
//! Жёсткая цель — hello без ML-KEM влезает в один TCP-сегмент. Двухсегментный
//! hello на 1,8 КБ режут ТСПУ на пути из РФ (октябрь 2026, Ростелеком и Dom.ru),
//! поэтому ключ X25519MLKEM768 добавляется только по прямому отказу сервера.

use rand::seq::SliceRandom;
use rand::{Rng, RngCore};

pub const X25519: u16 = 0x001d;
pub const SECP256R1: u16 = 0x0017;
pub const SECP384R1: u16 = 0x0018;
pub const X25519_MLKEM768: u16 = 0x11ec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Profile {
    Chrome,
    Firefox,
    Safari,
}

impl Profile {
    /// edge, qq, 360, android, random — наследники Chromium или маскировка под него.
    pub fn from_fingerprint(name: &str) -> Self {
        match name {
            "firefox" => Profile::Firefox,
            "safari" | "ios" => Profile::Safari,
            _ => Profile::Chrome,
        }
    }
}

pub struct HelloParams<'a> {
    pub profile: Profile,
    pub sni: Option<&'a str>,
    pub alpn: &'a [String],
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub x25519_pub: [u8; 32],
    pub mlkem_pub: Option<&'a [u8]>,
}

/// Значения GREASE из RFC 8701: 0x0a0a, 0x1a1a … 0xfafa.
fn grease(rng: &mut impl Rng) -> u16 {
    let n: u16 = rng.gen_range(0..16);
    (n << 12) | (0x0a << 8) | (n << 4) | 0x0a
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn ext(id: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    put_u16(&mut out, id);
    put_u16(&mut out, body.len() as u16);
    out.extend_from_slice(body);
    out
}

fn u16_list(values: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 2 + 2);
    put_u16(&mut out, (values.len() * 2) as u16);
    for v in values {
        put_u16(&mut out, *v);
    }
    out
}

fn sni_ext(name: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(name.len() + 5);
    put_u16(&mut body, (name.len() + 3) as u16);
    body.push(0);
    put_u16(&mut body, name.len() as u16);
    body.extend_from_slice(name.as_bytes());
    ext(0, &body)
}

fn alpn_ext(alpn: &[String]) -> Vec<u8> {
    let mut list = Vec::new();
    for proto in alpn {
        list.push(proto.len() as u8);
        list.extend_from_slice(proto.as_bytes());
    }
    let mut body = Vec::with_capacity(list.len() + 2);
    put_u16(&mut body, list.len() as u16);
    body.extend_from_slice(&list);
    ext(16, &body)
}

/// `(группа, публичный ключ)` по порядку отправки.
fn key_share_ext(shares: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut list = Vec::new();
    for (group, key) in shares {
        put_u16(&mut list, *group);
        put_u16(&mut list, key.len() as u16);
        list.extend_from_slice(key);
    }
    let mut body = Vec::with_capacity(list.len() + 2);
    put_u16(&mut body, list.len() as u16);
    body.extend_from_slice(&list);
    ext(51, &body)
}

/// GREASE для ECH (draft-ietf-tls-esni): Chrome шлёт случайный «внешний» конфиг.
fn ech_grease_ext(rng: &mut impl RngCore) -> Vec<u8> {
    let mut body = vec![0u8, 0, 1, 0, 1];
    body.push(rng.next_u32() as u8);
    put_u16(&mut body, 32);
    let mut enc = [0u8; 32];
    rng.fill_bytes(&mut enc);
    body.extend_from_slice(&enc);
    // Длина полезной нагрузки у Chrome кратна 32 и зависит от имени сервера.
    let mut payload = vec![0u8; 144];
    rng.fill_bytes(&mut payload);
    put_u16(&mut body, payload.len() as u16);
    body.extend_from_slice(&payload);
    ext(65037, &body)
}

const SIG_CHROME: &[u16] = &[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];
const SIG_FIREFOX: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201];
const SIG_SAFARI: &[u16] = &[0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201];

/// Рукопожатие целиком, с четырёхбайтным заголовком — в таком виде оно идёт и в
/// хэш транскрипта, и как AAD у REALITY.
pub fn build(p: &HelloParams<'_>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let (ciphers, exts) = match p.profile {
        Profile::Chrome => chrome(p, &mut rng),
        Profile::Firefox => firefox(p, &mut rng),
        Profile::Safari => safari(p, &mut rng),
    };

    let mut body = Vec::with_capacity(700);
    put_u16(&mut body, 0x0303);
    body.extend_from_slice(&p.random);
    body.push(32);
    body.extend_from_slice(&p.session_id);
    body.extend_from_slice(&u16_list(&ciphers));
    body.extend_from_slice(&[1, 0]); // compression: null

    let total: usize = exts.iter().map(Vec::len).sum();
    put_u16(&mut body, total as u16);
    for e in &exts {
        body.extend_from_slice(e);
    }

    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(1);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&body);
    out
}

fn chrome(p: &HelloParams<'_>, rng: &mut impl RngCore) -> (Vec<u16>, Vec<Vec<u8>>) {
    let mut r = rand::thread_rng();
    let g_cipher = grease(&mut r);
    let g_ext_a = grease(&mut r);
    let mut g_ext_b = grease(&mut r);
    if g_ext_b == g_ext_a {
        g_ext_b ^= 0x1010;
    }
    let g_group = grease(&mut r);
    let g_version = grease(&mut r);

    let ciphers = vec![
        g_cipher, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
        0x009d, 0x002f, 0x0035,
    ];

    let mut groups = vec![g_group];
    if p.mlkem_pub.is_some() {
        groups.push(X25519_MLKEM768);
    }
    groups.extend_from_slice(&[X25519, SECP256R1, SECP384R1]);

    let mut shares = vec![(g_group, vec![0u8])];
    if let Some(key) = p.mlkem_pub {
        shares.push((X25519_MLKEM768, key.to_vec()));
    }
    shares.push((X25519, p.x25519_pub.to_vec()));

    // Chrome с версии 110 тасует расширения; GREASE остаются по краям.
    let mut middle = vec![
        ext(23, &[]),
        ext(65281, &[0]),
        ext(10, &u16_list(&groups)),
        ext(11, &[1, 0]),
        ext(35, &[]),
        ext(5, &[1, 0, 0, 0, 0]),
        ext(13, &u16_list(SIG_CHROME)),
        ext(18, &[]),
        key_share_ext(&shares),
        ext(45, &[1, 1]),
        ext(43, &[6, (g_version >> 8) as u8, g_version as u8, 3, 4, 3, 3]),
        ext(27, &[2, 0, 2]),
        ech_grease_ext(rng),
    ];
    if let Some(name) = p.sni {
        middle.push(sni_ext(name));
    }
    if !p.alpn.is_empty() {
        middle.push(alpn_ext(p.alpn));
        // ALPS есть только там, где предложен h2.
        if p.alpn.iter().any(|a| a == "h2") {
            middle.push(ext(17613, &[0, 3, 2, b'h', b'2']));
        }
    }
    middle.shuffle(&mut r);

    let mut exts = Vec::with_capacity(middle.len() + 2);
    exts.push(ext(g_ext_a, &[]));
    exts.append(&mut middle);
    exts.push(ext(g_ext_b, &[0]));
    (ciphers, exts)
}

fn p256_share() -> Vec<u8> {
    // Настоящая точка кривой: мусор здесь отличил бы нас от браузера. Сам обмен
    // по P-256 не поддержан: на него сервер перейдёт только через HRR, а клиент
    // первым предлагает X25519.
    let rng = ring::rand::SystemRandom::new();
    match ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P256, &rng)
        .and_then(|key| key.compute_public_key())
    {
        Ok(public) => public.as_ref().to_vec(),
        Err(_) => vec![4; 65],
    }
}

fn firefox(p: &HelloParams<'_>, rng: &mut impl RngCore) -> (Vec<u16>, Vec<Vec<u8>>) {
    let ciphers = vec![
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ];
    let mut groups = Vec::new();
    if p.mlkem_pub.is_some() {
        groups.push(X25519_MLKEM768);
    }
    groups.extend_from_slice(&[X25519, SECP256R1, SECP384R1, 0x0019, 0x0100, 0x0101]);

    let mut shares = Vec::new();
    if let Some(key) = p.mlkem_pub {
        shares.push((X25519_MLKEM768, key.to_vec()));
    }
    shares.push((X25519, p.x25519_pub.to_vec()));
    shares.push((SECP256R1, p256_share()));

    let mut exts = Vec::with_capacity(16);
    if let Some(name) = p.sni {
        exts.push(sni_ext(name));
    }
    exts.push(ext(23, &[]));
    exts.push(ext(65281, &[0]));
    exts.push(ext(10, &u16_list(&groups)));
    exts.push(ext(11, &[1, 0]));
    if !p.alpn.is_empty() {
        exts.push(alpn_ext(p.alpn));
    }
    exts.push(ext(5, &[1, 0, 0, 0, 0]));
    exts.push(ext(34, &u16_list(&[0x0403, 0x0503, 0x0603, 0x0203])));
    exts.push(key_share_ext(&shares));
    exts.push(ext(43, &[4, 3, 4, 3, 3]));
    exts.push(ext(13, &u16_list(SIG_FIREFOX)));
    exts.push(ext(45, &[1, 1]));
    exts.push(ext(28, &[0x40, 0x01]));
    exts.push(ext(27, &[6, 0, 1, 0, 2, 0, 3]));
    exts.push(ech_grease_ext(rng));
    (ciphers, exts)
}

fn safari(p: &HelloParams<'_>, _rng: &mut impl RngCore) -> (Vec<u16>, Vec<Vec<u8>>) {
    let mut r = rand::thread_rng();
    let g_cipher = grease(&mut r);
    let g_ext_a = grease(&mut r);
    let mut g_ext_b = grease(&mut r);
    if g_ext_b == g_ext_a {
        g_ext_b ^= 0x1010;
    }
    let g_group = grease(&mut r);
    let g_version = grease(&mut r);

    let ciphers = vec![
        g_cipher, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009, 0xc014,
        0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
    ];
    let mut groups = vec![g_group];
    if p.mlkem_pub.is_some() {
        groups.push(X25519_MLKEM768);
    }
    groups.extend_from_slice(&[X25519, SECP256R1, SECP384R1, 0x0019]);

    let mut shares = vec![(g_group, vec![0u8])];
    if let Some(key) = p.mlkem_pub {
        shares.push((X25519_MLKEM768, key.to_vec()));
    }
    shares.push((X25519, p.x25519_pub.to_vec()));

    let mut exts = Vec::with_capacity(14);
    exts.push(ext(g_ext_a, &[]));
    if let Some(name) = p.sni {
        exts.push(sni_ext(name));
    }
    exts.push(ext(23, &[]));
    exts.push(ext(65281, &[0]));
    exts.push(ext(10, &u16_list(&groups)));
    exts.push(ext(11, &[1, 0]));
    if !p.alpn.is_empty() {
        exts.push(alpn_ext(p.alpn));
    }
    exts.push(ext(5, &[1, 0, 0, 0, 0]));
    exts.push(ext(13, &u16_list(SIG_SAFARI)));
    exts.push(ext(18, &[]));
    exts.push(key_share_ext(&shares));
    exts.push(ext(45, &[1, 1]));
    exts.push(ext(43, &[10, (g_version >> 8) as u8, g_version as u8, 3, 4, 3, 3, 3, 2, 3, 1]));
    exts.push(ext(27, &[2, 0, 1]));
    exts.push(ext(g_ext_b, &[0]));
    (ciphers, exts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params<'a>(profile: Profile, alpn: &'a [String], mlkem: Option<&'a [u8]>) -> HelloParams<'a> {
        HelloParams {
            profile,
            sni: Some("www.microsoft.com"),
            alpn,
            random: [7; 32],
            session_id: [9; 32],
            x25519_pub: [1; 32],
            mlkem_pub: mlkem,
        }
    }

    /// Разобрать hello и вернуть id расширений: проверка, что длины сходятся.
    fn extensions(hello: &[u8]) -> Vec<u16> {
        assert_eq!(hello[0], 1);
        let len = u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize;
        assert_eq!(len, hello.len() - 4);
        let mut i = 4 + 2 + 32;
        assert_eq!(hello[i], 32);
        i += 1 + 32;
        i += 2 + u16::from_be_bytes([hello[i], hello[i + 1]]) as usize;
        i += 1 + hello[i] as usize;
        let total = u16::from_be_bytes([hello[i], hello[i + 1]]) as usize;
        i += 2;
        assert_eq!(i + total, hello.len());
        let mut ids = Vec::new();
        while i < hello.len() {
            ids.push(u16::from_be_bytes([hello[i], hello[i + 1]]));
            i += 4 + u16::from_be_bytes([hello[i + 2], hello[i + 3]]) as usize;
        }
        ids
    }

    #[test]
    fn short_hello_fits_one_tcp_segment_on_every_profile() {
        // MSS на практике ≈1450; TLS-запись добавляет ещё 5 байт заголовка.
        let alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        for profile in [Profile::Chrome, Profile::Firefox, Profile::Safari] {
            let hello = build(&params(profile, &alpn, None));
            assert!(hello.len() + 5 < 1000, "{profile:?}: {}", hello.len());
            let ids = extensions(&hello);
            assert!(ids.contains(&0) && ids.contains(&51) && ids.contains(&43), "{ids:?}");
        }
    }

    #[test]
    fn post_quantum_share_is_only_there_when_asked() {
        let alpn = vec!["h2".to_string()];
        let key = vec![5u8; 1216];
        let with = build(&params(Profile::Chrome, &alpn, Some(&key)));
        let without = build(&params(Profile::Chrome, &alpn, None));
        assert!(with.len() > 1500, "{}", with.len());
        assert!(without.len() < 1000, "{}", without.len());
        extensions(&with);
    }

    #[test]
    fn chrome_keeps_grease_on_both_ends() {
        let ids = extensions(&build(&params(Profile::Chrome, &[], None)));
        let is_grease = |v: u16| v & 0x0f0f == 0x0a0a;
        assert!(is_grease(ids[0]));
        assert!(is_grease(*ids.last().unwrap()));
        assert_ne!(ids[0], *ids.last().unwrap());
    }
}
