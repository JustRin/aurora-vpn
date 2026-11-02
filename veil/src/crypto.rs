//! Ключи пользователя, жетон входа и ключи потока.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

pub const NONCE_LEN: usize = 16;
pub const TOKEN_LEN: usize = NONCE_LEN + 8 + 16;
/// Насколько часы клиента могут расходиться с сервером, секунды.
pub const MAX_SKEW: u64 = 300;

type HmacSha256 = Hmac<Sha256>;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Случайный пароль для нового пользователя: 32 байта в base64url.
pub fn generate_password() -> String {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

/// Разобранный жетон из cookie.
pub struct Token {
    pub nonce: [u8; NONCE_LEN],
    pub ts: u64,
    mac: [u8; 16],
}

impl Token {
    pub fn parse(text: &str) -> Option<Token> {
        let raw = URL_SAFE_NO_PAD.decode(text.trim()).ok()?;
        if raw.len() != TOKEN_LEN {
            return None;
        }
        Some(Token {
            nonce: raw[..NONCE_LEN].try_into().ok()?,
            ts: u64::from_be_bytes(raw[NONCE_LEN..NONCE_LEN + 8].try_into().ok()?),
            mac: raw[NONCE_LEN + 8..].try_into().ok()?,
        })
    }

    pub fn fresh(&self, now: u64) -> bool {
        self.ts.abs_diff(now) <= MAX_SKEW
    }
}

/// Всё, что выводится из пароля. Пароль сам по себе дальше не живёт.
#[derive(Clone)]
pub struct UserKey {
    master: [u8; 32],
    auth: [u8; 32],
}

impl UserKey {
    pub fn new(password: &str) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"aura-veil/1"), password.as_bytes());
        let mut master = [0u8; 32];
        let mut auth = [0u8; 32];
        hk.expand(b"master", &mut master).expect("32 байта HKDF всегда выводит");
        hk.expand(b"auth", &mut auth).expect("32 байта HKDF всегда выводит");
        Self { master, auth }
    }

    fn mac(&self, nonce: &[u8; NONCE_LEN], ts: u64) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.auth).expect("HMAC принимает любой ключ");
        mac.update(b"veil-token");
        mac.update(nonce);
        mac.update(&ts.to_be_bytes());
        mac
    }

    /// Новый жетон: nonce и текст для cookie.
    pub fn token(&self) -> ([u8; NONCE_LEN], String) {
        self.token_at(now())
    }

    /// Жетон с заданным временем: клиент подставляет часы сервера.
    pub fn token_at(&self, ts: u64) -> ([u8; NONCE_LEN], String) {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let tag = self.mac(&nonce, ts).finalize().into_bytes();
        let mut raw = Vec::with_capacity(TOKEN_LEN);
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&ts.to_be_bytes());
        raw.extend_from_slice(&tag[..16]);
        (nonce, URL_SAFE_NO_PAD.encode(raw))
    }

    /// Подпись жетона сверяется за постоянное время.
    pub fn verify(&self, token: &Token) -> bool {
        self.mac(&token.nonce, token.ts).verify_truncated_left(&token.mac).is_ok()
    }

    /// Ключи потока: (клиент → сервер, сервер → клиент). У каждого потока свои,
    /// поэтому счётчик nonce в записях можно начинать с нуля.
    pub fn stream_keys(&self, nonce: &[u8; NONCE_LEN]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(nonce), &self.master);
        let mut up = [0u8; 32];
        let mut down = [0u8; 32];
        hk.expand(b"veil up", &mut up).expect("32 байта HKDF всегда выводит");
        hk.expand(b"veil down", &mut down).expect("32 байта HKDF всегда выводит");
        (up, down)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_roundtrip() {
        let key = UserKey::new("пароль");
        let (nonce, text) = key.token();
        let token = Token::parse(&text).unwrap();
        assert_eq!(token.nonce, nonce);
        assert!(token.fresh(now()));
        assert!(key.verify(&token));
        assert!(!UserKey::new("другой").verify(&token));
        assert!(!token.fresh(now() + MAX_SKEW + 10));
    }

    #[test]
    fn stream_keys_differ_per_nonce() {
        let key = UserKey::new("x");
        let (a_up, a_down) = key.stream_keys(&[1; 16]);
        let (b_up, _) = key.stream_keys(&[2; 16]);
        assert_ne!(a_up, a_down);
        assert_ne!(a_up, b_up);
    }

    #[test]
    fn bad_tokens_rejected() {
        assert!(Token::parse("").is_none());
        assert!(Token::parse("!!!").is_none());
        assert!(Token::parse(&URL_SAFE_NO_PAD.encode([0u8; 10])).is_none());
    }
}
