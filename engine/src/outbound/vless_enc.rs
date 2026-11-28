//! VLESS Encryption (`mlkem768x25519plus`), побайтово совместимое с Xray-core.
//!
//! Реализует гибридную постквантовую аутентификацию (X25519 и/или ML-KEM-768,
//! в том числе цепочки релеев), 1-RTT и 0-RTT (с кэшированием тикетов),
//! все три режима маскировки (`native`, `xorpub`, `random`), реключевание
//! на `MaxNonce`, набивку и встроенный BLAKE3 без внешних зависимостей.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use base64::Engine;
use ml_kem::kem::{Decapsulate, Encapsulate, EncapsulationKey};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use parking_lot::RwLock;
use rand::Rng;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::common::{invalid, other, BoxStream};

const MAX_NONCE: [u8; 12] = [0xff; 12];
const MAX_PLAINTEXT_CHUNK: usize = 8192;
const MLKEM_EK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;

// ------------------------------------------------------------------ BLAKE3
// Стандартный BLAKE3 (спецификация 2021-11-02): Sum256 и DeriveKey с полной
// поддержкой многочанкового дерева Меркла (ключи ML-KEM-768 = 1184 байта > 1024).

const B3_IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];
const B3_MSG_PERM: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const B3_CHUNK_START: u32 = 1 << 0;
const B3_CHUNK_END: u32 = 1 << 1;
const B3_PARENT: u32 = 1 << 2;
const B3_ROOT: u32 = 1 << 3;
const B3_DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const B3_DERIVE_KEY_MATERIAL: u32 = 1 << 6;

#[inline]
fn b3_g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

#[inline]
fn b3_round(state: &mut [u32; 16], m: &[u32; 16]) {
    b3_g(state, 0, 4, 8, 12, m[0], m[1]);
    b3_g(state, 1, 5, 9, 13, m[2], m[3]);
    b3_g(state, 2, 6, 10, 14, m[4], m[5]);
    b3_g(state, 3, 7, 11, 15, m[6], m[7]);
    b3_g(state, 0, 5, 10, 15, m[8], m[9]);
    b3_g(state, 1, 6, 11, 12, m[10], m[11]);
    b3_g(state, 2, 7, 8, 13, m[12], m[13]);
    b3_g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn b3_compress(cv: &[u32; 8], block_words: &[u32; 16], counter: u64, block_len: u32, flags: u32) -> [u32; 16] {
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        B3_IV[0],
        B3_IV[1],
        B3_IV[2],
        B3_IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut m = *block_words;
    for r in 0..7 {
        b3_round(&mut state, &m);
        if r < 6 {
            let mut next = [0u32; 16];
            for i in 0..16 {
                next[i] = m[B3_MSG_PERM[i]];
            }
            m = next;
        }
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    state
}

#[inline]
fn words_from_le_bytes(block: &[u8; 64]) -> [u32; 16] {
    let mut out = [0u32; 16];
    for (i, w) in out.iter_mut().enumerate() {
        *w = u32::from_le_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }
    out
}

#[inline]
fn first_8_words(state: [u32; 16]) -> [u32; 8] {
    [state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]]
}

#[inline]
fn words_to_le_bytes(words: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

struct B3Output {
    input_cv: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl B3Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_8_words(b3_compress(&self.input_cv, &self.block_words, self.counter, self.block_len, self.flags))
    }

    fn root_hash(&self) -> [u8; 32] {
        let words = b3_compress(
            &self.input_cv,
            &self.block_words,
            0,
            self.block_len,
            self.flags | B3_ROOT,
        );
        words_to_le_bytes(first_8_words(words))
    }
}

struct B3ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    buf: [u8; 64],
    buf_len: usize,
    blocks_compressed: u8,
    flags: u32,
}

impl B3ChunkState {
    fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self { cv: key_words, chunk_counter, buf: [0; 64], buf_len: 0, blocks_compressed: 0, flags }
    }

    fn len(&self) -> usize {
        64 * usize::from(self.blocks_compressed) + self.buf_len
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            B3_CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.buf_len == 64 {
                let words = words_from_le_bytes(&self.buf);
                self.cv = first_8_words(b3_compress(
                    &self.cv,
                    &words,
                    self.chunk_counter,
                    64,
                    self.flags | self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.buf = [0; 64];
                self.buf_len = 0;
            }
            let take = (64 - self.buf_len).min(input.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&input[..take]);
            self.buf_len += take;
            input = &input[take..];
        }
    }

    fn output(&self) -> B3Output {
        B3Output {
            input_cv: self.cv,
            block_words: words_from_le_bytes(&self.buf),
            counter: self.chunk_counter,
            block_len: self.buf_len as u32,
            flags: self.flags | self.start_flag() | B3_CHUNK_END,
        }
    }
}

fn b3_parent_output(left: [u32; 8], right: [u32; 8], key_words: [u32; 8], flags: u32) -> B3Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left);
    block_words[8..].copy_from_slice(&right);
    B3Output { input_cv: key_words, block_words, counter: 0, block_len: 64, flags: flags | B3_PARENT }
}

struct B3Hasher {
    chunk_state: B3ChunkState,
    key_words: [u32; 8],
    cv_stack: [[u32; 8]; 54],
    cv_stack_len: usize,
    flags: u32,
}

impl B3Hasher {
    fn new_internal(key_words: [u32; 8], flags: u32) -> Self {
        Self {
            chunk_state: B3ChunkState::new(key_words, 0, flags),
            key_words,
            cv_stack: [[0; 8]; 54],
            cv_stack_len: 0,
            flags,
        }
    }

    fn push_stack(&mut self, cv: [u32; 8]) {
        self.cv_stack[self.cv_stack_len] = cv;
        self.cv_stack_len += 1;
    }

    fn pop_stack(&mut self) -> [u32; 8] {
        self.cv_stack_len -= 1;
        self.cv_stack[self.cv_stack_len]
    }

    fn add_chunk_cv(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            let left = self.pop_stack();
            new_cv = b3_parent_output(left, new_cv, self.key_words, self.flags).chaining_value();
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == 1024 {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_cv(chunk_cv, total_chunks);
                self.chunk_state = B3ChunkState::new(self.key_words, total_chunks, self.flags);
            }
            let want = 1024 - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    fn finalize(&self) -> [u8; 32] {
        let mut output = self.chunk_state.output();
        let mut remaining = self.cv_stack_len;
        while remaining > 0 {
            remaining -= 1;
            output = b3_parent_output(self.cv_stack[remaining], output.chaining_value(), self.key_words, self.flags);
        }
        output.root_hash()
    }
}

pub fn blake3_sum256(data: &[u8]) -> [u8; 32] {
    let mut h = B3Hasher::new_internal(B3_IV, 0);
    h.update(data);
    h.finalize()
}

pub fn blake3_derive_key(context: &[u8], key_material: &[u8]) -> [u8; 32] {
    let mut ctx_hasher = B3Hasher::new_internal(B3_IV, B3_DERIVE_KEY_CONTEXT);
    ctx_hasher.update(context);
    let ctx_key = ctx_hasher.finalize();
    let mut ctx_words = [0u32; 8];
    for i in 0..8 {
        ctx_words[i] = u32::from_le_bytes([
            ctx_key[i * 4],
            ctx_key[i * 4 + 1],
            ctx_key[i * 4 + 2],
            ctx_key[i * 4 + 3],
        ]);
    }
    let mut key_hasher = B3Hasher::new_internal(ctx_words, B3_DERIVE_KEY_MATERIAL);
    key_hasher.update(key_material);
    key_hasher.finalize()
}

// ------------------------------------------------------------------ AES-256-CTR & AEAD

struct Aes256Ctr {
    cipher: Aes256,
    counter: u128,
    keystream: [u8; 16],
    pos: usize,
}

impl Aes256Ctr {
    fn new(key: &[u8], iv: &[u8]) -> Self {
        let k = blake3_derive_key(b"VLESS", key);
        let cipher = Aes256::new_from_slice(&k).expect("32-byte AES-256 key");
        let mut iv16 = [0u8; 16];
        let n = iv.len().min(16);
        iv16[..n].copy_from_slice(&iv[..n]);
        Self { cipher, counter: u128::from_be_bytes(iv16), keystream: [0; 16], pos: 16 }
    }

    fn apply_keystream(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            if self.pos == 16 {
                let mut block = self.counter.to_be_bytes().into();
                self.cipher.encrypt_block(&mut block);
                self.keystream.copy_from_slice(&block);
                self.counter = self.counter.wrapping_add(1);
                self.pos = 0;
            }
            *b ^= self.keystream[self.pos];
            self.pos += 1;
        }
    }
}

struct VlessAead {
    key: LessSafeKey,
    nonce: [u8; 12],
}

impl VlessAead {
    fn new(ctx: &[u8], key_material: &[u8], use_aes: bool) -> Self {
        let k = blake3_derive_key(ctx, key_material);
        let alg = if use_aes { &AES_256_GCM } else { &CHACHA20_POLY1305 };
        let unbound = UnboundKey::new(alg, &k).expect("32-byte AEAD key");
        Self { key: LessSafeKey::new(unbound), nonce: [0u8; 12] }
    }

    fn increase_nonce(&mut self) -> [u8; 12] {
        for i in (0..12).rev() {
            self.nonce[i] = self.nonce[i].wrapping_add(1);
            if self.nonce[i] != 0 {
                break;
            }
        }
        self.nonce
    }

    fn seal_vec(&mut self, explicit_nonce: Option<[u8; 12]>, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let n = explicit_nonce.unwrap_or_else(|| self.increase_nonce());
        let mut out = Vec::with_capacity(plaintext.len() + 16);
        out.extend_from_slice(plaintext);
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(n), Aad::from(aad), &mut out)
            .expect("AEAD seal");
        out
    }

    fn open_in_place(&mut self, explicit_nonce: Option<[u8; 12]>, aad: &[u8], buf: &mut [u8]) -> io::Result<usize> {
        if buf.len() < 16 {
            return Err(invalid("vless-enc: шифртекст короче тега"));
        }
        let n = explicit_nonce.unwrap_or_else(|| self.increase_nonce());
        let plain = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(n), Aad::from(aad), buf)
            .map_err(|_| invalid("vless-enc: ошибка проверки AEAD"))?;
        Ok(plain.len())
    }
}

#[inline]
fn encode_length(l: usize) -> [u8; 2] {
    [(l >> 8) as u8, l as u8]
}

#[inline]
fn decode_length(b: &[u8]) -> usize {
    (usize::from(b[0]) << 8) | usize::from(b[1])
}

#[inline]
fn encode_header(l: usize) -> [u8; 5] {
    [23, 3, 3, (l >> 8) as u8, l as u8]
}

#[inline]
fn decode_header(h: &[u8; 5]) -> Result<usize, String> {
    let mut l = (usize::from(h[3]) << 8) | usize::from(h[4]);
    if h[0] != 23 || h[1] != 3 || h[2] != 3 {
        l = 0;
    }
    if !(17..=16640).contains(&l) {
        return Err(format!("invalid header: {h:?}"));
    }
    Ok(l)
}

// ------------------------------------------------------------------ набивка

fn parse_padding(padding: &str) -> Result<(Vec<[i32; 3]>, Vec<[i32; 3]>), String> {
    if padding.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut lens = Vec::new();
    let mut gaps = Vec::new();
    let mut max_len: i64 = 0;
    for (i, s) in padding.split('.').enumerate() {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
            return Err(format!("vless-enc: неверный параметр padding: {s}"));
        }
        let y = [
            parts[0].parse::<i32>().map_err(|e| e.to_string())?,
            parts[1].parse::<i32>().map_err(|e| e.to_string())?,
            parts[2].parse::<i32>().map_err(|e| e.to_string())?,
        ];
        if i == 0 && (y[0] < 100 || y[1] < 35 || y[2] < 35) {
            return Err("vless-enc: первая длина padding должна быть не меньше 35".into());
        }
        if i % 2 == 0 {
            lens.push(y);
            max_len += i64::from(y[1].max(y[2]));
        } else {
            gaps.push(y);
        }
    }
    if max_len > 18 + 65535 {
        return Err("vless-enc: суммарная длина padding больше 65553".into());
    }
    Ok((lens, gaps))
}

fn rand_between(a: i32, b: i32) -> i32 {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    if lo == hi {
        return lo;
    }
    rand::thread_rng().gen_range(lo..=hi)
}

fn create_padding(lens_cfg: &[[i32; 3]], gaps_cfg: &[[i32; 3]]) -> (usize, Vec<usize>, Vec<Duration>) {
    let default_lens = [[100, 111, 1111], [50, 0, 3333]];
    let default_gaps = [[75, 0, 111]];
    let (lens_cfg, gaps_cfg) = if lens_cfg.is_empty() {
        (&default_lens[..], &default_gaps[..])
    } else {
        (lens_cfg, gaps_cfg)
    };
    let mut total = 0usize;
    let mut lens = Vec::with_capacity(lens_cfg.len());
    for y in lens_cfg {
        let mut l = 0usize;
        if y[0] >= rand_between(0, 100) {
            l = rand_between(y[1], y[2]).max(0) as usize;
        }
        lens.push(l);
        total += l;
    }
    let mut gaps = Vec::with_capacity(gaps_cfg.len());
    for y in gaps_cfg {
        let mut g = 0u64;
        if y[0] >= rand_between(0, 100) {
            g = rand_between(y[1], y[2]).max(0) as u64;
        }
        gaps.push(Duration::from_millis(g));
    }
    (total, lens, gaps)
}

// ------------------------------------------------------------------ клиент

enum NfsPeerKey {
    X25519(X25519PublicKey),
    MlKem768(Box<EncapsulationKey<MlKem768Params>>),
}

#[derive(Clone)]
struct TicketCache {
    expire: Instant,
    pfs_key: [u8; 64],
    ticket: [u8; 16],
}

pub struct VlessEncClient {
    keys: Vec<NfsPeerKey>,
    key_bytes: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_len: usize,
    xor_mode: u32,
    allow_0rtt: bool,
    padding_lens: Vec<[i32; 3]>,
    padding_gaps: Vec<[i32; 3]>,
    use_aes: bool,
    cache: RwLock<Option<TicketCache>>,
}

impl VlessEncClient {
    /// Разобрать строку `encryption` из конфига/ссылки VLESS (совместимо с `infra/conf/vless.go`).
    pub fn parse(spec: &str) -> Result<Self, String> {
        let parts: Vec<&str> = spec.trim().split('.').collect();
        if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
            return Err(format!("vless-enc: неподдержанное шифрование «{spec}»"));
        }
        let xor_mode = match parts[1] {
            "native" => 0,
            "xorpub" => 1,
            "random" => 2,
            other => return Err(format!("vless-enc: неизвестный режим «{other}»")),
        };
        let allow_0rtt = match parts[2] {
            "1rtt" => false,
            "0rtt" => true,
            other => return Err(format!("vless-enc: неизвестный rtt «{other}»")),
        };

        let mut padding_parts = Vec::new();
        let mut raw_keys = Vec::new();
        for &r in &parts[3..] {
            if raw_keys.is_empty() && r.len() < 20 {
                padding_parts.push(r);
                continue;
            }
            let trimmed = r.trim_end_matches('=');
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(trimmed)
                .map_err(|_| format!("vless-enc: неверный base64url ключа «{r}»"))?;
            if bytes.len() != 32 && bytes.len() != MLKEM_EK_LEN {
                return Err(format!("vless-enc: неверная длина ключа ({} байт)", bytes.len()));
            }
            raw_keys.push(bytes);
        }
        if raw_keys.is_empty() {
            return Err("vless-enc: не задано ни одного публичного ключа".into());
        }
        let padding_str = padding_parts.join(".");
        Self::from_parts(raw_keys, xor_mode, allow_0rtt, &padding_str, true)
    }

    pub fn from_parts(
        key_bytes: Vec<Vec<u8>>,
        xor_mode: u32,
        allow_0rtt: bool,
        padding: &str,
        use_aes: bool,
    ) -> Result<Self, String> {
        if key_bytes.is_empty() {
            return Err("vless-enc: пустой список ключей".into());
        }
        let (padding_lens, padding_gaps) = parse_padding(padding)?;
        let mut keys = Vec::with_capacity(key_bytes.len());
        let mut hash32s = Vec::with_capacity(key_bytes.len());
        let mut relays_len = 0usize;
        for kb in &key_bytes {
            match kb.len() {
                32 => {
                    let arr: [u8; 32] = kb.as_slice().try_into().unwrap();
                    keys.push(NfsPeerKey::X25519(X25519PublicKey::from(arr)));
                    relays_len += 32 + 32;
                }
                MLKEM_EK_LEN => {
                    let enc = Encoded::<EncapsulationKey<MlKem768Params>>::try_from(kb.as_slice())
                        .map_err(|_| "vless-enc: неверный ключ ML-KEM-768")?;
                    let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&enc);
                    keys.push(NfsPeerKey::MlKem768(Box::new(ek)));
                    relays_len += MLKEM_CT_LEN + 32;
                }
                n => return Err(format!("vless-enc: неверная длина ключа ({n})")),
            }
            hash32s.push(blake3_sum256(kb));
        }
        relays_len -= 32;
        Ok(Self {
            keys,
            key_bytes,
            hash32s,
            relays_len,
            xor_mode,
            allow_0rtt,
            padding_lens,
            padding_gaps,
            use_aes,
            cache: RwLock::new(None),
        })
    }

    fn invalidate_cache(&self, united_key: &[u8]) {
        let mut g = self.cache.write();
        if let Some(c) = g.as_ref() {
            if united_key.starts_with(&c.pfs_key) {
                *g = None;
            }
        }
    }

    /// Выполнить рукопожатие VLESS Encryption поверх транспортного потока.
    pub async fn handshake(self: &Arc<Self>, mut conn: BoxStream) -> io::Result<VlessEncStream> {
        let iv_and_relays_len = 16 + self.relays_len;
        let mut iv_and_relays = vec![0u8; iv_and_relays_len];
        let mut os_rng = rand::rngs::OsRng;
        os_rng.fill(&mut iv_and_relays[..16]);
        let iv: [u8; 16] = iv_and_relays[..16].try_into().unwrap();

        let mut nfs_key = [0u8; 32];
        let mut last_ctr: Option<Aes256Ctr> = None;
        let mut off = 16usize;

        for (j, key) in self.keys.iter().enumerate() {
            let index = match key {
                NfsPeerKey::X25519(peer_pk) => {
                    let sk = X25519Secret::random_from_rng(os_rng);
                    let pk = X25519PublicKey::from(&sk);
                    iv_and_relays[off..off + 32].copy_from_slice(pk.as_bytes());
                    let ss = sk.diffie_hellman(peer_pk);
                    nfs_key.copy_from_slice(ss.as_bytes());
                    32
                }
                NfsPeerKey::MlKem768(ek) => {
                    let (ct, ss) = ek
                        .encapsulate(&mut os_rng)
                        .map_err(|_| other("vless-enc: ошибка капсуляции ML-KEM-768"))?;
                    iv_and_relays[off..off + MLKEM_CT_LEN].copy_from_slice(ct.as_slice());
                    nfs_key.copy_from_slice(ss.as_slice());
                    MLKEM_CT_LEN
                }
            };
            if self.xor_mode > 0 {
                Aes256Ctr::new(&self.key_bytes[j], &iv).apply_keystream(&mut iv_and_relays[off..off + index]);
            }
            if let Some(ref mut lc) = last_ctr {
                lc.apply_keystream(&mut iv_and_relays[off..off + 32]);
            }
            if j + 1 == self.keys.len() {
                break;
            }
            let mut ctr = Aes256Ctr::new(&nfs_key, &iv);
            iv_and_relays[off + index..off + index + 32].copy_from_slice(&self.hash32s[j + 1]);
            ctr.apply_keystream(&mut iv_and_relays[off + index..off + index + 32]);
            last_ctr = Some(ctr);
            off += index + 32;
        }

        let mut nfs_aead = VlessAead::new(&iv, &nfs_key, self.use_aes);

        // Попытка 0-RTT по кэшированному тикету.
        if self.allow_0rtt {
            let cached = {
                let g = self.cache.read();
                g.as_ref().filter(|c| Instant::now() < c.expire).cloned()
            };
            if let Some(cached) = cached {
                let mut united_key = Vec::with_capacity(96);
                united_key.extend_from_slice(&cached.pfs_key);
                united_key.extend_from_slice(&nfs_key);

                let enc_len = nfs_aead.seal_vec(None, &[], &encode_length(32));
                let enc_ticket = nfs_aead.seal_vec(None, &[], &cached.ticket);
                let mut pre_write = Vec::with_capacity(iv_and_relays_len + 18 + 32);
                pre_write.extend_from_slice(&iv_and_relays);
                pre_write.extend_from_slice(&enc_len);
                pre_write.extend_from_slice(&enc_ticket);

                let tx_aead = VlessAead::new(&enc_ticket, &united_key, self.use_aes);
                let xor = (self.xor_mode == 2).then(|| {
                    XorState::new(Aes256Ctr::new(&united_key, &iv), None, pre_write.len(), 16)
                });
                return Ok(VlessEncStream::new(
                    conn,
                    xor,
                    self.use_aes,
                    Some(self.clone()),
                    united_key,
                    Some(pre_write),
                    tx_aead,
                    None,
                    0,
                ));
            }
        }

        // Полное 1-RTT рукопожатие с эфемерным гибридным ML-KEM-768 + X25519.
        let pfs_kex_len = 18 + MLKEM_EK_LEN + 32 + 16;
        let (padding_len, mut padding_lens, padding_gaps) =
            create_padding(&self.padding_lens, &self.padding_gaps);

        let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut os_rng);
        let x25519_sk = X25519Secret::random_from_rng(os_rng);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        let mut pfs_public_key = Vec::with_capacity(MLKEM_EK_LEN + 32);
        pfs_public_key.extend_from_slice(mlkem_ek.as_bytes().as_slice());
        pfs_public_key.extend_from_slice(x25519_pk.as_bytes());

        let enc_pfs_len = nfs_aead.seal_vec(None, &[], &encode_length(pfs_kex_len - 18));
        let enc_pfs_pub = nfs_aead.seal_vec(None, &[], &pfs_public_key);

        let pad_plain_len = padding_len.saturating_sub(18 + 16);
        let enc_pad_len = nfs_aead.seal_vec(None, &[], &encode_length(padding_len - 18));
        let enc_pad = nfs_aead.seal_vec(None, &[], &vec![0u8; pad_plain_len]);

        let mut client_hello = Vec::with_capacity(iv_and_relays_len + pfs_kex_len + padding_len);
        client_hello.extend_from_slice(&iv_and_relays);
        client_hello.extend_from_slice(&enc_pfs_len);
        client_hello.extend_from_slice(&enc_pfs_pub);
        client_hello.extend_from_slice(&enc_pad_len);
        client_hello.extend_from_slice(&enc_pad);

        padding_lens[0] += iv_and_relays_len + pfs_kex_len;
        let mut cursor = 0usize;
        for (idx, l) in padding_lens.iter().copied().enumerate() {
            if l > 0 {
                let end = (cursor + l).min(client_hello.len());
                conn.write_all(&client_hello[cursor..end]).await?;
                cursor = end;
            }
            if let Some(&gap) = padding_gaps.get(idx) {
                if !gap.is_zero() {
                    conn.flush().await?;
                    tokio::time::sleep(gap).await;
                }
            }
        }
        if cursor < client_hello.len() {
            conn.write_all(&client_hello[cursor..]).await?;
        }
        conn.flush().await?;

        // Ответ сервера: encryptedPfsPublicKey (1088 + 32 + 16), открывается через MaxNonce.
        let mut srv_pfs = vec![0u8; MLKEM_CT_LEN + 32 + 16];
        conn.read_exact(&mut srv_pfs).await?;
        let srv_pfs_plain_len = nfs_aead.open_in_place(Some(MAX_NONCE), &[], &mut srv_pfs)?;
        if srv_pfs_plain_len != MLKEM_CT_LEN + 32 {
            return Err(invalid("vless-enc: длина ответа PFS сервера"));
        }
        let ct = ml_kem::Ciphertext::<MlKem768>::try_from(&srv_pfs[..MLKEM_CT_LEN])
            .map_err(|_| invalid("vless-enc: шифртекст ML-KEM-768"))?;
        let mlkem_ss = mlkem_dk
            .decapsulate(&ct)
            .map_err(|_| invalid("vless-enc: декапсуляция ML-KEM-768"))?;
        let peer_x25519_bytes: [u8; 32] = srv_pfs[MLKEM_CT_LEN..MLKEM_CT_LEN + 32].try_into().unwrap();
        let x25519_ss = x25519_sk.diffie_hellman(&X25519PublicKey::from(peer_x25519_bytes));

        let mut pfs_key = [0u8; 64];
        pfs_key[..32].copy_from_slice(mlkem_ss.as_slice());
        pfs_key[32..].copy_from_slice(x25519_ss.as_bytes());

        let mut united_key = Vec::with_capacity(96);
        united_key.extend_from_slice(&pfs_key);
        united_key.extend_from_slice(&nfs_key);

        let tx_aead = VlessAead::new(&pfs_public_key, &united_key, self.use_aes);
        let mut rx_aead = VlessAead::new(&srv_pfs[..MLKEM_CT_LEN + 32], &united_key, self.use_aes);

        let mut enc_ticket = [0u8; 32];
        conn.read_exact(&mut enc_ticket).await?;
        rx_aead.open_in_place(None, &[], &mut enc_ticket)?;
        let ticket: [u8; 16] = enc_ticket[..16].try_into().unwrap();
        let seconds = decode_length(&ticket[..2]);
        if self.allow_0rtt && seconds > 0 {
            *self.cache.write() = Some(TicketCache {
                expire: Instant::now() + Duration::from_secs(seconds as u64),
                pfs_key,
                ticket,
            });
        }

        let mut enc_pad_len = [0u8; 18];
        conn.read_exact(&mut enc_pad_len).await?;
        rx_aead.open_in_place(None, &[], &mut enc_pad_len)?;
        let peer_padding_len = decode_length(&enc_pad_len[..2]);

        let xor = (self.xor_mode == 2).then(|| {
            XorState::new(
                Aes256Ctr::new(&united_key, &iv),
                Some(Aes256Ctr::new(&united_key, &ticket)),
                0,
                peer_padding_len,
            )
        });

        Ok(VlessEncStream::new(
            conn,
            xor,
            self.use_aes,
            None,
            united_key,
            None,
            tx_aead,
            Some(rx_aead),
            peer_padding_len,
        ))
    }
}

// ------------------------------------------------------------------ XorState (`random` режим)

struct XorState {
    ctr: Aes256Ctr,
    peer_ctr: Option<Aes256Ctr>,
    out_skip: usize,
    out_header: Vec<u8>,
    in_skip: usize,
    in_header: Vec<u8>,
}

impl XorState {
    fn new(ctr: Aes256Ctr, peer_ctr: Option<Aes256Ctr>, out_skip: usize, in_skip: usize) -> Self {
        Self {
            ctr,
            peer_ctr,
            out_skip,
            out_header: Vec::with_capacity(5),
            in_skip,
            in_header: Vec::with_capacity(5),
        }
    }

    fn mask_write(&mut self, mut p: &mut [u8]) {
        loop {
            if p.len() <= self.out_skip {
                self.out_skip -= p.len();
                return;
            }
            p = &mut p[self.out_skip..];
            self.out_skip = 0;
            let need = 5 - self.out_header.len();
            if p.len() < need {
                self.out_header.extend_from_slice(p);
                self.ctr.apply_keystream(p);
                return;
            }
            let mut full = [0u8; 5];
            let have = self.out_header.len();
            full[..have].copy_from_slice(&self.out_header);
            full[have..].copy_from_slice(&p[..need]);
            self.out_skip = decode_header(&full).unwrap_or(0);
            self.out_header.clear();
            self.ctr.apply_keystream(&mut p[..need]);
            p = &mut p[need..];
        }
    }

    fn unmask_read(&mut self, mut p: &mut [u8]) {
        loop {
            if p.len() <= self.in_skip {
                self.in_skip -= p.len();
                return;
            }
            p = &mut p[self.in_skip..];
            self.in_skip = 0;
            let Some(peer_ctr) = self.peer_ctr.as_mut() else {
                return;
            };
            let need = 5 - self.in_header.len();
            if p.len() < need {
                peer_ctr.apply_keystream(p);
                self.in_header.extend_from_slice(p);
                return;
            }
            peer_ctr.apply_keystream(&mut p[..need]);
            let mut full = [0u8; 5];
            let have = self.in_header.len();
            full[..have].copy_from_slice(&self.in_header);
            full[have..].copy_from_slice(&p[..need]);
            self.in_skip = decode_header(&full).unwrap_or(0);
            self.in_header.clear();
            p = &mut p[need..];
        }
    }
}

// ------------------------------------------------------------------ VlessEncStream

enum ReadStage {
    /// 0-RTT: ждём 16 байт `serverRandom`.
    NeedServerRandom { buf: [u8; 16], filled: usize },
    /// 1-RTT: дочитываем `PeerPadding` и проверяем AEAD.
    NeedPeerPadding { buf: Vec<u8>, filled: usize },
    /// Обычное чтение 5-байтного заголовка записи.
    NeedHeader { buf: [u8; 5], filled: usize },
    /// Чтение тела записи длиной `len`.
    NeedBody { header: [u8; 5], buf: Vec<u8>, filled: usize },
}

pub struct VlessEncStream {
    io: BoxStream,
    xor: Option<XorState>,
    use_aes: bool,
    client_0rtt: Option<Arc<VlessEncClient>>,
    united_key: Vec<u8>,
    pre_write: Option<Vec<u8>>,
    tx_aead: VlessAead,
    rx_aead: Option<VlessAead>,

    write_buf: Vec<u8>,
    write_pos: usize,

    read_stage: ReadStage,
    ready: Vec<u8>,
    ready_pos: usize,
}

impl VlessEncStream {
    #[allow(clippy::too_many_arguments)]
    fn new(
        io: BoxStream,
        xor: Option<XorState>,
        use_aes: bool,
        client_0rtt: Option<Arc<VlessEncClient>>,
        united_key: Vec<u8>,
        pre_write: Option<Vec<u8>>,
        tx_aead: VlessAead,
        rx_aead: Option<VlessAead>,
        peer_padding_len: usize,
    ) -> Self {
        let read_stage = if rx_aead.is_none() {
            ReadStage::NeedServerRandom { buf: [0u8; 16], filled: 0 }
        } else if peer_padding_len > 0 {
            ReadStage::NeedPeerPadding { buf: vec![0u8; peer_padding_len], filled: 0 }
        } else {
            ReadStage::NeedHeader { buf: [0u8; 5], filled: 0 }
        };
        Self {
            io,
            xor,
            use_aes,
            client_0rtt,
            united_key,
            pre_write,
            tx_aead,
            rx_aead,
            write_buf: Vec::new(),
            write_pos: 0,
            read_stage,
            ready: Vec::new(),
            ready_pos: 0,
        }
    }

    fn poll_read_raw(
        io: &mut BoxStream,
        xor: &mut Option<XorState>,
        cx: &mut Context<'_>,
        dst: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut rb = ReadBuf::new(dst);
        ready!(Pin::new(io).poll_read(cx, &mut rb))?;
        let n = rb.filled().len();
        if n > 0 {
            if let Some(x) = xor.as_mut() {
                x.unmask_read(&mut dst[..n]);
            }
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.write_buf[self.write_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_pos += n;
        }
        if !self.write_buf.is_empty() {
            self.write_buf.clear();
            self.write_pos = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for VlessEncStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.ready_pos < this.ready.len() {
                let n = out.remaining().min(this.ready.len() - this.ready_pos);
                out.put_slice(&this.ready[this.ready_pos..this.ready_pos + n]);
                this.ready_pos += n;
                if this.ready_pos == this.ready.len() {
                    this.ready.clear();
                    this.ready_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match &mut this.read_stage {
                ReadStage::NeedServerRandom { buf, filled } => {
                    let n = ready!(Self::poll_read_raw(&mut this.io, &mut this.xor, cx, &mut buf[*filled..]))?;
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    *filled += n;
                    if *filled == 16 {
                        let sr = *buf;
                        this.rx_aead = Some(VlessAead::new(&sr, &this.united_key, this.use_aes));
                        if let Some(x) = this.xor.as_mut() {
                            x.peer_ctr = Some(Aes256Ctr::new(&this.united_key, &sr));
                        }
                        this.read_stage = ReadStage::NeedHeader { buf: [0u8; 5], filled: 0 };
                    }
                }
                ReadStage::NeedPeerPadding { buf, filled } => {
                    let n = ready!(Self::poll_read_raw(&mut this.io, &mut this.xor, cx, &mut buf[*filled..]))?;
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    *filled += n;
                    if *filled == buf.len() {
                        let rx = this.rx_aead.as_mut().expect("rx_aead initialized");
                        rx.open_in_place(None, &[], buf)?;
                        this.read_stage = ReadStage::NeedHeader { buf: [0u8; 5], filled: 0 };
                    }
                }
                ReadStage::NeedHeader { buf, filled } => {
                    let n = ready!(Self::poll_read_raw(&mut this.io, &mut this.xor, cx, &mut buf[*filled..]))?;
                    if n == 0 {
                        if *filled == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    *filled += n;
                    if *filled == 5 {
                        let header = *buf;
                        match decode_header(&header) {
                            Ok(len) => {
                                this.client_0rtt = None;
                                this.read_stage = ReadStage::NeedBody { header, buf: vec![0u8; len], filled: 0 };
                            }
                            Err(msg) => {
                                if let Some(client) = this.client_0rtt.take() {
                                    client.invalidate_cache(&this.united_key);
                                    return Poll::Ready(Err(other("vless-enc: new handshake needed")));
                                }
                                return Poll::Ready(Err(invalid(format!("vless-enc: {msg}"))));
                            }
                        }
                    }
                }
                ReadStage::NeedBody { header, buf, filled } => {
                    let n = ready!(Self::poll_read_raw(&mut this.io, &mut this.xor, cx, &mut buf[*filled..]))?;
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    *filled += n;
                    if *filled == buf.len() {
                        let hdr = *header;
                        let mut body = std::mem::take(buf);
                        this.read_stage = ReadStage::NeedHeader { buf: [0u8; 5], filled: 0 };
                        let rx = this.rx_aead.as_mut().expect("rx_aead initialized");
                        let next_aead = if rx.nonce == MAX_NONCE {
                            let mut ctx_bytes = Vec::with_capacity(5 + body.len());
                            ctx_bytes.extend_from_slice(&hdr);
                            ctx_bytes.extend_from_slice(&body);
                            Some(VlessAead::new(&ctx_bytes, &this.united_key, this.use_aes))
                        } else {
                            None
                        };
                        let plain_len = rx.open_in_place(None, &hdr, &mut body)?;
                        if let Some(next) = next_aead {
                            this.rx_aead = Some(next);
                        }
                        body.truncate(plain_len);
                        this.ready = body;
                        this.ready_pos = 0;
                    }
                }
            }
        }
    }
}

impl AsyncWrite for VlessEncStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_flush_write(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk = &data[..data.len().min(MAX_PLAINTEXT_CHUNK)];
        let hdr = encode_header(chunk.len() + 16);
        let at_max = this.tx_aead.nonce == MAX_NONCE;
        let ct = this.tx_aead.seal_vec(None, &hdr, chunk);

        let mut record = Vec::with_capacity(5 + ct.len());
        record.extend_from_slice(&hdr);
        record.extend_from_slice(&ct);
        if at_max {
            this.tx_aead = VlessAead::new(&record, &this.united_key, this.use_aes);
        }

        let mut frame = if let Some(mut pre) = this.pre_write.take() {
            pre.extend_from_slice(&record);
            pre
        } else {
            record
        };
        if let Some(x) = this.xor.as_mut() {
            x.mask_write(&mut frame);
        }
        this.write_buf = frame;
        this.write_pos = 0;
        let _ = this.poll_flush_write(cx)?;
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_flush_write(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_flush_write(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn b3_test_input(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn blake3_matches_official_test_vectors() {
        // Официальные векторы BLAKE3 (включая > 1024 байт — дерево Меркла).
        assert_eq!(
            hex(&blake3_sum256(&b3_test_input(0))),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            hex(&blake3_sum256(&b3_test_input(1))),
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"
        );
        assert_eq!(
            hex(&blake3_sum256(&b3_test_input(64))),
            "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"
        );
        assert_eq!(
            hex(&blake3_sum256(&b3_test_input(1024))),
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"
        );
        assert_eq!(
            hex(&blake3_sum256(&b3_test_input(1025))),
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"
        );
        // Официальный вектор derive_key для 0 и 1025 байт (сверено также вживую с Xray blake3).
        let ctx = b"BLAKE3 2019-12-27 16:29:52 test vectors context";
        assert_eq!(
            hex(&blake3_derive_key(ctx, &b3_test_input(0))),
            "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"
        );
        assert_eq!(
            hex(&blake3_derive_key(ctx, &b3_test_input(1025))),
            "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"
        );
    }

    #[test]
    fn parses_real_xray_encryption_strings() {
        let k32 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let k1184 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9u8; MLKEM_EK_LEN]);

        let c = VlessEncClient::parse(&format!("mlkem768x25519plus.native.0rtt.{k32}")).unwrap();
        assert_eq!(c.xor_mode, 0);
        assert!(c.allow_0rtt);
        assert_eq!(c.keys.len(), 1);
        assert_eq!(c.relays_len, 32);

        let c2 = VlessEncClient::parse(&format!(
            "mlkem768x25519plus.random.1rtt.100-111-1111.75-0-111.{k32}.{k1184}"
        ))
        .unwrap();
        assert_eq!(c2.xor_mode, 2);
        assert!(!c2.allow_0rtt);
        assert_eq!(c2.keys.len(), 2);
        assert_eq!(c2.padding_lens.len(), 1);
        assert_eq!(c2.padding_gaps.len(), 1);
        assert_eq!(c2.relays_len, 32 + 32 + MLKEM_CT_LEN);

        assert!(VlessEncClient::parse("none").is_err());
        assert!(VlessEncClient::parse("mlkem768x25519plus.bogus.0rtt.AAAA").is_err());
    }

    /// Эталонный мини-сервер по `proxy/vless/encryption/server.go` для сквозной проверки 1-RTT и 0-RTT.
    struct MockServer {
        sk: X25519Secret,
        pk_bytes: [u8; 32],
        xor_mode: u32,
        sessions: parking_lot::Mutex<std::collections::HashMap<[u8; 16], [u8; 64]>>,
    }

    impl MockServer {
        fn new(xor_mode: u32) -> Self {
            let sk = X25519Secret::random_from_rng(rand::rngs::OsRng);
            let pk_bytes = *X25519PublicKey::from(&sk).as_bytes();
            Self { sk, pk_bytes, xor_mode, sessions: Default::default() }
        }

        async fn accept(&self, mut io: BoxStream) -> io::Result<VlessEncStream> {
            let mut iv_rel = [0u8; 48];
            io.read_exact(&mut iv_rel).await?;
            let iv: [u8; 16] = iv_rel[..16].try_into().unwrap();
            let mut peer_pub = [0u8; 32];
            peer_pub.copy_from_slice(&iv_rel[16..48]);
            if self.xor_mode > 0 {
                Aes256Ctr::new(&self.pk_bytes, &iv).apply_keystream(&mut peer_pub);
            }
            assert!(peer_pub[31] <= 127);
            let nfs_key = *self.sk.diffie_hellman(&X25519PublicKey::from(peer_pub)).as_bytes();

            let mut enc_len = [0u8; 18];
            io.read_exact(&mut enc_len).await?;
            let mut use_aes = true;
            let mut nfs_aead = VlessAead::new(&iv, &nfs_key, use_aes);
            let mut try_len = enc_len;
            if nfs_aead.open_in_place(None, &[], &mut try_len).is_err() {
                use_aes = false;
                nfs_aead = VlessAead::new(&iv, &nfs_key, use_aes);
                try_len = enc_len;
                nfs_aead.open_in_place(None, &[], &mut try_len)?;
            }
            let len = decode_length(&try_len[..2]);

            if len == 32 {
                let mut enc_ticket = [0u8; 32];
                io.read_exact(&mut enc_ticket).await?;
                let mut dec = enc_ticket;
                nfs_aead.open_in_place(None, &[], &mut dec)?;
                let ticket: [u8; 16] = dec[..16].try_into().unwrap();
                let pfs_key = *self.sessions.lock().get(&ticket).ok_or_else(|| other("expired"))?;
                let mut united = Vec::with_capacity(96);
                united.extend_from_slice(&pfs_key);
                united.extend_from_slice(&nfs_key);
                let mut srv_rand = [0u8; 16];
                rand::rngs::OsRng.fill(&mut srv_rand);
                let tx_aead = VlessAead::new(&srv_rand, &united, use_aes);
                let rx_aead = VlessAead::new(&enc_ticket, &united, use_aes);
                let xor = (self.xor_mode == 2).then(|| {
                    XorState::new(Aes256Ctr::new(&united, &srv_rand), Some(Aes256Ctr::new(&united, &iv)), 16, 0)
                });
                return Ok(VlessEncStream::new(
                    io,
                    xor,
                    use_aes,
                    None,
                    united,
                    Some(srv_rand.to_vec()),
                    tx_aead,
                    Some(rx_aead),
                    0,
                ));
            }

            let mut enc_pfs = vec![0u8; len];
            io.read_exact(&mut enc_pfs).await?;
            nfs_aead.open_in_place(None, &[], &mut enc_pfs)?;
            let ek_enc = Encoded::<EncapsulationKey<MlKem768Params>>::try_from(&enc_pfs[..MLKEM_EK_LEN]).unwrap();
            let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&ek_enc);
            let (ct, mlkem_ss) = ek.encapsulate(&mut rand::rngs::OsRng).unwrap();
            let peer_x = X25519PublicKey::from(<[u8; 32]>::try_from(&enc_pfs[MLKEM_EK_LEN..MLKEM_EK_LEN + 32]).unwrap());
            let srv_x_sk = X25519Secret::random_from_rng(rand::rngs::OsRng);
            let srv_x_pk = X25519PublicKey::from(&srv_x_sk);
            let x_ss = srv_x_sk.diffie_hellman(&peer_x);

            let mut pfs_key = [0u8; 64];
            pfs_key[..32].copy_from_slice(mlkem_ss.as_slice());
            pfs_key[32..].copy_from_slice(x_ss.as_bytes());
            let mut srv_pfs_pub = Vec::with_capacity(MLKEM_CT_LEN + 32);
            srv_pfs_pub.extend_from_slice(ct.as_slice());
            srv_pfs_pub.extend_from_slice(srv_x_pk.as_bytes());

            let mut united = Vec::with_capacity(96);
            united.extend_from_slice(&pfs_key);
            united.extend_from_slice(&nfs_key);

            let mut tx_aead = VlessAead::new(&srv_pfs_pub, &united, use_aes);
            let rx_aead = VlessAead::new(&enc_pfs[..MLKEM_EK_LEN + 32], &united, use_aes);

            let mut ticket = [0u8; 16];
            rand::rngs::OsRng.fill(&mut ticket);
            ticket[0..2].copy_from_slice(&encode_length(600));
            self.sessions.lock().insert(ticket, pfs_key);

            let mut hello = Vec::new();
            hello.extend_from_slice(&nfs_aead.seal_vec(Some(MAX_NONCE), &[], &srv_pfs_pub));
            hello.extend_from_slice(&tx_aead.seal_vec(None, &[], &ticket));
            let pad_plain = vec![0u8; 40];
            hello.extend_from_slice(&tx_aead.seal_vec(None, &[], &encode_length(pad_plain.len() + 16)));
            hello.extend_from_slice(&tx_aead.seal_vec(None, &[], &pad_plain));
            io.write_all(&hello).await?;
            io.flush().await?;

            // Читаем padding клиента.
            let mut cl_pad_len = [0u8; 18];
            io.read_exact(&mut cl_pad_len).await?;
            nfs_aead.open_in_place(None, &[], &mut cl_pad_len)?;
            let mut cl_pad = vec![0u8; decode_length(&cl_pad_len[..2])];
            io.read_exact(&mut cl_pad).await?;
            nfs_aead.open_in_place(None, &[], &mut cl_pad)?;

            let xor = (self.xor_mode == 2).then(|| {
                XorState::new(Aes256Ctr::new(&united, &ticket), Some(Aes256Ctr::new(&united, &iv)), 0, 0)
            });
            Ok(VlessEncStream::new(io, xor, use_aes, None, united, None, tx_aead, Some(rx_aead), 0))
        }
    }

    #[tokio::test]
    async fn full_1rtt_and_0rtt_roundtrip_across_all_xor_modes() {
        for xor_mode in [0u32, 1, 2] {
            let srv = Arc::new(MockServer::new(xor_mode));
            let client = Arc::new(
                VlessEncClient::from_parts(vec![srv.pk_bytes.to_vec()], xor_mode, true, "100-40-50", true).unwrap(),
            );

            // 1) Первое соединение — 1-RTT, получает и кэширует тикет.
            let (c_io, s_io) = tokio::io::duplex(64 * 1024);
            let srv1 = srv.clone();
            let s_task = tokio::spawn(async move {
                let mut s = srv1.accept(Box::new(s_io)).await.unwrap();
                let mut buf = vec![0u8; 20000];
                let mut got = Vec::new();
                while got.len() < 12000 {
                    let n = s.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                s.write_all(&got).await.unwrap();
                s.flush().await.unwrap();
            });

            let mut c = client.handshake(Box::new(c_io)).await.unwrap();
            let payload: Vec<u8> = (0..12000).map(|i| (i % 251) as u8).collect();
            c.write_all(&payload).await.unwrap();
            c.flush().await.unwrap();
            let mut reply = vec![0u8; payload.len()];
            c.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, payload, "1-RTT mismatch in xor_mode={xor_mode}");
            s_task.await.unwrap();
            assert!(client.cache.read().is_some(), "ticket should be cached");

            // 2) Второе соединение — 0-RTT по кэшированному тикету.
            let (c_io2, s_io2) = tokio::io::duplex(64 * 1024);
            let srv2 = srv.clone();
            let s_task2 = tokio::spawn(async move {
                let mut s = srv2.accept(Box::new(s_io2)).await.unwrap();
                let mut buf = [0u8; 64];
                let n = s.read(&mut buf).await.unwrap();
                s.write_all(&buf[..n]).await.unwrap();
                s.flush().await.unwrap();
            });
            let mut c2 = client.handshake(Box::new(c_io2)).await.unwrap();
            c2.write_all(b"zero-rtt hello!").await.unwrap();
            c2.flush().await.unwrap();
            let mut echo = [0u8; 15];
            c2.read_exact(&mut echo).await.unwrap();
            assert_eq!(&echo, b"zero-rtt hello!", "0-RTT mismatch in xor_mode={xor_mode}");
            s_task2.await.unwrap();
        }
    }
}
