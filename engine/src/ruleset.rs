//! Бинарные наборы правил sing-box (`.srs`): заголовок SRS, версия, zlib, правила.
//!
//! Домены лежат сжатым деревом (succinct trie, sing/common/domain) и так и остаются
//! в памяти: геосайт на сотни тысяч имён занимает мегабайты, а не сотни мегабайт.

use std::io::{self, Read};
use std::net::IpAddr;

use crate::common::invalid;

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP: u8 = 5;
const ITEM_IP: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_FINAL: u8 = 0xff;

const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

fn read_byte<R: Read>(r: &mut R) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

fn read_uvarint<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let b = read_byte(r)?;
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid("srs: длинный varint"))
}

/// Верхняя граница длины списка: испорченный файл не должен просить гигабайты.
const MAX_ITEMS: u64 = 1 << 28;

fn read_len<R: Read>(r: &mut R) -> io::Result<usize> {
    let n = read_uvarint(r)?;
    if n > MAX_ITEMS {
        return Err(invalid("srs: неправдоподобная длина"));
    }
    Ok(n as usize)
}

fn read_strings<R: Read>(r: &mut R) -> io::Result<Vec<String>> {
    let n = read_len(r)?;
    let mut out = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        let len = read_len(r)?;
        let mut s = vec![0u8; len];
        r.read_exact(&mut s)?;
        out.push(String::from_utf8_lossy(&s).into_owned());
    }
    Ok(out)
}

fn read_u64s<R: Read>(r: &mut R) -> io::Result<Vec<u64>> {
    let n = read_len(r)?;
    let mut out = Vec::with_capacity(n);
    let mut b = [0u8; 8];
    for _ in 0..n {
        r.read_exact(&mut b)?;
        out.push(u64::from_be_bytes(b));
    }
    Ok(out)
}

fn skip_u16s<R: Read>(r: &mut R) -> io::Result<()> {
    let n = read_len(r)?;
    let mut b = vec![0u8; n * 2];
    r.read_exact(&mut b)
}

/// Сжатое дерево доменов: уровни в ширину, метка на ребро, бит «конец узла».
pub struct DomainSet {
    leaves: Vec<u64>,
    bitmap: Vec<u64>,
    labels: Vec<u8>,
    ranks: Vec<u32>,
    selects: Vec<u32>,
}

impl DomainSet {
    fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        let _version = read_byte(r)?;
        let mut leaves = read_u64s(r)?;
        let bitmap = read_u64s(r)?;
        let labels_len = read_len(r)?;
        let mut labels = vec![0u8; labels_len];
        r.read_exact(&mut labels)?;

        let ones: usize = bitmap.iter().map(|w| w.count_ones() as usize).sum();
        let last_one = bitmap
            .iter()
            .enumerate()
            .rev()
            .find(|(_, w)| **w != 0)
            .map(|(i, w)| (i << 6) as i64 | (63 - i64::from(w.leading_zeros())))
            .unwrap_or(-1);
        let zeros = (last_one + 1) as usize - ones.min((last_one + 1) as usize);
        if ones != zeros + 1 || labels.len() != zeros {
            return Err(invalid("srs: повреждённое дерево доменов"));
        }
        let need = (ones + 63) >> 6;
        if leaves.len() < need {
            leaves.resize(need, 0);
        }

        let mut ranks = Vec::with_capacity(bitmap.len() + 1);
        let mut selects = Vec::with_capacity(bitmap.len());
        let mut count = 0u32;
        for (wi, word) in bitmap.iter().enumerate() {
            ranks.push(count);
            let mut w = *word;
            while w != 0 {
                let bit = w.trailing_zeros();
                if count & 31 == 0 {
                    selects.push(((wi as u32) << 6) | bit);
                }
                count += 1;
                w &= w - 1;
            }
        }
        ranks.push(count);
        Ok(Self { leaves, bitmap, labels, ranks, selects })
    }

    #[inline]
    fn bit(words: &[u64], i: usize) -> bool {
        words.get(i >> 6).is_some_and(|w| w & (1 << (i & 63)) != 0)
    }

    #[inline]
    fn count_zeros(&self, i: usize) -> usize {
        let word = i >> 6;
        let mask = (1u64 << (i & 63)) - 1;
        let w = self.bitmap.get(word).copied().unwrap_or(0);
        let rank = self.ranks.get(word).copied().unwrap_or(*self.ranks.last().unwrap_or(&0));
        i - (rank as usize + (w & mask).count_ones() as usize)
    }

    /// Позиция i-й единицы.
    fn select_one(&self, i: usize) -> Option<usize> {
        let mut word = (*self.selects.get(i >> 5)? >> 6) as usize;
        while *self.ranks.get(word + 1)? as usize <= i {
            word += 1;
        }
        let mut left = i - self.ranks[word] as usize;
        let mut w = *self.bitmap.get(word)?;
        while left > 0 {
            w &= w - 1;
            left -= 1;
        }
        Some((word << 6) | w.trailing_zeros() as usize)
    }

    /// Сверка идёт с конца имени к началу, как и строилось дерево.
    pub fn matches(&self, domain: &str) -> bool {
        self.lookup(domain).unwrap_or(false)
    }

    fn lookup(&self, domain: &str) -> Option<bool> {
        let (mut node, mut bm) = (0usize, 0usize);
        for &c in domain.as_bytes().iter().rev() {
            loop {
                if Self::bit(&self.bitmap, bm) {
                    return Some(false);
                }
                let label = *self.labels.get(bm.checked_sub(node)?)?;
                if label == PREFIX_LABEL {
                    return Some(true);
                }
                if label == ROOT_LABEL {
                    let next = self.count_zeros(bm + 1);
                    if c == b'.' && Self::bit(&self.leaves, next) {
                        return Some(true);
                    }
                }
                if label == c {
                    break;
                }
                bm += 1;
            }
            node = self.count_zeros(bm + 1);
            bm = self.select_one(node.checked_sub(1)?)? + 1;
        }
        if Self::bit(&self.leaves, node) {
            return Some(true);
        }
        loop {
            if Self::bit(&self.bitmap, bm) {
                return Some(false);
            }
            let label = *self.labels.get(bm.checked_sub(node)?)?;
            if label == PREFIX_LABEL || label == ROOT_LABEL {
                return Some(true);
            }
            bm += 1;
        }
    }
}

/// Диапазоны, упорядоченные по началу: бинарный поиск.
#[derive(Default)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpSet {
    fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        if read_byte(r)? != 1 {
            return Err(invalid("srs: версия набора адресов"));
        }
        let mut b = [0u8; 8];
        r.read_exact(&mut b)?;
        let n = u64::from_be_bytes(b);
        if n > MAX_ITEMS {
            return Err(invalid("srs: длина набора адресов"));
        }
        let mut set = IpSet::default();
        let read_addr = |r: &mut R| -> io::Result<u128> {
            let len = read_uvarint(r)?;
            match len {
                4 => {
                    let mut a = [0u8; 4];
                    r.read_exact(&mut a)?;
                    Ok(u128::from(u32::from_be_bytes(a)) | (1 << 127))
                }
                16 => {
                    let mut a = [0u8; 16];
                    r.read_exact(&mut a)?;
                    Ok(u128::from_be_bytes(a))
                }
                _ => Err(invalid("srs: длина адреса")),
            }
        };
        const V4_FLAG: u128 = 1 << 127;
        for _ in 0..n {
            let from = read_addr(r)?;
            let to = read_addr(r)?;
            if from & V4_FLAG != 0 && to & V4_FLAG != 0 && from >> 32 == V4_FLAG >> 32 {
                set.v4.push((from as u32, to as u32));
            } else {
                set.v6.push((from, to));
            }
        }
        set.v4.sort_unstable();
        set.v6.sort_unstable();
        Ok(set)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                let ip = u32::from(ip);
                let i = self.v4.partition_point(|(from, _)| *from <= ip);
                i > 0 && self.v4[i - 1].1 >= ip
            }
            IpAddr::V6(ip) => {
                let ip = u128::from(ip);
                let i = self.v6.partition_point(|(from, _)| *from <= ip);
                i > 0 && self.v6[i - 1].1 >= ip
            }
        }
    }
}

#[derive(Default)]
pub struct HeadlessRule {
    domains: Option<DomainSet>,
    keywords: Vec<String>,
    regexes: Vec<regex_lite::Regex>,
    ips: Option<IpSet>,
    invert: bool,
    /// Условия, которые движок не проверяет (порт, процесс из набора): такое правило
    /// не срабатывает, чтобы не расширить набор сверх написанного.
    unsupported: bool,
}

impl HeadlessRule {
    fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut rule = HeadlessRule::default();
        loop {
            match read_byte(r)? {
                ITEM_DOMAIN => rule.domains = Some(DomainSet::read(r)?),
                ITEM_DOMAIN_KEYWORD => rule.keywords = read_strings(r)?,
                ITEM_DOMAIN_REGEX => {
                    rule.regexes = read_strings(r)?
                        .iter()
                        .filter_map(|p| regex_lite::Regex::new(p).ok())
                        .collect();
                }
                ITEM_IP => rule.ips = Some(IpSet::read(r)?),
                ITEM_SOURCE_IP => {
                    IpSet::read(r)?;
                    rule.unsupported = true;
                }
                ITEM_QUERY_TYPE | ITEM_SOURCE_PORT | ITEM_PORT => {
                    skip_u16s(r)?;
                    rule.unsupported = true;
                }
                ITEM_NETWORK | ITEM_SOURCE_PORT_RANGE | ITEM_PORT_RANGE | ITEM_PROCESS_NAME | ITEM_PROCESS_PATH
                | ITEM_PACKAGE_NAME | ITEM_WIFI_SSID | ITEM_WIFI_BSSID => {
                    read_strings(r)?;
                    rule.unsupported = true;
                }
                ITEM_FINAL => {
                    rule.invert = read_byte(r)? != 0;
                    return Ok(rule);
                }
                other => return Err(invalid(format!("srs: неизвестный элемент правила {other}"))),
            }
        }
    }

    fn matches(&self, domain: Option<&str>, ip: Option<IpAddr>) -> bool {
        if self.unsupported {
            return false;
        }
        let has_domain_items = self.domains.is_some() || !self.keywords.is_empty() || !self.regexes.is_empty();
        let mut hit = false;
        if let Some(d) = domain {
            hit = self.domains.as_ref().is_some_and(|set| set.matches(d))
                || self.keywords.iter().any(|k| d.contains(k.as_str()))
                || self.regexes.iter().any(|re| re.is_match(d));
        }
        if !hit {
            if let (Some(set), Some(ip)) = (&self.ips, ip) {
                hit = set.contains(ip);
            }
        }
        if !has_domain_items && self.ips.is_none() {
            hit = false;
        }
        hit != self.invert
    }
}

pub struct RuleSet {
    rules: Vec<HeadlessRule>,
}

impl RuleSet {
    pub fn load(path: &std::path::Path) -> io::Result<Self> {
        Self::parse(&std::fs::read(path)?)
    }

    pub fn parse(data: &[u8]) -> io::Result<Self> {
        if data.len() < 4 || &data[..3] != b"SRS" {
            return Err(invalid("srs: это не набор правил sing-box"));
        }
        let mut r = io::BufReader::new(flate2::read::ZlibDecoder::new(&data[4..]));
        let count = read_len(&mut r)?;
        let mut rules = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            match read_byte(&mut r)? {
                0 => rules.push(HeadlessRule::read(&mut r)?),
                1 => return Err(invalid("srs: логические правила пока не поддержаны")),
                other => return Err(invalid(format!("srs: тип правила {other}"))),
            }
        }
        Ok(Self { rules })
    }

    pub fn matches(&self, domain: Option<&str>, ip: Option<IpAddr>) -> bool {
        self.rules.iter().any(|r| r.matches(domain, ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Построение дерева как в sing/common/domain: только для проверки чтения.
    fn build_set(mut keys: Vec<Vec<u8>>) -> Vec<u8> {
        keys.sort();
        keys.dedup();
        let (mut leaves, mut bitmap, mut labels): (Vec<u64>, Vec<u64>, Vec<u8>) = (vec![], vec![], vec![]);
        let set = |bm: &mut Vec<u64>, i: usize, v: u64| {
            while i >> 6 >= bm.len() {
                bm.push(0);
            }
            bm[i >> 6] |= v << (i & 63);
        };
        let mut queue = vec![(0usize, keys.len(), 0usize)];
        let mut l = 0usize;
        let mut i = 0;
        while i < queue.len() {
            let (mut s, e, col) = queue[i];
            if col == keys[s].len() {
                s += 1;
                set(&mut leaves, i, 1);
            }
            let mut j = s;
            while j < e {
                let from = j;
                while j < e && keys[j][col] == keys[from][col] {
                    j += 1;
                }
                queue.push((from, j, col + 1));
                labels.push(keys[from][col]);
                set(&mut bitmap, l, 0);
                l += 1;
            }
            set(&mut bitmap, l, 1);
            l += 1;
            i += 1;
        }
        let mut out = vec![0u8];
        let uvar = |out: &mut Vec<u8>, mut v: u64| {
            while v >= 0x80 {
                out.push(v as u8 | 0x80);
                v >>= 7;
            }
            out.push(v as u8);
        };
        uvar(&mut out, leaves.len() as u64);
        for w in &leaves {
            out.extend_from_slice(&w.to_be_bytes());
        }
        uvar(&mut out, bitmap.len() as u64);
        for w in &bitmap {
            out.extend_from_slice(&w.to_be_bytes());
        }
        uvar(&mut out, labels.len() as u64);
        out.extend_from_slice(&labels);
        out
    }

    fn rev(s: &str) -> Vec<u8> {
        s.bytes().rev().collect()
    }

    fn domain_set(domains: &[&str], suffixes: &[&str]) -> DomainSet {
        let mut keys: Vec<Vec<u8>> = domains.iter().map(|d| rev(d)).collect();
        for s in suffixes {
            let mut raw = vec![ROOT_LABEL];
            raw.extend_from_slice(s.as_bytes());
            raw.reverse();
            keys.push(raw);
        }
        DomainSet::read(&mut &build_set(keys)[..]).unwrap()
    }

    #[test]
    fn exact_and_suffix_domains() {
        let set = domain_set(&["exact.com"], &["yandex.ru", "vk.com"]);
        assert!(set.matches("exact.com"));
        assert!(!set.matches("sub.exact.com"));
        assert!(set.matches("yandex.ru"));
        assert!(set.matches("mail.yandex.ru"));
        assert!(set.matches("a.b.vk.com"));
        assert!(!set.matches("notyandex.ru"));
        assert!(!set.matches("yandex.com"));
        assert!(!set.matches("ru"));
    }

    #[test]
    fn many_domains_cross_the_select_sampling() {
        // Больше 32 единиц в карте: проверка шага select-индекса.
        let names: Vec<String> = (0..500).map(|i| format!("host{i}.example.net")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let set = domain_set(&refs, &[]);
        for name in &names {
            assert!(set.matches(name), "{name}");
        }
        assert!(!set.matches("host500.example.net"));
        assert!(!set.matches("example.net"));
    }

    #[test]
    fn ip_ranges() {
        let set = IpSet { v4: vec![(0x0a00_0000, 0x0aff_ffff), (0x7f00_0000, 0x7f00_0001)], v6: vec![] };
        assert!(set.contains("10.1.2.3".parse().unwrap()));
        assert!(set.contains("127.0.0.1".parse().unwrap()));
        assert!(!set.contains("127.0.0.2".parse().unwrap()));
        assert!(!set.contains("9.255.255.255".parse().unwrap()));
        assert!(!set.contains("::1".parse().unwrap()));
    }

    #[test]
    fn garbage_is_rejected_without_panicking() {
        assert!(RuleSet::parse(b"").is_err());
        assert!(RuleSet::parse(b"NOPE").is_err());
        assert!(RuleSet::parse(b"SRS\x01not zlib at all").is_err());
        assert!(DomainSet::read(&mut &[0u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f][..]).is_err());
    }
}
