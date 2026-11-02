//! Российские адреса, которые сервер не выпускает наружу.
//!
//! Крупные российские платформы обязаны выявлять VPN (методика Минцифры,
//! апрель 2026): запрос их приложения, пришедший с IP сервера, — готовый повод
//! сдать этот IP в блокировку, и тогда сервер теряют все. Клиент Aurora шлёт
//! Россию мимо туннеля сам; здесь страховка на случай, когда у кого-то это
//! выключено или стоит другой клиент. Российский сервис тогда просто не
//! откроется через VPN, а IP сервера он не увидит.

use std::net::IpAddr;

/// Зоны РФ и домены российских сервисов вне этих зон. Тот же список, что
/// `RU_DIRECT_SUFFIXES` в приложении.
pub const SUFFIXES: &[&str] = &[
    "ru", "su", "xn--p1ai", "xn--d1acj3b", "xn--80adxhks", "moscow", "tatar",
    "yandex.net", "yandex.com", "yandex.cloud", "yastatic.net", "yandexcloud.net", "ya.cc",
    "vk.com", "vk.me", "vk.link", "vkontakte.com", "userapi.com", "vkuser.net", "vkuseraudio.net",
    "vkuservideo.net", "vk-portal.net", "vk-cdn.net", "mycdn.me", "my.com", "mradx.net",
    "avito.st", "2gis.com", "okko.tv", "ivi.tv",
];

pub fn is_ru_domain(domain: &str) -> bool {
    let d = domain.trim_end_matches('.');
    SUFFIXES.iter().any(|s| {
        d == *s || (d.len() > s.len() && d.ends_with(s) && d.as_bytes()[d.len() - s.len() - 1] == b'.')
    })
}

/// Диапазоны адресов из списка CIDR (по строке на сеть), слитые и
/// отсортированные: проверка — двоичный поиск.
#[derive(Default)]
pub struct CidrSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn merge<T: Ord + Copy>(mut ranges: Vec<(T, T)>, next: impl Fn(T) -> Option<T>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = out.last_mut() {
            if next(last.1).is_some_and(|n| start <= n) || start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        out.push((start, end));
    }
    out
}

fn find<T: Ord + Copy>(ranges: &[(T, T)], x: T) -> bool {
    let i = ranges.partition_point(|r| r.0 <= x);
    i > 0 && ranges[i - 1].1 >= x
}

impl CidrSet {
    /// Разобрать список. Вторым — сколько строк не удалось понять.
    pub fn parse(text: &str) -> (Self, usize) {
        let (mut v4, mut v6, mut bad) = (Vec::new(), Vec::new(), 0);
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let (addr, bits) = line.split_once('/').unwrap_or((line, ""));
            match addr.parse::<IpAddr>() {
                Ok(IpAddr::V4(ip)) => match bits.parse::<u32>().ok().or(bits.is_empty().then_some(32)).filter(|b| *b <= 32) {
                    Some(bits) => {
                        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                        let start = u32::from(ip) & mask;
                        v4.push((start, start | !mask));
                    }
                    None => bad += 1,
                },
                Ok(IpAddr::V6(ip)) => match bits.parse::<u32>().ok().or(bits.is_empty().then_some(128)).filter(|b| *b <= 128) {
                    Some(bits) => {
                        let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                        let start = u128::from(ip) & mask;
                        v6.push((start, start | !mask));
                    }
                    None => bad += 1,
                },
                Err(_) => bad += 1,
            }
        }
        let set = Self { v4: merge(v4, |x: u32| x.checked_add(1)), v6: merge(v6, |x: u128| x.checked_add(1)) };
        (set, bad)
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => find(&self.v4, u32::from(v4)),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => find(&self.v4, u32::from(v4)),
                None => find(&self.v6, u128::from(v6)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russian_domains() {
        for d in ["ozon.ru", "api.vk.ru", "vk.com", "sun9-1.userapi.com", "egress.yandex.net", "xn--d1abbgf6aiiy.xn--p1ai", "ru"] {
            assert!(is_ru_domain(d), "{d}");
        }
        for d in ["guru", "github.com", "ruby-lang.org", "notvk.com", "yandex.net.example.org", "tiktokcdn.com"] {
            assert!(!is_ru_domain(d), "{d}");
        }
    }

    #[test]
    fn cidr_lookup() {
        let (set, bad) = CidrSet::parse("# РФ\n5.3.0.0/16\n5.4.0.0/16\n77.88.8.8\n2a02:6b8::/32\nмусор\n10.0.0.0/40\n");
        assert_eq!(bad, 2);
        assert_eq!(set.v4.len(), 2, "соседние сети слились");
        for ip in ["5.3.0.1", "5.4.255.255", "77.88.8.8", "2a02:6b8:a::1", "::ffff:5.3.1.1"] {
            assert!(set.contains(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["5.2.255.255", "5.5.0.0", "77.88.8.9", "2a02:6b9::1", "8.8.8.8"] {
            assert!(!set.contains(ip.parse().unwrap()), "{ip}");
        }
        assert!(CidrSet::default().is_empty());
    }
}
