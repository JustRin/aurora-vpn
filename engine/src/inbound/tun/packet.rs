//! Разбор и правка IP-пакетов. Без выделений памяти: это самый горячий код движка,
//! и через него идёт каждый пакет каждого приложения.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    /// Начало заголовка транспорта.
    pub l4: usize,
    /// Длина IP-пакета по его заголовку.
    pub total: usize,
}

pub fn parse(p: &[u8]) -> Option<Parsed> {
    let (proto, src, dst, l4, total) = match p.first()? >> 4 {
        4 => {
            if p.len() < 20 {
                return None;
            }
            let ihl = usize::from(p[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([p[2], p[3]]));
            // Фрагменты не собираем: портов во втором куске нет. Ядро шлёт TCP с DF,
            // а редкий фрагментированный UDP приложение перешлёт само.
            let frag = u16::from_be_bytes([p[6], p[7]]) & 0x3fff;
            if ihl < 20 || total > p.len() || total < ihl || frag != 0 {
                return None;
            }
            let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
            let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
            (p[9], IpAddr::V4(src), IpAddr::V4(dst), ihl, total)
        }
        6 => {
            if p.len() < 40 {
                return None;
            }
            let total = 40 + usize::from(u16::from_be_bytes([p[4], p[5]]));
            if total > p.len() {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).ok()?);
            // Цепочки дополнительных заголовков у TCP/UDP приложений не встречаются.
            (p[6], IpAddr::V6(src), IpAddr::V6(dst), 40, total)
        }
        _ => return None,
    };
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return None;
    }
    let need = l4 + if proto == PROTO_TCP { 20 } else { 8 };
    if total < need {
        return None;
    }
    Some(Parsed {
        proto,
        src,
        dst,
        sport: u16::from_be_bytes([p[l4], p[l4 + 1]]),
        dport: u16::from_be_bytes([p[l4 + 2], p[l4 + 3]]),
        l4,
        total,
    })
}

pub fn tcp_flags(p: &[u8], parsed: &Parsed) -> u8 {
    p.get(parsed.l4 + 13).copied().unwrap_or(0)
}

fn sum_words(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        acc += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = chunks.remainder() {
        acc += u32::from(*last) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// Инкрементальная правка контрольной суммы (RFC 1624): пересчитывать весь сегмент
/// на каждом пакете в MTU 9000 незачем.
fn adjust(check: u16, old: u32, new: u32) -> u16 {
    !fold(u32::from(!check) + u32::from(!fold(old)) + u32::from(fold(new)))
}

fn addr_bytes(ip: IpAddr, out: &mut [u8; 16]) -> usize {
    match ip {
        IpAddr::V4(v4) => {
            out[..4].copy_from_slice(&v4.octets());
            4
        }
        IpAddr::V6(v6) => {
            out.copy_from_slice(&v6.octets());
            16
        }
    }
}

/// Переписать адреса и порты TCP-сегмента на месте.
pub fn rewrite_tcp(p: &mut [u8], parsed: &Parsed, src: IpAddr, sport: u16, dst: IpAddr, dport: u16) -> bool {
    let v4 = p[0] >> 4 == 4;
    if v4 != src.is_ipv4() || v4 != dst.is_ipv4() {
        return false;
    }
    let (mut new_src, mut new_dst) = ([0u8; 16], [0u8; 16]);
    let len = addr_bytes(src, &mut new_src);
    addr_bytes(dst, &mut new_dst);
    let (src_at, dst_at) = if v4 { (12, 16) } else { (8, 24) };
    let l4 = parsed.l4;

    let old_addr_sum = sum_words(&p[src_at..dst_at + len], 0);
    let new_addr_sum = sum_words(&new_dst[..len], sum_words(&new_src[..len], 0));

    if v4 {
        let check = u16::from_be_bytes([p[10], p[11]]);
        let fixed = adjust(check, old_addr_sum, new_addr_sum);
        p[10..12].copy_from_slice(&fixed.to_be_bytes());
    }

    let old_ports = sum_words(&p[l4..l4 + 4], 0);
    let new_ports = u32::from(sport) + u32::from(dport);
    let check_at = l4 + 16;
    let check = u16::from_be_bytes([p[check_at], p[check_at + 1]]);
    let fixed = adjust(check, old_addr_sum + old_ports, new_addr_sum + new_ports);
    p[check_at..check_at + 2].copy_from_slice(&fixed.to_be_bytes());

    p[src_at..src_at + len].copy_from_slice(&new_src[..len]);
    p[dst_at..dst_at + len].copy_from_slice(&new_dst[..len]);
    p[l4..l4 + 2].copy_from_slice(&sport.to_be_bytes());
    p[l4 + 2..l4 + 4].copy_from_slice(&dport.to_be_bytes());
    true
}

pub fn udp_packet_len(src: IpAddr, payload: usize) -> usize {
    (if src.is_ipv4() { 20 } else { 40 }) + 8 + payload
}

/// Собрать UDP-пакет в `out` (длиной ровно `udp_packet_len`).
pub fn write_udp(out: &mut [u8], src: IpAddr, sport: u16, dst: IpAddr, dport: u16, payload: &[u8]) {
    let udp_len = (8 + payload.len()) as u16;
    let l4 = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = out.len() as u16;
            out[0] = 0x45;
            out[1] = 0;
            out[2..4].copy_from_slice(&total.to_be_bytes());
            out[4..6].copy_from_slice(&[0, 0]);
            out[6..8].copy_from_slice(&[0x40, 0]); // DF
            out[8] = 64;
            out[9] = PROTO_UDP;
            out[10..12].copy_from_slice(&[0, 0]);
            out[12..16].copy_from_slice(&s.octets());
            out[16..20].copy_from_slice(&d.octets());
            let check = !fold(sum_words(&out[..20], 0));
            out[10..12].copy_from_slice(&check.to_be_bytes());
            20
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            out[0] = 0x60;
            out[1..4].copy_from_slice(&[0, 0, 0]);
            out[4..6].copy_from_slice(&udp_len.to_be_bytes());
            out[6] = PROTO_UDP;
            out[7] = 64;
            out[8..24].copy_from_slice(&s.octets());
            out[24..40].copy_from_slice(&d.octets());
            40
        }
        // Вызывающий проверяет, что семейства совпадают.
        _ => return,
    };
    out[l4..l4 + 2].copy_from_slice(&sport.to_be_bytes());
    out[l4 + 2..l4 + 4].copy_from_slice(&dport.to_be_bytes());
    out[l4 + 4..l4 + 6].copy_from_slice(&udp_len.to_be_bytes());
    out[l4 + 6..l4 + 8].copy_from_slice(&[0, 0]);
    out[l4 + 8..l4 + 8 + payload.len()].copy_from_slice(payload);

    let mut acc = u32::from(PROTO_UDP) + u32::from(udp_len);
    let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
    let n = addr_bytes(src, &mut a);
    addr_bytes(dst, &mut b);
    acc = sum_words(&a[..n], acc);
    acc = sum_words(&b[..n], acc);
    acc = sum_words(&out[l4..l4 + 8 + payload.len()], acc);
    let check = !fold(acc);
    // Ноль в UDP значит «контрольной суммы нет», настоящий ноль пишется единицами.
    let check = if check == 0 { 0xffff } else { check };
    out[l4 + 6..l4 + 8].copy_from_slice(&check.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_v4(payload: &[u8]) -> Vec<u8> {
        let total = 40 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[6] = 0x40;
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&[172, 19, 0, 1]);
        p[16..20].copy_from_slice(&[93, 184, 216, 34]);
        let check = !fold(sum_words(&p[..20], 0));
        p[10..12].copy_from_slice(&check.to_be_bytes());
        p[20..22].copy_from_slice(&50000u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[32] = 0x50;
        p[33] = TCP_SYN;
        p[40..].copy_from_slice(payload);
        let c = tcp_checksum(&p);
        p[36..38].copy_from_slice(&c.to_be_bytes());
        p
    }

    fn tcp_checksum(p: &[u8]) -> u16 {
        let mut copy = p.to_vec();
        copy[36..38].copy_from_slice(&[0, 0]);
        let seg = (copy.len() - 20) as u32;
        let mut acc = u32::from(PROTO_TCP) + seg;
        acc = sum_words(&copy[12..20], acc);
        acc = sum_words(&copy[20..], acc);
        !fold(acc)
    }

    fn ipv4_header_valid(p: &[u8]) -> bool {
        fold(sum_words(&p[..20], 0)) == 0xffff
    }

    #[test]
    fn parses_a_tcp_segment() {
        let p = tcp_v4(b"hi");
        let got = parse(&p).unwrap();
        assert_eq!(got.proto, PROTO_TCP);
        assert_eq!((got.sport, got.dport), (50000, 443));
        assert_eq!(got.src, "172.19.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(got.total, p.len());
        assert_eq!(tcp_flags(&p, &got), TCP_SYN);
    }

    #[test]
    fn rewrite_keeps_both_checksums_valid() {
        // Инкрементальная правка обязана совпасть с честным пересчётом.
        for payload in [&b""[..], b"x", b"odd payload", &[0xffu8; 1000][..]] {
            let mut p = tcp_v4(payload);
            let parsed = parse(&p).unwrap();
            let (s, d): (IpAddr, IpAddr) = ("172.19.0.2".parse().unwrap(), "172.19.0.1".parse().unwrap());
            assert!(rewrite_tcp(&mut p, &parsed, s, 12345, d, 40000));
            assert!(ipv4_header_valid(&p));
            assert_eq!(u16::from_be_bytes([p[36], p[37]]), tcp_checksum(&p));
            let again = parse(&p).unwrap();
            assert_eq!((again.src, again.sport, again.dst, again.dport), (s, 12345, d, 40000));
        }
    }

    #[test]
    fn rewrite_there_and_back_restores_the_packet() {
        let original = tcp_v4(b"payload");
        let mut p = original.clone();
        let parsed = parse(&p).unwrap();
        let (s, d): (IpAddr, IpAddr) = ("172.19.0.2".parse().unwrap(), "172.19.0.1".parse().unwrap());
        rewrite_tcp(&mut p, &parsed, s, 12345, d, 40000);
        let parsed = parse(&p).unwrap();
        rewrite_tcp(&mut p, &parsed, "172.19.0.1".parse().unwrap(), 50000, "93.184.216.34".parse().unwrap(), 443);
        assert_eq!(p, original);
    }

    #[test]
    fn built_udp_is_parsed_back_with_a_valid_checksum() {
        let (s, d): (IpAddr, IpAddr) = ("1.1.1.1".parse().unwrap(), "172.19.0.1".parse().unwrap());
        let mut out = vec![0u8; udp_packet_len(s, 5)];
        write_udp(&mut out, s, 53, d, 50000, b"hello");
        assert!(ipv4_header_valid(&out));
        let got = parse(&out).unwrap();
        assert_eq!((got.proto, got.sport, got.dport), (PROTO_UDP, 53, 50000));
        assert_eq!(&out[got.l4 + 8..], b"hello");
        let mut acc = u32::from(PROTO_UDP) + 13;
        acc = sum_words(&out[12..20], acc);
        acc = sum_words(&out[20..], acc);
        assert_eq!(fold(acc), 0xffff);
    }

    #[test]
    fn built_udp_v6() {
        let (s, d): (IpAddr, IpAddr) = ("2001:db8::1".parse().unwrap(), "fdfe:dcba:9876::1".parse().unwrap());
        let mut out = vec![0u8; udp_packet_len(s, 3)];
        write_udp(&mut out, s, 443, d, 40000, b"abc");
        let got = parse(&out).unwrap();
        assert_eq!((got.src, got.dst, got.sport), (s, d, 443));
        assert_eq!(got.total, out.len());
    }

    #[test]
    fn garbage_and_fragments_are_dropped() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45; 19]).is_none());
        assert!(parse(&[0x60; 39]).is_none());
        assert!(parse(&[0x10; 60]).is_none());
        let mut p = tcp_v4(b"");
        p[6] = 0x20; // More Fragments
        assert!(parse(&p).is_none());
        let mut p = tcp_v4(b"");
        p[2..4].copy_from_slice(&5000u16.to_be_bytes()); // длина больше буфера
        assert!(parse(&p).is_none());
    }

    #[test]
    fn mixed_families_are_refused() {
        let mut p = tcp_v4(b"");
        let parsed = parse(&p).unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        assert!(!rewrite_tcp(&mut p, &parsed, v6, 1, v6, 2));
    }
}
