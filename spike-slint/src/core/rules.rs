//! Cleaning up the hand-written routing lists.
//!
//! People paste whatever their browser shows — `https://github.com/user/repo`,
//! `www.youtube.com/watch?v=…`, `*.example.com`, `1.2.3.4:443` — while sing-box
//! wants a bare hostname for `domain_suffix` and an address or CIDR for
//! `ip_cidr`. Anything else either never matches (a URL is not a hostname) or,
//! for the address lists, stops the core outright: one malformed `ip_cidr`
//! entry is a config error. So every list goes through here before it is
//! stored: the host is cut out of the URL, Cyrillic names become punycode (the
//! form the core sees on the wire), an address typed into a domain list moves
//! to the matching address list and vice versa, and what cannot be made sense
//! of is dropped rather than left to break the tunnel.

use std::net::IpAddr;

use crate::settings::SplitConfig;

#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Domain(String),
    Ip(String),
}

/// The same rules with every list in the form the core understands.
pub fn normalize_split(mut split: SplitConfig) -> SplitConfig {
    let (direct_domains, direct_ips) = sort_out(&split.direct_domains, &split.direct_ips);
    let (proxy_domains, proxy_ips) = sort_out(&split.proxy_domains, &split.proxy_ips);
    // There is no address block list, so an address here has nowhere to go.
    let (block_domains, _) = sort_out(&split.block_domains, &[]);
    split.direct_domains = direct_domains;
    split.direct_ips = direct_ips;
    split.proxy_domains = proxy_domains;
    split.proxy_ips = proxy_ips;
    split.block_domains = block_domains;
    split
}

/// One domain list and its address counterpart, each entry put where it belongs.
fn sort_out(domains: &[String], ips: &[String]) -> (Vec<String>, Vec<String>) {
    let mut out_domains: Vec<String> = Vec::new();
    let mut out_ips: Vec<String> = Vec::new();
    for entry in domains.iter().chain(ips).flat_map(|line| tokens(line)).filter_map(parse) {
        let (list, value) = match entry {
            Entry::Domain(d) => (&mut out_domains, d),
            Entry::Ip(ip) => (&mut out_ips, ip),
        };
        if !list.contains(&value) {
            list.push(value);
        }
    }
    (out_domains, out_ips)
}

/// Several entries may share a line: `a.com, b.com` or `a.com b.com`.
fn tokens(line: &str) -> impl Iterator<Item = &str> {
    // A comment runs to the end of the line; a URL fragment is never preceded
    // by whitespace, so `#` after a space is safe to treat as one.
    let line = if line.trim_start().starts_with('#') {
        ""
    } else {
        line.split(" #").next().unwrap_or_default()
    };
    line.split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\''))
        .filter(|t| !t.is_empty())
}

fn parse(raw: &str) -> Option<Entry> {
    let raw = raw.trim();
    // v2ray-style prefixes, as found in rule lists people copy from elsewhere.
    let raw = ["domain:", "full:", "suffix:", "host:"]
        .iter()
        .find_map(|p| raw.strip_prefix(p))
        .unwrap_or(raw);

    // A CIDR has a slash that is not a path: `10.0.0.0/8`, `2001:db8::/32`.
    // A prefix length out of range is a typo, not a path to cut off.
    if !raw.contains("://") {
        if let Some((addr, len)) = raw.split_once('/') {
            if addr.parse::<IpAddr>().is_ok() && len.bytes().all(|b| b.is_ascii_digit()) {
                return parse_cidr(raw).map(Entry::Ip);
            }
        }
    }

    let authority = authority(raw);
    if authority.is_empty() {
        return None;
    }
    if let Some(ip) = parse_ip(authority) {
        return Some(Entry::Ip(ip.to_string()));
    }
    host(authority).map(Entry::Domain)
}

fn parse_cidr(raw: &str) -> Option<String> {
    let (addr, len) = raw.split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (len <= max).then(|| format!("{addr}/{len}"))
}

/// `scheme://user@host:port/path?query#frag` → `host:port`.
fn authority(raw: &str) -> &str {
    let rest = match raw.find("://") {
        Some(i) => &raw[i + 3..],
        // Protocol-relative: `//cdn.example.com/x`.
        None => raw.trim_start_matches('/'),
    };
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let rest = &rest[..end];
    match rest.rfind('@') {
        Some(i) => &rest[i + 1..],
        None => rest,
    }
}

/// An address with or without a port: `1.2.3.4`, `1.2.3.4:443`, `::1`, `[::1]:80`.
fn parse_ip(authority: &str) -> Option<IpAddr> {
    if let Some(inner) = authority.strip_prefix('[') {
        let end = inner.find(']')?;
        return inner[..end].parse().ok();
    }
    if let Ok(ip) = authority.parse() {
        return Some(ip);
    }
    let (host, port) = authority.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    host.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
}

fn host(authority: &str) -> Option<String> {
    // `*.example.com` and `.example.com` mean the same as `example.com` here:
    // the match is by suffix anyway.
    let authority = authority.trim_start_matches(['*', '.']);
    let url = url::Url::parse(&format!("http://{authority}")).ok()?;
    // A purely numeric name the URL parser read as an address (`192.` while it
    // is still being typed) is neither a real address nor a domain.
    let url::Host::Domain(host) = url.host()? else {
        return None;
    };
    let host = host.trim_end_matches('.');
    // `www.` is how a link looks, not how people mean the rule: `www.github.com`
    // would leave out `github.com` itself and every other subdomain.
    let host = match host.strip_prefix("www.") {
        Some(rest) if rest.contains('.') => rest,
        _ => host,
    };
    let valid = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && !host.split('.').any(str::is_empty);
    valid.then(|| host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(raw: &str) -> Option<String> {
        match parse(raw)? {
            Entry::Domain(d) => Some(d),
            Entry::Ip(_) => None,
        }
    }

    fn ip(raw: &str) -> Option<String> {
        match parse(raw)? {
            Entry::Ip(ip) => Some(ip),
            Entry::Domain(_) => None,
        }
    }

    #[test]
    fn urls_are_cut_down_to_the_host() {
        assert_eq!(domain("https://github.com/Natfii/UnrealClaude").as_deref(), Some("github.com"));
        assert_eq!(domain("https://www.youtube.com/watch?v=x&t=1").as_deref(), Some("youtube.com"));
        assert_eq!(domain("mangabuff.ru/manga/123#top").as_deref(), Some("mangabuff.ru"));
        assert_eq!(domain("http://user:pw@Example.COM:8080/").as_deref(), Some("example.com"));
        assert_eq!(domain("//cdn.example.com/lib.js").as_deref(), Some("cdn.example.com"));
        assert_eq!(domain("kodikplayer.com.").as_deref(), Some("kodikplayer.com"));
    }

    #[test]
    fn wildcards_and_prefixes_reduce_to_the_suffix() {
        assert_eq!(domain("*.example.com").as_deref(), Some("example.com"));
        assert_eq!(domain(".example.com").as_deref(), Some("example.com"));
        assert_eq!(domain("domain:example.com").as_deref(), Some("example.com"));
        // `www` alone is a name in its own right, not a prefix to drop.
        assert_eq!(domain("www.localhost").as_deref(), Some("www.localhost"));
    }

    #[test]
    fn cyrillic_names_become_punycode() {
        assert_eq!(domain("https://госуслуги.рф/").as_deref(), Some("xn--c1aapkosapc.xn--p1ai"));
    }

    #[test]
    fn addresses_keep_their_prefix_and_lose_their_port() {
        assert_eq!(ip("10.0.0.0/8").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(ip("2001:db8::/32").as_deref(), Some("2001:db8::/32"));
        assert_eq!(ip("1.2.3.4").as_deref(), Some("1.2.3.4"));
        assert_eq!(ip("1.2.3.4:443").as_deref(), Some("1.2.3.4"));
        assert_eq!(ip("http://1.2.3.4:8080/admin").as_deref(), Some("1.2.3.4"));
        assert_eq!(ip("[2001:db8::1]:443").as_deref(), Some("2001:db8::1"));
        assert_eq!(ip("10.0.0.0/33"), None);
    }

    #[test]
    fn garbage_is_dropped_instead_of_breaking_the_core() {
        // Half-typed addresses would be fatal in `ip_cidr`.
        assert_eq!(parse("192."), None);
        assert_eq!(parse("192.168"), None);
        assert_eq!(parse("https://"), None);
        assert_eq!(parse("*"), None);
        assert_eq!(parse("a..b"), None);
    }

    #[test]
    fn entries_land_in_the_list_they_belong_to() {
        let split = SplitConfig {
            direct_domains: vec![
                "https://github.com/a/b, https://github.com/c".into(),
                "1.2.3.4".into(),
                "# comment".into(),
            ],
            direct_ips: vec!["https://mangabuff.ru/".into(), "10.0.0.0/8".into(), "192.".into()],
            block_domains: vec!["ads.example.com 5.6.7.8".into()],
            ..Default::default()
        };
        let split = normalize_split(split);
        assert_eq!(split.direct_domains, vec!["github.com", "mangabuff.ru"]);
        assert_eq!(split.direct_ips, vec!["1.2.3.4", "10.0.0.0/8"]);
        assert_eq!(split.block_domains, vec!["ads.example.com"]);
    }
}
