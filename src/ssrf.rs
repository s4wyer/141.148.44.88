use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use hickory_resolver::TokioAsyncResolver;
use url::{Host, Url};

pub const MAX_HOPS: usize = 15;

pub fn is_forbidden_ip(ip: IpAddr, self_ip: Option<IpAddr>) -> bool {
    if let Some(s) = self_ip {
        if normalize_v4_mapped(ip) == normalize_v4_mapped(s) {
            return true;
        }
    }

    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_forbidden_v4(v4);
            }
            is_forbidden_v6(v6)
        }
    }
}

fn normalize_v4_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

fn is_forbidden_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    if o[0] == 0 {
        return true;
    }
    if o[0] == 10 {
        return true;
    }
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return true;
    }
    if o[0] == 127 {
        return true;
    }
    if o[0] == 169 && o[1] == 254 {
        return true;
    }
    if o[0] == 172 && (16..=31).contains(&o[1]) {
        return true;
    }
    if o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2) {
        return true;
    }
    if o[0] == 192 && o[1] == 88 && o[2] == 99 {
        return true;
    }
    if o[0] == 192 && o[1] == 168 {
        return true;
    }
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return true;
    }
    if o[0] == 198 && o[1] == 51 && o[2] == 100 {
        return true;
    }
    if o[0] == 203 && o[1] == 0 && o[2] == 113 {
        return true;
    }
    if o[0] >= 224 {
        return true;
    }
    false
}

fn is_forbidden_v6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return true;
    }
    let s = ip.segments();
    if (s[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    if (s[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    if s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0 {
        return true;
    }
    if s[0] == 0x0064 && s[1] == 0xff9b {
        return true;
    }
    if s[0] == 0x2001 && (s[1] == 0 || s[1] == 0x0002 || s[1] == 0x0db8) {
        return true;
    }
    (s[0] & 0xe000) != 0x2000
}

pub fn is_forbidden_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return true;
    }
    if matches!(
        h.as_str(),
        "localhost" | "metadata" | "metadata.google.internal" | "instance-data"
    ) {
        return true;
    }
    h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".internal")
        || h.ends_with(".arpa")
}

pub async fn validate_and_resolve(
    url: &Url,
    resolver: &TokioAsyncResolver,
    self_ip: Option<IpAddr>,
) -> Result<(String, u16, IpAddr), String> {
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!("blocked scheme '{scheme}': only http and https are allowed"));
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err("blocked URL credentials (userinfo not allowed)".to_string());
    }

    let port = url
        .port_or_known_default()
        .ok_or_else(|| "missing or invalid port".to_string())?;
    if port != 80 && port != 443 {
        return Err(format!(
            "blocked port {port}: only ports 80 and 443 are allowed"
        ));
    }

    let host = url
        .host()
        .ok_or_else(|| "URL has no host".to_string())?;

    match host {
        Host::Ipv4(v4) => {
            let ip = IpAddr::V4(v4);
            if is_forbidden_ip(ip, self_ip) {
                return Err(format!("blocked non-public IP address: {ip}"));
            }
            Ok((v4.to_string(), port, ip))
        }
        Host::Ipv6(v6) => {
            let ip = IpAddr::V6(v6);
            if is_forbidden_ip(ip, self_ip) {
                return Err(format!("blocked non-public IPv6 address: {ip}"));
            }
            Ok((format!("[{v6}]"), port, ip))
        }
        Host::Domain(domain) => {
            if is_forbidden_host(domain) {
                return Err(format!("blocked internal hostname: {domain}"));
            }
            let lookup = tokio::time::timeout(Duration::from_secs(4), resolver.lookup_ip(domain))
                .await
                .map_err(|_| format!("DNS lookup timed out for {domain}"))?
                .map_err(|e| format!("DNS lookup failed for {domain}: {e}"))?;

            let ips: Vec<IpAddr> = lookup.iter().collect();
            if ips.is_empty() {
                return Err(format!("DNS returned no addresses for {domain}"));
            }

            for ip in &ips {
                if is_forbidden_ip(*ip, self_ip) {
                    return Err(format!(
                        "blocked hostname {domain}: resolved to non-public IP {ip}"
                    ));
                }
            }

            let chosen = ips
                .iter()
                .copied()
                .find(|ip| ip.is_ipv4())
                .unwrap_or(ips[0]);
            Ok((domain.to_string(), port, chosen))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_resolver() -> TokioAsyncResolver {
        use hickory_resolver::config::{ResolverConfig, ResolverOpts};
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default())
    }

    #[test]
    fn blocks_metadata_and_private_ips() {
        let self_ip = Some("141.148.44.88".parse().unwrap());
        let blocked = [
            "127.0.0.1",
            "127.1.2.3",
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "100.100.100.200",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "fd00:ec2::254",
            "fe80::1",
            "141.148.44.88",
        ];

        for addr in blocked {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(is_forbidden_ip(ip, self_ip), "expected {addr} to be blocked");
        }

        let allowed = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"];
        for addr in allowed {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(!is_forbidden_ip(ip, self_ip), "expected {addr} to be allowed");
        }
    }

    #[tokio::test]
    async fn blocks_ssrf_urls() {
        let resolver = test_resolver();
        let self_ip = Some("141.148.44.88".parse().unwrap());

        let bad_urls = [
            "http://127.0.0.1:22/",
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/",
            "http://localhost/",
            "http://metadata.google.internal/",
            "http://8.8.8.8:22/",
            "http://8.8.8.8:6379/",
            "file:///etc/passwd",
            "http://user:pass@8.8.8.8/",
            "http://141.148.44.88/status/200",
        ];

        for raw in bad_urls {
            let url = Url::parse(raw).unwrap();
            let res = validate_and_resolve(&url, &resolver, self_ip).await;
            assert!(res.is_err(), "expected {raw} to be rejected, got {res:?}");
        }

        let ok_url = Url::parse("https://1.1.1.1/").unwrap();
        let res = validate_and_resolve(&ok_url, &resolver, self_ip).await;
        assert!(res.is_ok(), "expected 1.1.1.1 to be allowed, got {res:?}");
    }
}
