use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use http::HeaderMap;

use crate::config::Config;

pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

pub fn extract_client_ip(peer: SocketAddr, headers: &HeaderMap, config: &Config) -> IpAddr {
    let peer_ip = normalize_ip(peer.ip());
    let is_trusted_proxy = config
        .trusted_proxies
        .iter()
        .any(|trusted| normalize_ip(*trusted) == peer_ip);

    if !is_trusted_proxy {
        return peer_ip;
    }

    if let Some(val) = headers
        .get(config.trusted_ip_header.as_str())
        .and_then(|v| v.to_str().ok())
    {
        if let Ok(ip) = IpAddr::from_str(val.trim()) {
            return normalize_ip(ip);
        }
    }

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        for part in xff.rsplit(',') {
            if let Ok(ip) = IpAddr::from_str(part.trim()) {
                return normalize_ip(ip);
            }
        }
    }

    peer_ip
}

pub fn wants_plain_text(headers: &HeaderMap, format_param: Option<&str>) -> bool {
    if let Some(fmt) = format_param {
        match fmt.trim().to_ascii_lowercase().as_str() {
            "text" | "plain" | "txt" => return true,
            "html" => return false,
            _ => {}
        }
    }

    let html = accept_preference(headers, "text/html");
    html.0 == 0.0 || accept_preference(headers, "text/plain") >= html
}

fn accept_preference(headers: &HeaderMap, media_type: &str) -> (f32, u8) {
    headers
        .get_all(http::header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|range| accept_match(range, media_type))
        .max_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.total_cmp(&b.1)))
        .map_or((0.0, 0), |(specificity, quality)| (quality, specificity))
}

fn accept_match(range: &str, media_type: &str) -> Option<(u8, f32)> {
    let mut parts = range.split(';');
    let range = parts.next()?.trim();
    let mut specificity = if range.eq_ignore_ascii_case(media_type) {
        4
    } else if range.eq_ignore_ascii_case("text/*") {
        2
    } else if range == "*/*" {
        0
    } else {
        return None;
    };

    let mut quality = 1.0;
    for param in parts {
        let (name, value) = param.split_once('=')?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("q") {
            quality = value.parse().ok()?;
            if !(0.0..=1.0).contains(&quality) {
                return None;
            }
        } else if name.eq_ignore_ascii_case("charset")
            && value.trim_matches('"').eq_ignore_ascii_case("utf-8")
        {
            specificity |= 1;
        } else {
            return None;
        }
    }
    Some((specificity, quality))
}

pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

pub fn base_url_from_headers(headers: &HeaderMap, default_ip: Option<IpAddr>) -> String {
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| s == "http" || s == "https")
        .unwrap_or_else(|| "http".to_string());

    let host = headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|h| {
            !h.is_empty()
                && h.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '[' | ']'))
        });

    match host {
        Some(h) => format!("{proto}://{h}"),
        None => {
            let fallback = default_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "141.148.44.88".to_string());
            format!("{proto}://{fallback}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn test_config() -> Config {
        Config {
            bind_addr: "127.0.0.1:8080".to_string(),
            self_ip: Some("141.148.44.88".parse().unwrap()),
            trusted_proxies: vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
            trusted_ip_header: "x-real-client-ip".to_string(),
            maxmind_asn_db: None,
            maxmind_account_id: None,
            maxmind_license_key: None,
            maxmind_asn_url: "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz".to_string(),
            maxmind_update_interval_hours: 24,
            allow_private_port_check: false,
        }
    }

    #[test]
    fn trusts_header_only_from_trusted_proxy() {
        let cfg = test_config();
        let mut headers = HeaderMap::new();
        headers.insert("x-real-client-ip", HeaderValue::from_static("203.0.113.9"));

        let trusted_peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        assert_eq!(
            extract_client_ip(trusted_peer, &headers, &cfg),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );

        let untrusted_peer: SocketAddr = "198.51.100.77:50000".parse().unwrap();
        assert_eq!(
            extract_client_ip(untrusted_peer, &headers, &cfg),
            "198.51.100.77".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn normalizes_ipv4_mapped_proxy_peer() {
        let cfg = test_config();
        let mut headers = HeaderMap::new();
        headers.insert("x-real-client-ip", HeaderValue::from_static("8.8.4.4"));
        let mapped_peer: SocketAddr = "[::ffff:127.0.0.1]:4444".parse().unwrap();
        assert_eq!(
            extract_client_ip(mapped_peer, &headers, &cfg),
            "8.8.4.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn xff_uses_rightmost_ip() {
        let cfg = test_config();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 198.51.100.22"),
        );
        let trusted_peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        assert_eq!(
            extract_client_ip(trusted_peer, &headers, &cfg),
            "198.51.100.22".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn plain_text_negotiation() {
        let mut headers = HeaderMap::new();
        assert!(wants_plain_text(&headers, None));
        for (accept, plain) in [
            ("*/*", true),
            ("text/*", true),
            ("text/html,application/xhtml+xml,*/*;q=0.8", false),
            ("text/plain, text/html;q=0", true),
            ("text/plain;q=0.8, text/html;q=0.7", true),
            ("text/plain;q=0.7, text/html;q=0.8", false),
            ("text/*;q=0.8, text/html;q=0", true),
            ("text/*;q=0.8, text/plain;q=0", false),
            ("text/html;charset=utf-8;q=0, text/html, text/plain", true),
            ("text/html;charset=ascii, text/plain;q=0.5", true),
        ] {
            headers.insert(http::header::ACCEPT, HeaderValue::from_static(accept));
            assert_eq!(wants_plain_text(&headers, None), plain, "{accept}");
        }

        headers.insert(http::header::ACCEPT, HeaderValue::from_static("text/plain;q=0.5"));
        headers.append(http::header::ACCEPT, HeaderValue::from_static("text/html"));
        assert!(!wants_plain_text(&headers, None));
        assert!(wants_plain_text(&headers, Some("text")));
        headers.insert(http::header::ACCEPT, HeaderValue::from_static("text/html;q=0"));
        assert!(!wants_plain_text(&headers, Some("html")));
    }
}
