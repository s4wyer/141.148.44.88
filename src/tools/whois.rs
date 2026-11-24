use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde::Deserialize;
use tokio::sync::Mutex;
use url::{Host, Url};

use crate::client_ip::{base_url_from_headers, escape_html, normalize_ip, wants_plain_text};
use crate::config::AppState;
use crate::html::render_page;
use crate::ssrf::{is_forbidden_host, is_forbidden_ip};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);
type LookupError = (StatusCode, &'static str);

const BAD_RESPONSE: LookupError = (
    StatusCode::BAD_GATEWAY,
    "The RDAP service returned an invalid response.",
);
const UNAVAILABLE: LookupError = (StatusCode::BAD_GATEWAY, "The RDAP service is unavailable.");
const TIMED_OUT: LookupError = (StatusCode::GATEWAY_TIMEOUT, "The RDAP lookup timed out.");

#[derive(Deserialize)]
pub struct WhoisQuery {
    q: Option<String>,
    format: Option<String>,
}

enum Target {
    Domain(String),
    Ip(IpAddr),
}

impl Target {
    fn parse(input: &str) -> Result<Self, LookupError> {
        if let Ok(ip) = input.parse::<IpAddr>() {
            return Ok(Self::Ip(normalize_ip(ip)));
        }

        let invalid = (
            StatusCode::BAD_REQUEST,
            "Enter a domain name or IP address.",
        );
        if input.len() > 1024
            || input.contains(['%', '/', '\\', ':', '@', '?', '#'])
            || input.chars().any(char::is_whitespace)
        {
            return Err(invalid);
        }
        let Ok(Host::Domain(domain)) = Host::parse(input) else {
            return Err(invalid);
        };
        let domain = domain.strip_suffix('.').unwrap_or(&domain);
        if domain.len() > 253
            || !domain.contains('.')
            || !domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(invalid);
        }
        Ok(Self::Domain(domain.to_owned()))
    }

    fn match_len(&self, entry: &str) -> Option<usize> {
        match self {
            Self::Domain(domain) => {
                let prefix = domain.strip_suffix(entry)?;
                (prefix.is_empty() || prefix.ends_with('.')).then_some(entry.len())
            }
            Self::Ip(ip) => {
                let network = entry.parse::<IpNet>().ok()?;
                network.contains(ip).then_some(network.prefix_len().into())
            }
        }
    }
}

#[derive(Deserialize)]
struct Bootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}

impl Bootstrap {
    fn service_url(&self, target: &Target) -> Option<Url> {
        let (_, urls) = self
            .services
            .iter()
            .flat_map(|(entries, urls)| entries.iter().map(move |entry| (entry, urls)))
            .filter_map(|(entry, urls)| Some((target.match_len(entry)?, urls)))
            .max_by_key(|(len, _)| *len)?;
        urls.iter()
            .filter_map(|url| Url::parse(url).ok())
            .find(allowed_service)
    }
}

struct CachedBootstrap {
    data: Bootstrap,
    expires: Instant,
}

#[derive(Default)]
struct BootstrapCache {
    dns: Mutex<Option<CachedBootstrap>>,
    ipv4: Mutex<Option<CachedBootstrap>>,
    ipv6: Mutex<Option<CachedBootstrap>>,
}

pub struct Whois {
    client: reqwest::Client,
    cache: BootstrapCache,
}

fn allowed_service(url: &Url) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(url.host(), Some(Host::Domain(host)) if !is_forbidden_host(host))
}

struct PublicDns(Option<IpAddr>);

impl Resolve for PublicDns {
    fn resolve(&self, name: Name) -> Resolving {
        let host = format!("{}.", name.as_str().trim_end_matches('.'));
        let self_ip = self.0;
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|addr| !is_forbidden_ip(addr.ip(), self_ip))
                .collect();
            if addresses.is_empty() {
                return Err(std::io::Error::other("RDAP host has no public addresses").into());
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

impl Whois {
    pub fn new(self_ip: Option<IpAddr>) -> Self {
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .dns_resolver(Arc::new(PublicDns(self_ip)))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 || !allowed_service(attempt.url()) {
                    return attempt.error("invalid RDAP redirect");
                }
                attempt.follow()
            }))
            .user_agent("brutalist-tools/0.1")
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(8))
            .build()
            .expect("valid RDAP HTTP client configuration");
        Self {
            client,
            cache: BootstrapCache::default(),
        }
    }

    async fn service_url(&self, target: &Target) -> Result<Url, LookupError> {
        let (cache, registry) = match target {
            Target::Domain(_) => (&self.cache.dns, "dns"),
            Target::Ip(IpAddr::V4(_)) => (&self.cache.ipv4, "ipv4"),
            Target::Ip(IpAddr::V6(_)) => (&self.cache.ipv6, "ipv6"),
        };
        let mut cache = cache.lock().await;
        if let Some(entry) = cache
            .as_ref()
            .filter(|entry| entry.expires > Instant::now())
        {
            return entry.data.service_url(target).ok_or_else(no_service);
        }

        let response = self
            .client
            .get(format!("https://data.iana.org/rdap/{registry}.json"))
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(request_error)?;
        let ttl = response
            .headers()
            .get(header::EXPIRES)
            .and_then(|value| DateTime::parse_from_rfc2822(value.to_str().ok()?).ok())
            .map(|expires| {
                expires
                    .signed_duration_since(Utc::now())
                    .to_std()
                    .unwrap_or_default()
            })
            .unwrap_or(Duration::from_secs(60 * 60));
        let expires = Instant::now() + ttl.min(Duration::from_secs(24 * 60 * 60));
        let data: Bootstrap = read_json(response).await?;
        let url = data.service_url(target);
        *cache = Some(CachedBootstrap { data, expires });
        url.ok_or_else(no_service)
    }

    async fn lookup(&self, target: &Target) -> Result<String, LookupError> {
        let mut url = self.service_url(target).await?;
        let (resource, value) = match target {
            Target::Domain(domain) => ("domain", domain.clone()),
            Target::Ip(ip) => ("ip", ip.to_string()),
        };
        url.path_segments_mut()
            .map_err(|_| BAD_RESPONSE)?
            .pop_if_empty()
            .extend([resource, &value]);
        let response = self
            .client
            .get(url)
            .header(header::ACCEPT, "application/rdap+json, application/json")
            .send()
            .await
            .map_err(request_error)?;
        match response.status() {
            StatusCode::NOT_FOUND => {
                return Err((StatusCode::NOT_FOUND, "No registration record found."))
            }
            StatusCode::TOO_MANY_REQUESTS => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "The RDAP service is rate limited. Try again shortly.",
                ));
            }
            status if !status.is_success() => return Err(UNAVAILABLE),
            _ => {}
        }
        let data: serde_json::Map<String, serde_json::Value> = read_json(response).await?;
        serde_json::to_string_pretty(&data).map_err(|_| BAD_RESPONSE)
    }
}

fn no_service() -> LookupError {
    (
        StatusCode::NOT_FOUND,
        "No public RDAP service found for this query.",
    )
}

fn request_error(error: reqwest::Error) -> LookupError {
    if error.is_timeout() {
        TIMED_OUT
    } else {
        UNAVAILABLE
    }
}

async fn read_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T, LookupError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(request_error)? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(BAD_RESPONSE);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| BAD_RESPONSE)
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<WhoisQuery>,
) -> Response {
    let input = query.q.as_deref().unwrap_or_default().trim();
    let base = base_url_from_headers(&headers, state.config.self_ip);
    let example = format!(r#"curl "{base}/whois?q=example.com""#);
    let plain = wants_plain_text(&headers, query.format.as_deref());
    if plain && input.is_empty() {
        return format!("/whois\n\nUsage:\n  {example}\n").into_response();
    }

    let result = match input {
        "" => Ok(String::new()),
        _ => match Target::parse(input) {
            Ok(target) => tokio::time::timeout(LOOKUP_TIMEOUT, state.whois.lookup(&target))
                .await
                .unwrap_or(Err(TIMED_OUT)),
            Err(error) => Err(error),
        },
    };
    let (status, output) = match result {
        Ok(record) => (StatusCode::OK, record),
        Err((status, message)) => (status, format!("ERROR: {message}")),
    };
    if plain {
        return (status, format!("{output}\n")).into_response();
    }

    let mut body = format!(
        r#"<p>Look up public domain and IP registration records via RDAP.</p>
<form method="GET" action="/whois">
<label for="q">Domain or IP address:</label><br>
<input id="q" name="q" type="text" value="{}" required>
<button type="submit">Look Up</button>
</form>
<p><code>{}</code></p>"#,
        escape_html(input),
        escape_html(&example)
    );
    if !output.is_empty() {
        body.push_str(&format!("\n<pre>{}</pre>", escape_html(&output)));
    }
    (status, render_page("/whois", &body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domains_and_ip_addresses_without_accepting_urls() {
        assert!(matches!(
            Target::parse("BÜCHER.DE."),
            Ok(Target::Domain(domain)) if domain == "xn--bcher-kva.de"
        ));
        assert!(matches!(
            Target::parse("2606:4700:4700::1111"),
            Ok(Target::Ip(IpAddr::V6(_)))
        ));
        assert!(matches!(
            Target::parse("::ffff:8.8.8.8"),
            Ok(Target::Ip(IpAddr::V4(ip))) if ip.octets() == [8, 8, 8, 8]
        ));
        for invalid in ["https://example.com", "a..com", "a.com/path", "a.%63om"] {
            assert!(Target::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn selects_the_most_specific_bootstrap_entry() {
        let bootstrap: Bootstrap = serde_json::from_str(
            r#"{"services":[
                [["uk"], ["https://rdap.example/"]],
                [["co.uk"], ["http://rdap.example/co/", "https://rdap.example/co/"]],
                [["8.0.0.0/8", "2600::/12"], ["https://rdap.example/broad/"]],
                [["8.8.8.0/24", "2606:4700::/32"], ["https://rdap.example/narrow/"]]
            ]}"#,
        )
        .unwrap();
        for (input, expected_path) in [
            ("example.co.uk", "/co/"),
            ("example.noco.uk", "/"),
            ("8.8.8.8", "/narrow/"),
            ("8.9.8.8", "/broad/"),
            ("2606:4700:4700::1111", "/narrow/"),
        ] {
            let target = Target::parse(input).unwrap();
            assert_eq!(
                bootstrap.service_url(&target).unwrap().path(),
                expected_path
            );
        }
        let target = Target::parse("example.com").unwrap();
        assert!(bootstrap.service_url(&target).is_none());
    }
}
