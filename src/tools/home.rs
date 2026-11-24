use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, Method, Uri, Version};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::client_ip::{base_url_from_headers, escape_html, extract_client_ip, wants_plain_text};
use crate::config::AppState;
use crate::html::render_page;
use crate::ssrf;

#[derive(Deserialize)]
pub struct HomeQuery {
    pub format: Option<String>,
}

fn lookup_asn(state: &AppState, ip: IpAddr) -> String {
    if ssrf::is_forbidden_ip(ip, None) {
        return "private/local (not routable)".to_string();
    }

    let Ok(guard) = state.asn_db.read() else {
        return "ASN database lock error".to_string();
    };
    let Some(reader) = guard.as_ref() else {
        return "GeoLite2-ASN.mmdb not loaded (place GeoLite2-ASN.mmdb in app dir)".to_string();
    };

    match reader.lookup::<maxminddb::geoip2::Asn>(ip) {
        Ok(asn) => match (
            asn.autonomous_system_number,
            asn.autonomous_system_organization,
        ) {
            (Some(num), Some(org)) => format!("AS{num} — {org}"),
            (Some(num), None) => format!("AS{num}"),
            (None, Some(org)) => org.to_string(),
            (None, None) => "unknown".to_string(),
        },
        Err(maxminddb::MaxMindDBError::AddressNotFoundError(_)) => "not found in GeoLite2-ASN".to_string(),
        Err(err) => format!("lookup error: {err}"),
    }
}

async fn lookup_rdns(state: &AppState, ip: IpAddr) -> String {
    if ssrf::is_forbidden_ip(ip, None) {
        return "none (private/local IP)".to_string();
    }

    let res = tokio::time::timeout(
        Duration::from_millis(1500),
        state.resolver.reverse_lookup(ip),
    )
    .await;

    match res {
        Ok(Ok(lookup)) => {
            let names: Vec<String> = lookup
                .iter()
                .map(|name| name.to_utf8().trim_end_matches('.').to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if names.is_empty() {
                "none".to_string()
            } else {
                names.join(", ")
            }
        }
        Ok(Err(_)) => "none".to_string(),
        Err(_) => "timeout (1500 ms)".to_string(),
    }
}

fn format_raw_headers(headers: &HeaderMap) -> String {
    let mut out = String::new();
    for (name, value) in headers.iter() {
        let val_str = String::from_utf8_lossy(value.as_bytes());
        out.push_str(&format!("{name}: {val_str}\n"));
    }
    out
}

pub async fn index(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    Query(query): Query<HomeQuery>,
) -> Response {
    let client_ip = extract_client_ip(peer, &headers, &state.config);
    let asn = lookup_asn(&state, client_ip);
    let rdns = lookup_rdns(&state, client_ip).await;
    let raw_headers = format_raw_headers(&headers);
    let request_line = format!("{method} {uri} {version:?}");
    let base = base_url_from_headers(&headers, state.config.self_ip);

    let dump = format!(
        "IP:          {client_ip}\nASN / ISP:   {asn}\nReverse DNS: {rdns}\n\n{request_line}\n{raw_headers}"
    );

    if wants_plain_text(&headers, query.format.as_deref()) {
        let plain = format!(
            "{dump}\nTOOLS:\n  {base}/ip\n  {base}/trace?url=<url>\n  {base}/ports/<port>\n  {base}/hook\n  {base}/httpbin\n  {base}/newlines (browser only)\n  {base}/whois?q=<domain-or-ip>\n  {base}/status/<code>\n  {base}/delay/<sec>\n  {base}/drip?bytes=1024&sec=5\n  {base}/headers\n"
        );
        return (
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            plain,
        )
            .into_response();
    }

    let body = format!(
        r#"<pre>{}</pre>
<h2 id="tools-heading">Tools</h2>
<table class="tools" aria-labelledby="tools-heading">
<tbody>
<tr><th scope="row"><a href="/trace">/trace</a></th><td>follow a URL's redirect chain (up to 15 hops) and strip tracking parameters</td></tr>
<tr><th scope="row"><a href="/ports">/ports</a></th><td>test whether a TCP port is open on your current IP</td></tr>
<tr><th scope="row"><a href="/hook">/hook</a></th><td>generate a temporary URL to watch incoming HTTP requests live (nothing is stored)</td></tr>
<tr><th scope="row"><a href="/httpbin">/httpbin</a></th><td>test HTTP failures and responses</td></tr>
<tr><th scope="row"><a href="/newlines">/newlines</a></th><td>remove all line breaks from text, or collapse single breaks while keeping paragraphs</td></tr>
<tr><th scope="row"><a href="/whois">/whois</a></th><td>look up public registration records for a domain or IP address</td></tr>
</tbody>
</table>
<p>Network tools return plain text for <code>curl</code>. Try <code>curl {}/</code> or <code>curl {}/ip</code>.</p>"#,
        escape_html(&dump),
        escape_html(&base),
        escape_html(&base)
    );

    render_page("141.148.44.88", &body).into_response()
}

pub async fn ip_only(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let client_ip = extract_client_ip(peer, &headers, &state.config);
    (
        [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{client_ip}\n"),
    )
        .into_response()
}
