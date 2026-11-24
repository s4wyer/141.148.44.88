use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use url::{Host, Url};

use crate::client_ip::{base_url_from_headers, escape_html, wants_plain_text};
use crate::config::AppState;
use crate::html::render_page;
use crate::ssrf::{self, MAX_HOPS};

#[derive(Deserialize, Default)]
pub struct TraceQuery {
    pub url: Option<String>,
    pub format: Option<String>,
}

struct HopRecord {
    index: usize,
    status: u16,
    reason: String,
    url: String,
    resolved_ip: IpAddr,
    location: Option<String>,
}

const TRACKER_PREFIXES: &[&str] = &[
    "utm_",
    "mc_",
    "hsa_",
    "oly_",
    "pk_",
    "mtm_",
    "vero_",
    "_hs",
    "sc_",
];

const TRACKER_EXACT: &[&str] = &[
    "fbclid",
    "gclid",
    "gclsrc",
    "dclid",
    "gbraid",
    "wbraid",
    "msclkid",
    "twclid",
    "ttclid",
    "li_fat_id",
    "igshid",
    "igsh",
    "si",
    "mkt_tok",
    "yclid",
    "_ga",
    "_gl",
    "_ke",
    "rb_clickid",
    "cjevent",
    "irclickid",
    "epik",
    "zanpid",
    "awc",
    "ref_src",
    "ref_url",
    "trk",
    "icid",
    "cmpid",
    "s_cid",
    "ck_subscriber_id",
    "ss_source",
    "ss_campaign_id",
    "ss_email_id",
    "ss_campaign_name",
    "ss_campaign_sent_date",
    "wickedid",
    "ndclid",
    "sclid",
];

pub fn is_tracking_param(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if TRACKER_EXACT.contains(&lower.as_str()) {
        return true;
    }
    TRACKER_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

pub fn strip_tracking_params(url: &Url) -> (Url, Vec<String>) {
    let mut clean = url.clone();
    let mut stripped = Vec::new();
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter_map(|(k, v)| {
            if is_tracking_param(&k) {
                stripped.push(k.into_owned());
                None
            } else {
                Some((k.into_owned(), v.into_owned()))
            }
        })
        .collect();

    if kept.is_empty() {
        clean.set_query(None);
    } else {
        clean.query_pairs_mut().clear().extend_pairs(kept);
    }

    (clean, stripped)
}

fn normalize_input_url(raw: &str) -> Result<Url, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty URL".to_string());
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    Url::parse(&candidate).map_err(|e| format!("invalid URL: {e}"))
}

async fn trace_redirects(
    start_url: Url,
    state: &AppState,
) -> (Vec<HopRecord>, Url, Option<String>) {
    let mut current = start_url;
    let mut hops = Vec::new();
    let mut error = None;

    for idx in 0..=MAX_HOPS {
        let (host, port, validated_ip) =
            match ssrf::validate_and_resolve(&current, &state.resolver, state.config.self_ip).await
            {
                Ok(v) => v,
                Err(err) => {
                    error = Some(format!("blocked at hop {idx} ({current}): {err}"));
                    break;
                }
            };

        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(8))
            .user_agent("Mozilla/5.0 (compatible; 141.148.44.88/1.0)");

        if matches!(current.host(), Some(Host::Domain(_))) {
            builder = builder.resolve(&host, SocketAddr::new(validated_ip, port));
        }

        let client = match builder.build() {
            Ok(c) => c,
            Err(err) => {
                error = Some(format!("http client error at hop {idx}: {err}"));
                break;
            }
        };

        let resp = match client.get(current.clone()).send().await {
            Ok(r) => r,
            Err(err) => {
                error = Some(format!("request failed at hop {idx} ({current}): {err}"));
                break;
            }
        };

        let status = resp.status();
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);

        drop(resp);

        hops.push(HopRecord {
            index: idx,
            status: status.as_u16(),
            reason: status.canonical_reason().unwrap_or("").to_string(),
            url: current.to_string(),
            resolved_ip: validated_ip,
            location: location.clone(),
        });

        let is_redirect = matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308);
        if is_redirect {
            let Some(loc) = location else {
                break;
            };
            if idx == MAX_HOPS {
                error = Some(format!("MAX HOPS ({MAX_HOPS}) EXCEEDED"));
                break;
            }
            match current.join(&loc) {
                Ok(next) => current = next,
                Err(err) => {
                    error = Some(format!("invalid redirect Location '{loc}': {err}"));
                    break;
                }
            }
        } else {
            break;
        }
    }

    (hops, current, error)
}

fn format_report(
    input: &str,
    hops: &[HopRecord],
    raw_final: &Url,
    clean_final: &Url,
    stripped: &[String],
    error: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("INPUT: {input}\n"));
    out.push_str(&format!("HOPS ({} max):\n", MAX_HOPS));

    if hops.is_empty() {
        out.push_str("  (no requests completed)\n");
    } else {
        for hop in hops {
            out.push_str(&format!(
                "  [{:02}] {} {} -> {} (ip: {})\n",
                hop.index, hop.status, hop.reason, hop.url, hop.resolved_ip
            ));
            if let Some(loc) = &hop.location {
                out.push_str(&format!("       Location: {loc}\n"));
            }
        }
    }

    if let Some(err) = error {
        out.push_str(&format!("\nERROR: {err}\n"));
    }

    out.push_str(&format!("\nRAW FINAL URL:   {raw_final}\n"));
    if stripped.is_empty() {
        out.push_str("STRIPPED PARAMS: none\n");
    } else {
        out.push_str(&format!("STRIPPED PARAMS: {}\n", stripped.join(", ")));
    }
    out.push_str(&format!("CLEAN FINAL URL: {clean_final}\n"));
    out
}

fn extract_post_url(headers: &HeaderMap, body: &Bytes) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?.trim();
    if text.is_empty() {
        return None;
    }

    let is_form = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.to_ascii_lowercase().contains("application/x-www-form-urlencoded"))
        .unwrap_or(false);

    if is_form || text.starts_with("url=") {
        for (k, v) in url::form_urlencoded::parse(text.as_bytes()) {
            if k == "url" {
                let val = v.trim().to_string();
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
    }

    Some(text.to_string())
}

async fn handle_trace(
    state: Arc<AppState>,
    headers: HeaderMap,
    raw_url: Option<String>,
    format: Option<String>,
) -> Response {
    let plain = wants_plain_text(&headers, format.as_deref());
    let base = base_url_from_headers(&headers, state.config.self_ip);

    let Some(raw_input) = raw_url.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        if plain {
            return (
                [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                format!(
                    "Usage:\n  curl \"{base}/trace?url=https://bit.ly/example\"\n  curl -X POST {base}/trace -d 'https://bit.ly/example'\n"
                ),
            )
                .into_response();
        }
        let body = render_form("", None, None);
        return render_page("/trace", &body).into_response();
    };

    let parsed = match normalize_input_url(&raw_input) {
        Ok(u) => u,
        Err(err) => {
            let msg = format!("ERROR: {err}\n");
            if plain {
                return (
                    StatusCode::BAD_REQUEST,
                    [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                    msg,
                )
                    .into_response();
            }
            let body = render_form(&raw_input, Some(&msg), None);
            return (StatusCode::BAD_REQUEST, render_page("/trace", &body)).into_response();
        }
    };

    let (hops, raw_final, error) = trace_redirects(parsed, &state).await;
    let (clean_final, stripped) = strip_tracking_params(&raw_final);
    let report = format_report(
        &raw_input,
        &hops,
        &raw_final,
        &clean_final,
        &stripped,
        error.as_deref(),
    );

    let status = if error.is_some() && hops.is_empty() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };

    if plain {
        return (
            status,
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            report,
        )
            .into_response();
    }

    let clean_link = if error.is_none() {
        Some(clean_final.to_string())
    } else {
        None
    };
    let body = render_form(&raw_input, Some(&report), clean_link.as_deref());
    (status, render_page("/trace", &body)).into_response()
}

fn render_form(input: &str, report: Option<&str>, clean_link: Option<&str>) -> String {
    let escaped_input = escape_html(input);
    let mut html = format!(
        r#"<p>Follows up to {MAX_HOPS} redirects and strips UTM/click-ID parameters.</p>
<form method="GET" action="/trace">
<label for="url">URL:</label><br>
<input id="url" name="url" type="url" value="{escaped_input}" placeholder="https://bit.ly/..." required>
<button type="submit">Trace</button>
</form>"#
    );

    if let Some(r) = report {
        html.push_str(&format!("\n<pre>{}</pre>", escape_html(r)));
    }
    if let Some(link) = clean_link {
        let esc = escape_html(link);
        html.push_str(&format!(
            r#"<p>Clean URL: <a href="{esc}" rel="noopener noreferrer">{esc}</a></p>"#
        ));
    }
    html
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    ConnectInfo(_peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<TraceQuery>,
) -> Response {
    handle_trace(state, headers, query.url, query.format).await
}

pub async fn post(
    State(state): State<Arc<AppState>>,
    ConnectInfo(_peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<TraceQuery>,
    body: Bytes,
) -> Response {
    let raw_url = query.url.or_else(|| extract_post_url(&headers, &body));
    handle_trace(state, headers, raw_url, query.format).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_trackers_and_keeps_real_params() {
        let url = Url::parse(
            "https://example.com/post?utm_source=news&id=42&fbclid=abc123&gclid=xyz&page=2&mc_cid=99",
        )
        .unwrap();
        let (clean, stripped) = strip_tracking_params(&url);
        assert_eq!(clean.as_str(), "https://example.com/post?id=42&page=2");
        assert_eq!(stripped, vec!["utm_source", "fbclid", "gclid", "mc_cid"]);
    }

    #[test]
    fn removes_question_mark_when_all_params_stripped() {
        let url = Url::parse("https://example.com/page?utm_medium=email&igshid=123").unwrap();
        let (clean, stripped) = strip_tracking_params(&url);
        assert_eq!(clean.as_str(), "https://example.com/page");
        assert_eq!(stripped, vec!["utm_medium", "igshid"]);
    }
}
