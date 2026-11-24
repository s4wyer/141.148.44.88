use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use rand::seq::SliceRandom;
use serde::Deserialize;

use crate::client_ip::{base_url_from_headers, escape_html, wants_plain_text};
use crate::config::AppState;
use crate::html::render_page;

const MAX_DELAY_SEC: f64 = 30.0;
const MAX_DRIP_BYTES: usize = 1_048_576;

#[derive(Deserialize, Default)]
pub struct HttpbinIndexQuery {
    pub format: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct DripQuery {
    pub bytes: Option<usize>,
    pub numbytes: Option<usize>,
    pub sec: Option<f64>,
    pub duration: Option<f64>,
    pub delay: Option<f64>,
    pub code: Option<u16>,
}

pub async fn index(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HttpbinIndexQuery>,
) -> Response {
    let base = base_url_from_headers(&headers, state.config.self_ip);

    if wants_plain_text(&headers, query.format.as_deref()) {
        let txt = format!(
            "/httpbin\n\n\
             ENDPOINTS:\n\
             \x20 GET/ANY {base}/status/<code>         Return status code (or random from comma list e.g. 200,500,503)\n\
             \x20 GET/ANY {base}/delay/<sec>           Sleep 0..30s then respond 200 OK\n\
             \x20 GET     {base}/drip?bytes=1024&sec=5 Stream bytes over duration\n\
             \x20 GET/ANY {base}/headers               Echo received HTTP request headers\n"
        );
        return (
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            txt,
        )
            .into_response();
    }

    let esc_base = escape_html(&base);
    let body = format!(
        r#"<ul>
<li><a href="/status/503">/status/503</a> — return arbitrary HTTP status (supports comma list like <code>/status/200,500,503</code>)</li>
<li><a href="/delay/2">/delay/2</a> — delay response by <code>0..30</code> seconds</li>
<li><a href="/drip?bytes=1024&amp;sec=5">/drip?bytes=1024&amp;sec=5</a> — stream bytes over duration</li>
<li><a href="/headers">/headers</a> — dump received HTTP request headers</li>
</ul>
<pre>curl -i {esc_base}/status/503
curl -i {esc_base}/delay/4
curl -N "{esc_base}/drip?bytes=1024&amp;sec=5"
curl {esc_base}/headers</pre>"#
    );

    render_page("/httpbin", &body).into_response()
}

pub async fn status(Path(code_spec): Path<String>) -> Response {
    let mut candidates = Vec::new();
    for part in code_spec.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(code) = trimmed.parse::<u16>() else {
            return (
                StatusCode::BAD_REQUEST,
                [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                format!("invalid status code: {trimmed}\n"),
            )
                .into_response();
        };
        if !(200..=599).contains(&code) {
            return (
                StatusCode::BAD_REQUEST,
                [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                format!("status code out of range (200..=599): {code}\n"),
            )
                .into_response();
        }
        let Ok(st) = StatusCode::from_u16(code) else {
            return (
                StatusCode::BAD_REQUEST,
                [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                format!("unsupported status code: {code}\n"),
            )
                .into_response();
        };
        candidates.push(st);
    }

    if candidates.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "missing status code\n",
        )
            .into_response();
    }

    let chosen = *candidates
        .choose(&mut rand::thread_rng())
        .unwrap_or(&StatusCode::OK);

    if chosen == StatusCode::NO_CONTENT || chosen == StatusCode::NOT_MODIFIED {
        return chosen.into_response();
    }

    let reason = chosen.canonical_reason().unwrap_or("Status");
    (
        chosen,
        [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{} {reason}\n", chosen.as_u16()),
    )
        .into_response()
}

pub async fn delay(Path(sec_raw): Path<String>, headers: HeaderMap) -> Response {
    let Ok(sec) = sec_raw.trim().parse::<f64>() else {
        return (
            StatusCode::BAD_REQUEST,
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "invalid delay seconds\n",
        )
            .into_response();
    };

    if !sec.is_finite() || !(0.0..=MAX_DELAY_SEC).contains(&sec) {
        return (
            StatusCode::BAD_REQUEST,
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("delay must be between 0 and {MAX_DELAY_SEC} seconds\n"),
        )
            .into_response();
    }

    tokio::time::sleep(Duration::from_secs_f64(sec)).await;

    let wants_json = headers
        .get(http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().contains("application/json"))
        .unwrap_or(false);

    if wants_json {
        return (
            StatusCode::OK,
            [(http::header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "delayed_sec": sec }).to_string(),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("delayed {sec}s\n"),
    )
        .into_response()
}

pub async fn drip(Query(q): Query<DripQuery>) -> Response {
    let total_bytes = q.bytes.or(q.numbytes).unwrap_or(1024);
    if total_bytes > MAX_DRIP_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("bytes exceeds max ({MAX_DRIP_BYTES})\n"),
        )
            .into_response();
    }

    let duration_sec = q.sec.or(q.duration).unwrap_or(2.0);
    if !duration_sec.is_finite() || !(0.0..=MAX_DELAY_SEC).contains(&duration_sec) {
        return (
            StatusCode::BAD_REQUEST,
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("sec must be between 0 and {MAX_DELAY_SEC}\n"),
        )
            .into_response();
    }

    let initial_delay = q.delay.unwrap_or(0.0);
    if !initial_delay.is_finite() || !(0.0..=10.0).contains(&initial_delay) {
        return (
            StatusCode::BAD_REQUEST,
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "delay must be between 0 and 10 seconds\n",
        )
            .into_response();
    }

    let code = q.code.unwrap_or(200);
    if !(200..=599).contains(&code) {
        return (
            StatusCode::BAD_REQUEST,
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "code must be between 200 and 599\n",
        )
            .into_response();
    }
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);

    let stream = async_stream(total_bytes, duration_sec, initial_delay);

    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header(http::header::CACHE_CONTROL, "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(stream))
        .unwrap()
}

fn async_stream(
    total_bytes: usize,
    duration_sec: f64,
    initial_delay: f64,
) -> impl futures_util::Stream<Item = Result<Bytes, Infallible>> + Send + 'static {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(16);

    tokio::spawn(async move {
        if initial_delay > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(initial_delay)).await;
        }

        if total_bytes == 0 {
            return;
        }

        if duration_sec == 0.0 {
            let _ = tx.send(Ok(Bytes::from(vec![b'*'; total_bytes]))).await;
            return;
        }

        let ticks = ((duration_sec * 10.0).ceil() as usize).clamp(1, 300);
        let interval = Duration::from_secs_f64(duration_sec / ticks as f64);
        let base_chunk = total_bytes / ticks;
        let remainder = total_bytes % ticks;

        for i in 0..ticks {
            let chunk_len = base_chunk + usize::from(i < remainder);
            if chunk_len > 0 && tx.send(Ok(Bytes::from(vec![b'*'; chunk_len]))).await.is_err() {
                return;
            }
            if i + 1 < ticks {
                tokio::time::sleep(interval).await;
            }
        }
    });

    tokio_stream::wrappers::ReceiverStream::new(rx)
}

pub async fn headers_echo(headers: HeaderMap) -> Response {
    let wants_json = headers
        .get(http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().contains("application/json"))
        .unwrap_or(false);

    if wants_json {
        let mut map = serde_json::Map::new();
        for (name, value) in headers.iter() {
            let val = String::from_utf8_lossy(value.as_bytes()).into_owned();
            map.insert(name.to_string(), serde_json::Value::String(val));
        }
        return (
            StatusCode::OK,
            [(http::header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "headers": map }).to_string(),
        )
            .into_response();
    }

    let mut out = String::new();
    for (name, value) in headers.iter() {
        let val = String::from_utf8_lossy(value.as_bytes());
        out.push_str(&format!("{name}: {val}\n"));
    }

    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        out,
    )
        .into_response()
}
