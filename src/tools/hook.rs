use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, Version};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use futures_util::Stream;
use rand::Rng;
use serde::Deserialize;
use tokio::sync::broadcast;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::client_ip::{base_url_from_headers, escape_html, extract_client_ip, wants_plain_text};
use crate::config::{AppState, WebhookEvent, WebhookSlot};
use crate::html::render_page;

const MAX_CHANNELS: usize = 1024;
const MAX_BODY_BYTES: usize = 256 * 1024;

#[derive(Deserialize, Default)]
pub struct WebhookQuery {
    pub format: Option<String>,
}

struct ChannelGuard {
    id: String,
    state: Arc<AppState>,
}

impl Drop for ChannelGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.state.webhooks.write() {
            if let Some(slot) = map.get_mut(&self.id) {
                slot.subscribers = slot.subscribers.saturating_sub(1);
                if slot.subscribers == 0 {
                    map.remove(&self.id);
                }
            }
        }
    }
}

struct GuardedStream<S> {
    inner: Pin<Box<S>>,
    _guard: ChannelGuard,
}

impl<S: Stream> Stream for GuardedStream<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

fn generate_id() -> String {
    let bytes: [u8; 4] = rand::thread_rng().gen();
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn subscribe_channel(
    state: &Arc<AppState>,
    id: &str,
) -> Result<(broadcast::Receiver<WebhookEvent>, ChannelGuard), StatusCode> {
    let mut map = state
        .webhooks
        .write()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !map.contains_key(id) && map.len() >= MAX_CHANNELS {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let slot = map.entry(id.to_string()).or_insert_with(|| {
        let (tx, _rx) = broadcast::channel(64);
        WebhookSlot { tx, subscribers: 0 }
    });
    slot.subscribers += 1;
    let rx = slot.tx.subscribe();

    Ok((
        rx,
        ChannelGuard {
            id: id.to_string(),
            state: Arc::clone(state),
        },
    ))
}

fn format_event_text(ev: &WebhookEvent) -> String {
    let mut out = format!(
        "=== {} | {} ===\n{} {} {}\n",
        ev.timestamp, ev.source_ip, ev.method, ev.path, ev.version
    );
    for (k, v) in &ev.headers {
        out.push_str(&format!("{k}: {v}\n"));
    }
    out.push('\n');
    if ev.body_bytes == 0 {
        out.push_str("(empty body)\n");
    } else {
        out.push_str(&ev.body);
        if !ev.body.ends_with('\n') {
            out.push('\n');
        }
        if ev.truncated {
            out.push_str("[body truncated at 256 KiB]\n");
        }
    }
    out.push('\n');
    out
}

pub async fn page(
    State(state): State<Arc<AppState>>,
    ConnectInfo(_peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<WebhookQuery>,
) -> Response {
    let id = generate_id();
    let base = base_url_from_headers(&headers, state.config.self_ip);
    let endpoint = format!("{base}/h/{id}");

    if wants_plain_text(&headers, query.format.as_deref()) {
        let (rx, guard) = match subscribe_channel(&state, &id) {
            Ok(v) => v,
            Err(status) => {
                return (
                    status,
                    [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                    "too many active webhook channels\n",
                )
                    .into_response();
            }
        };

        let header_chunk = Ok::<Bytes, Infallible>(Bytes::from(format!(
            "ENDPOINT: {endpoint}\nListening (Ctrl+C to stop)...\n\n"
        )));

        let event_stream = BroadcastStream::new(rx).filter_map(|item| match item {
            Ok(ev) => Some(Ok::<Bytes, Infallible>(Bytes::from(format_event_text(&ev)))),
            Err(BroadcastStreamRecvError::Lagged(n)) => Some(Ok(Bytes::from(format!(
                "[warning: dropped {n} lagged events]\n\n"
            )))),
        });

        let stream = futures_util::stream::once(async move { header_chunk }).chain(event_stream);
        let guarded = GuardedStream {
            inner: Box::pin(stream),
            _guard: guard,
        };

        return Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(http::header::CACHE_CONTROL, "no-cache")
            .header("X-Accel-Buffering", "no")
            .body(Body::from_stream(guarded))
            .unwrap();
    }

    let esc_endpoint = escape_html(&endpoint);
    let esc_id = escape_html(&id);
    let body = format!(
        r#"<p>Endpoint: <code id="endpoint">{esc_endpoint}</code></p>
<p>Test: <code>curl -X POST {esc_endpoint} -H "Content-Type: application/json" -d '{{"ok":true}}'</code></p>
<form method="GET" action="/hook">
Status: <span id="status">connecting...</span> | <button type="button" id="clear">Clear</button> | <button type="submit">New ID</button>
</form>
<p>In-memory only. Requests stream via SSE and are discarded when you close this tab.</p>
<hr>
<div id="events"></div>
<script>
(function() {{
  var id = "{esc_id}";
  var statusEl = document.getElementById("status");
  var eventsEl = document.getElementById("events");
  var clearBtn = document.getElementById("clear");
  clearBtn.addEventListener("click", function() {{ eventsEl.textContent = ""; }});

  var es = new EventSource("/hook/events/" + id);
  es.onopen = function() {{ statusEl.textContent = "listening (live)"; }};
  es.onerror = function() {{ statusEl.textContent = "disconnected / reconnecting..."; }};
  es.onmessage = function(msg) {{
    var ev = JSON.parse(msg.data);
    var pre = document.createElement("pre");
    var lines = [];
    lines.push("=== " + ev.timestamp + " | " + ev.source_ip + " ===");
    lines.push(ev.method + " " + ev.path + " " + ev.version);
    for (var i = 0; i < ev.headers.length; i++) {{
      lines.push(ev.headers[i][0] + ": " + ev.headers[i][1]);
    }}
    lines.push("");
    lines.push(ev.body_bytes === 0 ? "(empty body)" : ev.body);
    if (ev.truncated) lines.push("[body truncated at 256 KiB]");
    pre.textContent = lines.join("\n");
    eventsEl.prepend(pre);
  }};
}})();
</script>"#
    );

    (
        [(http::header::CACHE_CONTROL, "no-store")],
        render_page("/hook", &body),
    )
        .into_response()
}

pub async fn events(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    if !is_valid_id(&id) {
        return (StatusCode::BAD_REQUEST, "invalid webhook id\n").into_response();
    }

    let (rx, guard) = match subscribe_channel(&state, &id) {
        Ok(v) => v,
        Err(status) => {
            return (status, "too many active webhook channels\n").into_response();
        }
    };

    let stream = BroadcastStream::new(rx).filter_map(|item| match item {
        Ok(ev) => {
            let json = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".to_string());
            Some(Ok::<Event, Infallible>(Event::default().data(json)))
        }
        Err(BroadcastStreamRecvError::Lagged(n)) => {
            Some(Ok(Event::default().comment(format!("lagged {n} events"))))
        }
    });

    let guarded = GuardedStream {
        inner: Box::pin(stream),
        _guard: guard,
    };

    let mut resp = Sse::new(guarded)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response();
    resp.headers_mut()
        .insert(http::header::CACHE_CONTROL, "no-cache".parse().unwrap());
    resp.headers_mut()
        .insert("X-Accel-Buffering", "no".parse().unwrap());
    resp
}

pub async fn ingest(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path_id): Path<String>,
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body: Body,
) -> Response {
    ingest_inner(state, peer, path_id, method, uri, version, headers, body).await
}

pub async fn ingest_subpath(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((path_id, _rest)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body: Body,
) -> Response {
    ingest_inner(state, peer, path_id, method, uri, version, headers, body).await
}

async fn ingest_inner(
    state: Arc<AppState>,
    peer: SocketAddr,
    id: String,
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let tx = {
        let Ok(map) = state.webhooks.read() else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "lock error\n").into_response();
        };
        map.get(&id).map(|slot| slot.tx.clone())
    };

    let Some(tx) = tx else {
        return (
            StatusCode::NOT_FOUND,
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "no active listener\n",
        )
            .into_response();
    };

    let bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES + 1).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "failed to read body\n").into_response();
        }
    };

    let truncated = bytes.len() > MAX_BODY_BYTES;
    let slice = if truncated {
        &bytes[..MAX_BODY_BYTES]
    } else {
        &bytes[..]
    };

    let source_ip = extract_client_ip(peer, &headers, &state.config).to_string();
    let header_pairs = headers
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();

    let event = WebhookEvent {
        timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        source_ip,
        method: method.to_string(),
        path: uri.to_string(),
        version: format!("{version:?}"),
        headers: header_pairs,
        body: String::from_utf8_lossy(slice).into_owned(),
        body_bytes: slice.len(),
        truncated,
    };

    let _ = tx.send(event);

    (
        StatusCode::OK,
        [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "ok\n",
    )
        .into_response()
}
