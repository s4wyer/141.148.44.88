use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tokio::net::TcpStream;

use crate::client_ip::{base_url_from_headers, escape_html, extract_client_ip, wants_plain_text};
use crate::config::AppState;
use crate::html::render_page;
use crate::ssrf;

const RATE_LIMIT_MAX: usize = 20;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Deserialize, Default)]
pub struct PortQuery {
    pub port: Option<String>,
    pub format: Option<String>,
}

async fn check_rate_limit(state: &AppState, ip: IpAddr) -> bool {
    let mut map = state.port_rate_limits.lock().await;
    let now = Instant::now();
    let entries = map.entry(ip).or_default();
    while let Some(front) = entries.front() {
        if now.duration_since(*front) > RATE_LIMIT_WINDOW {
            entries.pop_front();
        } else {
            break;
        }
    }
    if entries.len() >= RATE_LIMIT_MAX {
        return false;
    }
    entries.push_back(now);
    true
}

async fn run_port_check(
    state: Arc<AppState>,
    peer: SocketAddr,
    headers: HeaderMap,
    raw_port: Option<String>,
    format: Option<String>,
) -> Response {
    let client_ip = extract_client_ip(peer, &headers, &state.config);
    let plain = wants_plain_text(&headers, format.as_deref());
    let base = base_url_from_headers(&headers, state.config.self_ip);

    let Some(port_str) = raw_port.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        if plain {
            return (
                [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                format!(
                    "/ports\nTarget: {client_ip} (caller IP only)\n\nUsage:\n  curl {base}/ports/443\n  curl \"{base}/ports?port=8080\"\n"
                ),
            )
                .into_response();
        }
        let body = render_port_form(client_ip, "", None);
        return render_page("/ports", &body).into_response();
    };

    let Ok(port) = port_str.parse::<u16>() else {
        return render_error(
            plain,
            StatusCode::BAD_REQUEST,
            client_ip,
            &port_str,
            "Invalid port: must be an integer between 1 and 65535.",
        );
    };

    if port == 0 {
        return render_error(
            plain,
            StatusCode::BAD_REQUEST,
            client_ip,
            &port_str,
            "Invalid port: port 0 is not valid.",
        );
    }

    if !state.config.allow_private_port_check && ssrf::is_forbidden_ip(client_ip, None) {
        return render_error(
            plain,
            StatusCode::BAD_REQUEST,
            client_ip,
            &port_str,
            &format!(
                "Refused: resolved client IP ({client_ip}) is private/loopback/reserved. Configure Caddy X-Real-Client-IP or access via public IP."
            ),
        );
    }

    if !check_rate_limit(&state, client_ip).await {
        return render_error(
            plain,
            StatusCode::TOO_MANY_REQUESTS,
            client_ip,
            &port_str,
            "Rate limit exceeded (max 20 checks per 60s per IP).",
        );
    }

    let target = SocketAddr::new(client_ip, port);
    let start = Instant::now();
    let result = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await;
    let elapsed_ms = start.elapsed().as_millis();

    let status_text = match result {
        Ok(Ok(_stream)) => format!("OPEN ({elapsed_ms} ms)"),
        Ok(Err(err)) => match err.kind() {
            ErrorKind::ConnectionRefused => format!("CLOSED (connection refused, {elapsed_ms} ms)"),
            ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => {
                format!("UNREACHABLE ({err}, {elapsed_ms} ms)")
            }
            ErrorKind::TimedOut => format!("FILTERED / TIMEOUT ({elapsed_ms} ms)"),
            _ => format!("ERROR: {err} ({elapsed_ms} ms)"),
        },
        Err(_) => format!("FILTERED / TIMEOUT ({} ms)", CONNECT_TIMEOUT.as_millis()),
    };

    let report = format!(
        "TARGET: {client_ip}:{port} (locked to your IP)\nSTATUS: {status_text}\n"
    );

    if plain {
        return (
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            report,
        )
            .into_response();
    }

    let body = render_port_form(client_ip, &port_str, Some(&report));
    render_page("/ports", &body).into_response()
}

fn render_error(
    plain: bool,
    status: StatusCode,
    client_ip: IpAddr,
    port_input: &str,
    msg: &str,
) -> Response {
    if plain {
        return (
            status,
            [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("TARGET: {client_ip}\nERROR:  {msg}\n"),
        )
            .into_response();
    }
    let body = render_port_form(client_ip, port_input, Some(msg));
    (status, render_page("/ports", &body)).into_response()
}

fn render_port_form(client_ip: IpAddr, port_input: &str, output: Option<&str>) -> String {
    let mut html = format!(
        r#"<p>Target: <code>{}</code> (caller IP only)</p>
<form method="GET" action="/ports">
<label for="port">TCP Port (1–65535):</label>
<input id="port" name="port" type="number" min="1" max="65535" value="{}" required>
<button type="submit">Check</button>
</form>"#,
        escape_html(&client_ip.to_string()),
        escape_html(port_input)
    );
    if let Some(out) = output {
        html.push_str(&format!("\n<pre>{}</pre>", escape_html(out)));
    }
    html
}

pub async fn get_query(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<PortQuery>,
) -> Response {
    run_port_check(state, peer, headers, query.port, query.format).await
}

pub async fn get_path(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(port): Path<String>,
    Query(query): Query<PortQuery>,
) -> Response {
    run_port_check(state, peer, headers, Some(port), query.format).await
}
