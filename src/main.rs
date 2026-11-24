mod client_ip;
mod config;
mod html;
mod mmdb_updater;
mod ssrf;
mod tools;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::{header, HeaderValue};
use axum::middleware;
use axum::response::Response;
use axum::routing::{any, get};
use axum::Router;

use config::{AppState, Config};

pub fn build_router(state: Arc<AppState>) -> Router {
    let negotiated = Router::new()
        .route("/", get(tools::home::index))
        .route("/trace", get(tools::trace::get).post(tools::trace::post))
        .route("/ports", get(tools::ports::get_query))
        .route("/ports/{port}", get(tools::ports::get_path))
        .route("/hook", get(tools::hook::page))
        .route("/httpbin", get(tools::httpbin::index))
        .route("/whois", get(tools::whois::get))
        .layer(middleware::map_response(|mut response: Response| async move {
            response
                .headers_mut()
                .append(header::VARY, HeaderValue::from_static("Accept"));
            response
        }));

    Router::new()
        .merge(negotiated)
        .route("/ip", get(tools::home::ip_only))
        .route("/hook/events/{id}", get(tools::hook::events))
        .route("/h/{id}", any(tools::hook::ingest))
        .route("/h/{id}/{*rest}", any(tools::hook::ingest_subpath))
        .route("/status/{code}", any(tools::httpbin::status))
        .route("/delay/{sec}", any(tools::httpbin::delay))
        .route("/drip", get(tools::httpbin::drip))
        .route("/headers", any(tools::httpbin::headers_echo))
        .route(
            "/newlines",
            get(|| async {
                html::render_page("/newlines", include_str!("tools/newlines.html"))
            }),
        )
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();
    let config = Config::from_env();
    let bind_addr = config.bind_addr.clone();

    eprintln!(
        "[info] Starting brutalist-tools on {} (self_ip={:?}, trusted_header={}, trusted_proxies={:?})",
        bind_addr, config.self_ip, config.trusted_ip_header, config.trusted_proxies
    );

    let state = Arc::new(AppState::new(config));
    mmdb_updater::spawn_updater(Arc::clone(&state));
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("failed to bind address");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::{header, Request, StatusCode};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    fn test_state(allow_private_port_check: bool) -> Arc<AppState> {
        let cfg = Config {
            bind_addr: "127.0.0.1:0".to_string(),
            self_ip: Some("141.148.44.88".parse().unwrap()),
            trusted_proxies: vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
            trusted_ip_header: "x-real-client-ip".to_string(),
            maxmind_asn_db: None,
            maxmind_account_id: None,
            maxmind_license_key: None,
            maxmind_asn_url: "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz".to_string(),
            maxmind_update_interval_hours: 24,
            allow_private_port_check,
        };
        Arc::new(AppState::new(cfg))
    }

    async fn spawn_test_server(allow_private_port_check: bool) -> (SocketAddr, Arc<AppState>) {
        let state = test_state(allow_private_port_check);
        let app = build_router(Arc::clone(&state));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (addr, state)
    }

    #[tokio::test]
    async fn homepage_plain_and_html_without_ipv6() {
        let app = build_router(test_state(false))
            .layer(MockConnectInfo("127.0.0.1:3000".parse::<SocketAddr>().unwrap()));

        let plain_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ACCEPT, "text/plain, text/html;q=0")
                    .header("x-real-client-ip", "8.8.8.8")
                    .header("x-custom-test", "brutalist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(plain_resp.status(), 200);
        let ct = plain_resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(ct.starts_with("text/plain"));
        assert_eq!(plain_resp.headers().get(header::VARY).unwrap(), "Accept");
        let body = to_bytes(plain_resp.into_body(), usize::MAX).await.unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("IP:          8.8.8.8"));
        assert!(body.contains("GeoLite2-ASN.mmdb not loaded"));
        assert!(body.contains("x-custom-test: brutalist"));
        assert!(body.contains("/trace?url=<url>"));
        assert!(body.contains("/ports/<port>"));
        assert!(body.contains("/whois?q=<domain-or-ip>"));
        assert!(!body.to_ascii_lowercase().contains("ipv6"));

        let html_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ACCEPT, "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = to_bytes(html_resp.into_body(), usize::MAX).await.unwrap();
        let html = std::str::from_utf8(&html).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        let (_, nav) = html.split_once("<nav>").unwrap();
        let (mut nav, _) = nav.split_once("</nav>").unwrap();
        let (_, table) = html.split_once("<table").unwrap();
        let (mut table, _) = table.split_once("</table>").unwrap();
        assert_eq!(table.matches("<tr>").count(), 6);
        for endpoint in ["/trace", "/ports", "/hook", "/httpbin", "/newlines", "/whois"] {
            let link = format!(r#"<a href="{endpoint}">{endpoint}</a>"#);
            nav = nav.split_once(&link).unwrap().1;
            table = table.split_once(&link).unwrap().1;
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(endpoint)
                        .header(header::ACCEPT, "text/html")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            let page = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let page = std::str::from_utf8(&page).unwrap();
            assert!(page.contains(&format!("<title>{endpoint}</title>")));
            assert!(page.contains(&format!("<h1>{endpoint}</h1>")));
        }
        assert!(!html.to_ascii_lowercase().contains("ipv6"));

        let invalid_whois = app
            .oneshot(
                Request::builder()
                    .uri("/whois?q=https%3A%2F%2Fexample.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_whois.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn trace_blocks_ssrf_targets() {
        let (addr, _state) = spawn_test_server(false).await;
        let client = reqwest::Client::new();

        for target in [
            "http://127.0.0.1:22/",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
        ] {
            let resp = client
                .get(format!("http://{addr}/trace"))
                .query(&[("url", target)])
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 400, "target {target} should return 400");
            let text = resp.text().await.unwrap();
            assert!(text.contains("ERROR: blocked"), "unexpected body: {text}");
        }
    }

    #[tokio::test]
    async fn port_checker_locks_to_requester_ip_and_refuses_private_by_default() {
        let (addr, _state) = spawn_test_server(false).await;
        let client = reqwest::Client::new();

        let refused = client
            .get(format!("http://{addr}/ports/80"))
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), 400);
        let text = refused.text().await.unwrap();
        assert!(text.contains("private/loopback/reserved"));

        let (dev_addr, _dev_state) = spawn_test_server(true).await;
        let open_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = open_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = open_listener.accept().await;
        });

        let ok = client
            .get(format!("http://{dev_addr}/ports/{open_port}"))
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), 200);
        let ok_text = ok.text().await.unwrap();
        assert!(ok_text.contains(&format!("TARGET: 127.0.0.1:{open_port}")));
        assert!(ok_text.contains("STATUS: OPEN"));
    }

    #[tokio::test]
    async fn webhook_ephemeral_lifecycle_and_sse() {
        let (addr, state) = spawn_test_server(false).await;
        let client = reqwest::Client::new();

        let missing = client
            .post(format!("http://{addr}/h/deadbeef"))
            .body("nope")
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), 404);

        let mut sse_resp = client
            .get(format!("http://{addr}/hook/events/test9f2a"))
            .send()
            .await
            .unwrap();
        assert_eq!(sse_resp.status(), 200);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(state.webhooks.read().unwrap().contains_key("test9f2a"));

        let post = client
            .post(format!("http://{addr}/h/test9f2a"))
            .header("x-real-client-ip", "198.51.100.42")
            .body("hello-webhook")
            .send()
            .await
            .unwrap();
        assert_eq!(post.status(), 200);

        let mut saw_payload = false;
        let mut buf = String::new();
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                chunk = sse_resp.chunk() => {
                    match chunk {
                        Ok(Some(bytes)) => {
                            buf.push_str(&String::from_utf8_lossy(&bytes));
                            if buf.contains("hello-webhook") && buf.contains("198.51.100.42") {
                                saw_payload = true;
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            }
        }
        assert!(saw_payload, "did not receive webhook payload over SSE");

        drop(sse_resp);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !state.webhooks.read().unwrap().contains_key("test9f2a"),
            "webhook channel should evaporate after SSE disconnect"
        );

        let after_drop = client
            .post(format!("http://{addr}/h/test9f2a"))
            .body("after")
            .send()
            .await
            .unwrap();
        assert_eq!(after_drop.status(), 404);
    }

    #[tokio::test]
    async fn httpbin_endpoints() {
        let (addr, _state) = spawn_test_server(false).await;
        let client = reqwest::Client::new();

        let st = client
            .get(format!("http://{addr}/status/503"))
            .send()
            .await
            .unwrap();
        assert_eq!(st.status(), 503);

        let st204 = client
            .get(format!("http://{addr}/status/204"))
            .send()
            .await
            .unwrap();
        assert_eq!(st204.status(), 204);

        let dl = client
            .get(format!("http://{addr}/delay/0.1"))
            .send()
            .await
            .unwrap();
        assert_eq!(dl.status(), 200);
        assert!(dl.text().await.unwrap().contains("delayed 0.1s"));

        let dr = client
            .get(format!("http://{addr}/drip?bytes=32&sec=0.1"))
            .send()
            .await
            .unwrap();
        assert_eq!(dr.status(), 200);
        assert_eq!(dr.bytes().await.unwrap().len(), 32);

        let hd = client
            .get(format!("http://{addr}/headers"))
            .header("x-probe", "ok")
            .send()
            .await
            .unwrap();
        assert_eq!(hd.status(), 200);
        assert!(hd.text().await.unwrap().contains("x-probe: ok"));
    }

    #[tokio::test]
    async fn newlines_only_serves_the_browser_tool() {
        let (addr, _state) = spawn_test_server(false).await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/newlines");
        let page = client.get(&url).send().await.unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert!(page.text().await.unwrap().contains("function strip()"));

        let post = client.post(&url).body("one\ntwo").send().await.unwrap();
        assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
