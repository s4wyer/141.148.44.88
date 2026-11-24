use std::fmt;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Instant;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use tokio::sync::{broadcast, Mutex};

use crate::tools::whois::Whois;

const DEFAULT_MAXMIND_ASN_URL: &str =
    "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz";

#[derive(Clone)]
pub struct Config {
    pub bind_addr: String,
    pub self_ip: Option<IpAddr>,
    pub trusted_proxies: Vec<IpAddr>,
    pub trusted_ip_header: String,
    pub maxmind_asn_db: Option<PathBuf>,
    pub maxmind_account_id: Option<String>,
    pub maxmind_license_key: Option<String>,
    pub maxmind_asn_url: String,
    pub maxmind_update_interval_hours: u64,
    pub allow_private_port_check: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("self_ip", &self.self_ip)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("trusted_ip_header", &self.trusted_ip_header)
            .field("maxmind_asn_db", &self.maxmind_asn_db)
            .field("maxmind_account_id", &self.maxmind_account_id)
            .field(
                "maxmind_license_key",
                &self.maxmind_license_key.as_ref().map(|_| "<redacted>"),
            )
            .field("maxmind_asn_url", &self.maxmind_asn_url)
            .field(
                "maxmind_update_interval_hours",
                &self.maxmind_update_interval_hours,
            )
            .field("allow_private_port_check", &self.allow_private_port_check)
            .finish()
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

impl Config {
    pub fn from_env() -> Self {
        let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

        let self_ip = match env::var("SELF_IP") {
            Ok(val) if val.trim().is_empty() => None,
            Ok(val) => val.trim().parse::<IpAddr>().ok(),
            Err(_) => Some("141.148.44.88".parse().expect("valid default self IP")),
        };

        let trusted_proxies_raw =
            env::var("TRUSTED_PROXIES").unwrap_or_else(|_| "127.0.0.1,::1".to_string());
        let trusted_proxies = trusted_proxies_raw
            .split(',')
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .collect();

        let trusted_ip_header = env::var("TRUSTED_IP_HEADER")
            .unwrap_or_else(|_| "x-real-client-ip".to_string())
            .trim()
            .to_ascii_lowercase();

        let maxmind_asn_db = match env::var("MAXMIND_ASN_DB") {
            Ok(p) if !p.trim().is_empty() => Some(PathBuf::from(p.trim())),
            _ => {
                let local = PathBuf::from("GeoLite2-ASN.mmdb");
                let system = PathBuf::from("/var/lib/GeoIP/GeoLite2-ASN.mmdb");
                if local.exists() {
                    Some(local)
                } else if system.exists() {
                    Some(system)
                } else {
                    Some(local)
                }
            }
        };

        let maxmind_account_id = non_empty_env("MAXMIND_ACCOUNT_ID");
        let maxmind_license_key = non_empty_env("MAXMIND_LICENSE_KEY");
        let maxmind_asn_url =
            non_empty_env("MAXMIND_ASN_URL").unwrap_or_else(|| DEFAULT_MAXMIND_ASN_URL.to_string());
        let maxmind_update_interval_hours = env::var("MAXMIND_UPDATE_INTERVAL_HOURS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(24)
            .clamp(1, 720);

        let allow_private_port_check = env::var("ALLOW_PRIVATE_PORT_CHECK")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        Self {
            bind_addr,
            self_ip,
            trusted_proxies,
            trusted_ip_header,
            maxmind_asn_db,
            maxmind_account_id,
            maxmind_license_key,
            maxmind_asn_url,
            maxmind_update_interval_hours,
            allow_private_port_check,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct WebhookEvent {
    pub timestamp: String,
    pub source_ip: String,
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub body_bytes: usize,
    pub truncated: bool,
}

pub struct WebhookSlot {
    pub tx: broadcast::Sender<WebhookEvent>,
    pub subscribers: usize,
}

pub struct AppState {
    pub config: Config,
    pub asn_db: RwLock<Option<maxminddb::Reader<Vec<u8>>>>,
    pub resolver: TokioAsyncResolver,
    pub webhooks: RwLock<HashMap<String, WebhookSlot>>,
    pub port_rate_limits: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    pub whois: Whois,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let asn_db = config.maxmind_asn_db.as_ref().and_then(|path| {
            if !path.exists() {
                eprintln!(
                    "[warn] GeoLite2-ASN.mmdb not found at {} (ASN lookup waiting for download/file)",
                    path.display()
                );
                return None;
            }
            match maxminddb::Reader::open_readfile(path) {
                Ok(reader) => {
                    eprintln!("[info] Loaded MaxMind ASN DB from {}", path.display());
                    Some(reader)
                }
                Err(err) => {
                    eprintln!(
                        "[warn] Failed to load MaxMind ASN DB at {}: {err}",
                        path.display()
                    );
                    None
                }
            }
        });

        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

        let whois = Whois::new(config.self_ip);
        Self {
            config,
            asn_db: RwLock::new(asn_db),
            resolver,
            webhooks: RwLock::new(HashMap::new()),
            port_rate_limits: Mutex::new(HashMap::new()),
            whois,
        }
    }
}
