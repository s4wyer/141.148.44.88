# 141.148.44.88

Self-hosted Rust web tools. Returns HTML in the browser and plain text for `curl`.

## Tools

- `/` and `/ip` — client IP, ASN/ISP, reverse DNS, and request headers
- `/trace` — follow a URL's redirect chain (up to 15 hops) and strip tracking parameters
- `/ports` — test whether a TCP port is open on your current IP
- `/hook` — generate a temporary URL to watch incoming HTTP requests live (nothing is stored)
- `/httpbin` — test HTTP failures and responses (`/status`, `/delay`, `/drip`, `/headers`)
- `/newlines` — remove all line breaks from text, or collapse single breaks while keeping paragraphs (runs locally in the browser)
- `/whois` — look up public registration records for a domain or IP address

## `curl`

```bash
curl https://141.148.44.88/
curl https://141.148.44.88/ip
curl "https://141.148.44.88/trace?url=https://nolog.link/s/2zjsNL"
curl https://141.148.44.88/ports/443
curl -N https://141.148.44.88/hook
curl -X POST https://141.148.44.88/h/<id> -d 'hello'
curl -i https://141.148.44.88/status/503
curl -i https://141.148.44.88/delay/2
curl -N "https://141.148.44.88/drip?bytes=1024&sec=5"
curl https://141.148.44.88/headers
curl "https://141.148.44.88/whois?q=example.com"

```

## Run

```bash
cargo build --release
./target/release/brutalist-tools

```

## Config

Copy `.env.example` to `.env`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `BIND_ADDR` | `127.0.0.1:8080` | Listen address |
| `SELF_IP` | `141.148.44.88` | Own public IP (blocked in `/trace` SSRF check) |
| `TRUSTED_PROXIES` | `127.0.0.1,::1` | Peer IPs allowed to set client IP headers |
| `TRUSTED_IP_HEADER` | `x-real-client-ip` | Client IP header injected by Caddy |
| `MAXMIND_ASN_DB` | `./GeoLite2-ASN.mmdb` | Path to GeoLite2 ASN DB (fallback: `/var/lib/GeoIP/GeoLite2-ASN.mmdb`) |
| `MAXMIND_ACCOUNT_ID` | — | MaxMind account ID for auto-updates |
| `MAXMIND_LICENSE_KEY` | — | MaxMind license key for auto-updates |
| `MAXMIND_ASN_URL` | MaxMind `.tar.gz` permalink | Override MMDB download URL |
| `MAXMIND_UPDATE_INTERVAL_HOURS` | `24` | Update check interval (`1..=720`) |
| `ALLOW_PRIVATE_PORT_CHECK` | `false` | Allow checking private/loopback IPs (dev only) |

If `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` are set, `GeoLite2-ASN.mmdb` is fetched on startup when missing or stale and hot-reloaded in memory.

## Caddy

See [Caddyfile](```markdown
# 141.148.44.88

Self-hosted Rust web tools. Returns HTML in the browser and plain text for `curl`.

## Tools

- `/` and `/ip` — client IP, ASN/ISP, reverse DNS, and request headers
- `/trace` — follow a URL's redirect chain (up to 15 hops) and strip tracking parameters
- `/ports` — test whether a TCP port is open on your current IP
- `/hook` — generate a temporary URL to watch incoming HTTP requests live (nothing is stored)
- `/httpbin` — test HTTP failures and responses (`/status`, `/delay`, `/drip`, `/headers`)
- `/newlines` — remove all line breaks from text, or collapse single breaks while keeping paragraphs (runs locally in the browser)
- `/whois` — look up public registration records for a domain or IP address

## `curl`

```bash
curl https://141.148.44.88/
curl http://141.148.44.88/ip
curl https://141.148.44.88/trace?url=https://bit.ly/example
curl https://141.148.44.88/ports/443
curl -N https://141.148.44.88/hook
curl -X POST https://141.148.44.88/h/<id> -d 'hello'
curl -i https://141.148.44.88/status/503
curl -i https://141.148.44.88/delay/2
curl -N "https://141.148.44.88/drip?bytes=1024&sec=5"
curl https://141.148.44.88/headers
curl "https://141.148.44.88/whois?q=example.com"

```

## Run

```bash
cargo build --release
./target/release/brutalist-tools

```

## Config

Copy `.env.example` to `.env` (`chmod 600 .env`).

| Variable | Default | Purpose |
| --- | --- | --- |
| `BIND_ADDR` | `127.0.0.1:8080` | Listen address |
| `SELF_IP` | `141.148.44.88` | Own public IP (blocked in `/trace` SSRF check) |
| `TRUSTED_PROXIES` | `127.0.0.1,::1` | Peer IPs allowed to set client IP headers |
| `TRUSTED_IP_HEADER` | `x-real-client-ip` | Client IP header injected by Caddy |
| `MAXMIND_ASN_DB` | `./GeoLite2-ASN.mmdb` | Path to GeoLite2 ASN DB (fallback: `/var/lib/GeoIP/GeoLite2-ASN.mmdb`) |
| `MAXMIND_ACCOUNT_ID` | — | MaxMind account ID for auto-updates |
| `MAXMIND_LICENSE_KEY` | — | MaxMind license key for auto-updates |
| `MAXMIND_ASN_URL` | MaxMind `.tar.gz` permalink | Override MMDB download URL |
| `MAXMIND_UPDATE_INTERVAL_HOURS` | `24` | Update check interval (`1..=720`) |
| `ALLOW_PRIVATE_PORT_CHECK` | `false` | Allow checking private/loopback IPs (dev only) |

If `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` are set, `GeoLite2-ASN.mmdb` is fetched on startup when missing or stale and hot-reloaded in memory.

## Caddy

See [Caddyfile](./caddyfile). Set two directives:

* `header_up X-Real-Client-IP {remote_host}` prevents IP spoofing on `/ports`.
* `flush_interval -1` disables proxy buffering for `/hook` streams and `/drip`.
