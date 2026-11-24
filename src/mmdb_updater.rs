use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use tar::Archive;

use crate::config::AppState;

const MAX_ARCHIVE_BYTES: usize = 50 * 1024 * 1024;
const MAX_MMDB_BYTES: usize = 50 * 1024 * 1024;

pub fn extract_mmdb_from_targz(archive_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let gz = GzDecoder::new(archive_bytes);
    let mut archive = Archive::new(gz);
    let entries = archive
        .entries()
        .map_err(|e| format!("failed to read tar entries: {e}"))?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| format!("corrupt tar entry: {e}"))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| format!("invalid tar entry path: {e}"))?;
        let is_mmdb = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("mmdb"))
            .unwrap_or(false);
        if !is_mmdb {
            continue;
        }

        let size = entry.header().size().unwrap_or(0) as usize;
        if size > MAX_MMDB_BYTES {
            return Err(format!("mmdb entry too large ({size} bytes)"));
        }

        let mut buf = Vec::with_capacity(size.min(MAX_MMDB_BYTES));
        entry
            .by_ref()
            .take((MAX_MMDB_BYTES + 1) as u64)
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed reading mmdb from archive: {e}"))?;

        if buf.len() > MAX_MMDB_BYTES {
            return Err("mmdb entry exceeds max allowed size".to_string());
        }
        return Ok(buf);
    }

    Err("archive did not contain any .mmdb file".to_string())
}

fn target_db_path(state: &AppState) -> PathBuf {
    state
        .config
        .maxmind_asn_db
        .clone()
        .unwrap_or_else(|| PathBuf::from("GeoLite2-ASN.mmdb"))
}

fn format_http_date(time: SystemTime) -> String {
    let dt: DateTime<Utc> = time.into();
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

pub async fn update_once(state: &AppState) -> Result<bool, String> {
    let account_id = state
        .config
        .maxmind_account_id
        .as_deref()
        .ok_or_else(|| "MAXMIND_ACCOUNT_ID is not set".to_string())?;
    let license_key = state
        .config
        .maxmind_license_key
        .as_deref()
        .ok_or_else(|| "MAXMIND_LICENSE_KEY is not set".to_string())?;
    let target_path = target_db_path(state);

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .user_agent("brutalist-tools/0.1 (maxmind-auto-updater)")
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let mut req = client
        .get(&state.config.maxmind_asn_url)
        .basic_auth(account_id, Some(license_key));

    if let Ok(meta) = std::fs::metadata(&target_path) {
        if let Ok(mtime) = meta.modified() {
            req = req.header(reqwest::header::IF_MODIFIED_SINCE, format_http_date(mtime));
        }
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("MaxMind download request failed: {e}"))?;

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(false);
    }

    if !resp.status().is_success() {
        return Err(format!("MaxMind download returned HTTP {}", resp.status()));
    }

    if let Some(len) = resp.content_length() {
        if len > MAX_ARCHIVE_BYTES as u64 {
            return Err(format!("MaxMind archive too large ({len} bytes)"));
        }
    }

    let archive_bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("failed reading MaxMind response body: {e}"))?;
    if archive_bytes.len() > MAX_ARCHIVE_BYTES {
        return Err("MaxMind archive exceeded max size".to_string());
    }

    let mmdb_bytes = extract_mmdb_from_targz(&archive_bytes)?;

    let reader = maxminddb::Reader::from_source(mmdb_bytes.clone())
        .map_err(|e| format!("downloaded .mmdb failed validation: {e}"))?;

    write_atomic(&target_path, &mmdb_bytes)?;

    let mut guard = state
        .asn_db
        .write()
        .map_err(|_| "asn_db lock poisoned".to_string())?;
    *guard = Some(reader);

    Ok(true)
}

fn write_atomic(target: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed creating parent dir {}: {e}", parent.display()))?;
        }
    }
    let tmp_path = target.with_extension("mmdb.tmp");
    std::fs::write(&tmp_path, data)
        .map_err(|e| format!("failed writing {}: {e}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, target)
        .map_err(|e| format!("failed moving {} into place: {e}", target.display()))?;
    Ok(())
}

fn needs_startup_update(state: &AppState, interval: Duration) -> bool {
    if state.asn_db.read().map(|g| g.is_none()).unwrap_or(true) {
        return true;
    }
    let path = target_db_path(state);
    match std::fs::metadata(&path).and_then(|m| m.modified()) {
        Ok(mtime) => match SystemTime::now().duration_since(mtime) {
            Ok(age) => age >= interval,
            Err(_) => false,
        },
        Err(_) => true,
    }
}

pub fn spawn_updater(state: Arc<AppState>) {
    if state.config.maxmind_account_id.is_none() || state.config.maxmind_license_key.is_none() {
        eprintln!(
            "[info] MaxMind auto-updater disabled (set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY in .env)"
        );
        return;
    }

    let interval_hours = state.config.maxmind_update_interval_hours;
    let interval = Duration::from_secs(interval_hours * 3600);
    let target = target_db_path(&state);
    eprintln!(
        "[info] MaxMind auto-updater enabled (target={}, interval={}h)",
        target.display(),
        interval_hours
    );

    tokio::spawn(async move {
        if needs_startup_update(&state, interval) {
            match update_once(&state).await {
                Ok(true) => eprintln!("[info] MaxMind GeoLite2-ASN.mmdb downloaded and loaded"),
                Ok(false) => eprintln!("[info] MaxMind GeoLite2-ASN.mmdb is already up to date (304)"),
                Err(err) => eprintln!("[warn] MaxMind initial update failed: {err}"),
            }
        }

        loop {
            tokio::time::sleep(interval).await;
            match update_once(&state).await {
                Ok(true) => eprintln!("[info] MaxMind GeoLite2-ASN.mmdb updated and hot-reloaded"),
                Ok(false) => eprintln!("[info] MaxMind GeoLite2-ASN.mmdb unchanged (304)"),
                Err(err) => eprintln!("[warn] MaxMind scheduled update failed: {err}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::Builder;

    #[test]
    fn extracts_mmdb_from_nested_targz() {
        let payload = b"fake-mmdb-binary-content";
        let mut tar_gz = Vec::new();
        {
            let enc = GzEncoder::new(&mut tar_gz, Compression::default());
            let mut builder = Builder::new(enc);

            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "GeoLite2-ASN_20261123/GeoLite2-ASN.mmdb",
                    &payload[..],
                )
                .unwrap();

            let readme = b"ignore me";
            let mut r_header = tar::Header::new_gnu();
            r_header.set_size(readme.len() as u64);
            r_header.set_mode(0o644);
            r_header.set_cksum();
            builder
                .append_data(&mut r_header, "GeoLite2-ASN_20261123/README.txt", &readme[..])
                .unwrap();

            builder.finish().unwrap();
        }

        let extracted = extract_mmdb_from_targz(&tar_gz).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn errors_when_targz_has_no_mmdb() {
        let mut tar_gz = Vec::new();
        {
            let enc = GzEncoder::new(&mut tar_gz, Compression::default());
            let mut builder = Builder::new(enc);
            let txt = b"hello";
            let mut header = tar::Header::new_gnu();
            header.set_size(txt.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, "README.txt", &txt[..]).unwrap();
            builder.finish().unwrap();
        }

        let err = extract_mmdb_from_targz(&tar_gz).unwrap_err();
        assert!(err.contains(".mmdb"));
    }
}
