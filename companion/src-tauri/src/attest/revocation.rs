//! Google's attestation certificate status list (https://android.googleapis.com/attestation/status),
//! cached in the companion's config directory.
//!
//! Format: `{"entries": {"<serial, lowercase hex without leading zeros>": {"status": "REVOKED",
//! "reason": "KEY_COMPROMISE"}, …}}`. Google serves it with `Cache-Control: max-age=86400`, so a
//! cached copy younger than a day is used without a request. If the fetch fails, a cached copy up
//! to 7 days old is still used (and said so); otherwise the status is "unknown", which is
//! reported but is not a failure: a network problem must not brick an offline wallet's companion.
//! Only the list is fetched; nothing about the phone is sent.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;

pub const STATUS_URL: &str = "https://android.googleapis.com/attestation/status";
const FRESH_SECS: u64 = 86_400;
const STALE_OK_SECS: u64 = 7 * 86_400;
const MAX_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum Status {
    /// serial → reason, and the day the list was fetched (YYYY-MM-DD)
    Checked {
        revoked: HashMap<String, String>,
        as_of: String,
    },
    Unknown(String),
}

/// Parse the status list. Only entries whose status is REVOKED count; serials are normalised to
/// lowercase without leading zeros.
pub fn parse(json: &str) -> Result<HashMap<String, String>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|_| "revocation list is not JSON".to_string())?;
    let entries = v.get("entries").and_then(|e| e.as_object()).ok_or("revocation list has no entries object")?;
    let mut out = HashMap::new();
    for (serial, entry) in entries {
        let s = serial.trim().to_ascii_lowercase();
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("revocation list has a malformed serial {serial:?}"));
        }
        let status = entry.get("status").and_then(|x| x.as_str()).unwrap_or("");
        if status == "REVOKED" {
            let reason = entry.get("reason").and_then(|x| x.as_str()).unwrap_or("UNSPECIFIED").to_string();
            let t = s.trim_start_matches('0');
            out.insert(if t.is_empty() { "0".into() } else { t.to_string() }, reason);
        }
    }
    Ok(out)
}

fn cache_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("PhoneVault").join("attestation-status.json"))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn day(ts: u64) -> String {
    super::chain::day_text(ts as i64)
}

fn read_cache() -> Option<(u64, HashMap<String, String>)> {
    let p = cache_path()?;
    let text = fs::read_to_string(p).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let fetched = v.get("fetchedAt")?.as_u64()?;
    let list = v.get("list")?.as_str()?;
    Some((fetched, parse(list).ok()?))
}

fn write_cache(fetched: u64, body: &str) {
    let Some(p) = cache_path() else { return };
    let Some(dir) = p.parent() else { return };
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    let tmp = dir.join(format!(".attestation-status.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let Ok(mut f) = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp) else { return };
    let doc = serde_json::json!({"fetchedAt": fetched, "source": STATUS_URL, "list": body});
    if f.write_all(doc.to_string().as_bytes()).is_ok() && f.sync_all().is_ok() {
        let _ = fs::rename(&tmp, &p);
    } else {
        let _ = fs::remove_file(&tmp);
    }
}

fn fetch() -> Result<String, String> {
    // No redirects, like every other fetch whose answer decides something: the list is trusted
    // because it comes over TLS from STATUS_URL itself (it answers 200 directly). A redirect is
    // answered as a failed fetch (cache, else unknown), never followed to another host or to http.
    let client = crate::http::client(Duration::from_secs(8), crate::http::Policy::none())?;
    let resp = client.get(STATUS_URL).send().map_err(|_| "Google's status list could not be reached".to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Google's status list answered HTTP {}", resp.status().as_u16()));
    }
    if resp.content_length().is_some_and(|l| l > MAX_BYTES) {
        return Err("status list is unexpectedly large".into());
    }
    // Read at most MAX_BYTES + 1 so a body without a Content-Length is never buffered whole.
    let bytes = crate::eth::read_capped(resp, MAX_BYTES).map_err(|e| {
        if e.contains("larger than") {
            "status list is unexpectedly large".to_string()
        } else {
            "status list download failed".to_string()
        }
    })?;
    String::from_utf8(bytes).map_err(|_| "status list download failed".to_string())
}

/// The current status list: cache if fresh, else the network, else a recent cache, else unknown.
pub fn current() -> Status {
    let t = now();
    let cached = read_cache();
    if let Some((fetched, list)) = &cached {
        if t.saturating_sub(*fetched) < FRESH_SECS {
            return Status::Checked { revoked: list.clone(), as_of: day(*fetched) };
        }
    }
    match fetch().and_then(|body| parse(&body).map(|list| (body, list))) {
        Ok((body, list)) => {
            write_cache(t, &body);
            Status::Checked { revoked: list, as_of: day(t) }
        }
        Err(e) => match cached {
            Some((fetched, list)) if t.saturating_sub(fetched) < STALE_OK_SECS => {
                Status::Checked { revoked: list, as_of: format!("{} (offline: {e})", day(fetched)) }
            }
            _ => Status::Unknown(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_google_format_and_normalises_serials() {
        let list = parse(
            r#"{"entries": {
            "6681152659205225093": {"status": "REVOKED", "reason": "KEY_COMPROMISE"},
            "00C35747A084470C3135AEEFE2B8D40CD6": {"status": "REVOKED", "reason": "SOFTWARE_FLAW"},
            "abc": {"status": "SUSPENDED"}
        }}"#,
        )
        .unwrap();
        assert_eq!(list.get("6681152659205225093").map(String::as_str), Some("KEY_COMPROMISE"));
        assert_eq!(list.get("c35747a084470c3135aeefe2b8d40cd6").map(String::as_str), Some("SOFTWARE_FLAW"));
        assert!(!list.contains_key("abc"), "only REVOKED entries count");
        assert!(parse(r#"{"entries": {"xyz": {"status": "REVOKED"}}}"#).is_err());
        assert!(parse("[]").is_err());
    }
}
