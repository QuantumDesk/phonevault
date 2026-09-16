//! The signer address pinned at pairing time, after the user compared it with the phone's own
//! screen. Stored 0600 in the app's config directory; anything looser is refused, like the
//! Python client does.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PairingError(pub String);
fn err(m: impl Into<String>) -> PairingError { PairingError(m.into()) }

pub fn path() -> Result<PathBuf, PairingError> {
    let base = dirs::config_dir().ok_or_else(|| err("no config directory"))?;
    Ok(base.join("PhoneVault").join("paired-signer.json"))
}

pub fn load() -> Result<Option<String>, PairingError> {
    let p = path()?;
    let meta = match fs::symlink_metadata(&p) { Ok(m) => m, Err(_) => return Ok(None) };
    if !meta.is_file() { return Err(err("pairing file is not a regular file")); }
    if meta.permissions().mode() & 0o077 != 0 { return Err(err(format!("pairing file {} is readable by others — refusing to use it", p.display()))); }
    let text = fs::read_to_string(&p).map_err(|e| err(e.to_string()))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| err("pairing file is not JSON"))?;
    let addr = v.get("address").and_then(|a| a.as_str()).ok_or_else(|| err("pairing file lacks an address"))?;
    if addr.len() != 42 || !addr.starts_with("0x") || !addr[2..].bytes().all(|b| b.is_ascii_hexdigit()) { return Err(err("pairing file holds an invalid address")); }
    Ok(Some(addr.to_ascii_lowercase()))
}

pub fn save(address: &str) -> Result<PathBuf, PairingError> {
    let p = path()?;
    let dir = p.parent().ok_or_else(|| err("bad pairing path"))?;
    fs::create_dir_all(dir).map_err(|e| err(e.to_string()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| err(e.to_string()))?;
    let tmp = dir.join(format!(".paired-signer.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| err(e.to_string()))?;
    let body = serde_json::json!({"address": address.to_ascii_lowercase(), "pairedAt": chrono_now()});
    f.write_all(serde_json::to_string_pretty(&body).unwrap().as_bytes()).map_err(|e| err(e.to_string()))?;
    f.sync_all().map_err(|e| err(e.to_string()))?;
    drop(f);
    fs::rename(&tmp, &p).map_err(|e| err(e.to_string()))?;
    Ok(p)
}

pub fn forget() -> Result<(), PairingError> {
    let p = path()?;
    match fs::remove_file(&p) { Ok(()) => Ok(()), Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), Err(e) => Err(err(e.to_string())) }
}

fn chrono_now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{secs}")
}
