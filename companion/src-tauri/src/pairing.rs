//! The signer addresses pinned at pairing time, each after the user compared it with the phone's
//! own screen. A phone can have several accounts (m/44'/60'/0'/0/i) and passphrase wallets, so the
//! Mac keeps a LIST of paired addresses, each with a label ("Account 1", "Account 2 · passphrase"),
//! and one ACTIVE address: the account the Mac UI shows. Every request is pinned to the account
//! active when it starts: `load()` returns it, the request names it (`from`, so the phone refuses
//! if a different account is active there), and the recovered signer must equal it.
//!
//! Stored 0600 in the app's config directory (`paired-accounts.json`); anything looser is refused,
//! like the Python client does. The single-address file of earlier versions (`paired-signer.json`)
//! is migrated on first read: it becomes "Account 1" and its activity history moves to that
//! address's own file.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PairingError(pub String);
impl From<PairingError> for String {
    fn from(e: PairingError) -> String {
        e.0
    }
}
fn err(m: impl Into<String>) -> PairingError {
    PairingError(m.into())
}

const FILE: &str = "paired-accounts.json";
const LEGACY_FILE: &str = "paired-signer.json";
const VERSION: u32 = 2;
pub const MAX_ACCOUNTS: usize = 64;
pub const MAX_LABEL: usize = 40;

/// One paired address.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Paired {
    /// lowercase 0x + 40 hex
    pub address: String,
    pub label: String,
    /// "standard" | "passphrase", when the phone said so at pairing time.
    #[serde(default)]
    pub wallet: Option<String>,
    /// 1-based account number on the phone, when the phone said so at pairing time.
    #[serde(default)]
    pub account: Option<u32>,
    #[serde(rename = "pairedAt", default)]
    pub paired_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Pairings {
    pub version: u32,
    /// The account the Mac UI shows and every new request is pinned to.
    pub active: Option<String>,
    pub accounts: Vec<Paired>,
}

impl Pairings {
    pub fn find(&self, address: &str) -> Option<&Paired> {
        self.accounts.iter().find(|p| p.address.eq_ignore_ascii_case(address))
    }
    pub fn active_account(&self) -> Option<&Paired> {
        self.active.as_deref().and_then(|a| self.find(a))
    }
}

/// Serialises read-modify-write of the file within this process.
static LOCK: Mutex<()> = Mutex::new(());

pub fn dir() -> Result<PathBuf, PairingError> {
    let base = dirs::config_dir().ok_or_else(|| err("no config directory"))?;
    Ok(base.join("PhoneVault"))
}

/// The pairing file. Other stores live next to it (`with_file_name`).
pub fn path() -> Result<PathBuf, PairingError> {
    Ok(dir()?.join(FILE))
}

/// `<stem>-<address>.json` next to the pairing file: per-account history, NFTs.
pub fn account_file(stem: &str, address: &str) -> Result<PathBuf, PairingError> {
    Ok(dir()?.join(account_file_name(stem, &valid_address(address)?)))
}

fn account_file_name(stem: &str, address: &str) -> String {
    format!("{stem}-{}.json", address.to_ascii_lowercase())
}

pub fn valid_address(addr: &str) -> Result<String, PairingError> {
    if addr.len() != 42 || !addr.starts_with("0x") || !addr[2..].bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err("invalid address"));
    }
    Ok(addr.to_ascii_lowercase())
}

/// Printable, trimmed, at most MAX_LABEL characters; empty → None.
pub fn clean_label(label: &str) -> Option<String> {
    let s: String = label.chars().filter(|c| !c.is_control()).take(MAX_LABEL).collect();
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// "Account 2", "Account 2 · passphrase", or "Account N" (N = next) when the phone did not say.
pub fn default_label(existing: &Pairings, account: Option<u32>, wallet: Option<&str>) -> String {
    let n = account.unwrap_or(existing.accounts.len() as u32 + 1);
    if wallet == Some("passphrase") {
        format!("Account {n} · passphrase")
    } else {
        format!("Account {n}")
    }
}

// ---------------------------------------------------------------- public API (config dir)

/// The ACTIVE paired address (lowercase), if any. Every signing path pins to this.
pub fn load() -> Result<Option<String>, PairingError> {
    Ok(load_in(&dir()?)?.active)
}
pub fn list() -> Result<Pairings, PairingError> {
    load_in(&dir()?)
}
/// Pair (or re-pair) an address and make it active.
pub fn add(
    address: &str,
    label: Option<&str>,
    wallet: Option<&str>,
    account: Option<u32>,
) -> Result<PathBuf, PairingError> {
    add_in(&dir()?, address, label, wallet, account).map(|_| path().unwrap_or_default())
}
pub fn select(address: &str) -> Result<Pairings, PairingError> {
    select_in(&dir()?, address)
}
pub fn rename(address: &str, label: &str) -> Result<Pairings, PairingError> {
    rename_in(&dir()?, address, label)
}
pub fn remove(address: &str) -> Result<Pairings, PairingError> {
    remove_in(&dir()?, address)
}
/// Forget every paired address.
pub fn forget() -> Result<(), PairingError> {
    forget_in(&dir()?)
}

// ---------------------------------------------------------------- directory-scoped (tested)

fn check_file(p: &Path) -> Result<Option<String>, PairingError> {
    let meta = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    if !meta.is_file() {
        return Err(err("pairing file is not a regular file"));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(err(format!("pairing file {} is readable by others — refusing to use it", p.display())));
    }
    fs::read_to_string(p).map(Some).map_err(|e| err(e.to_string()))
}

fn parse(text: &str) -> Result<Pairings, PairingError> {
    let mut p: Pairings = serde_json::from_str(text).map_err(|_| err("pairing file is not valid"))?;
    if p.version != VERSION {
        return Err(err("pairing file has an unknown version"));
    }
    if p.accounts.len() > MAX_ACCOUNTS {
        return Err(err("pairing file lists too many accounts"));
    }
    for a in p.accounts.iter_mut() {
        a.address = valid_address(&a.address).map_err(|_| err("pairing file holds an invalid address"))?;
        a.label = clean_label(&a.label).ok_or_else(|| err("pairing file holds an empty label"))?;
        if a.wallet.as_deref().is_some_and(|w| w != "standard" && w != "passphrase") {
            return Err(err("pairing file holds an unknown wallet kind"));
        }
    }
    let mut seen = std::collections::HashSet::new();
    if !p.accounts.iter().all(|a| seen.insert(a.address.clone())) {
        return Err(err("pairing file lists an address twice"));
    }
    if let Some(a) = &p.active {
        let a = valid_address(a).map_err(|_| err("pairing file holds an invalid active address"))?;
        if p.find(&a).is_none() {
            return Err(err("pairing file's active address is not paired"));
        }
        p.active = Some(a);
    } else if !p.accounts.is_empty() {
        return Err(err("pairing file has accounts but none active"));
    }
    Ok(p)
}

/// Read the pairings, migrating the single-address file of earlier versions on first use.
pub fn load_in(dir: &Path) -> Result<Pairings, PairingError> {
    let _g = LOCK.lock().map_err(|_| err("pairing lock poisoned"))?;
    load_locked(dir)
}

fn load_locked(dir: &Path) -> Result<Pairings, PairingError> {
    if let Some(text) = check_file(&dir.join(FILE))? {
        return parse(&text);
    }
    let Some(legacy) = check_file(&dir.join(LEGACY_FILE))? else {
        return Ok(Pairings { version: VERSION, ..Default::default() });
    };
    let v: serde_json::Value = serde_json::from_str(&legacy).map_err(|_| err("pairing file is not JSON"))?;
    let addr = v.get("address").and_then(|a| a.as_str()).ok_or_else(|| err("pairing file lacks an address"))?;
    let addr = valid_address(addr).map_err(|_| err("pairing file holds an invalid address"))?;
    let paired_at = v.get("pairedAt").and_then(|a| a.as_str()).unwrap_or("").to_string();
    let migrated = Pairings {
        version: VERSION,
        active: Some(addr.clone()),
        accounts: vec![Paired {
            address: addr.clone(),
            label: "Account 1".into(),
            wallet: None,
            account: None,
            paired_at,
        }],
    };
    write(dir, &migrated)?;
    // Per-account stores: the old single history belongs to the one address that was paired.
    let old_history = dir.join("history.json");
    let new_history = dir.join(account_file_name("history", &addr));
    if old_history.exists() && !new_history.exists() {
        let _ = fs::rename(&old_history, &new_history);
    }
    let _ = fs::rename(dir.join(LEGACY_FILE), dir.join(format!("{LEGACY_FILE}.migrated")));
    Ok(migrated)
}

fn write(dir: &Path, p: &Pairings) -> Result<(), PairingError> {
    fs::create_dir_all(dir).map_err(|e| err(e.to_string()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| err(e.to_string()))?;
    let tmp = dir.join(format!(".paired-accounts.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut f =
        fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| err(e.to_string()))?;
    f.write_all(serde_json::to_string_pretty(p).map_err(|e| err(e.to_string()))?.as_bytes())
        .map_err(|e| err(e.to_string()))?;
    f.sync_all().map_err(|e| err(e.to_string()))?;
    drop(f);
    fs::rename(&tmp, dir.join(FILE)).map_err(|e| err(e.to_string()))
}

fn modify(dir: &Path, f: impl FnOnce(&mut Pairings) -> Result<(), PairingError>) -> Result<Pairings, PairingError> {
    let _g = LOCK.lock().map_err(|_| err("pairing lock poisoned"))?;
    let mut p = load_locked(dir)?;
    f(&mut p)?;
    write(dir, &p)?;
    Ok(p)
}

pub fn add_in(
    dir: &Path,
    address: &str,
    label: Option<&str>,
    wallet: Option<&str>,
    account: Option<u32>,
) -> Result<Pairings, PairingError> {
    let address = valid_address(address)?;
    let wallet = match wallet {
        None => None,
        Some(w @ ("standard" | "passphrase")) => Some(w.to_string()),
        Some(_) => return Err(err("unknown wallet kind")),
    };
    if account.is_some_and(|n| n == 0 || n > 20) {
        return Err(err("account number out of range"));
    }
    modify(dir, |p| {
        let label = label.and_then(clean_label).unwrap_or_else(|| default_label(p, account, wallet.as_deref()));
        match p.accounts.iter_mut().find(|a| a.address == address) {
            Some(existing) => {
                existing.label = label;
                if wallet.is_some() {
                    existing.wallet = wallet;
                }
                if account.is_some() {
                    existing.account = account;
                }
            }
            None => {
                if p.accounts.len() >= MAX_ACCOUNTS {
                    return Err(err("too many paired accounts"));
                }
                p.accounts.push(Paired { address: address.clone(), label, wallet, account, paired_at: now() });
            }
        }
        p.active = Some(address);
        Ok(())
    })
}

pub fn select_in(dir: &Path, address: &str) -> Result<Pairings, PairingError> {
    let address = valid_address(address)?;
    modify(dir, |p| {
        if p.find(&address).is_none() {
            return Err(err("that address is not paired with this Mac"));
        }
        p.active = Some(address);
        Ok(())
    })
}

pub fn rename_in(dir: &Path, address: &str, label: &str) -> Result<Pairings, PairingError> {
    let address = valid_address(address)?;
    let label = clean_label(label).ok_or_else(|| err("the name is empty"))?;
    modify(dir, |p| {
        let a = p
            .accounts
            .iter_mut()
            .find(|a| a.address == address)
            .ok_or_else(|| err("that address is not paired with this Mac"))?;
        a.label = label;
        Ok(())
    })
}

pub fn remove_in(dir: &Path, address: &str) -> Result<Pairings, PairingError> {
    let address = valid_address(address)?;
    modify(dir, |p| {
        p.accounts.retain(|a| a.address != address);
        if p.active.as_deref() == Some(address.as_str()) {
            p.active = p.accounts.first().map(|a| a.address.clone());
        }
        Ok(())
    })
}

pub fn forget_in(dir: &Path) -> Result<(), PairingError> {
    let _g = LOCK.lock().map_err(|_| err("pairing lock poisoned"))?;
    for f in [FILE, LEGACY_FILE] {
        match fs::remove_file(dir.join(f)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(err(e.to_string())),
        }
    }
    Ok(())
}

fn now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const A1: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const A2: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
    const P1: &str = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc";

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("pv-pairing-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    fn write_legacy(dir: &Path, addr: &str, mode: u32) {
        let p = dir.join(LEGACY_FILE);
        fs::write(&p, format!("{{\"address\":\"{addr}\",\"pairedAt\":\"1700000000\"}}")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn empty_dir_is_unpaired() {
        let d = tmp();
        let p = load_in(&d).unwrap();
        assert_eq!(p.active, None);
        assert!(p.accounts.is_empty());
    }

    #[test]
    fn legacy_single_pairing_migrates_to_account_1_with_its_history() {
        let d = tmp();
        write_legacy(&d, &A1.to_ascii_uppercase().replace("0X", "0x"), 0o600);
        fs::write(d.join("history.json"), "[]").unwrap();
        let p = load_in(&d).unwrap();
        assert_eq!(p.active.as_deref(), Some(A1));
        assert_eq!(p.accounts.len(), 1);
        assert_eq!(p.accounts[0].label, "Account 1");
        assert_eq!(p.accounts[0].paired_at, "1700000000");
        // the v2 file exists 0600, the legacy file is set aside, the history moved to the address
        let meta = fs::metadata(d.join(FILE)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert!(!d.join(LEGACY_FILE).exists());
        assert!(d.join(format!("{LEGACY_FILE}.migrated")).exists());
        assert!(!d.join("history.json").exists());
        assert!(d.join(format!("history-{A1}.json")).exists());
        // idempotent: a second read uses the v2 file
        assert_eq!(load_in(&d).unwrap(), p);
    }

    #[test]
    fn legacy_file_readable_by_others_is_refused_not_migrated() {
        let d = tmp();
        write_legacy(&d, A1, 0o644);
        assert!(load_in(&d).unwrap_err().0.contains("readable by others"));
        assert!(!d.join(FILE).exists());
    }

    #[test]
    fn several_accounts_one_active() {
        let d = tmp();
        add_in(&d, A1, None, Some("standard"), Some(1)).unwrap();
        let p = add_in(&d, A2, None, Some("standard"), Some(2)).unwrap();
        assert_eq!(p.active.as_deref(), Some(A2), "a newly paired account becomes active");
        assert_eq!(p.find(A2).unwrap().label, "Account 2");
        let p = add_in(&d, P1, None, Some("passphrase"), Some(1)).unwrap();
        assert_eq!(p.find(P1).unwrap().label, "Account 1 · passphrase");
        assert_eq!(p.accounts.len(), 3);
        let p = select_in(&d, A1).unwrap();
        assert_eq!(p.active.as_deref(), Some(A1));
        assert_eq!(load_in(&d).unwrap().active.as_deref(), Some(A1));
        assert!(
            select_in(&d, "0x0000000000000000000000000000000000000001").is_err(),
            "only paired addresses can be selected"
        );
        // re-pairing an address keeps one entry and updates it
        let p = add_in(&d, A2, Some("Savings"), None, None).unwrap();
        assert_eq!(p.accounts.len(), 3);
        assert_eq!(p.find(A2).unwrap().label, "Savings");
        assert_eq!(p.find(A2).unwrap().account, Some(2));
        let p = rename_in(&d, A2, "  Daily \u{7} ").unwrap();
        assert_eq!(p.find(A2).unwrap().label, "Daily");
        assert!(rename_in(&d, A2, "   ").is_err());
        // removing the active account falls back to the first remaining one
        let p = remove_in(&d, A2).unwrap();
        assert_eq!(p.active.as_deref(), Some(A1));
        let p = remove_in(&d, A1).unwrap();
        assert_eq!(p.active.as_deref(), Some(P1));
        forget_in(&d).unwrap();
        assert_eq!(load_in(&d).unwrap().active, None);
    }

    #[test]
    fn default_label_without_phone_info_counts_up() {
        let d = tmp();
        add_in(&d, A1, None, None, None).unwrap();
        let p = add_in(&d, A2, None, None, None).unwrap();
        assert_eq!(p.find(A1).unwrap().label, "Account 1");
        assert_eq!(p.find(A2).unwrap().label, "Account 2");
        assert!(add_in(&d, A2, None, Some("hidden"), None).is_err());
        assert!(add_in(&d, A2, None, None, Some(0)).is_err());
        assert!(add_in(&d, "0x12", None, None, None).is_err());
    }

    #[test]
    fn tampered_files_are_refused() {
        let d = tmp();
        add_in(&d, A1, None, None, None).unwrap();
        let good = fs::read_to_string(d.join(FILE)).unwrap();
        let bad_cases = [
            good.replace(A1, "0xnothex"),
            good.replace("\"version\": 2", "\"version\": 3"),
            good.replace(&format!("\"active\": \"{A1}\""), &format!("\"active\": \"{A2}\"")),
            good.replace(&format!("\"active\": \"{A1}\""), "\"active\": null"),
            "not json".to_string(),
        ];
        for bad in bad_cases {
            fs::write(d.join(FILE), &bad).unwrap();
            fs::set_permissions(d.join(FILE), fs::Permissions::from_mode(0o600)).unwrap();
            assert!(load_in(&d).is_err(), "accepted: {bad}");
        }
        fs::write(d.join(FILE), &good).unwrap();
        fs::set_permissions(d.join(FILE), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_in(&d).is_err());
    }

    #[test]
    fn account_files_are_per_address() {
        assert_eq!(
            account_file_name("history", &A1.to_ascii_uppercase().replace("0X", "0x")),
            format!("history-{A1}.json")
        );
        assert!(account_file("history", "../../etc/passwd").is_err());
    }
}
