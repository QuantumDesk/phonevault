//! What the Mac keeps about Bitcoin, next to the EVM pairing file and with the same rules (0600
//! files in a 0700 directory, anything looser refused, atomic writes):
//!
//! * `btc-accounts.json`: the paired watch-only accounts (fingerprint, network, type, account
//!   number, xpub, descriptor, label), the account shown per network, and custom servers. Every
//!   entry is re-derived on load (the descriptor and id must match the xpub), so a hand-edited or
//!   corrupted file is refused rather than trusted.
//! * `btc-wallet-<id>.json`: per account, the scan cache (used addresses, balances, history) and
//!   what this Mac sent (so a stuck transaction can be sped up). Public-chain facts only.

use super::wallet::{Account, Kind, Net};
use bitcoin::bip32::{Fingerprint, Xpub};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

const FILE: &str = "btc-accounts.json";
const VERSION: u32 = 1;
const MAX_ACCOUNTS: usize = 60;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StoredAccount {
    pub id: String,
    pub network: Net,
    #[serde(rename = "type")]
    pub kind: Kind,
    pub account: u32,
    pub fingerprint: String,
    pub xpub: String,
    pub descriptor: String,
    pub label: String,
    #[serde(rename = "pairedAt", default)]
    pub paired_at: String,
}

impl StoredAccount {
    pub fn from_account(a: &Account, label: &str) -> StoredAccount {
        StoredAccount { id: a.id(), network: a.net, kind: a.kind, account: a.number, fingerprint: a.fingerprint.to_string(), xpub: a.xpub.to_string(),
            descriptor: a.descriptor(), label: label.to_string(), paired_at: crate::history::now().to_string() }
    }
    /// Rebuild and re-check the account from the stored fields.
    pub fn account(&self) -> Result<Account, String> {
        if !(1..=super::wallet::MAX_ACCOUNT).contains(&self.account) { return Err("account number out of range".into()); }
        let xpub = Xpub::from_str(&self.xpub).map_err(|_| "invalid xpub".to_string())?;
        let fingerprint = Fingerprint::from_str(&self.fingerprint).map_err(|_| "invalid fingerprint".to_string())?;
        let a = Account { net: self.network, kind: self.kind, number: self.account, fingerprint, xpub };
        if xpub.network != self.network.kind() || xpub.depth != 3 { return Err("xpub does not fit the account".into()); }
        if a.descriptor() != self.descriptor || a.id() != self.id { return Err("descriptor or id does not match the xpub".into()); }
        Ok(a)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Accounts {
    pub version: u32,
    /// network ("bitcoin"/"testnet"/"signet") → id of the account shown
    #[serde(default)]
    pub active: BTreeMap<String, String>,
    #[serde(default)]
    pub accounts: Vec<StoredAccount>,
    /// network → custom Esplora server (absent: the defaults)
    #[serde(default)]
    pub servers: BTreeMap<String, String>,
}
impl Default for Accounts { fn default() -> Self { Accounts { version: VERSION, active: BTreeMap::new(), accounts: Vec::new(), servers: BTreeMap::new() } } }

impl Accounts {
    pub fn find(&self, id: &str) -> Option<&StoredAccount> { self.accounts.iter().find(|a| a.id == id) }
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn active_for(&self, net: Net) -> Option<&StoredAccount> { self.active.get(net.wire()).and_then(|id| self.find(id)) }
    pub fn server(&self, net: Net) -> Option<String> { self.servers.get(net.wire()).cloned() }
}

static LOCK: Mutex<()> = Mutex::new(());

pub fn valid_id(id: &str) -> bool { id.len() <= 48 && !id.is_empty() && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') }

fn dir() -> Result<PathBuf, String> { crate::pairing::dir().map_err(|e| e.0) }

pub fn check_file(p: &Path) -> Result<Option<String>, String> {
    let meta = match fs::symlink_metadata(p) { Ok(m) => m, Err(_) => return Ok(None) };
    if !meta.is_file() { return Err(format!("{} is not a regular file", p.display())); }
    if meta.permissions().mode() & 0o077 != 0 { return Err(format!("{} is readable by others — refusing to use it", p.display())); }
    fs::read_to_string(p).map(Some).map_err(|e| e.to_string())
}

pub fn write_private(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    fs::rename(&tmp, dir.join(name)).map_err(|e| e.to_string())
}

fn parse(text: &str) -> Result<Accounts, String> {
    let mut p: Accounts = serde_json::from_str(text).map_err(|_| "Bitcoin accounts file is not valid".to_string())?;
    if p.version != VERSION { return Err("Bitcoin accounts file has an unknown version".into()); }
    if p.accounts.len() > MAX_ACCOUNTS { return Err("Bitcoin accounts file lists too many accounts".into()); }
    for a in p.accounts.iter_mut() {
        a.account().map_err(|e| format!("Bitcoin accounts file: {e}"))?;
        a.label = crate::pairing::clean_label(&a.label).ok_or("Bitcoin accounts file holds an empty label")?;
    }
    let mut seen = std::collections::HashSet::new();
    if !p.accounts.iter().all(|a| seen.insert(a.id.clone())) { return Err("Bitcoin accounts file lists an account twice".into()); }
    for (net, id) in &p.active {
        let n = Net::parse(net)?;
        if p.find(id).map(|a| a.network) != Some(n) { return Err("Bitcoin accounts file: shown account is not paired".into()); }
    }
    for (net, url) in &p.servers { Net::parse(net)?; super::esplora::check_server(url)?; }
    Ok(p)
}

pub fn load_in(dir: &Path) -> Result<Accounts, String> {
    let _g = LOCK.lock().map_err(|_| "lock poisoned")?;
    match check_file(&dir.join(FILE))? { Some(t) => parse(&t), None => Ok(Accounts::default()) }
}

pub fn modify_in(dir: &Path, f: impl FnOnce(&mut Accounts) -> Result<(), String>) -> Result<Accounts, String> {
    let _g = LOCK.lock().map_err(|_| "lock poisoned")?;
    let mut p = match check_file(&dir.join(FILE))? { Some(t) => parse(&t)?, None => Accounts::default() };
    f(&mut p)?;
    write_private(dir, FILE, serde_json::to_string_pretty(&p).map_err(|e| e.to_string())?.as_bytes())?;
    Ok(p)
}

pub fn load() -> Result<Accounts, String> { load_in(&dir()?) }
pub fn modify(f: impl FnOnce(&mut Accounts) -> Result<(), String>) -> Result<Accounts, String> { modify_in(&dir()?, f) }

/// Add (or re-pair) an account and show it for its network.
pub fn add_in(dir: &Path, a: &Account, label: Option<&str>) -> Result<Accounts, String> {
    modify_in(dir, |p| {
        let label = label.and_then(crate::pairing::clean_label).unwrap_or_else(|| default_label(a));
        match p.accounts.iter_mut().find(|x| x.id == a.id()) {
            Some(x) => x.label = label,
            None => {
                if p.accounts.len() >= MAX_ACCOUNTS { return Err("too many Bitcoin accounts".into()); }
                p.accounts.push(StoredAccount::from_account(a, &label));
            }
        }
        p.active.insert(a.net.wire().to_string(), a.id());
        Ok(())
    })
}

pub fn default_label(a: &Account) -> String {
    let base = if a.kind == Kind::P2tr { format!("Bitcoin {} · Taproot", a.number) } else { format!("Bitcoin {}", a.number) };
    match a.net { Net::Bitcoin => base, Net::Testnet => format!("{base} · testnet"), Net::Signet => format!("{base} · signet") }
}

pub fn remove_in(dir: &Path, id: &str) -> Result<Accounts, String> {
    modify_in(dir, |p| {
        let net = p.find(id).map(|a| a.network).ok_or("that Bitcoin account is not paired")?;
        p.accounts.retain(|a| a.id != id);
        if p.active.get(net.wire()).map(String::as_str) == Some(id) {
            match p.accounts.iter().find(|a| a.network == net) { Some(n) => { p.active.insert(net.wire().into(), n.id.clone()); } None => { p.active.remove(net.wire()); } }
        }
        Ok(())
    })
}

// ---------------------------------------------------------------- per-account wallet cache

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AddrState {
    pub chain: u32,
    pub index: u32,
    pub chain_txs: u64,
    pub mempool_txs: u64,
    /// confirmed funded − spent
    pub confirmed: u64,
    /// mempool funded − spent (can be negative)
    pub mempool: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    pub txid: String,
    /// net effect on this account in sat (incoming > 0)
    pub net: i64,
    pub fee: Option<u64>,
    pub height: Option<u64>,
    /// block time, or when this Mac first saw it
    pub time: u64,
    /// the other side: first foreign output (sends) or first foreign input (receives)
    pub counterparty: Option<String>,
    /// "pending" | "confirmed" | "dropped" (replaced or evicted)
    pub status: String,
    /// our addresses it touches (to notice when it disappears from the server)
    #[serde(default)]
    pub addrs: Vec<String>,
    /// signals RBF (any input nSequence < 0xfffffffe)
    #[serde(default)]
    pub rbf: bool,
}

/// What this Mac built and broadcast, kept for speed-up (RBF).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Sent {
    pub txid: String,
    pub time: u64,
    pub recipient: String,
    pub amount: u64,
    pub fee: u64,
    pub vsize: u64,
    pub rate_kvb: u64,
    /// (txid, vout, value, chain, index) of every input
    pub inputs: Vec<(String, u32, u64, u32, u32)>,
    /// (index on the change chain, value)
    pub change: Option<(u32, u64)>,
    #[serde(default)]
    pub replaces: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Cache {
    /// used addresses → state
    pub addrs: BTreeMap<String, AddrState>,
    /// first unused index per chain (receive, change)
    pub next: [u32; 2],
    pub history: Vec<Entry>,
    pub sent: Vec<Sent>,
    /// receive indices whose address the user confirmed on the phone's screen
    pub verified: Vec<u32>,
    pub scanned_at: u64,
    pub full_scan_at: u64,
    pub tip: Option<u64>,
    /// the first complete scan has run (later new incoming transactions notify)
    pub initial_done: bool,
    pub error: Option<String>,
}

impl Cache {
    pub fn confirmed(&self) -> u64 { self.addrs.values().map(|a| a.confirmed).sum() }
    pub fn unconfirmed(&self) -> i64 { self.addrs.values().map(|a| a.mempool).sum() }
}

static CACHE_LOCK: Mutex<()> = Mutex::new(());

fn cache_name(id: &str) -> String { format!("btc-wallet-{id}.json") }

pub fn load_cache(id: &str) -> Result<Cache, String> {
    if !valid_id(id) { return Err("bad account id".into()); }
    let _g = CACHE_LOCK.lock().map_err(|_| "lock poisoned")?;
    Ok(check_file(&dir()?.join(cache_name(id)))?.and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default())
}

pub fn update_cache<T>(id: &str, f: impl FnOnce(&mut Cache) -> T) -> Result<(T, Cache), String> {
    if !valid_id(id) { return Err("bad account id".into()); }
    let _g = CACHE_LOCK.lock().map_err(|_| "lock poisoned")?;
    let d = dir()?;
    let mut c: Cache = check_file(&d.join(cache_name(id)))?.and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let r = f(&mut c);
    c.history.sort_by(|a, b| b.time.cmp(&a.time));
    c.history.truncate(1000);
    if c.sent.len() > 200 { let n = c.sent.len() - 200; c.sent.drain(..n); }
    write_private(&d, &cache_name(id), &serde_json::to_vec_pretty(&c).map_err(|e| e.to_string())?)?;
    Ok((r, c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc::wallet::test_account;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("pv-btc-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    #[test]
    fn accounts_round_trip_and_tampering_is_refused() {
        let d = tmp();
        let (a1, _) = test_account(Net::Bitcoin, Kind::P2wpkh, 1);
        let (a2, _) = test_account(Net::Bitcoin, Kind::P2tr, 1);
        let (t1, _) = test_account(Net::Signet, Kind::P2wpkh, 1);
        add_in(&d, &a1, None).unwrap();
        add_in(&d, &a2, Some("Savings")).unwrap();
        let p = add_in(&d, &t1, None).unwrap();
        assert_eq!(p.active_for(Net::Bitcoin).unwrap().id, a2.id());
        assert_eq!(p.active_for(Net::Signet).unwrap().label, "Bitcoin 1 · signet");
        assert_eq!(p.find(&a1.id()).unwrap().label, "Bitcoin 1");
        assert_eq!(p.find(&a1.id()).unwrap().account().unwrap(), a1);
        assert_eq!(fs::metadata(d.join(FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load_in(&d).unwrap(), p);
        // removing the shown account shows another one of the same network
        let p = remove_in(&d, &a2.id()).unwrap();
        assert_eq!(p.active_for(Net::Bitcoin).unwrap().id, a1.id());
        let good = fs::read_to_string(d.join(FILE)).unwrap();
        let (other, _) = test_account(Net::Bitcoin, Kind::P2wpkh, 2);
        for bad in [
            good.replace(&a1.xpub.to_string(), &other.xpub.to_string()), // xpub swapped: descriptor no longer matches
            good.replace("\"version\": 1", "\"version\": 2"),
            good.replacen("73c5da0a", "deadbeef", 1),
            "nope".to_string(),
        ] {
            fs::write(d.join(FILE), &bad).unwrap();
            fs::set_permissions(d.join(FILE), fs::Permissions::from_mode(0o600)).unwrap();
            assert!(load_in(&d).is_err(), "accepted tampered file");
        }
        fs::write(d.join(FILE), &good).unwrap();
        fs::set_permissions(d.join(FILE), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_in(&d).unwrap_err().contains("readable by others"));
    }

    #[test]
    fn ids_are_file_safe() {
        let (a, _) = test_account(Net::Bitcoin, Kind::P2tr, 12);
        assert_eq!(a.id(), "73c5da0a-bitcoin-p2tr-12");
        assert!(valid_id(&a.id()));
        assert!(!valid_id("../x"));
        assert!(!valid_id(""));
    }
}
