//! Local activity history: transactions this companion broadcast, plus balance increases the
//! watcher noticed. Public-chain facts only (hashes, amounts, counterparties): no keys, nothing
//! the node or an explorer does not already know. Stored 0600 next to the pairing file.

use crate::{blocking, eth, pairing, CmdResult};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ENTRIES: usize = 300;
static LOCK: Mutex<()> = Mutex::new(());

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    /// "out" (sent from this companion) or "in" (balance increase seen by the watcher)
    pub kind: String,
    pub hash: Option<String>,
    pub chain_id: u128,
    pub counterparty: Option<String>,
    pub amount_eth: String,
    pub fee_max_eth: Option<String>,
    pub nonce: Option<u128>,
    /// unix seconds
    pub time: u64,
    /// "pending" | "confirmed" | "failed" | "received"
    pub status: String,
    pub block: Option<u128>,
    /// ERC-20 sends: symbol, exact amount and contract from the built-in list (absent for ETH).
    #[serde(default)]
    pub token_symbol: Option<String>,
    #[serde(default)]
    pub token_amount: Option<String>,
    #[serde(default)]
    pub token_contract: Option<String>,
}

fn path() -> Result<PathBuf, String> {
    Ok(pairing::path().map_err(|e| e.0)?.with_file_name("history.json"))
}

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

fn load() -> Result<Vec<Entry>, String> {
    let p = path()?;
    match fs::read_to_string(&p) {
        Ok(text) => Ok(serde_json::from_str(&text).unwrap_or_default()), // a corrupt history is not worth failing over
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.to_string()),
    }
}

fn save(entries: &[Entry]) -> Result<(), String> {
    let p = path()?;
    if let Some(dir) = p.parent() { fs::create_dir_all(dir).map_err(|e| e.to_string())?; }
    let tmp = p.with_extension("json.tmp");
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
    f.write_all(&serde_json::to_vec_pretty(entries).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&tmp, &p).map_err(|e| e.to_string())
}

fn update(f: impl FnOnce(&mut Vec<Entry>)) -> Result<Vec<Entry>, String> {
    let _g = LOCK.lock().map_err(|_| "history lock poisoned".to_string())?;
    let mut entries = load()?;
    f(&mut entries);
    entries.sort_by(|a, b| b.time.cmp(&a.time));
    entries.truncate(MAX_ENTRIES);
    save(&entries)?;
    Ok(entries)
}

pub fn record_sent(hash: &str, chain_id: u128, to: &str, value_wei: u128, max_fee_wei: u128, nonce: u128) -> Result<(), String> {
    update(|e| {
        if e.iter().any(|x| x.hash.as_deref().map(str::to_ascii_lowercase) == Some(hash.to_ascii_lowercase())) { return; }
        e.push(Entry {
            kind: "out".into(), hash: Some(hash.to_string()), chain_id, counterparty: Some(to.to_string()),
            amount_eth: eth::format_eth(value_wei), fee_max_eth: Some(eth::format_eth(max_fee_wei)), nonce: Some(nonce),
            time: now(), status: "pending".into(), block: None, token_symbol: None, token_amount: None, token_contract: None,
        });
    }).map(|_| ())
}

/// A token send: the counterparty is the token recipient (not the contract), no ETH moved.
pub fn record_sent_token(hash: &str, chain_id: u128, t: &crate::tokens::TokenIntent, max_fee_wei: u128, nonce: u128) -> Result<(), String> {
    update(|e| {
        if e.iter().any(|x| x.hash.as_deref().map(str::to_ascii_lowercase) == Some(hash.to_ascii_lowercase())) { return; }
        e.push(Entry {
            kind: "out".into(), hash: Some(hash.to_string()), chain_id, counterparty: Some(crate::verify::checksum(&t.recipient)),
            amount_eth: "0".into(), fee_max_eth: Some(eth::format_eth(max_fee_wei)), nonce: Some(nonce),
            time: now(), status: "pending".into(), block: None,
            token_symbol: Some(t.symbol.clone()), token_amount: Some(t.amount.clone()), token_contract: Some(crate::verify::checksum(&t.contract)),
        });
    }).map(|_| ())
}

#[tauri::command]
pub(crate) async fn history_list() -> CmdResult<Vec<Entry>> {
    blocking(|| { let _g = LOCK.lock().map_err(|_| "history lock poisoned".to_string())?; load() }).await
}

/// Record a receipt outcome for a transaction sent from here.
#[tauri::command]
pub(crate) async fn history_mark(hash: String, status: String, block: Option<u128>) -> CmdResult<Vec<Entry>> {
    if !matches!(status.as_str(), "pending" | "confirmed" | "failed") { return Err("bad status".into()); }
    blocking(move || update(|e| {
        for x in e.iter_mut().filter(|x| x.hash.as_deref().map(str::to_ascii_lowercase) == Some(hash.to_ascii_lowercase())) {
            x.status = status.clone();
            x.block = block;
        }
    })).await
}

/// Record a balance increase the watcher saw (no hash: the watcher only compares balances).
#[tauri::command]
pub(crate) async fn history_add_incoming(chain_id: u128, amount_wei: String) -> CmdResult<Vec<Entry>> {
    let wei: u128 = amount_wei.parse().map_err(|_| "bad amount".to_string())?;
    blocking(move || update(|e| e.push(Entry {
        kind: "in".into(), hash: None, chain_id, counterparty: None, amount_eth: eth::format_eth(wei),
        fee_max_eth: None, nonce: None, time: now(), status: "received".into(), block: None,
        token_symbol: None, token_amount: None, token_contract: None,
    }))).await
}
