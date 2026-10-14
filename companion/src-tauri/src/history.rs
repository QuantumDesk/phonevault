//! Local activity history: transactions this companion broadcast, transfers into the wallet that
//! the background watcher found (with their real hashes when the node can show them), and balance
//! increases it could not attribute to a transaction. Public-chain facts only (hashes, amounts,
//! counterparties): no keys, nothing the node or an explorer does not already know. Stored 0600
//! next to the pairing file, one file per paired account (`history-<address>.json`); the commands
//! work on the account the Mac currently shows, the watcher names the account it scanned.

use crate::{blocking, eth, pairing, verify, CmdResult};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ENTRIES: usize = 500;
static LOCK: Mutex<()> = Mutex::new(());

/// The exact fields of a transaction this companion broadcast, as signed (quantities in 0x hex).
/// Kept so a stuck transaction can be re-sent with the same nonce and higher fees.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TxParams {
    pub to: String, pub value: String, pub data: String, pub gas_limit: String,
    pub max_fee_per_gas: String, pub max_priority_fee_per_gas: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    /// "out" (sent from this companion) or "in" (into the wallet, seen by the watcher)
    pub kind: String,
    pub hash: Option<String>,
    pub chain_id: u128,
    pub counterparty: Option<String>,
    pub amount_eth: String,
    pub fee_max_eth: Option<String>,
    pub nonce: Option<u128>,
    /// unix seconds
    pub time: u64,
    /// "pending" | "confirmed" | "failed" | "received" | "dropped" (another transaction with the
    /// same nonce was mined instead: a speed-up/cancel replaced it, or it replaced nothing)
    pub status: String,
    pub block: Option<u128>,
    /// ERC-20: symbol, exact amount and contract from the built-in list (absent for ETH).
    #[serde(default)]
    pub token_symbol: Option<String>,
    #[serde(default)]
    pub token_amount: Option<String>,
    #[serde(default)]
    pub token_contract: Option<String>,
    /// Sent from here: the signed fields (absent for entries written before this was kept).
    #[serde(default)]
    pub tx: Option<TxParams>,
    /// A speed-up or cancel: the hash of the transaction it replaces, and which kind.
    #[serde(default)]
    pub replaces: Option<String>,
    #[serde(default)]
    pub replacement_kind: Option<String>,
    /// Incoming token transfer: the log index (hash + index identify one transfer).
    #[serde(default)]
    pub log_index: Option<u64>,
}

impl Entry {
    fn blank(kind: &str, chain_id: u128, status: &str) -> Entry {
        Entry {
            kind: kind.into(), hash: None, chain_id, counterparty: None, amount_eth: "0".into(), fee_max_eth: None, nonce: None,
            time: now(), status: status.into(), block: None, token_symbol: None, token_amount: None, token_contract: None,
            tx: None, replaces: None, replacement_kind: None, log_index: None,
        }
    }
    fn is_hash(&self, hash: &str) -> bool { self.hash.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(hash)) }
}

fn path(owner: &str) -> Result<PathBuf, String> { pairing::account_file("history", owner).map_err(|e| e.0) }

/// The account the Mac shows (pairing::load).
fn active_owner() -> Result<String, String> { pairing::load().map_err(|e| e.0)?.ok_or_else(|| "not paired yet".to_string()) }

pub fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

fn load(owner: &str) -> Result<Vec<Entry>, String> {
    let p = path(owner)?;
    match fs::read_to_string(&p) {
        Ok(text) => Ok(serde_json::from_str(&text).unwrap_or_default()), // a corrupt history is not worth failing over
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.to_string()),
    }
}

fn save(owner: &str, entries: &[Entry]) -> Result<(), String> {
    let p = path(owner)?;
    if let Some(dir) = p.parent() { fs::create_dir_all(dir).map_err(|e| e.to_string())?; }
    let tmp = p.with_extension("json.tmp");
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
    f.write_all(&serde_json::to_vec_pretty(entries).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&tmp, &p).map_err(|e| e.to_string())
}

fn update(f: impl FnOnce(&mut Vec<Entry>)) -> Result<Vec<Entry>, String> { update_for(&active_owner()?, f) }

fn update_for(owner: &str, f: impl FnOnce(&mut Vec<Entry>)) -> Result<Vec<Entry>, String> {
    let _g = LOCK.lock().map_err(|_| "history lock poisoned".to_string())?;
    let mut entries = load(owner)?;
    f(&mut entries);
    entries.sort_by_key(|e| std::cmp::Reverse(e.time));
    entries.truncate(MAX_ENTRIES);
    save(owner, &entries)?;
    Ok(entries)
}

/// The history of the account the Mac shows (empty when nothing is paired).
pub fn list() -> Result<Vec<Entry>, String> {
    match pairing::load().map_err(|e| e.0)? { Some(owner) => list_for(&owner), None => Ok(Vec::new()) }
}

pub fn list_for(owner: &str) -> Result<Vec<Entry>, String> {
    let _g = LOCK.lock().map_err(|_| "history lock poisoned".to_string())?;
    load(owner)
}


/// What `broadcast_verified` knows about a transaction it just sent.
pub struct Broadcast<'a> {
    pub hash: &'a str, pub chain_id: u128, pub value_wei: u128, pub max_fee_wei: u128, pub nonce: u128,
    pub token: Option<&'a crate::tokens::TokenIntent>, pub tx: TxParams, pub replaces: Option<(String, String)>,
}

/// Record a transaction broadcast from here. The counterparty is the token recipient for a token
/// transfer (not the contract) and the plain `to` otherwise.
pub fn record_broadcast(b: Broadcast) -> Result<(), String> {
    update(|e| {
        if e.iter().any(|x| x.is_hash(b.hash)) { return; }
        let mut x = Entry::blank("out", b.chain_id, "pending");
        x.hash = Some(b.hash.to_string());
        x.nonce = Some(b.nonce);
        x.fee_max_eth = Some(eth::format_eth(b.max_fee_wei));
        match b.token {
            Some(t) => {
                x.counterparty = Some(verify::checksum(&t.recipient));
                x.token_symbol = Some(t.symbol.clone()); x.token_amount = Some(t.amount.clone()); x.token_contract = Some(verify::checksum(&t.contract));
            }
            None => { x.counterparty = Some(verify::checksum(&b.tx.to)); x.amount_eth = eth::format_eth(b.value_wei); }
        }
        if let Some((hash, kind)) = b.replaces { x.replaces = Some(hash); x.replacement_kind = Some(kind); }
        x.tx = Some(b.tx);
        e.push(x);
    }).map(|_| ())
}

/// An incoming transfer with a real hash (native, or an ERC-20 from the built-in list).
pub struct Incoming { pub hash: String, pub chain_id: u128, pub from: Option<String>, pub amount_eth: String,
    pub token: Option<(String, String, String)>, pub log_index: Option<u64>, pub block: Option<u128> }

/// Add incoming transfers to `owner` not seen before. Returns the ones that were new.
pub fn record_incoming(owner: &str, items: Vec<Incoming>) -> Result<Vec<Entry>, String> {
    let mut added = Vec::new();
    update_for(owner, |e| {
        for i in items {
            if e.iter().any(|x| x.kind == "in" && x.chain_id == i.chain_id && x.is_hash(&i.hash) && x.log_index == i.log_index) { continue; }
            let mut x = Entry::blank("in", i.chain_id, "received");
            x.hash = Some(i.hash); x.counterparty = i.from.map(|f| verify::checksum(&f)); x.amount_eth = i.amount_eth;
            x.block = i.block; x.log_index = i.log_index;
            if let Some((symbol, amount, contract)) = i.token { x.token_symbol = Some(symbol); x.token_amount = Some(amount); x.token_contract = Some(verify::checksum(&contract)); }
            added.push(x.clone());
            e.push(x);
        }
    })?;
    Ok(added)
}

/// A balance increase the watcher could not attribute to a transaction (e.g. an internal transfer
/// from a contract, or a window too wide to scan): no hash.
pub fn record_balance_increase(owner: &str, chain_id: u128, wei: u128) -> Result<Vec<Entry>, String> {
    update_for(owner, |e| { let mut x = Entry::blank("in", chain_id, "received"); x.amount_eth = eth::format_eth(wei); e.push(x); })
}

fn set_status(e: &mut [Entry], hash: &str, status: &str, block: Option<u128>) {
    for x in e.iter_mut().filter(|x| x.is_hash(hash)) { x.status = status.into(); x.block = block; }
}

/// One transaction of a nonce group was mined: it gets its outcome, every other pending one with
/// the same chain and nonce is dropped (it can never be mined now).
pub fn settle(e: &mut [Entry], chain_id: u128, nonce: u128, mined_hash: &str, ok: bool, block: u128) {
    set_status(e, mined_hash, if ok { "confirmed" } else { "failed" }, Some(block));
    for x in e.iter_mut().filter(|x| x.kind == "out" && x.chain_id == chain_id && x.nonce == Some(nonce) && x.status == "pending" && !x.is_hash(mined_hash)) {
        x.status = "dropped".into();
    }
}

/// Check every pending transaction on this node's chain: mined ones get their outcome (and drop
/// the rest of their nonce group); ones whose nonce was used by a transaction not sent from here
/// are dropped. Returns true if anything changed.
pub fn reconcile(rpc: &eth::Rpc, chain_id: u128, owner: &str) -> Result<bool, String> {
    let pending: Vec<Entry> = list_for(owner)?.into_iter().filter(|x| x.kind == "out" && x.status == "pending" && x.chain_id == chain_id && x.hash.is_some()).collect();
    if pending.is_empty() { return Ok(false); }
    let mut outcomes: Vec<(u128, String, bool, u128)> = Vec::new();
    let mut unmined: Vec<(u128, String)> = Vec::new();
    for x in &pending {
        let (hash, nonce) = (x.hash.clone().unwrap_or_default(), x.nonce.unwrap_or(u128::MAX));
        match rpc.receipt_status(&hash).map_err(|e| e.0)? {
            Some((ok, block)) => outcomes.push((nonce, hash, ok, block)),
            None => unmined.push((nonce, hash)),
        }
    }
    // A nonce below the account's mined count with no receipt for any of ours: something else used it.
    let mined_count = if unmined.is_empty() { 0 } else { rpc.nonce_latest(owner).map_err(|e| e.0)? };
    let mut dropped: Vec<String> = Vec::new();
    for (nonce, hash) in &unmined {
        if *nonce < mined_count && !outcomes.iter().any(|o| o.0 == *nonce) {
            // ask once more: the receipt may have landed between the two calls
            if rpc.receipt_status(hash).map_err(|e| e.0)?.is_none() { dropped.push(hash.clone()); }
        }
    }
    if outcomes.is_empty() && dropped.is_empty() { return Ok(false); }
    update_for(owner, |e| {
        for (nonce, hash, ok, block) in &outcomes { settle(e, chain_id, *nonce, hash, *ok, *block); }
        for hash in &dropped { set_status(e, hash, "dropped", None); }
    })?;
    Ok(true)
}

#[tauri::command]
pub(crate) async fn history_list() -> CmdResult<Vec<Entry>> { blocking(list).await }

/// Record a receipt outcome for a transaction sent from here (and drop its nonce siblings).
#[tauri::command]
pub(crate) async fn history_mark(hash: String, status: String, block: Option<u128>) -> CmdResult<Vec<Entry>> {
    if !matches!(status.as_str(), "pending" | "confirmed" | "failed") { return Err("bad status".into()); }
    blocking(move || update(|e| {
        let group = e.iter().find(|x| x.is_hash(&hash)).and_then(|x| x.nonce.map(|n| (x.chain_id, n)));
        match (group, status.as_str(), block) {
            (Some((chain, nonce)), "confirmed" | "failed", Some(b)) => settle(e, chain, nonce, &hash, status == "confirmed", b),
            _ => set_status(e, &hash, &status, block),
        }
    })).await
}

/// Check pending transactions on the node's chain now (UI: after a speed-up, on opening Activity).
#[tauri::command]
pub(crate) async fn history_reconcile(rpc_url: String) -> CmdResult<Vec<Entry>> {
    blocking(move || {
        let owner = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let chain = rpc.chain_id().map_err(|e| e.0)?;
        reconcile(&rpc, chain, &owner)?;
        list()
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(hash: &str, nonce: u128) -> Entry {
        let mut x = Entry::blank("out", 8453, "pending");
        x.hash = Some(hash.into()); x.nonce = Some(nonce); x
    }

    #[test]
    fn settling_a_nonce_group_drops_the_siblings_only() {
        let mut e = vec![out("0xaa", 7), out("0xbb", 7), out("0xcc", 8), { let mut x = out("0xdd", 7); x.chain_id = 1; x }];
        settle(&mut e, 8453, 7, "0xBB", true, 100);
        assert_eq!(e[0].status, "dropped");
        assert_eq!((e[1].status.as_str(), e[1].block), ("confirmed", Some(100)));
        assert_eq!(e[2].status, "pending", "other nonce untouched");
        assert_eq!(e[3].status, "pending", "other chain untouched");
        // a reverted replacement still settles the group
        let mut e = vec![out("0xaa", 7), out("0xbb", 7)];
        settle(&mut e, 8453, 7, "0xaa", false, 5);
        assert_eq!((e[0].status.as_str(), e[1].status.as_str()), ("failed", "dropped"));
    }

    #[test]
    fn old_history_files_still_load() {
        let old = r#"[{"kind":"out","hash":"0x1","chain_id":8453,"counterparty":null,"amount_eth":"0.1","fee_max_eth":"0.0001","nonce":3,"time":1,"status":"pending","block":null}]"#;
        let e: Vec<Entry> = serde_json::from_str(old).unwrap();
        assert!(e[0].tx.is_none() && e[0].replaces.is_none() && e[0].log_index.is_none());
    }
}
