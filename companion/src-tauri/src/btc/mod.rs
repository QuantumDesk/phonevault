//! Bitcoin: a watch-only wallet on this Mac for keys that stay on the phone.
//!
//! * Pairing: `btcGetAccount` → strict check (`wallet.rs`) → the user has the phone show the first
//!   receive address (`btcShowAddress`) and compares it with the one derived here → stored
//!   (`store.rs`, 0600). Nothing is stored before that comparison.
//! * Balances/history: Esplora (`esplora.rs`, untrusted), gap-limit discovery (`scan.rs`).
//! * Send: coins checked against their previous transactions, coin selection and PSBT (`tx.rs`),
//!   `btcSignPsbt` on the phone, then `verify.rs` (same transaction, our keys, valid signatures,
//!   consensus) before the verified transaction is kept here by txid. Broadcast is a separate
//!   click and only broadcasts what was verified in this session; the UI never hands bytes back.
//!
//! Wire contract (all values strings; the phone validates strictly):
//! ```text
//! → {"id","method":"btcGetAccount","network","type","account"}
//! ← {"id","status":"ok","fingerprint","path","xpub","descriptor"}
//! → {"id","method":"btcShowAddress","network","type","account","change","index"}
//! ← {"id","status":"ok","address"}
//! → {"id","method":"btcSignPsbt","network","psbt"}
//! ← {"id","status":"approved","psbt"} | {"id","status":"rejected"} | {"id","status":"error","error"}
//! ```

pub mod esplora;
pub mod scan;
pub mod store;
pub mod tx;
pub mod verify;
pub mod wallet;
pub mod watch;

use crate::send_flow::{self, fail, SendError};
use crate::{aoa, blocking, CmdResult};
use bitcoin::{consensus, OutPoint, Transaction, Txid};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tauri::AppHandle;
use tx::Built;
use wallet::{Account, Kind, Net};

/// The phone may wait for unlock and the user's review.
const PHONE_TIMEOUT: Duration = Duration::from_secs(300);
/// The phone reads a btcSignPsbt line of up to 288 KiB (AccessoryTransport.MAX_PSBT_REQUEST_BYTES,
/// other requests 32 KiB); a little is kept for the newline.
pub(crate) const MAX_REQUEST_BYTES: usize = 288 * 1024 - 16;

struct Candidate {
    account: Account,
    shown_first: bool,
    at: Instant,
}

static CANDIDATES: LazyLock<Mutex<HashMap<String, Candidate>>> = LazyLock::new(Default::default);
static QUOTES: LazyLock<Mutex<HashMap<String, Built>>> = LazyLock::new(Default::default);
static VERIFIED: LazyLock<Mutex<HashMap<String, (Built, verify::Verified)>>> = LazyLock::new(Default::default);
static CANCELS: LazyLock<send_flow::Cancels> = LazyLock::new(Default::default);
static SCANS: LazyLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = LazyLock::new(Default::default);
/// Previous transactions already fetched and hashed (txid → tx), for coin checks and non_witness_utxo.
static PREV_TXS: LazyLock<Mutex<HashMap<String, Transaction>>> = LazyLock::new(Default::default);

fn lock<T>(m: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, String> {
    m.lock().map_err(|_| "state poisoned".to_string())
}

// ---------------------------------------------------------------- accounts

fn load_account(id: &str) -> Result<(store::StoredAccount, Account, Option<String>), String> {
    let all = store::load()?;
    let s = all.find(id).ok_or("that Bitcoin account is not paired with this Mac")?.clone();
    let a = s.account()?;
    let server = all.server(a.net);
    Ok((s, a, server))
}

fn client(net: Net, server: Option<&str>) -> Result<esplora::Client, String> {
    esplora::Client::new(net, server)
}

#[derive(Serialize)]
pub struct AccountView {
    id: String,
    network: Net,
    kind: Kind,
    kind_name: &'static str,
    account: u32,
    label: String,
    fingerprint: String,
    path: String,
    xpub: String,
    descriptor: String,
    active: bool,
    unit: &'static str,
    network_name: &'static str,
}

fn view(s: &store::StoredAccount, active: bool) -> AccountView {
    AccountView {
        id: s.id.clone(),
        network: s.network,
        kind: s.kind,
        kind_name: s.kind.name(),
        account: s.account,
        label: s.label.clone(),
        fingerprint: s.fingerprint.clone(),
        path: format!("m/{}", wallet::account_path(s.kind, s.network, s.account)).replace('\'', "h"),
        xpub: s.xpub.clone(),
        descriptor: s.descriptor.clone(),
        active,
        unit: s.network.unit(),
        network_name: s.network.name(),
    }
}

#[derive(Serialize)]
pub struct AccountsView {
    accounts: Vec<AccountView>,
    servers: BTreeMap<String, String>,
    defaults: BTreeMap<String, Vec<String>>,
}

#[tauri::command]
pub(crate) async fn btc_accounts() -> CmdResult<AccountsView> {
    blocking(|| {
        let p = store::load()?;
        let accounts = p.accounts.iter().map(|a| view(a, p.active.get(a.network.wire()) == Some(&a.id))).collect();
        let defaults = [Net::Bitcoin, Net::Testnet, Net::Signet]
            .iter()
            .map(|n| (n.wire().to_string(), esplora::defaults(*n).iter().map(ToString::to_string).collect()))
            .collect();
        Ok(AccountsView { accounts, servers: p.servers.clone(), defaults })
    })
    .await
}

fn phone_request(request: &Value, timeout: Duration) -> Result<Value, String> {
    let _turn = aoa::take_turn(|| {}, || false).map_err(|e| e.to_string())?;
    crate::attest::require_genuine().map_err(|m| m.trim_start_matches("attestation:").trim().to_string())?;
    let mut session = aoa::Session::connect().map_err(|e| e.to_string())?;
    session.exchange(request, timeout).map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct CandidateView {
    id: String,
    network: Net,
    kind: Kind,
    account: u32,
    fingerprint: String,
    path: String,
    xpub: String,
    descriptor: String,
    first_address: String,
    already_paired: bool,
    label: String,
}

/// Ask the phone for an account's xpub (the phone asks the user to approve sharing it the first
/// time). Nothing is stored: the candidate waits here until the first address is compared.
#[tauri::command]
pub(crate) async fn btc_read_account(network: String, kind: String, account: u32) -> CmdResult<CandidateView> {
    blocking(move || {
        let net = Net::parse(&network)?;
        let kind = Kind::parse(&kind)?;
        if !(1..=wallet::MAX_ACCOUNT).contains(&account) { return Err("account number must be 1 to 20".into()); }
        let request = json!({"id": uuid::Uuid::new_v4().to_string(), "method": "btcGetAccount", "network": net.wire(), "type": kind.wire(), "account": account.to_string()});
        let response = phone_request(&request, PHONE_TIMEOUT)?;
        let a = wallet::parse_account_response(&request, &response, net, kind, account)?;
        let first = a.derive(0, 0)?.address.to_string();
        let existing = store::load()?;
        let already = existing.find(&a.id());
        let label = already.map(|x| x.label.clone()).unwrap_or_else(|| store::default_label(&a));
        let v = CandidateView {
            id: a.id(), network: net, kind, account, fingerprint: a.fingerprint.to_string(), path: format!("m/{}", a.path()).replace('\'', "h"),
            xpub: a.xpub.to_string(), descriptor: a.descriptor(), first_address: first, already_paired: already.is_some(), label,
        };
        let mut c = lock(&CANDIDATES)?;
        c.retain(|_, x| x.at.elapsed() < Duration::from_secs(1800));
        c.insert(a.id(), Candidate { account: a, shown_first: false, at: Instant::now() });
        Ok(v)
    }).await
}

#[derive(Serialize)]
pub struct ShownAddress {
    address: String,
    expected: String,
    matches: bool,
}

/// Have the phone display one of the account's addresses (for a candidate being paired, or a
/// paired account's receive address) and compare it with the one derived here.
#[tauri::command]
pub(crate) async fn btc_show_address(id: String, change: u32, index: u32) -> CmdResult<ShownAddress> {
    blocking(move || {
        let candidate = lock(&CANDIDATES)?.get(&id).map(|c| c.account.clone());
        let a = match candidate { Some(a) => a, None => load_account(&id)?.1 };
        let expected = a.derive(change, index)?.address.to_string();
        let request = json!({"id": uuid::Uuid::new_v4().to_string(), "method": "btcShowAddress", "network": a.net.wire(), "type": a.kind.wire(),
            "account": a.number.to_string(), "change": change.to_string(), "index": index.to_string()});
        let response = phone_request(&request, PHONE_TIMEOUT)?;
        let address = wallet::parse_show_response(&request, &response)?;
        let matches = address == expected;
        if matches && change == 0 {
            if index == 0 { if let Some(c) = lock(&CANDIDATES)?.get_mut(&id) { c.shown_first = true; } }
            if store::load()?.find(&id).is_some() {
                store::update_cache(&id, |c| if !c.verified.contains(&index) { c.verified.push(index) })?;
            }
        }
        Ok(ShownAddress { address, expected, matches })
    }).await
}

/// Store an account read in this session, once its first receive address was shown on the phone
/// and matched (the user confirms that it is the same on both screens).
#[tauri::command]
pub(crate) async fn btc_confirm_account(id: String, label: Option<String>) -> CmdResult<AccountView> {
    blocking(move || {
        let c = lock(&CANDIDATES)?.remove(&id).ok_or("read the account from the phone again")?;
        if !c.shown_first {
            lock(&CANDIDATES)?.insert(id, c);
            return Err("show the first address on the phone and compare it first".into());
        }
        let p = store::add_in(&crate::pairing::dir()?, &c.account, label.as_deref())?;
        store::update_cache(&id, |x| {
            if !x.verified.contains(&0) {
                x.verified.push(0)
            }
        })?;
        watch::WAKE.store(true, Ordering::SeqCst);
        Ok(view(p.find(&id).ok_or("not stored")?, true))
    })
    .await
}

#[tauri::command]
pub(crate) async fn btc_select(id: String) -> CmdResult<()> {
    blocking(move || {
        store::modify(|p| {
            let n = p.find(&id).ok_or("that Bitcoin account is not paired")?.network;
            p.active.insert(n.wire().into(), id.clone());
            Ok(())
        })?;
        watch::WAKE.store(true, Ordering::SeqCst);
        Ok(())
    })
    .await
}

#[tauri::command]
pub(crate) async fn btc_rename(id: String, label: String) -> CmdResult<()> {
    blocking(move || {
        let l = crate::pairing::clean_label(&label).ok_or("the name is empty")?;
        store::modify(|p| {
            p.accounts.iter_mut().find(|a| a.id == id).ok_or("that Bitcoin account is not paired")?.label = l;
            Ok(())
        })
        .map(|_| ())
    })
    .await
}

/// Unpair (its cache file stays, like EVM history).
#[tauri::command]
pub(crate) async fn btc_forget(id: String) -> CmdResult<()> {
    blocking(move || store::remove_in(&crate::pairing::dir()?, &id).map(|_| ())).await
}

#[tauri::command]
pub(crate) async fn btc_set_server(network: String, url: Option<String>) -> CmdResult<()> {
    blocking(move || {
        let net = Net::parse(&network)?;
        let url = match url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            Some(u) => Some(esplora::check_server(u)?),
            None => None,
        };
        store::modify(|p| {
            match url {
                Some(u) => {
                    p.servers.insert(net.wire().into(), u);
                }
                None => {
                    p.servers.remove(net.wire());
                }
            }
            Ok(())
        })?;
        watch::WAKE.store(true, Ordering::SeqCst);
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------- wallet view and refresh

#[derive(Serialize, Clone)]
pub struct HistoryView {
    txid: String,
    net_sats: i64,
    fee_sats: Option<u64>,
    status: String,
    confirmations: u64,
    time: u64,
    counterparty: Option<String>,
    explorer: String,
    can_bump: bool,
    sent_here: bool,
}

#[derive(Serialize)]
pub struct WalletView {
    id: String,
    network: Net,
    unit: &'static str,
    confirmed_sats: u64,
    unconfirmed_sats: i64,
    receive_address: String,
    receive_index: u32,
    receive_verified: bool,
    history: Vec<HistoryView>,
    scanned_at: u64,
    error: Option<String>,
    server: String,
    used_addresses: usize,
}

fn wallet_view(id: &str, a: &Account, server: Option<&str>, c: &store::Cache) -> Result<WalletView, String> {
    let r = c.next[0];
    let tip = c.tip.unwrap_or(0);
    let mut history: Vec<HistoryView> = c
        .history
        .iter()
        .map(|e| {
            let sent = c.sent.iter().find(|s| s.txid == e.txid);
            HistoryView {
                txid: e.txid.clone(),
                net_sats: e.net,
                fee_sats: e.fee,
                status: e.status.clone(),
                confirmations: e.height.map_or(0, |h| tip.saturating_sub(h) + 1),
                time: e.time,
                counterparty: e.counterparty.clone(),
                explorer: esplora::explorer_tx(a.net, &e.txid),
                can_bump: e.status == "pending" && sent.is_some_and(|s| s.change.is_some()),
                sent_here: sent.is_some(),
            }
        })
        .collect();
    // sent from here but not seen by the server yet
    for s in c.sent.iter().filter(|s| !c.history.iter().any(|e| e.txid == s.txid)) {
        if crate::history::now().saturating_sub(s.time) > 86400 * 3 {
            continue;
        }
        history.push(HistoryView {
            txid: s.txid.clone(),
            net_sats: -((s.amount + s.fee) as i64),
            fee_sats: Some(s.fee),
            status: "pending".into(),
            confirmations: 0,
            time: s.time,
            counterparty: Some(s.recipient.clone()),
            explorer: esplora::explorer_tx(a.net, &s.txid),
            can_bump: s.change.is_some(),
            sent_here: true,
        });
    }
    history.sort_by_key(|x| std::cmp::Reverse(x.time));
    Ok(WalletView {
        id: id.to_string(),
        network: a.net,
        unit: a.net.unit(),
        confirmed_sats: c.confirmed(),
        unconfirmed_sats: c.unconfirmed(),
        receive_address: a.derive(0, r)?.address.to_string(),
        receive_index: r,
        receive_verified: c.verified.contains(&r),
        history,
        scanned_at: c.scanned_at,
        error: c.error.clone(),
        server: client(a.net, server).map(|c| c.host()).unwrap_or_default(),
        used_addresses: c.addrs.len(),
    })
}

/// The cached state (no network).
#[tauri::command]
pub(crate) async fn btc_wallet(id: String) -> CmdResult<WalletView> {
    blocking(move || {
        let (_, a, server) = load_account(&id)?;
        wallet_view(&id, &a, server.as_deref(), &store::load_cache(&id)?)
    })
    .await
}

/// Scan now (one scan per account at a time). Returns the new incoming payments.
pub fn refresh(id: &str, full: bool) -> Result<(Vec<store::Entry>, store::Cache), String> {
    let (_, a, server) = load_account(id)?;
    let gate = lock(&SCANS)?.entry(id.to_string()).or_default().clone();
    let _g = gate.lock().map_err(|_| "scan lock poisoned")?;
    let c = client(a.net, server.as_deref())?;
    let mut cache = store::load_cache(id)?;
    let now = crate::history::now();
    let full = full || now.saturating_sub(cache.full_scan_at) > 1800;
    let result = scan::scan(&a, &c, &mut cache, full, now);
    let tip = c.tip().ok();
    let (incoming, cache) = store::update_cache(id, |stored| {
        match result {
            Ok(inc) => {
                // keep what other paths wrote meanwhile: verified indices, sends, a change index a
                // broadcast just used (indices only move forward)
                let verified = std::mem::take(&mut stored.verified);
                let sent = std::mem::take(&mut stored.sent);
                let next = stored.next;
                *stored = cache;
                stored.verified = verified;
                stored.sent = sent;
                for (s, n) in stored.next.iter_mut().zip(next) {
                    *s = (*s).max(n);
                }
                if let Some(t) = tip {
                    stored.tip = Some(t);
                }
                Ok(inc)
            }
            Err(e) => {
                stored.error = Some(e.clone());
                Err(e)
            }
        }
    })?;
    Ok((incoming?, cache))
}

#[tauri::command]
pub(crate) async fn btc_refresh(id: String, full: Option<bool>) -> CmdResult<WalletView> {
    blocking(move || {
        let (_, a, server) = load_account(&id)?;
        match refresh(&id, full.unwrap_or(true)) {
            Ok((_, c)) => wallet_view(&id, &a, server.as_deref(), &c),
            Err(e) => {
                let mut v = wallet_view(&id, &a, server.as_deref(), &store::load_cache(&id)?)?;
                v.error = Some(e);
                Ok(v)
            }
        }
    })
    .await
}

// ---------------------------------------------------------------- send

#[derive(Serialize)]
pub struct AddressCheck {
    ok: bool,
    error: Option<String>,
    own: bool,
    kind: Option<&'static str>,
}

#[tauri::command]
pub(crate) async fn btc_check_address(id: String, address: String) -> CmdResult<AddressCheck> {
    blocking(move || {
        let (_, a, _) = load_account(&id)?;
        Ok(match wallet::parse_recipient(&address, a.net) {
            Err(e) => AddressCheck { ok: false, error: Some(e), own: false, kind: None },
            Ok(addr) => {
                let kind = match addr.address_type() {
                    Some(bitcoin::AddressType::P2wpkh) => Some("Native SegWit"),
                    Some(bitcoin::AddressType::P2tr) => Some("Taproot"),
                    Some(bitcoin::AddressType::P2pkh) => Some("Legacy"),
                    Some(bitcoin::AddressType::P2sh) => Some("Script (P2SH)"),
                    Some(bitcoin::AddressType::P2wsh) => Some("SegWit script"),
                    _ => None,
                };
                AddressCheck { ok: true, error: None, own: is_own(&a, &addr.to_string())?, kind }
            }
        })
    })
    .await
}

/// One of this account's addresses (any used one, or within the next 20 on either chain).
fn is_own(a: &Account, addr: &str) -> Result<bool, String> {
    let c = store::load_cache(&a.id())?;
    if c.addrs.contains_key(addr) {
        return Ok(true);
    }
    for chain in 0..=1u32 {
        for i in c.next[chain as usize]..c.next[chain as usize] + scan::GAP {
            if a.derive(chain, i)?.address.to_string() == addr {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[derive(Serialize)]
pub struct Fees {
    fast: f64,
    normal: f64,
    slow: f64,
    server: String,
}

fn round_up_tenth(v: f64) -> f64 {
    (v * 10.0).ceil() / 10.0
}

#[tauri::command]
pub(crate) async fn btc_fees(id: String) -> CmdResult<Fees> {
    blocking(move || {
        let (_, a, server) = load_account(&id)?;
        let c = client(a.net, server.as_deref())?;
        let f = c.fees()?;
        let pick = |t| round_up_tenth(esplora::rate_for(&f, t).unwrap_or(1.0)).max(1.0);
        Ok(Fees { fast: pick(1), normal: pick(6), slow: pick(144), server: c.host() })
    })
    .await
}

/// A coin as the server lists it, accepted only if its previous transaction (hashed here to the
/// txid) pays exactly that value to exactly this address.
fn checked_coin(c: &esplora::Client, u: &esplora::Utxo, d: &wallet::Derived) -> Result<tx::Coin, String> {
    let cached = lock(&PREV_TXS)?.get(&u.txid).cloned();
    let prev = match cached {
        Some(t) => t,
        None => {
            let bytes = hex::decode(c.tx_hex(&u.txid)?).map_err(|_| "server: bad hex")?;
            let t: Transaction =
                consensus::deserialize(&bytes).map_err(|_| "server: transaction does not parse".to_string())?;
            if t.compute_txid().to_string() != u.txid {
                return Err("server sent a transaction that does not hash to the txid it was asked for".into());
            }
            let mut m = lock(&PREV_TXS)?;
            if m.len() > 2000 {
                m.clear();
            }
            m.insert(u.txid.clone(), t.clone());
            t
        }
    };
    let out = prev.output.get(u.vout as usize).ok_or("server: the coin's output does not exist")?;
    if out.value.to_sat() != u.value || out.script_pubkey != d.script {
        return Err("server: a coin's amount or address does not match its transaction".into());
    }
    Ok(tx::Coin {
        outpoint: OutPoint { txid: Txid::from_str(&u.txid).map_err(|e| e.to_string())?, vout: u.vout },
        value: u.value,
        derived: d.clone(),
        confirmed: u.status.confirmed,
        prev_tx: Some(prev),
    })
}

fn spendable(a: &Account, c: &esplora::Client, cache: &store::Cache) -> Result<Vec<tx::Coin>, String> {
    let mut coins = Vec::new();
    for (addr, s) in cache.addrs.iter().filter(|(_, s)| s.confirmed > 0 || s.mempool > 0) {
        let d = a.derive(s.chain, s.index)?;
        if d.address.to_string() != *addr {
            return Err("internal: address cache mismatch".into());
        }
        for u in c.utxos(addr)? {
            coins.push(checked_coin(c, &u, &d)?);
        }
    }
    Ok(coins)
}

#[derive(Serialize)]
pub struct OutView {
    address: String,
    sats: u64,
    change: bool,
    path: Option<String>,
}
#[derive(Serialize)]
pub struct InView {
    outpoint: String,
    sats: u64,
    address: String,
    confirmed: bool,
}

#[derive(Serialize)]
pub struct QuoteView {
    quote_id: String,
    network: Net,
    unit: &'static str,
    recipient: String,
    amount_sats: u64,
    fee_sats: u64,
    vsize: u64,
    rate: String,
    total_sats: u64,
    change_sats: u64,
    inputs: Vec<InView>,
    outputs: Vec<OutView>,
    replaces: Option<String>,
    own_recipient: bool,
    unconfirmed_inputs: bool,
    balance_sats: u64,
    sequence: String,
}

fn quote_view(id: String, b: &Built, own: bool) -> QuoteView {
    QuoteView {
        quote_id: id,
        network: b.account.net,
        unit: b.account.net.unit(),
        recipient: b.recipient.to_string(),
        amount_sats: b.amount,
        fee_sats: b.fee,
        vsize: b.vsize,
        rate: format!("{:.1}", b.rate_kvb as f64 / 1000.0),
        total_sats: b.amount + b.fee,
        change_sats: b.change().map_or(0, |c| c.value),
        inputs: b
            .inputs
            .iter()
            .map(|c| InView {
                outpoint: format!("{}:{}", c.outpoint.txid, c.outpoint.vout),
                sats: c.value,
                address: c.derived.address.to_string(),
                confirmed: c.confirmed,
            })
            .collect(),
        outputs: b
            .outputs
            .iter()
            .map(|o| OutView {
                address: o.address.to_string(),
                sats: o.value,
                change: o.change.is_some(),
                path: o.change.as_ref().map(|d| format!("m/{}", d.origin).replace('\'', "h")),
            })
            .collect(),
        replaces: b.replaces.clone(),
        own_recipient: own,
        unconfirmed_inputs: b.inputs.iter().any(|c| !c.confirmed),
        balance_sats: b.input_total(),
        sequence: format!("0x{:08x} (replaceable)", tx::RBF_SEQUENCE),
    }
}

fn keep_quote(b: Built) -> Result<String, String> {
    let id = uuid::Uuid::new_v4().to_string();
    let mut q = lock(&QUOTES)?;
    if q.len() > 50 {
        q.clear();
    }
    q.insert(id.clone(), b);
    Ok(id)
}

/// Build a send: refresh, check the coins against their transactions, select, build the PSBT.
/// `amount` in BTC (exact decimal); `max` sends everything (no change).
#[tauri::command]
pub(crate) async fn btc_quote(
    id: String,
    to: String,
    amount: Option<String>,
    max: bool,
    fee_rate: String,
) -> CmdResult<QuoteView> {
    blocking(move || {
        let (_, a, server) = load_account(&id)?;
        let recipient = wallet::parse_recipient(&to, a.net)?;
        let rate = tx::parse_rate(&fee_rate)?;
        let amount = if max { None } else { Some(tx::parse_btc(amount.as_deref().ok_or("enter an amount")?)?) };
        if amount == Some(0) {
            return Err("amount must be more than zero".into());
        }
        let (_, cache) = refresh(&id, false)?;
        let c = client(a.net, server.as_deref())?;
        let coins = spendable(&a, &c, &cache)?;
        if coins.is_empty() {
            return Err("no spendable coins".into());
        }
        let change = a.derive(1, cache.next[1])?;
        let own = is_own(&a, &recipient.to_string())?;
        let b = tx::plan(&a, coins, recipient, amount, change, rate, true)?;
        let v = quote_view(String::new(), &b, own);
        Ok(QuoteView { quote_id: keep_quote(b)?, ..v })
    })
    .await
}

/// Speed up a pending transaction sent from here (RBF): same inputs and recipient, higher fee from the change.
#[tauri::command]
pub(crate) async fn btc_bump_quote(id: String, txid: String, fee_rate: String) -> CmdResult<QuoteView> {
    blocking(move || {
        let (_, a, server) = load_account(&id)?;
        let rate = tx::parse_rate(&fee_rate)?;
        let cache = store::load_cache(&id)?;
        let s = cache
            .sent
            .iter()
            .find(|s| s.txid == txid)
            .ok_or("only transactions sent from this Mac can be sped up here")?
            .clone();
        let c = client(a.net, server.as_deref())?;
        if c.tx_status(&txid).is_ok_and(|st| st.confirmed) {
            return Err("it is already confirmed".into());
        }
        if rate <= s.rate_kvb {
            return Err(format!("choose a fee rate above the current {:.1} sat/vB", s.rate_kvb as f64 / 1000.0));
        }
        let mut inputs = Vec::new();
        for (t, vout, value, chain, index) in &s.inputs {
            let d = a.derive(*chain, *index)?;
            let u = esplora::Utxo { txid: t.clone(), vout: *vout, value: *value, status: Default::default() };
            let mut coin = checked_coin(&c, &u, &d)?;
            coin.confirmed = true;
            inputs.push(coin);
        }
        let recipient = wallet::parse_recipient(&s.recipient, a.net)?;
        let (ci, cv) = s.change.ok_or("this transaction has no change output to take a higher fee from")?;
        let change = a.derive(1, ci)?;
        let old = tx::build(&a, inputs, recipient, s.amount, Some((change, cv)), s.fee, s.rate_kvb, s.vsize, false)?;
        let mut b = tx::bump(&old, rate)?;
        b.replaces = Some(txid.clone());
        let v = quote_view(String::new(), &b, false);
        Ok(QuoteView { quote_id: keep_quote(b)?, ..v })
    })
    .await
}

#[derive(Serialize)]
pub struct SignedView {
    txid: String,
    fee_sats: u64,
    vsize: u64,
    rate: String,
    amount_sats: u64,
    recipient: String,
    explorer: String,
    checks: Vec<String>,
}

/// Hand the PSBT to the phone, wait for the user's review there, verify what comes back.
#[tauri::command]
pub(crate) async fn btc_sign_start(app: AppHandle, ticket: String, quote_id: String) -> Result<SignedView, SendError> {
    let (flow, guard) = send_flow::start(&CANCELS, app, ticket)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let built = QUOTES.lock().map_err(|_| fail("internal", "state poisoned", false))?.get(&quote_id).cloned()
            .ok_or_else(|| fail("internal", "this quote expired; review the send again", false))?;
        let _turn = flow.take_turn()?;
        // Unlike the ETH flow, "a device check is already running" stays `connect` here.
        crate::attest::require_genuine().map_err(send_flow::gate_failure)?;
        flow.check_cancelled()?;
        let request = json!({"id": uuid::Uuid::new_v4().to_string(), "method": "btcSignPsbt", "network": built.account.net.wire(), "psbt": verify::psbt_base64(&built.psbt)});
        if serde_json::to_vec(&request).map(|v| v.len()).unwrap_or(usize::MAX) > MAX_REQUEST_BYTES { return Err(fail("internal", "the transaction is too large for one request to the phone", false)); }
        let response = flow.exchange(&request, PHONE_TIMEOUT)?;
        let b64 = verify::parse_sign_response(&request, &response).map_err(|m| {
            if m == "rejected on the phone" { fail("rejected", m, true) }
            else if let Some(x) = m.strip_prefix("phone error:") { fail("phone_error", x.trim().to_string(), true) }
            else { fail("protocol", m, true) }
        })?;
        let v = verify::verify_signed(&built, &b64).map_err(|m| fail("verify", m, true))?;
        let checks = vec![
            format!("Same transaction as reviewed: {} input{}, {} output{}, recipient and amount unchanged", built.inputs.len(), if built.inputs.len() == 1 { "" } else { "s" }, built.outputs.len(), if built.outputs.len() == 1 { "" } else { "s" }),
            format!("Fee exactly {} sat (inputs − outputs, amounts from this Mac's records)", v.fee),
            match built.account.kind { Kind::P2wpkh => "Every input signed by this wallet's key for that address (ECDSA, SIGHASH_ALL)".to_string(), Kind::P2tr => "Every input signed by this wallet's Taproot key for that address (Schnorr, SIGHASH_DEFAULT)".to_string() },
            "Each input verified by Bitcoin Core's script interpreter (libbitcoinconsensus)".to_string(),
        ];
        let view = SignedView { txid: v.txid.clone(), fee_sats: v.fee, vsize: v.vsize, rate: format!("{:.1}", v.fee as f64 / v.vsize as f64), amount_sats: built.amount,
            recipient: built.recipient.to_string(), explorer: esplora::explorer_tx(built.account.net, &v.txid), checks };
        VERIFIED.lock().map_err(|_| fail("internal", "state poisoned", true))?.insert(v.txid.clone(), (built, v));
        Ok(view)
    }).await.map_err(|e| fail("internal", e.to_string(), false))?
}

#[tauri::command]
pub(crate) fn btc_sign_cancel(ticket: Option<String>) {
    send_flow::cancel(&CANCELS, ticket.as_deref());
}

/// Broadcast a transaction verified in this session, by txid. Records it for history and speed-up.
#[tauri::command]
pub(crate) async fn btc_broadcast(txid: String) -> CmdResult<String> {
    blocking(move || {
        let (built, v) = lock(&VERIFIED)?
            .get(&txid)
            .cloned()
            .ok_or("this transaction was not verified in this session, so it will not be broadcast")?;
        let id = built.account.id();
        let (_, _, server) = load_account(&id)?;
        let c = client(built.account.net, server.as_deref())?;
        let sent = match c.broadcast(&v.hex) {
            Ok(t) => t,
            Err(e)
                if e.contains("already in block chain")
                    || e.contains("txn-already-known")
                    || e.contains("txn-already-in-mempool") =>
            {
                v.txid.clone()
            }
            Err(e) => return Err(e),
        };
        if sent != v.txid {
            return Err(format!("the server answered with txid {sent}, expected {}", v.txid));
        }
        let change = built.change().and_then(|o| o.change.as_ref().map(|d| (d.index, o.value)));
        let inputs = built
            .inputs
            .iter()
            .map(|c| (c.outpoint.txid.to_string(), c.outpoint.vout, c.value, c.derived.chain, c.derived.index))
            .collect();
        store::update_cache(&id, |cache| {
            if !cache.sent.iter().any(|s| s.txid == v.txid) {
                cache.sent.push(store::Sent {
                    txid: v.txid.clone(),
                    time: crate::history::now(),
                    recipient: built.recipient.to_string(),
                    amount: built.amount,
                    fee: v.fee,
                    vsize: built.vsize,
                    rate_kvb: built.rate_kvb,
                    inputs,
                    change,
                    replaces: built.replaces.clone(),
                });
            }
            // the change index is now used: the next send uses the next one
            if let Some((i, _)) = change {
                cache.next[1] = cache.next[1].max(i + 1);
            }
        })?;
        lock(&VERIFIED)?.remove(&txid);
        watch::WAKE.store(true, Ordering::SeqCst);
        Ok(v.txid)
    })
    .await
}

#[derive(Serialize)]
pub struct TxState {
    confirmed: bool,
    confirmations: u64,
    height: Option<u64>,
}

#[tauri::command]
pub(crate) async fn btc_tx_status(id: String, txid: String) -> CmdResult<TxState> {
    blocking(move || {
        let (_, a, server) = load_account(&id)?;
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("bad txid".into());
        }
        let c = client(a.net, server.as_deref())?;
        let st = c.tx_status(&txid)?;
        let h = st.block_height.filter(|_| st.confirmed);
        let conf = match h {
            Some(h) => c.tip().map(|t| t.saturating_sub(h) + 1).unwrap_or(1),
            None => 0,
        };
        Ok(TxState { confirmed: st.confirmed, confirmations: conf, height: h })
    })
    .await
}

// ---------------------------------------------------------------- export (Sparrow and others)

#[derive(Serialize)]
pub struct Export {
    descriptor: String,
    receive: String,
    change: String,
    fingerprint: String,
    path: String,
    xpub: String,
    text: String,
}

fn export_for(s: &store::StoredAccount, a: &Account) -> Export {
    let path = format!("m/{}", a.path()).replace('\'', "h");
    let text = format!(
        "Phone Vault — watch-only Bitcoin wallet\n{}\n\nNetwork: {}\nScript type: {} ({})\nMaster fingerprint: {}\nDerivation: {}\nAccount xpub: {}\n\nOutput descriptor (Sparrow: File → New Wallet → Import → Output Descriptor):\n{}\n\nReceive: {}\nChange:  {}\n\nThis file holds no private key. Anyone with it can see this account's addresses, balance and history.\n",
        s.label, a.net.name(), a.kind.name(), if a.kind == Kind::P2tr { "BIP-86" } else { "BIP-84" }, a.fingerprint, path, a.xpub, a.descriptor(), a.chain_descriptor(0), a.chain_descriptor(1));
    Export {
        descriptor: a.descriptor(),
        receive: a.chain_descriptor(0),
        change: a.chain_descriptor(1),
        fingerprint: a.fingerprint.to_string(),
        path,
        xpub: a.xpub.to_string(),
        text,
    }
}

#[tauri::command]
pub(crate) async fn btc_export(id: String) -> CmdResult<Export> {
    blocking(move || {
        let (s, a, _) = load_account(&id)?;
        Ok(export_for(&s, &a))
    })
    .await
}

/// Save the export as a .txt in Downloads (never overwriting) and return its path.
#[tauri::command]
pub(crate) async fn btc_save_export(id: String) -> CmdResult<String> {
    blocking(move || {
        let (s, a, _) = load_account(&id)?;
        let dir = dirs::download_dir().ok_or("no Downloads folder")?;
        let stem: String = s
            .label
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .trim_matches('-')
            .to_string();
        for n in 0..100 {
            let name = if n == 0 {
                format!("phone-vault-{stem}-watch-only.txt")
            } else {
                format!("phone-vault-{stem}-watch-only-{n}.txt")
            };
            let p = dir.join(name);
            use std::io::Write;
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&p) {
                Ok(mut f) => {
                    f.write_all(export_for(&s, &a).text.as_bytes()).map_err(|e| e.to_string())?;
                    return Ok(p.display().to_string());
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("could not pick a file name".into())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet::tests::account as test_account;

    #[test]
    fn export_text_names_everything_sparrow_needs() {
        let (a, _) = test_account(Net::Bitcoin, Kind::P2wpkh, 1);
        let s = store::StoredAccount::from_account(&a, "Bitcoin 1");
        let e = export_for(&s, &a);
        assert!(e.text.contains("73c5da0a") && e.text.contains("m/84h/0h/0h") && e.text.contains(&a.descriptor()));
        assert!(e.receive.contains("/0/*)#") && e.change.contains("/1/*)#"));
        assert!(!e.text.to_lowercase().contains("xprv"));
    }

    #[test]
    fn requests_follow_the_wire_contract() {
        // every value a string, exactly these fields
        let (a, _) = test_account(Net::Signet, Kind::P2tr, 2);
        let r = json!({"id": "x", "method": "btcShowAddress", "network": a.net.wire(), "type": a.kind.wire(), "account": a.number.to_string(), "change": "0", "index": "5"});
        assert!(r.as_object().unwrap().values().all(Value::is_string));
        assert_eq!(r["network"], "signet");
        assert_eq!(r["type"], "p2tr");
    }
}
