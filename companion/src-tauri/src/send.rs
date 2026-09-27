//! The send flow behind the redesigned UI. Same request, same verifier and same pinned signer as
//! the original `sign`/`broadcast` commands, with three differences the UI needs to be honest:
//!
//! * progress events (`send-progress`) say when the phone was reached and when the request was
//!   actually delivered, so "Review on your phone" is only shown once it is true;
//! * the wait can be cancelled from the Mac;
//! * the verified transaction stays here. The UI broadcasts by hash, and only a transaction that
//!   `verify::validate_signature` accepted in this session, for exactly the quoted fields, can be
//!   sent to a node. The UI never hands raw bytes back to Rust.

use crate::{aoa, blocking, eth, history, pairing, verify, CmdResult, Quote};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter, State};

/// How long the phone may take between receiving the request and answering (unlock + review).
const REVIEW_TIMEOUT: Duration = Duration::from_secs(300);

struct VerifiedTx { raw: String, chain_id: u128, to: String, value_wei: u128, max_fee_wei: u128, nonce: u128 }

#[derive(Default)]
pub struct SendState {
    cancel: Arc<AtomicBool>,
    busy: Arc<AtomicBool>,
    verified: Arc<Mutex<HashMap<String, VerifiedTx>>>,
}

/// A failure the UI can explain: `kind` picks the plain-language text, `message` is the detail.
#[derive(Serialize, Debug)]
pub struct SendError { kind: &'static str, message: String, delivered: bool }
fn fail(kind: &'static str, message: impl Into<String>, delivered: bool) -> SendError { SendError { kind, message: message.into(), delivered } }

#[derive(Serialize, Clone)]
struct Progress { ticket: String, stage: &'static str }

#[derive(Serialize)]
pub struct Signed { hash: String, signer: String }

/// Clears the busy flag however the command ends.
struct BusyGuard(Arc<AtomicBool>);
impl Drop for BusyGuard { fn drop(&mut self) { self.0.store(false, Ordering::SeqCst); } }

fn q(v: &str, what: &str) -> Result<u128, SendError> { verify::quantity(v).map_err(|e| fail("internal", format!("{what}: {e}"), false)) }

#[tauri::command]
pub(crate) async fn sign_start(app: AppHandle, state: State<'_, SendState>, ticket: String, quote: Quote) -> Result<Signed, SendError> {
    if state.busy.swap(true, Ordering::SeqCst) { return Err(fail("busy", "another request is already waiting for the phone", false)); }
    let guard = BusyGuard(state.busy.clone());
    state.cancel.store(false, Ordering::SeqCst);
    let cancel = state.cancel.clone();
    let store = state.verified.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let emit = |stage: &'static str| { let _ = app.emit("send-progress", Progress { ticket: ticket.clone(), stage }); };
        let pinned = pairing::load().map_err(|e| fail("not_paired", e.0, false))?.ok_or_else(|| fail("not_paired", "not paired yet", false))?;
        // Exactly the request the original `sign` command builds.
        let request = json!({
            "id": uuid::Uuid::new_v4().to_string(), "method": "signEip1559",
            "chainId": quote.chain_id, "nonce": quote.nonce, "maxPriorityFeePerGas": quote.max_priority_fee_per_gas,
            "maxFeePerGas": quote.max_fee_per_gas, "gasLimit": quote.gas_limit, "to": quote.to, "value": quote.value, "data": quote.data,
        });
        emit("connecting");
        let mut session = aoa::Session::connect().map_err(|e| match e {
            aoa::AoaError::NoDevice => fail("no_phone", e.to_string(), false),
            aoa::AoaError::Protocol(ref m) if m.contains("held by another program") => fail("usb_busy", e.to_string(), false),
            other => fail("connect", other.to_string(), false),
        })?;
        if cancel.load(Ordering::SeqCst) { return Err(fail("cancelled", aoa::CANCELLED, false)); }
        let delivered = AtomicBool::new(false);
        let response = session.exchange_observed(
            &request, REVIEW_TIMEOUT,
            || { delivered.store(true, Ordering::SeqCst); emit("delivered"); },
            || cancel.load(Ordering::SeqCst),
        ).map_err(|e| {
            let d = delivered.load(Ordering::SeqCst);
            match e {
                aoa::AoaError::Protocol(ref m) if m == aoa::CANCELLED => fail("cancelled", m.clone(), d),
                aoa::AoaError::Timeout(_) => fail("timeout", e.to_string(), d),
                aoa::AoaError::Usb(_) => fail("disconnected", e.to_string(), d),
                other if !d => fail("not_delivered", other.to_string(), d),
                other => fail("protocol", other.to_string(), d),
            }
        })?;
        drop(session);
        emit("verifying");
        let v = verify::validate_signature(&request, &response, &pinned).map_err(|e| {
            let m = e.0;
            if m == "rejected on the phone" { fail("rejected", m, true) }
            else if m.starts_with("phone error:") { fail("phone_error", m.trim_start_matches("phone error:").trim().to_string(), true) }
            else { fail("verify", m, true) }
        })?;
        let gas = q(&quote.gas_limit, "gasLimit")?;
        let max_fee = q(&quote.max_fee_per_gas, "maxFeePerGas")?;
        let tx = VerifiedTx {
            raw: v.raw_hex, chain_id: q(&quote.chain_id, "chainId")?, to: verify::checksum(&quote.to),
            value_wei: q(&quote.value, "value")?, max_fee_wei: gas.saturating_mul(max_fee), nonce: q(&quote.nonce, "nonce")?,
        };
        store.lock().map_err(|_| fail("internal", "state poisoned", true))?.insert(v.tx_hash.to_ascii_lowercase(), tx);
        Ok(Signed { hash: v.tx_hash, signer: verify::checksum(&v.signer) })
    }).await.map_err(|e| fail("internal", e.to_string(), false))?
}

/// Stop waiting for the phone. The phone may still show the request; the user rejects it there.
#[tauri::command]
pub(crate) fn sign_cancel(state: State<'_, SendState>) { state.cancel.store(true, Ordering::SeqCst); }

/// Broadcast a transaction this session verified, by hash. Records it in the local history.
#[tauri::command]
pub(crate) async fn broadcast_verified(state: State<'_, SendState>, rpc_url: String, hash: String) -> CmdResult<String> {
    let store = state.verified.clone();
    blocking(move || {
        let key = hash.to_ascii_lowercase();
        let (raw, chain_id, to, value_wei, max_fee_wei, nonce) = {
            let map = store.lock().map_err(|_| "state poisoned".to_string())?;
            let tx = map.get(&key).ok_or("this transaction was not verified in this session, so it will not be broadcast")?;
            (tx.raw.clone(), tx.chain_id, tx.to.clone(), tx.value_wei, tx.max_fee_wei, tx.nonce)
        };
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let node_chain = rpc.chain_id().map_err(|e| e.0)?;
        if node_chain != chain_id { return Err(format!("the selected node is on chain {node_chain}, but this transaction is for chain {chain_id}; switch back to that network")); }
        let sent = rpc.send_raw(&raw).map_err(|e| e.0)?;
        if sent.to_ascii_lowercase() != key { return Err(format!("node returned hash {sent}, expected {hash}")); }
        let _ = history::record_sent(&hash, chain_id, &to, value_wei, max_fee_wei, nonce);
        Ok(hash)
    }).await
}

#[derive(Serialize)]
pub struct FeeEstimate { chain_id: u128, gas: u128, typical_fee_wei: String, typical_fee_eth: String, max_fee_wei: String, max_fee_eth: String }

/// Fee for a plain transfer at current prices: typical (base + tip) and the ceiling the phone signs.
#[tauri::command]
pub(crate) async fn fee_estimate(rpc_url: String) -> CmdResult<FeeEstimate> {
    blocking(move || {
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let chain_id = rpc.chain_id().map_err(|e| e.0)?;
        let (priority, max_fee) = rpc.fees().map_err(|e| e.0)?;
        let base = max_fee.saturating_sub(priority) / 2; // fees() = 2 × base + priority
        let gas = 21_000u128;
        let typical = gas * (base + priority);
        let ceiling = gas * max_fee;
        Ok(FeeEstimate { chain_id, gas, typical_fee_wei: typical.to_string(), typical_fee_eth: eth::format_eth(typical), max_fee_wei: ceiling.to_string(), max_fee_eth: eth::format_eth(ceiling) })
    }).await
}

#[derive(Serialize)]
pub struct MaxAmount { amount_eth: String, amount_wei: String }

/// The largest amount the quote will accept: balance − gas × maxFee with headroom for fee drift,
/// and on rollups a small reserve for the L1 data fee nobody can bound in advance.
#[tauri::command]
pub(crate) async fn max_sendable(rpc_url: String, to: Option<String>) -> CmdResult<MaxAmount> {
    blocking(move || {
        let from = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let chain = rpc.chain_id().map_err(|e| e.0)?;
        let balance = rpc.balance(&from).map_err(|e| e.0)?;
        let (_, max_fee) = rpc.fees().map_err(|e| e.0)?;
        let gas = match to.as_deref().map(str::trim) {
            Some(t) if t.len() == 42 && t.starts_with("0x") && t[2..].bytes().all(|b| b.is_ascii_hexdigit()) => rpc.estimate_gas(&from, t, 1).unwrap_or(21_000).max(21_000),
            _ => 21_000,
        };
        let cost = gas.saturating_mul(max_fee).saturating_mul(5) / 4;
        let l1_reserve: u128 = if matches!(chain, 8453 | 10 | 42161) { 50_000_000_000_000 } else { 0 }; // 0.00005 ETH
        let amount = balance.saturating_sub(cost).saturating_sub(l1_reserve);
        // round down to what format_eth shows (8 decimals) so the field and the quote agree
        let shown = eth::parse_eth(&eth::format_eth(amount)).map_err(|e| e.0)?;
        Ok(MaxAmount { amount_eth: eth::format_eth(shown), amount_wei: shown.to_string() })
    }).await
}

#[derive(Serialize)]
pub struct AddressCheck { ok: bool, checksum: Option<String>, error: Option<String> }

/// Same recipient rules as `quote`, for live feedback while typing.
#[tauri::command]
pub(crate) fn check_address(address: String) -> AddressCheck {
    let a = address.trim();
    let bad = |m: &str| AddressCheck { ok: false, checksum: None, error: Some(m.into()) };
    if !a.starts_with("0x") { return bad("An address starts with 0x"); }
    if a.len() != 42 || !a[2..].bytes().all(|b| b.is_ascii_hexdigit()) { return bad("An address is 0x followed by 40 hex characters"); }
    if a[2..].bytes().all(|b| b == b'0') { return bad("That is the zero address; funds sent there are lost"); }
    let mixed = a[2..].bytes().any(|b| b.is_ascii_uppercase()) && a[2..].bytes().any(|b| b.is_ascii_lowercase());
    let sum = verify::checksum(a);
    if mixed && sum != a { return bad("Checksum mismatch: one character is probably wrong"); }
    AddressCheck { ok: true, checksum: Some(sum), error: None }
}
