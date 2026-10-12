//! The send flow behind the redesigned UI. Same request, same verifier and same pinned signer as
//! the original `sign`/`broadcast` commands, with three differences the UI needs to be honest:
//!
//! * progress events (`send-progress`) say when the phone was reached and when the request was
//!   actually delivered, so "Review on your phone" is only shown once it is true;
//! * the wait can be cancelled from the Mac;
//! * the verified transaction stays here. The UI broadcasts by hash, and only a transaction that
//!   `verify::validate_signature` accepted in this session, for exactly the quoted fields, can be
//!   sent to a node. The UI never hands raw bytes back to Rust.

use crate::{aoa, blocking, eth, history, pairing, tokens, verify, CmdResult, Quote};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter, State};

/// How long the phone may take between receiving the request and answering (unlock + review).
const REVIEW_TIMEOUT: Duration = Duration::from_secs(300);

struct VerifiedTx {
    raw: String, chain_id: u128, value_wei: u128, max_fee_wei: u128, nonce: u128, token: Option<tokens::TokenIntent>,
    /// the signed fields, kept in history so a stuck transaction can be sped up or cancelled
    params: history::TxParams,
    /// (hash, "speedup" | "cancel") when this replaces a pending transaction
    replaces: Option<(String, String)>,
}

/// Requests in flight, by ticket: each can be cancelled on its own (a queued Send and a
/// WalletConnect request may both be waiting for the phone).
#[derive(Default)]
pub struct SendState {
    cancels: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
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

/// Forgets the ticket however the command ends.
struct TicketGuard(Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>, String);
impl Drop for TicketGuard { fn drop(&mut self) { if let Ok(mut m) = self.0.lock() { m.remove(&self.1); } } }

fn q(v: &str, what: &str) -> Result<u128, SendError> { verify::quantity(v).map_err(|e| fail("internal", format!("{what}: {e}"), false)) }

#[tauri::command]
pub(crate) async fn sign_start(app: AppHandle, state: State<'_, SendState>, ticket: String, quote: Quote) -> Result<Signed, SendError> {
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut m = state.cancels.lock().map_err(|_| fail("internal", "state poisoned", false))?;
        if m.contains_key(&ticket) { return Err(fail("busy", "this request is already running", false)); }
        m.insert(ticket.clone(), cancel.clone());
    }
    let guard = TicketGuard(state.cancels.clone(), ticket.clone());
    let store = state.verified.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let emit = |stage: &'static str| { let _ = app.emit("send-progress", Progress { ticket: ticket.clone(), stage }); };
        let pinned = pairing::load().map_err(|e| fail("not_paired", e.0, false))?.ok_or_else(|| fail("not_paired", "not paired yet", false))?;
        // Wait our turn with the phone (an identify, a device check or a dApp request may be on
        // it): the UI shows "waiting for the phone" instead of failing with "USB busy".
        let mut waited = false;
        let _turn = aoa::take_turn(|| { waited = true; emit("waiting"); }, || cancel.load(Ordering::SeqCst))
            .map_err(|_| fail("cancelled", aoa::CANCELLED, false))?;
        if waited { emit("connecting"); }
        // The phone must have passed the device check in this connection (runs it if not yet).
        crate::attest::require_ok(&pinned).map_err(|m| {
            if m.starts_with("attestation:") { fail("attestation", m.trim_start_matches("attestation:").trim().to_string(), false) }
            else if m.contains("no Android device") { fail("no_phone", m, false) }
            else if m.contains("held by another program") { fail("usb_busy", m, false) }
            else if m.contains("already running") { fail("busy", m, false) }
            else { fail("connect", m, false) }
        })?;
        if cancel.load(Ordering::SeqCst) { return Err(fail("cancelled", aoa::CANCELLED, false)); }
        // A token send is re-derived from the built-in list before anything reaches the phone.
        let token_check = match &quote.token {
            Some(t) => Some(tokens::check_quote(&quote, t).map_err(|m| fail("internal", format!("token quote rejected: {m}"), false))?),
            None => None,
        };
        // A speed-up/cancel must really replace a pending transaction from here (replace.rs).
        crate::replace::check(&quote, &pinned).map_err(|m| fail("internal", format!("replacement rejected: {m}"), false))?;
        // A transaction whose latest simulation in this session reverts never reaches the phone (sim.rs).
        let simulation = crate::sim::recall(&quote);
        if let Some(s) = simulation.as_ref().filter(|s| s.status == "reverts") {
            return Err(fail("reverts", s.reason.clone().unwrap_or_else(|| "the simulation reverted".into()), false));
        }
        // Exactly the request the original `sign` command builds, plus the Mac's simulation claim
        // (`hostSimulation`) when there is a complete one: display-only on the phone, never signed,
        // never read by verify.rs.
        let mut request = json!({
            "id": uuid::Uuid::new_v4().to_string(), "method": "signEip1559",
            "chainId": quote.chain_id, "nonce": quote.nonce, "maxPriorityFeePerGas": quote.max_priority_fee_per_gas,
            "maxFeePerGas": quote.max_fee_per_gas, "gasLimit": quote.gas_limit, "to": quote.to, "value": quote.value, "data": quote.data,
        });
        if let Some(claim) = simulation.as_ref().and_then(crate::sim::host_claim) { request["hostSimulation"] = claim; }
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
        // Token sends: the calldata decoded FROM THE SIGNED BYTES must be the transfer the UI showed.
        if let Some((contract, recipient, amount)) = &token_check {
            verify::check_erc20_transfer(&v, contract, recipient, *amount).map_err(|e| fail("verify", e.0, true))?;
        }
        let gas = q(&quote.gas_limit, "gasLimit")?;
        let max_fee = q(&quote.max_fee_per_gas, "maxFeePerGas")?;
        // These are the signed fields: validate_signature compared every one with the request.
        let params = history::TxParams {
            to: quote.to.to_ascii_lowercase(), value: quote.value.clone(), data: quote.data.to_ascii_lowercase(), gas_limit: quote.gas_limit.clone(),
            max_fee_per_gas: quote.max_fee_per_gas.clone(), max_priority_fee_per_gas: quote.max_priority_fee_per_gas.clone(),
        };
        let tx = VerifiedTx {
            raw: v.raw_hex, chain_id: q(&quote.chain_id, "chainId")?,
            value_wei: q(&quote.value, "value")?, max_fee_wei: gas.saturating_mul(max_fee), nonce: q(&quote.nonce, "nonce")?,
            token: quote.token.clone(), params, replaces: quote.replaces.as_ref().map(|r| (r.hash.clone(), r.kind.clone())),
        };
        store.lock().map_err(|_| fail("internal", "state poisoned", true))?.insert(v.tx_hash.to_ascii_lowercase(), tx);
        Ok(Signed { hash: v.tx_hash, signer: verify::checksum(&v.signer) })
    }).await.map_err(|e| fail("internal", e.to_string(), false))?
}

/// Stop waiting for the phone: one request by ticket, or every request in flight without one.
/// The phone may still show the request; the user rejects it there.
#[tauri::command]
pub(crate) fn sign_cancel(state: State<'_, SendState>, ticket: Option<String>) {
    if let Ok(m) = state.cancels.lock() {
        for (t, c) in m.iter() { if ticket.as_deref().map_or(true, |x| x == t) { c.store(true, Ordering::SeqCst); } }
    }
}

/// Broadcast a transaction this session verified, by hash. Records it in the local history.
#[tauri::command]
pub(crate) async fn broadcast_verified(state: State<'_, SendState>, rpc_url: String, hash: String) -> CmdResult<String> {
    let store = state.verified.clone();
    blocking(move || {
        let key = hash.to_ascii_lowercase();
        let (raw, chain_id, value_wei, max_fee_wei, nonce, token, params, replaces) = {
            let map = store.lock().map_err(|_| "state poisoned".to_string())?;
            let tx = map.get(&key).ok_or("this transaction was not verified in this session, so it will not be broadcast")?;
            (tx.raw.clone(), tx.chain_id, tx.value_wei, tx.max_fee_wei, tx.nonce, tx.token.clone(), tx.params.clone(), tx.replaces.clone())
        };
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let node_chain = rpc.chain_id().map_err(|e| e.0)?;
        if node_chain != chain_id { return Err(format!("the selected node is on chain {node_chain}, but this transaction is for chain {chain_id}; switch back to that network")); }
        let sent = rpc.send_raw(&raw).map_err(|e| e.0)?;
        if sent.to_ascii_lowercase() != key { return Err(format!("node returned hash {sent}, expected {hash}")); }
        let _ = history::record_broadcast(history::Broadcast { hash: &hash, chain_id, value_wei, max_fee_wei, nonce, token: token.as_ref(), tx: params, replaces });
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
