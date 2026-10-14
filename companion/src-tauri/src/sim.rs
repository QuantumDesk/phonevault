//! Transaction simulation on the user's own node, before anything goes to the phone
//! (vault-os/docs/simulation.md).
//!
//! Every transaction (Send, token send, speed-up/cancel, WalletConnect and browser-extension
//! `eth_sendTransaction`) is run with `eth_simulateV1` (`traceTransfers: true`, so native-coin
//! movements appear as Transfer logs from 0xEeee…EEeE) on top of the latest block, from the paired
//! address, with the exact `to`, `value`, `data` and gas limit that will be signed. The paired
//! wallet's balance changes are computed from the logs: the native coin (plus the estimated fee),
//! ERC-20 Transfer, ERC-721 Transfer, ERC-1155 TransferSingle/Batch, and wrapped-native
//! Deposit/Withdrawal on the known WETH/WPOL contracts. A node without `eth_simulateV1` gets the
//! fallback: `eth_call` (revert detection only) + `eth_estimateGas`, and "Balance changes
//! unavailable on this node".
//!
//! No third-party service and no keys: only the node the user configured. Node answers are
//! untrusted: the result is shown on the Mac and offered to the phone as `hostSimulation`, which
//! the phone labels as the Mac's unverified claim and checks against its own decoding. It is
//! never part of the signed data, and verify.rs never reads it.
//!
//! A simulation that REVERTS blocks the send: `send::sign_start` refuses a quote whose latest
//! simulation in this session reverted. Uncertainty (the node could not simulate at all) only asks
//! the user to confirm ("Send anyway").

use crate::{blocking, eth, pairing, tokens, verify, CmdResult, Quote};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const TRANSFER: &str = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const TRANSFER_SINGLE: &str = "c3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62";
const TRANSFER_BATCH: &str = "4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb";
const DEPOSIT: &str = "e1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c";
const WITHDRAWAL: &str = "7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65";
/// Pseudo-address eth_simulateV1 uses for native-coin transfers when `traceTransfers` is on.
const NATIVE_LOG: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
/// The phone's limit for `hostSimulation.changes` (HostSimulation.MAX_CHANGES).
pub const MAX_CLAIM_CHANGES: usize = 16;
const MAX_LOGS: usize = 2_000;
const MAX_BATCH: usize = 256;
/// A simulation is used for the phone and the revert block only while it is this fresh.
const FRESH: Duration = Duration::from_secs(600);

/// The canonical wrapped native coin per chain: its Deposit/Withdrawal events move the wallet's
/// wrapped balance without a Transfer log (WETH9 does not emit one).
fn wrapped_native(chain: u64) -> Option<&'static str> {
    match chain {
        1 => Some("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
        8453 | 10 => Some("0x4200000000000000000000000000000000000006"),
        42161 => Some("0x82af49447d8a07e3bd95bd0d56f35241523fbab1"),
        137 => Some("0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"),
        11155111 => Some("0xfff9976782d46cc05630d1f6ebab18b2324d6b14"),
        _ => None,
    }
}

fn native_symbol(chain: u64) -> &'static str { if chain == 137 { "POL" } else { "ETH" } }

// ---------------------------------------------------------------- 256-bit amounts

/// Unsigned 256-bit integer, most significant limb first (so the derived order is numeric).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug, Hash)]
pub struct U256([u64; 4]);

impl U256 {
    pub fn from_u128(v: u128) -> U256 { U256([0, 0, (v >> 64) as u64, v as u64]) }
    #[deny(clippy::indexing_slicing)]
    fn from_be(bytes: &[u8]) -> Option<U256> {
        let mut full = [0u8; 32];
        full.get_mut(32usize.checked_sub(bytes.len())?..)?.copy_from_slice(bytes);
        let mut l = [0u64; 4];
        for (limb, chunk) in l.iter_mut().zip(full.as_chunks::<8>().0) { *limb = u64::from_be_bytes(*chunk); }
        Some(U256(l))
    }
    pub fn is_zero(&self) -> bool { self.0 == [0; 4] }
    fn checked_add(self, o: U256) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in (0..4).rev() {
            let s = self.0[i] as u128 + o.0[i] as u128 + carry;
            out[i] = s as u64;
            carry = s >> 64;
        }
        if carry != 0 { None } else { Some(U256(out)) }
    }
    /// self − o, for self ≥ o.
    fn sub(self, o: U256) -> U256 {
        let mut out = [0u64; 4];
        let mut borrow = 0i128;
        for i in (0..4).rev() {
            let mut d = self.0[i] as i128 - o.0[i] as i128 - borrow;
            borrow = if d < 0 { d += 1i128 << 64; 1 } else { 0 };
            out[i] = d as u64;
        }
        U256(out)
    }
    pub fn to_decimal(self) -> String {
        if self.is_zero() { return "0".into(); }
        let mut limbs = self.0;
        let mut digits = Vec::new();
        while limbs != [0; 4] {
            let mut rem = 0u128;
            for limb in limbs.iter_mut() {
                let cur = (rem << 64) | *limb as u128;
                *limb = (cur / 10) as u64;
                rem = cur % 10;
            }
            digits.push(b'0' + rem as u8);
        }
        digits.reverse();
        String::from_utf8(digits).unwrap_or_default()
    }
    fn to_u128(self) -> Option<u128> { if self.0[0] == 0 && self.0[1] == 0 { Some(((self.0[2] as u128) << 64) | self.0[3] as u128) } else { None } }
}

/// Decimal text of `raw` with `decimals` places, trailing zeros trimmed (exact, any size).
fn format_decimal(raw: &str, decimals: u32) -> String {
    let d = decimals as usize;
    if d == 0 { return raw.to_string(); }
    let padded = if raw.len() <= d { format!("{}{}", "0".repeat(d + 1 - raw.len()), raw) } else { raw.to_string() };
    let (whole, frac) = padded.split_at(padded.len() - d);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() { whole.to_string() } else { format!("{whole}.{frac}") }
}

// ---------------------------------------------------------------- the result

/// One balance change of the paired wallet.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Change {
    /// "native" or the lower-case contract address
    pub asset: String,
    /// decimal token ID for an NFT
    pub token_id: Option<String>,
    /// signed decimal in base units (wei, token base units, NFT count); never "0"
    pub delta: String,
    /// from the built-in token list (or the native coin); None for unknown tokens and NFTs
    pub symbol: Option<String>,
    pub decimals: Option<u32>,
    /// "−100 USDC", "+0.0312 ETH", "−500 base units of 0x2222…2222", "−1 × NFT #1 of 0xBC4C…f13D"
    pub display: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Simulation {
    /// "ok" (balance changes known) · "reverts" (blocked) · "no_changes" (eth_call fallback: does
    /// not revert, changes unknown) · "unavailable" (could not simulate; the user may send anyway)
    pub status: &'static str,
    /// "eth_simulateV1" · "eth_call" · "none"
    pub method: &'static str,
    pub changes: Vec<Change>,
    /// estimated fee in wei (gas used × min(max fee, base fee + priority)), included in the native change
    pub fee_wei: Option<String>,
    pub gas_used: Option<String>,
    /// why it reverts (status "reverts") or why it could not be simulated
    pub reason: Option<String>,
    /// plain-language note for the UI (fallback, rollup L1 fee, too many changes for the phone)
    pub note: Option<String>,
    /// host[:port] of the node that answered
    pub node: String,
    /// the block the simulation ran on top of
    pub block: Option<u128>,
    /// whether this result will be shown to the phone as `hostSimulation`
    pub for_phone: bool,
}

impl Simulation {
    fn new(status: &'static str, method: &'static str, node: &str, block: Option<u128>) -> Simulation {
        Simulation { status, method, changes: vec![], fee_wei: None, gas_used: None, reason: None, note: None, node: node.to_string(), block, for_phone: false }
    }
}

// ---------------------------------------------------------------- logs → deltas

#[derive(Default, Clone, Copy)]
struct Flow { inn: U256, out: U256 }

type Key = (String, Option<U256>);

fn strip(h: &str) -> &str { h.strip_prefix("0x").unwrap_or(h) }
/// `0x` + 40 hex (any case), the only log `address` this reads.
fn is_address(a: &str) -> bool { a.len() == 42 && a.starts_with("0x") && a.bytes().skip(2).all(|b| b.is_ascii_hexdigit()) }
#[deny(clippy::indexing_slicing)]
fn topic_address(t: &str) -> Option<String> {
    let t = strip(t);
    if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) { return None; }
    let (pad, addr) = (t.get(..24)?, t.get(24..)?);
    if !pad.bytes().all(|b| b == b'0') { return None; }
    Some(format!("0x{}", addr.to_ascii_lowercase()))
}
#[deny(clippy::indexing_slicing)]
fn word(bytes: &[u8], i: usize) -> Option<U256> {
    let start = i.checked_mul(32)?;
    U256::from_be(bytes.get(start..start.checked_add(32)?)?)
}
fn word_usize(bytes: &[u8], i: usize) -> Option<usize> { word(bytes, i)?.to_u128().and_then(|v| usize::try_from(v).ok()) }

/// `uint256[]` at a head offset of ABI-encoded data.
#[deny(clippy::indexing_slicing)]
fn uint_array(data: &[u8], head: usize) -> Option<Vec<U256>> {
    let at = word_usize(data, head)?;
    if at % 32 != 0 { return None; }
    let n = word_usize(data, at / 32)?;
    if n > MAX_BATCH { return None; }
    (0..n).map(|i| word(data, (at / 32).checked_add(1)?.checked_add(i)?)).collect()
}

fn credit(map: &mut BTreeMap<Key, Flow>, key: Key, from: &str, to: &str, amount: U256, wallet: &str) -> Result<(), String> {
    if from == to || amount.is_zero() || (from != wallet && to != wallet) { return Ok(()); }
    let f = map.entry(key).or_default();
    let overflow = || "a simulated amount overflows 256 bits".to_string();
    if to == wallet { f.inn = f.inn.checked_add(amount).ok_or_else(overflow)?; }
    if from == wallet { f.out = f.out.checked_add(amount).ok_or_else(overflow)?; }
    Ok(())
}

/// Apply one log of the simulated call to the wallet's flows. Unrecognised logs are ignored.
#[deny(clippy::indexing_slicing)]
fn apply_log(map: &mut BTreeMap<Key, Flow>, log: &Value, wallet: &str, chain: u64) -> Result<(), String> {
    // the node's answer is untrusted: a log from something that is not an address is ignored
    let address = match log.get("address").and_then(Value::as_str) { Some(a) if is_address(a) => a.to_ascii_lowercase(), _ => return Ok(()) };
    let topics: Vec<String> = log.get("topics").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(|t| strip(t).to_ascii_lowercase()).collect()).unwrap_or_default();
    let data = match log.get("data").and_then(Value::as_str).map(|d| hex::decode(strip(d))) { Some(Ok(d)) => d, _ => return Ok(()) };
    let topics: Vec<&str> = topics.iter().map(String::as_str).collect();
    match topics.as_slice() {
        [TRANSFER, t1, t2] if data.len() == 32 => {
            let (Some(from), Some(to)) = (topic_address(t1), topic_address(t2)) else { return Ok(()) };
            let asset = if address == NATIVE_LOG { "native".to_string() } else { address };
            credit(map, (asset, None), &from, &to, word(&data, 0).unwrap_or_default(), wallet)
        }
        [TRANSFER, t1, t2, t3] if data.is_empty() => {
            let (Some(from), Some(to)) = (topic_address(t1), topic_address(t2)) else { return Ok(()) };
            let id = hex::decode(t3).ok().and_then(|b| U256::from_be(&b)).unwrap_or_default();
            credit(map, (address, Some(id)), &from, &to, U256::from_u128(1), wallet)
        }
        [TRANSFER_SINGLE, _, t2, t3] if data.len() == 64 => {
            let (Some(from), Some(to)) = (topic_address(t2), topic_address(t3)) else { return Ok(()) };
            let (Some(id), Some(v)) = (word(&data, 0), word(&data, 1)) else { return Ok(()) };
            credit(map, (address, Some(id)), &from, &to, v, wallet)
        }
        [TRANSFER_BATCH, _, t2, t3] => {
            let (Some(from), Some(to)) = (topic_address(t2), topic_address(t3)) else { return Ok(()) };
            let (Some(ids), Some(values)) = (uint_array(&data, 0), uint_array(&data, 1)) else { return Ok(()) };
            if ids.len() != values.len() { return Ok(()); }
            for (id, v) in ids.into_iter().zip(values) { credit(map, (address.clone(), Some(id)), &from, &to, v, wallet)?; }
            Ok(())
        }
        [t0 @ (DEPOSIT | WITHDRAWAL), t1] if data.len() == 32 && wrapped_native(chain) == Some(address.as_str()) => {
            let Some(who) = topic_address(t1) else { return Ok(()) };
            let amount = word(&data, 0).unwrap_or_default();
            // a deposit mints to `who` (as if from the zero address); a withdrawal burns from `who`
            let zero = "0x0000000000000000000000000000000000000000";
            if *t0 == DEPOSIT { credit(map, (address, None), zero, &who, amount, wallet) } else { credit(map, (address, None), &who, zero, amount, wallet) }
        }
        _ => Ok(()),
    }
}

/// The wallet's balance changes from the simulated call's logs, with `fee_wei` taken from the native coin.
#[deny(clippy::indexing_slicing)]
pub fn changes_from_logs(logs: &[Value], wallet: &str, chain: u64, fee_wei: u128) -> Result<Vec<Change>, String> {
    if logs.len() > MAX_LOGS { return Err(format!("the simulation produced more than {MAX_LOGS} logs")); }
    let wallet = wallet.to_ascii_lowercase();
    let mut map: BTreeMap<Key, Flow> = BTreeMap::new();
    for log in logs { apply_log(&mut map, log, &wallet, chain)?; }
    if fee_wei > 0 {
        let f = map.entry(("native".to_string(), None)).or_default();
        f.out = f.out.checked_add(U256::from_u128(fee_wei)).ok_or("fee overflow")?;
    }
    let mut out = Vec::new();
    // native first, then tokens, then NFTs (BTreeMap order within each group)
    let mut flows: Vec<(&Key, &Flow)> = map.iter().collect();
    flows.sort_by_key(|((asset, id), _)| (asset != "native", id.is_some(), asset.clone(), *id));
    for (key, f) in flows {
        if f.inn == f.out { continue; }
        let (negative, magnitude) = if f.inn > f.out { (false, f.inn.sub(f.out)) } else { (true, f.out.sub(f.inn)) };
        out.push(describe(&key.0, key.1, negative, magnitude, chain));
    }
    Ok(out)
}

fn describe(asset: &str, token_id: Option<U256>, negative: bool, magnitude: U256, chain: u64) -> Change {
    let sign = if negative { "−" } else { "+" };
    let raw = magnitude.to_decimal();
    let delta = if negative { format!("-{raw}") } else { raw.clone() };
    if asset == "native" {
        let sym = native_symbol(chain);
        return Change { asset: asset.into(), token_id: None, delta, symbol: Some(sym.into()), decimals: Some(18), display: format!("{sign}{} {sym}", format_decimal(&raw, 18)) };
    }
    if let Some(id) = token_id {
        let id = id.to_decimal();
        return Change { asset: asset.into(), display: format!("{sign}{raw} × NFT #{id} of {}", verify::short_address(asset)), token_id: Some(id), delta, symbol: None, decimals: None };
    }
    match tokens::lookup(chain, asset) {
        Some(t) => Change { asset: asset.into(), token_id: None, delta, symbol: Some(t.symbol.clone()), decimals: Some(t.decimals), display: format!("{sign}{} {}", format_decimal(&raw, t.decimals), t.symbol) },
        None => Change { asset: asset.into(), token_id: None, delta, symbol: None, decimals: None, display: format!("{sign}{raw} base units of unknown token {}", verify::short_address(asset)) },
    }
}

// ---------------------------------------------------------------- revert reasons

fn printable(s: &str, max: usize) -> String {
    let t: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>().trim().to_string();
    if t.chars().count() > max { format!("{}…", t.chars().take(max).collect::<String>()) } else { t }
}

/// The revert reason in words, from the node's error message and the revert data.
#[deny(clippy::indexing_slicing)]
pub fn revert_reason(message: Option<&str>, data: Option<&str>) -> String {
    let bytes = data.and_then(|d| hex::decode(strip(d)).ok()).unwrap_or_default();
    if bytes.len() >= 4 {
        let (sel, body) = bytes.split_at(4);
        if sel == [0x08, 0xc3, 0x79, 0xa0] {
            // Error(string)
            if let Some(off) = word_usize(body, 0) {
                let start = off.checked_add(32);
                if let Some(len) = start.and_then(|s| body.get(off..s)).and_then(U256::from_be).and_then(|l| l.to_u128()).and_then(|l| usize::try_from(l).ok()) {
                    let text = start.and_then(|s| Some((s, s.checked_add(len)?))).and_then(|(s, e)| body.get(s..e)).and_then(|b| std::str::from_utf8(b).ok());
                    if let Some(text) = text {
                        let t = printable(text, 160);
                        return if t.is_empty() { "reverted with an empty reason".into() } else { t };
                    }
                }
            }
        } else if sel == [0x4e, 0x48, 0x7b, 0x71] {
            // Panic(uint256)
            let code = word(body, 0).and_then(|w| w.to_u128()).unwrap_or(u128::MAX);
            let what = match code { 0x01 => "assertion failed", 0x11 => "arithmetic overflow or underflow", 0x12 => "division by zero", 0x21 => "invalid enum value",
                0x31 => "pop from an empty array", 0x32 => "array index out of bounds", 0x41 => "out of memory", 0x51 => "call to an uninitialised function", _ => "panic" };
            return format!("{what} (panic 0x{code:x})");
        } else {
            return format!("custom error 0x{}", hex::encode(sel));
        }
    }
    let m = message.unwrap_or("").trim();
    let m = m.strip_prefix("execution reverted:").or_else(|| m.strip_prefix("execution reverted")).map(str::trim).unwrap_or(m);
    if m.is_empty() { "reverted without a reason".into() } else { printable(m, 160) }
}

fn is_revert(error: &Value) -> bool {
    let code = error.get("code").and_then(Value::as_i64);
    let msg = error.get("message").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
    code == Some(3) || code == Some(-32015) || msg.contains("revert") || msg.contains("out of gas") || msg.contains("invalid opcode")
}

fn is_insufficient_funds(error: &Value) -> bool {
    error.get("message").and_then(Value::as_str).is_some_and(|m| m.to_ascii_lowercase().contains("insufficient funds")) || error.get("code").and_then(Value::as_i64) == Some(-38014)
}

fn error_text(error: &Value) -> String { printable(error.get("message").and_then(Value::as_str).unwrap_or("unknown error"), 160) }

// ---------------------------------------------------------------- interpreting a node's answers

/// What the transaction to simulate is: the exact signed fields that matter for execution.
#[derive(Clone, Debug)]
pub struct Tx { pub from: String, pub to: String, pub value: u128, pub data: String, pub gas: u128, pub max_fee: u128, pub priority: u128, pub chain: u64 }

impl Tx {
    fn call_object(&self, with_gas: bool) -> Value {
        let mut o = json!({"from": self.from, "to": self.to, "value": verify::to_quantity(self.value), "data": self.data});
        if with_gas { o["gas"] = json!(verify::to_quantity(self.gas)); }
        o
    }
    fn fee(&self, gas_used: u128, base_fee: u128) -> u128 { gas_used.saturating_mul(self.max_fee.min(base_fee.saturating_add(self.priority))) }
}

/// Interpret an `eth_simulateV1` JSON-RPC response. `None` means "this node could not simulate"
/// (method missing, odd shape, other errors): the caller falls back to eth_call.
pub fn interpret_simulate_v1(resp: &Value, tx: &Tx, base_fee: u128, node: &str, block: Option<u128>) -> Option<Simulation> {
    if let Some(e) = resp.get("error") {
        if is_insufficient_funds(e) {
            let mut s = Simulation::new("reverts", "eth_simulateV1", node, block);
            s.reason = Some(format!("not enough {} for the amount ({})", native_symbol(tx.chain), error_text(e)));
            return Some(s);
        }
        return None;
    }
    let call = resp.get("result")?.as_array()?.first()?.get("calls")?.as_array()?.first()?;
    let status = call.get("status").and_then(Value::as_str)?;
    let gas_used = call.get("gasUsed").and_then(Value::as_str).and_then(|g| verify::quantity(g).ok().or_else(|| u128::from_str_radix(strip(g), 16).ok()))?;
    if status == "0x0" {
        let e = call.get("error").cloned().unwrap_or(Value::Null);
        let msg = e.get("message").and_then(Value::as_str);
        let mut s = Simulation::new("reverts", "eth_simulateV1", node, block);
        s.reason = Some(if msg.is_some_and(|m| m.to_ascii_lowercase().contains("out of gas")) {
            format!("runs out of gas: the gas limit is {}", tx.gas)
        } else {
            revert_reason(msg, e.get("data").and_then(Value::as_str))
        });
        s.gas_used = Some(gas_used.to_string());
        return Some(s);
    }
    if status != "0x1" { return None; }
    let logs: Vec<Value> = call.get("logs").and_then(Value::as_array).cloned().unwrap_or_default();
    let fee = tx.fee(gas_used, base_fee);
    let mut s = Simulation::new("ok", "eth_simulateV1", node, block);
    match changes_from_logs(&logs, &tx.from, tx.chain, fee) {
        Ok(c) => s.changes = c,
        Err(m) => { let mut u = Simulation::new("unavailable", "eth_simulateV1", node, block); u.reason = Some(m); return Some(u); }
    }
    s.fee_wei = Some(fee.to_string());
    s.gas_used = Some(gas_used.to_string());
    if matches!(tx.chain, 8453 | 10 | 42161) { s.note = Some("Plus a small L1 data fee the simulation does not include.".into()); }
    s.for_phone = s.changes.len() <= MAX_CLAIM_CHANGES;
    if !s.for_phone { s.note = Some(format!("{} balance changes: too many to show on the phone, which reviews the transaction on its own.", s.changes.len())); }
    Some(s)
}

/// The fallback: `eth_call` (reverts?) then `eth_estimateGas` (fits the gas limit?).
pub fn interpret_fallback(call: &Value, estimate: Option<&Value>, tx: &Tx, node: &str, block: Option<u128>, why: &str) -> Simulation {
    if let Some(e) = call.get("error") {
        if is_insufficient_funds(e) {
            let mut s = Simulation::new("reverts", "eth_call", node, block);
            s.reason = Some(format!("not enough {} for the amount ({})", native_symbol(tx.chain), error_text(e)));
            return s;
        }
        if is_revert(e) {
            let mut s = Simulation::new("reverts", "eth_call", node, block);
            let msg = e.get("message").and_then(Value::as_str);
            s.reason = Some(if msg.is_some_and(|m| m.to_ascii_lowercase().contains("out of gas")) { format!("runs out of gas: the gas limit is {}", tx.gas) } else { revert_reason(msg, e.get("data").and_then(Value::as_str)) });
            return s;
        }
        let mut s = Simulation::new("unavailable", "none", node, block);
        s.reason = Some(format!("the node could not run it: {}", error_text(e)));
        return s;
    }
    if let Some(est) = estimate {
        if let Some(g) = est.get("result").and_then(Value::as_str).and_then(|g| u128::from_str_radix(strip(g), 16).ok()) {
            if g > tx.gas {
                let mut s = Simulation::new("reverts", "eth_call", node, block);
                s.reason = Some(format!("needs about {g} gas, but the gas limit is {}: it would run out of gas", tx.gas));
                return s;
            }
            let mut s = Simulation::new("no_changes", "eth_call", node, block);
            s.gas_used = Some(g.to_string());
            s.note = Some(format!("Balance changes unavailable on this node ({why}). eth_call says it does not revert."));
            return s;
        }
    }
    let mut s = Simulation::new("no_changes", "eth_call", node, block);
    s.note = Some(format!("Balance changes unavailable on this node ({why}). eth_call says it does not revert; the gas estimate was not available."));
    s
}

/// Why eth_simulateV1 was not used, in a few words.
fn simulate_v1_failure(resp: &Result<Value, eth::EthError>) -> String {
    match resp {
        Err(e) => printable(&e.0, 120),
        Ok(v) => match v.get("error") {
            Some(e) if e.get("code").and_then(Value::as_i64) == Some(-32601) || error_text(e).to_ascii_lowercase().contains("not found") || error_text(e).to_ascii_lowercase().contains("not supported") || error_text(e).to_ascii_lowercase().contains("does not exist") =>
                "it does not support eth_simulateV1".into(),
            Some(e) => format!("eth_simulateV1 failed: {}", error_text(e)),
            None => "eth_simulateV1 answered in an unexpected format".into(),
        },
    }
}

/// Run the simulation against a node. Never errs: a node problem is a status the UI explains.
pub fn run(rpc: &eth::Rpc, tx: &Tx, node: &str) -> Simulation {
    // some nodes refuse a full header read; then the block number and the fee quote's base fee
    let header = rpc.latest_header().or_else(|e| match (rpc.block_number(), rpc.fees()) {
        (Ok(n), Ok((prio, max))) => Ok((n, max.saturating_sub(prio) / 2)),
        _ => Err(e),
    });
    // …and when even that fails, "latest" with no fee estimate (such a result never goes to the phone: no block)
    let (block, base_fee) = match header { Ok((n, b)) => (Some(n), b), Err(_) => (None, 0) };
    let tag = block.map(verify::to_quantity).unwrap_or_else(|| "latest".into());
    let params = json!([{"blockStateCalls": [{"calls": [tx.call_object(true)]}], "traceTransfers": true, "validation": false}, tag]);
    let resp = rpc.call_raw("eth_simulateV1", params);
    if let Ok(v) = &resp { if let Some(s) = interpret_simulate_v1(v, tx, base_fee, node, block) { return s; } }
    let why = simulate_v1_failure(&resp);
    let call = match rpc.call_raw("eth_call", json!([tx.call_object(true), tag])) {
        Ok(v) => v,
        Err(e) => { let mut s = Simulation::new("unavailable", "none", node, block); s.reason = Some(format!("{why}; eth_call failed too: {}", printable(&e.0, 120))); return s; }
    };
    let estimate = if call.get("error").is_none() { rpc.call_raw("eth_estimateGas", json!([tx.call_object(false), tag])).ok() } else { None };
    interpret_fallback(&call, estimate.as_ref(), tx, node, block, &why)
}

// ---------------------------------------------------------------- the phone's view

/// host[:port] of the node URL in the phone's accepted form; "custom-node" otherwise.
pub fn node_label(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host).to_ascii_lowercase();
    let (name, port) = match host.rsplit_once(':') { Some((n, p)) => (n.to_string(), Some(p.to_string())), None => (host.clone(), None) };
    let name_ok = !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    let port_ok = port.as_ref().is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()));
    if name_ok && port_ok && host.len() <= 100 { host } else { "custom-node".into() }
}

/// The `hostSimulation` field for the phone: only for a complete simulation ("ok") with at most
/// 16 changes. Exactly the schema the phone parses (HostSimulation.java); never signed.
pub fn host_claim(sim: &Simulation) -> Option<Value> {
    if sim.status != "ok" || !sim.for_phone || sim.changes.len() > MAX_CLAIM_CHANGES { return None; }
    let block = sim.block?;
    let changes: Vec<Value> = sim.changes.iter().map(|c| {
        let mut o = json!({"asset": c.asset, "delta": c.delta});
        if let Some(id) = &c.token_id { o["tokenId"] = json!(id); }
        else if let (Some(sym), Some(dec)) = (&c.symbol, c.decimals) {
            if dec <= 36 && !sym.is_empty() && sym.len() <= 16 && sym.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)) {
                o["symbol"] = json!(sym); o["decimals"] = json!(dec);
            }
        }
        o
    }).collect();
    Some(json!({"changes": changes, "node": node_label(&sim.node), "block": verify::to_quantity(block)}))
}

// ---------------------------------------------------------------- this session's results

struct Entry { key: String, at: Instant, sim: Simulation }
static RESULTS: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

/// What identifies a simulation: the sender (the paired account it ran from) and the fields that
/// change execution (fees and nonce do not). A result for one account never stands in for another.
pub fn fingerprint(q: &Quote, from: &str) -> String {
    format!("{}|{}|{}|{}|{}|{}", from.to_ascii_lowercase(), q.chain_id.to_ascii_lowercase(), q.to.to_ascii_lowercase(), q.value.to_ascii_lowercase(), q.data.to_ascii_lowercase(), q.gas_limit.to_ascii_lowercase())
}

pub fn remember(q: &Quote, from: &str, sim: &Simulation) {
    if let Ok(mut v) = RESULTS.lock() {
        let key = fingerprint(q, from);
        v.retain(|e| e.key != key && e.at.elapsed() < FRESH);
        if v.len() >= 64 { v.remove(0); }
        v.push(Entry { key, at: Instant::now(), sim: sim.clone() });
    }
}

/// The latest simulation of this exact transaction from this account in this session, if still fresh.
pub fn recall(q: &Quote, from: &str) -> Option<Simulation> {
    let key = fingerprint(q, from);
    RESULTS.lock().ok()?.iter().rev().find(|e| e.key == key && e.at.elapsed() < FRESH).map(|e| e.sim.clone())
}

fn tx_of(q: &Quote, from: &str) -> Result<Tx, String> {
    let n = |v: &str, what: &str| verify::quantity(v).map_err(|e| format!("{what}: {}", e.0));
    let chain = u64::try_from(n(&q.chain_id, "chainId")?).map_err(|_| "chainId out of range".to_string())?;
    Ok(Tx { from: from.to_ascii_lowercase(), to: q.to.to_ascii_lowercase(), value: n(&q.value, "value")?, data: q.data.to_ascii_lowercase(),
        gas: n(&q.gas_limit, "gasLimit")?, max_fee: n(&q.max_fee_per_gas, "maxFeePerGas")?, priority: n(&q.max_priority_fee_per_gas, "maxPriorityFeePerGas")?, chain })
}

/// Simulate a quote on the user's node before it goes to the phone. The result is remembered for
/// `send::sign_start` (revert block, `hostSimulation` for the phone).
#[tauri::command]
pub(crate) async fn simulate(rpc_url: String, quote: Quote) -> CmdResult<Simulation> {
    blocking(move || {
        // Always the ACTIVE paired account: the one the phone will be asked to sign with (`from`).
        let from = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
        let tx = tx_of(&quote, &from)?;
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let node = node_label(&rpc_url);
        let sim = match rpc.chain_id() {
            Ok(c) if c == tx.chain as u128 => run(&rpc, &tx, &node),
            Ok(c) => { let mut s = Simulation::new("unavailable", "none", &node, None); s.reason = Some(format!("the node is on chain {c}, not {}", tx.chain)); s }
            Err(e) => { let mut s = Simulation::new("unavailable", "none", &node, None); s.reason = Some(format!("the node did not answer: {}", printable(&e.0, 120))); s }
        };
        remember(&quote, &from, &sim);
        Ok(sim)
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Recorded 2026-10-11 from ethereum-rpc.publicnode.com (eth_simulateV1, traceTransfers, validation off).
    const USDC_TRANSFER: &str = include_str!("../tests/fixtures/sim/usdc_transfer.json");
    const USDC_REVERT: &str = include_str!("../tests/fixtures/sim/usdc_revert.json");
    const ETH_SEND: &str = include_str!("../tests/fixtures/sim/eth_send.json");
    const ETH_INSUFFICIENT: &str = include_str!("../tests/fixtures/sim/eth_insufficient.json");
    const WETH_DEPOSIT: &str = include_str!("../tests/fixtures/sim/weth_deposit.json");
    const NFT_TRANSFER: &str = include_str!("../tests/fixtures/sim/nft_transfer.json");
    const SWAP_ETH_USDC: &str = include_str!("../tests/fixtures/sim/swap_eth_usdc.json");
    const ERC1155_BATCH: &str = include_str!("../tests/fixtures/sim/erc1155_batch.json");
    const METHOD_NOT_FOUND: &str = include_str!("../tests/fixtures/sim/method_not_found.json");

    const HOLDER: &str = "0x28c6c06298d514db089934071355e5743bf21d60";
    const OTHER: &str = "0x7f3a9c04e2b16d58a41c0f9e6b2d7a8c5e1f4b93";
    const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    const WETH: &str = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
    const BLOCK: u128 = 0x18f603b;
    const BASE_FEE: u128 = 62_081_795; // the recorded block's base fee

    fn v(s: &str) -> Value { serde_json::from_str(s).unwrap() }
    /// The fixtures are either the raw response or {call, response}.
    fn response(s: &str) -> Value { let j = v(s); if j.get("response").is_some() { j["response"].clone() } else { j } }
    fn tx(from: &str, to: &str, value: u128, data: &str, gas: u128) -> Tx {
        Tx { from: from.into(), to: to.into(), value, data: data.into(), gas, max_fee: 2_000_000_000, priority: 1_000_000_000, chain: 1 }
    }
    fn displays(s: &Simulation) -> Vec<&str> { s.changes.iter().map(|c| c.display.as_str()).collect() }

    #[test]
    fn u256_arithmetic_and_decimal() {
        let max = U256([u64::MAX; 4]);
        assert_eq!(max.to_decimal(), "115792089237316195423570985008687907853269984665640564039457584007913129639935");
        assert!(max.checked_add(U256::from_u128(1)).is_none());
        assert_eq!(U256::from_u128(1000).sub(U256::from_u128(1)).to_decimal(), "999");
        assert_eq!(U256::from_u128(u128::MAX).checked_add(U256::from_u128(1)).unwrap().to_decimal(), "340282366920938463463374607431768211456");
        assert_eq!(format_decimal("1300000000000", 18), "0.0000013");
        assert_eq!(format_decimal("100000000", 6), "100");
    }

    #[test]
    fn a_usdc_transfer_is_minus_100_usdc_and_the_fee() {
        let t = tx(HOLDER, USDC, 0, "0xa9059cbb", 100_000);
        let s = interpret_simulate_v1(&response(USDC_TRANSFER), &t, BASE_FEE, "ethereum-rpc.publicnode.com", Some(BLOCK)).unwrap();
        assert_eq!(s.status, "ok");
        assert_eq!(s.method, "eth_simulateV1");
        // gasUsed 0xf328 = 62248 × min(2 gwei, base 0.062 gwei + 1 gwei)
        let fee = 62_248u128 * (BASE_FEE + 1_000_000_000);
        assert_eq!(s.fee_wei.as_deref(), Some(fee.to_string().as_str()));
        assert_eq!(displays(&s), vec![format!("−{} ETH", format_decimal(&fee.to_string(), 18)).as_str(), "−100 USDC"]);
        assert_eq!(s.changes[1], Change { asset: USDC.into(), token_id: None, delta: "-100000000".into(), symbol: Some("USDC".into()), decimals: Some(6), display: "−100 USDC".into() });
        assert!(s.for_phone);
        // the recipient's view of the same logs: +100 USDC, no fee
        let r = changes_from_logs(response(USDC_TRANSFER)["result"][0]["calls"][0]["logs"].as_array().unwrap(), OTHER, 1, 0).unwrap();
        assert_eq!(r.iter().map(|c| c.display.as_str()).collect::<Vec<_>>(), vec!["+100 USDC"]);
    }

    #[test]
    fn a_native_send_counts_the_traced_value() {
        let t = tx(HOLDER, OTHER, 500_000_000_000_000_000, "0x", 21_000);
        let s = interpret_simulate_v1(&response(ETH_SEND), &t, BASE_FEE, "n", Some(BLOCK)).unwrap();
        let fee = 21_000u128 * (BASE_FEE + 1_000_000_000);
        assert_eq!(s.changes.len(), 1);
        assert_eq!(s.changes[0].delta, format!("-{}", 500_000_000_000_000_000u128 + fee));
        assert!(s.changes[0].display.starts_with("−0.500"));
    }

    #[test]
    fn a_revert_is_reported_with_its_reason() {
        let t = tx("0x9a3f1c2b7e8d4a5f6b0c1d2e3f4a5b6c7d8e9f01", USDC, 0, "0xa9059cbb", 100_000);
        let s = interpret_simulate_v1(&response(USDC_REVERT), &t, BASE_FEE, "n", Some(BLOCK)).unwrap();
        assert_eq!(s.status, "reverts");
        assert_eq!(s.reason.as_deref(), Some("ERC20: transfer amount exceeds balance"));
        assert!(s.changes.is_empty());
        assert!(host_claim(&s).is_none(), "a revert is never offered to the phone");
    }

    #[test]
    fn insufficient_funds_blocks_like_a_revert() {
        let t = tx("0x9a3f1c2b7e8d4a5f6b0c1d2e3f4a5b6c7d8e9f01", OTHER, 1_000_000_000_000_000_000, "0x", 21_000);
        let s = interpret_simulate_v1(&response(ETH_INSUFFICIENT), &t, BASE_FEE, "n", Some(BLOCK)).unwrap();
        assert_eq!(s.status, "reverts");
        assert!(s.reason.as_deref().unwrap().starts_with("not enough ETH"));
    }

    #[test]
    fn a_weth_deposit_is_eth_out_weth_in() {
        let t = tx(HOLDER, WETH, 500_000_000_000_000_000, "0xd0e30db0", 100_000);
        let s = interpret_simulate_v1(&response(WETH_DEPOSIT), &t, 0, "n", Some(BLOCK)).unwrap();
        assert_eq!(displays(&s), vec!["−0.500027938 ETH", "+0.5 WETH"]); // fee 27938 gas × 1 gwei (base fee 0 here)
    }

    #[test]
    fn an_nft_transfer_is_one_token_id_out() {
        let j = v(NFT_TRANSFER);
        let owner = j["call"]["from"].as_str().unwrap().to_string();
        let t = tx(&owner, "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", 0, "0x42842e0e", 200_000);
        let s = interpret_simulate_v1(&response(NFT_TRANSFER), &t, BASE_FEE, "n", Some(BLOCK)).unwrap();
        let nft = s.changes.iter().find(|c| c.token_id.is_some()).unwrap();
        assert_eq!((nft.asset.as_str(), nft.token_id.as_deref(), nft.delta.as_str()), ("0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", Some("1"), "-1"));
        assert_eq!(nft.display, "−1 × NFT #1 of 0xBC4C…f13D");
        let claim = host_claim(&s).unwrap();
        assert_eq!(claim["changes"][1], json!({"asset": "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", "delta": "-1", "tokenId": "1"}));
    }

    #[test]
    fn a_swap_nets_out_the_routers_internal_moves() {
        // 0.5 ETH → USDC through SwapRouter02: the wrap and the pool's WETH are the router's, not ours
        let j = v(SWAP_ETH_USDC);
        let t = tx(HOLDER, "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45", 500_000_000_000_000_000, &j["call"]["data"].as_str().unwrap().to_string(), 300_000);
        let s = interpret_simulate_v1(&response(SWAP_ETH_USDC), &t, BASE_FEE, "n", Some(BLOCK)).unwrap();
        assert_eq!(s.changes.len(), 2);
        assert_eq!(s.changes[0].asset, "native");
        // −0.5 ETH and the fee: gasUsed 0x1f5a3 × (base fee + 1 gwei priority)
        assert_eq!(s.changes[0].delta, format!("-{}", 500_000_000_000_000_000u128 + 0x1f5a3u128 * (BASE_FEE + 1_000_000_000)));
        assert_eq!(s.changes[1].asset, USDC);
        assert_eq!(s.changes[1].delta, "1274194362"); // 0x4bf2a9ba
        assert_eq!(s.changes[1].display, "+1274.194362 USDC");
    }

    #[test]
    fn erc1155_batches_are_split_per_token_id() {
        let me = "0x1111111111111111111111111111111111111111";
        let s = changes_from_logs(v(ERC1155_BATCH)["logs"].as_array().unwrap(), me, 1, 0).unwrap();
        assert_eq!(s.iter().map(|c| (c.token_id.clone().unwrap(), c.delta.clone())).collect::<Vec<_>>(),
            vec![("5".to_string(), "-3".to_string()), ("7".to_string(), "10".to_string())]);
    }

    #[test]
    fn spoofed_wrapped_native_events_are_ignored() {
        // a Deposit event from a contract that is not the chain's WETH moves nothing
        let me = "0x1111111111111111111111111111111111111111";
        let log = json!({"address": "0x2222222222222222222222222222222222222222", "topics": [format!("0x{DEPOSIT}"), format!("0x{:0>64}", &me[2..])], "data": format!("0x{:064x}", 5u8)});
        assert!(changes_from_logs(&[log], me, 1, 0).unwrap().is_empty());
    }

    #[test]
    fn a_node_without_simulate_v1_falls_back_to_eth_call() {
        let t = tx(HOLDER, USDC, 0, "0xa9059cbb", 100_000);
        assert!(interpret_simulate_v1(&response(METHOD_NOT_FOUND), &t, BASE_FEE, "n", Some(BLOCK)).is_none());
        assert_eq!(simulate_v1_failure(&Ok(response(METHOD_NOT_FOUND))), "it does not support eth_simulateV1");
        // eth_call succeeds, estimate fits: no revert, changes unavailable
        let ok = interpret_fallback(&json!({"result": "0x01"}), Some(&json!({"result": "0xf328"})), &t, "n", Some(BLOCK), "it does not support eth_simulateV1");
        assert_eq!((ok.status, ok.method), ("no_changes", "eth_call"));
        assert!(ok.note.as_deref().unwrap().starts_with("Balance changes unavailable on this node"));
        assert!(host_claim(&ok).is_none());
        // eth_call reverts with Error(string)
        let data = response(USDC_REVERT)["result"][0]["calls"][0]["error"]["data"].clone();
        let rev = interpret_fallback(&json!({"error": {"code": 3, "message": "execution reverted", "data": data}}), None, &t, "n", Some(BLOCK), "x");
        assert_eq!((rev.status, rev.reason.as_deref()), ("reverts", Some("ERC20: transfer amount exceeds balance")));
        // the estimate exceeds the signed gas limit
        let oog = interpret_fallback(&json!({"result": "0x"}), Some(&json!({"result": "0x30d40"})), &t, "n", Some(BLOCK), "x");
        assert_eq!(oog.status, "reverts");
        assert!(oog.reason.unwrap().contains("run out of gas"));
        // the node fails for another reason: uncertainty, not a revert
        let un = interpret_fallback(&json!({"error": {"code": -32000, "message": "header not found"}}), None, &t, "n", Some(BLOCK), "x");
        assert_eq!(un.status, "unavailable");
    }

    #[test]
    fn revert_reasons_are_decoded() {
        assert_eq!(revert_reason(Some("execution reverted: Too little received"), None), "Too little received");
        assert_eq!(revert_reason(Some("execution reverted"), None), "reverted without a reason");
        assert_eq!(revert_reason(None, Some("0x4e487b710000000000000000000000000000000000000000000000000000000000000011")), "arithmetic overflow or underflow (panic 0x11)");
        assert_eq!(revert_reason(Some("execution reverted"), Some("0x5bf6f916")), "custom error 0x5bf6f916"); // TransactionDeadlinePassed()
        // control characters and length are tamed
        let long = format!("execution reverted: {}\u{7}", "x".repeat(300));
        let r = revert_reason(Some(&long), None);
        assert!(r.chars().count() <= 161 && !r.contains('\u{7}'));
    }

    #[test]
    fn the_phone_claim_matches_the_phones_schema() {
        let t = tx(HOLDER, USDC, 0, "0xa9059cbb", 100_000);
        let mut s = interpret_simulate_v1(&response(USDC_TRANSFER), &t, BASE_FEE, "https://user:secret@ethereum-rpc.publicnode.com/path?key=abc", Some(BLOCK)).unwrap();
        s.node = "https://user:secret@ethereum-rpc.publicnode.com/path?key=abc".into();
        let c = host_claim(&s).unwrap();
        let mut keys: Vec<&str> = c.as_object().unwrap().keys().map(String::as_str).collect(); keys.sort();
        assert_eq!(keys, ["block", "changes", "node"]);
        assert_eq!(c["node"], "ethereum-rpc.publicnode.com", "no credentials, path or query reach the phone");
        assert_eq!(c["block"], "0x18f603b");
        assert_eq!(c["changes"][1], json!({"asset": USDC, "delta": "-100000000", "symbol": "USDC", "decimals": 6}));
        assert_eq!(c["changes"][0]["asset"], "native");
        assert_eq!(c["changes"][0]["symbol"], "ETH");
        // more than 16 changes: shown on the Mac, not sent
        s.changes = (0..17).map(|i| Change { asset: OTHER.into(), token_id: Some(i.to_string()), delta: "1".into(), symbol: None, decimals: None, display: String::new() }).collect();
        s.for_phone = false;
        assert!(host_claim(&s).is_none());
        assert_eq!(node_label("https://[::1]:8545"), "custom-node");
        assert_eq!(node_label("https://mainnet.base.org"), "mainnet.base.org");
        assert_eq!(node_label("https://localhost:8545/"), "localhost:8545");
    }

    /// The claim for the recorded USDC transfer is exactly the shared vector the phone's JVM test
    /// (HostSimulationTest.theSharedVectorFromTheMacParsesAndMatches) parses and checks.
    #[test]
    fn the_phone_claim_matches_the_shared_vector() {
        let vector = v(include_str!("../../../app/src/test/resources/host-simulation-vector.json"));
        let r = &vector["request"];
        let t = Tx { from: HOLDER.into(), to: r["to"].as_str().unwrap().into(), value: 0, data: r["data"].as_str().unwrap().into(),
            gas: verify::quantity(r["gasLimit"].as_str().unwrap()).unwrap(), max_fee: verify::quantity(r["maxFeePerGas"].as_str().unwrap()).unwrap(),
            priority: verify::quantity(r["maxPriorityFeePerGas"].as_str().unwrap()).unwrap(), chain: 1 };
        let s = interpret_simulate_v1(&response(USDC_TRANSFER), &t, BASE_FEE, "ethereum-rpc.publicnode.com", Some(BLOCK)).unwrap();
        assert_eq!(host_claim(&s).unwrap(), vector["hostSimulation"]);
    }

    /// Which default nodes support eth_simulateV1 (network; run with `--ignored`).
    #[test]
    #[ignore]
    fn live_default_nodes() {
        for (chain, url) in [(1u64, "https://ethereum-rpc.publicnode.com"), (8453, "https://mainnet.base.org"), (10, "https://optimism-rpc.publicnode.com"),
            (42161, "https://arbitrum-one-rpc.publicnode.com"), (137, "https://polygon-bor-rpc.publicnode.com"), (11155111, "https://ethereum-sepolia-rpc.publicnode.com")] {
            let rpc = eth::Rpc::new(url).unwrap();
            let mut t = tx(OTHER, "0x1111111111111111111111111111111111111111", 0, "0x", 21_000);
            t.chain = chain;
            let s = run(&rpc, &t, &node_label(url));
            println!("{chain} {url}: {} via {} {:?} {:?} {:?}", s.status, s.method, displays(&s), s.reason, s.note);
            assert_eq!((s.status, s.method), ("ok", "eth_simulateV1"), "{url}");
        }
        // a node without eth_simulateV1 (Cloudflare answers -32601): the eth_call fallback
        let s = run(&eth::Rpc::new("https://cloudflare-eth.com").unwrap(), &tx(OTHER, "0x1111111111111111111111111111111111111111", 0, "0x", 21_000), "cloudflare-eth.com");
        println!("fallback: {} via {} {:?} {:?}", s.status, s.method, s.reason, s.note);
        // (Cloudflare's gateway also fails eth_call at times: then "unavailable", which only asks the user to confirm)
        assert!(matches!(s.status, "no_changes" | "unavailable"), "{}", s.status);
    }

    #[test]
    fn results_are_remembered_per_exact_transaction() {
        let mut q: Quote = serde_json::from_value(json!({"chain_id": "0x1", "nonce": "0x0", "max_priority_fee_per_gas": "0x1", "max_fee_per_gas": "0x2", "gas_limit": "0x5208",
            "to": "0xabcdefabcdefabcdefabcdefabcdefabcdef0001", "value": "0x1", "data": "0x", "amount_eth": "", "max_fee_eth": "", "total_eth": "", "balance_eth": "", "network": ""})).unwrap();
        let mut s = Simulation::new("reverts", "eth_simulateV1", "n", Some(1));
        s.reason = Some("nope".into());
        let a1 = "0x1111111111111111111111111111111111111111";
        let a2 = "0x2222222222222222222222222222222222222222";
        remember(&q, a1, &s);
        assert_eq!(recall(&q, a1).unwrap().status, "reverts");
        assert_eq!(recall(&q, &a1.to_ascii_uppercase().replace("0X", "0x")).unwrap().status, "reverts");
        // another paired account sending the same transaction was not simulated
        assert!(recall(&q, a2).is_none());
        // a fee or nonce change is the same execution; another amount is not
        q.max_fee_per_gas = "0x3".into(); q.nonce = "0x1".into();
        assert!(recall(&q, a1).is_some());
        q.value = "0x2".into();
        assert!(recall(&q, a1).is_none());
    }
}
