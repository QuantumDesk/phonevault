//! WalletConnect v2 request policy. The WalletConnect SDK runs in the webview and only moves
//! messages; every decision about what a dApp may ask for is made here, and every signature still
//! comes from the existing commands (`send::sign_start` + `send::broadcast_verified` for
//! transactions, `signing::sign_message` / `signing::sign_typed_data` for messages), which send the
//! request to the phone for review and verify what comes back. Nothing in this file talks to the
//! phone or can produce a signature.
//!
//! What lives here:
//! * the session plan: which requested networks the phone can sign for, and the namespaces to
//!   approve, always with the PAIRED address read from the pairing file (never from the dApp or JS);
//! * request mapping: the method allow-list, JSON-RPC errors for everything else, and strict
//!   normalization of `eth_sendTransaction` parameters (hex quantities, `from` = paired address,
//!   chainId = the session chain, size limits), after which missing fields are filled from the node
//!   and the result is the same `Quote` the Send flow hands to the phone.

use crate::{eth, message, pairing, verify, Quote};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::time::Duration;

/// Chains the phone has a reviewed profile for (Eip1559Request.supportedChain). Must match it.
pub const ALLOWED_CHAINS: [u64; 6] = [1, 10, 137, 8453, 42161, 11155111];
/// Methods a session is offered. Everything else is refused per request.
pub const SUPPORTED_METHODS: [&str; 7] = [
    "eth_sendTransaction", "personal_sign", "eth_signTypedData_v4",
    "eth_chainId", "eth_accounts", "eth_requestAccounts", "wallet_switchEthereumChain",
];
const EVENTS: [&str; 2] = ["chainChanged", "accountsChanged"];
/// Calldata cap. The USB request line is 32 KiB and the phone currently accepts only empty
/// calldata or a 68-byte token call, so this is generous; it bounds what is shown and sent.
pub const MAX_DATA_BYTES: usize = 12 * 1024;
/// Upper bound for a gas limit a dApp may ask for (about one mainnet block).
pub const MAX_GAS: u128 = 30_000_000;

// JSON-RPC / EIP-1193 error codes
pub const UNAUTHORIZED: i64 = 4100;
pub const UNSUPPORTED_METHOD: i64 = 4200;
pub const CHAIN_DISCONNECTED: i64 = 4901;
pub const UNRECOGNIZED_CHAIN: i64 = 4902;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL: i64 = -32603;
pub const TX_REJECTED: i64 = -32003;

/// A JSON-RPC error to send back to the dApp. Also the error type of `wc_prepare`.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct RpcError { pub code: i64, pub message: String }
fn rpc_err(code: i64, message: impl Into<String>) -> RpcError { RpcError { code, message: message.into() } }
fn bad(message: impl Into<String>) -> RpcError { rpc_err(INVALID_PARAMS, message) }

pub fn chain_allowed(id: u64) -> bool { ALLOWED_CHAINS.contains(&id) }

pub fn chain_name(id: u64) -> String {
    match id {
        1 => "Ethereum".into(), 10 => "Optimism".into(), 137 => "Polygon".into(), 8453 => "Base".into(),
        42161 => "Arbitrum One".into(), 11155111 => "Sepolia (testnet)".into(), c => format!("Chain {c}"),
    }
}

/// "eip155:8453" → 8453. Anything else (other namespaces, junk) → None.
pub fn parse_caip2(s: &str) -> Option<u64> {
    let id = s.strip_prefix("eip155:")?;
    if id.is_empty() || id.len() > 19 || !id.bytes().all(|b| b.is_ascii_digit()) || (id.len() > 1 && id.starts_with('0')) { return None; }
    id.parse().ok()
}

fn is_address(s: &str) -> bool { s.len() == 42 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit()) }

/// Address from a dApp: 0x + 40 hex; if written in mixed case it must be a valid EIP-55 checksum.
pub fn dapp_address(s: &str, what: &str) -> Result<String, RpcError> {
    if !is_address(s) { return Err(bad(format!("{what} must be a 0x address with 40 hex characters"))); }
    let body = &s[2..];
    let mixed = body.bytes().any(|b| b.is_ascii_uppercase()) && body.bytes().any(|b| b.is_ascii_lowercase());
    if mixed && verify::checksum(s) != s { return Err(bad(format!("{what} fails its EIP-55 checksum"))); }
    Ok(s.to_ascii_lowercase())
}

/// Hex quantity from a dApp: "0x" + 1…64 hex digits. Leading zeros are tolerated (JSON-RPC
/// clients differ) but the value must fit in 128 bits. Decimal strings and JSON numbers are refused.
pub fn dapp_quantity(v: &Value, what: &str) -> Result<u128, RpcError> {
    let s = v.as_str().ok_or_else(|| bad(format!("{what} must be a 0x hex string")))?;
    let body = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).ok_or_else(|| bad(format!("{what} must be 0x-prefixed hex, got {s:?}")))?;
    if body.is_empty() || body.len() > 64 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad(format!("{what} is not a hex quantity: {s:?}")));
    }
    let digits = body.trim_start_matches('0');
    if digits.len() > 32 { return Err(bad(format!("{what} is too large"))); }
    if digits.is_empty() { return Ok(0); }
    u128::from_str_radix(digits, 16).map_err(|_| bad(format!("{what} is not a hex quantity")))
}

fn dapp_bytes(v: &Value, what: &str) -> Result<String, RpcError> {
    let s = v.as_str().ok_or_else(|| bad(format!("{what} must be a 0x hex string")))?;
    let body = s.strip_prefix("0x").ok_or_else(|| bad(format!("{what} must be 0x-prefixed hex")))?;
    if body.len() % 2 != 0 || !body.bytes().all(|b| b.is_ascii_hexdigit()) { return Err(bad(format!("{what} must be even-length hex"))); }
    if body.len() / 2 > MAX_DATA_BYTES { return Err(bad(format!("{what} is {} bytes; the limit is {MAX_DATA_BYTES}", body.len() / 2))); }
    Ok(format!("0x{}", body.to_ascii_lowercase()))
}

// ---------------------------------------------------------------- session plan

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ChainOffer { pub caip: String, pub id: u64, pub name: String, pub supported: bool, pub required: bool }

#[derive(Serialize, Debug, Default)]
pub struct SessionPlan {
    /// Every eip155 chain the dApp named, required ones first.
    pub chains: Vec<ChainOffer>,
    /// Every method the dApp named (required and optional).
    pub methods: Vec<String>,
    /// Methods the dApp named that this wallet always refuses.
    pub refused_methods: Vec<String>,
    /// Required methods among `refused_methods`: approved so the session can exist, refused per call.
    pub required_refused_methods: Vec<String>,
    /// Non-EVM namespaces the dApp asked for.
    pub other_namespaces: Vec<String>,
    /// Why this proposal cannot be approved, if it cannot.
    pub blocker: Option<String>,
}

struct Requested { chains: Vec<(String, bool)>, methods: Vec<(String, bool)>, events: Vec<(String, bool)>, other: Vec<(String, bool)> }

/// Flatten requiredNamespaces/optionalNamespaces. Keys are "eip155" (with a `chains` list) or a
/// chain-specific key like "eip155:1" (no list).
fn requested(required: &Value, optional: &Value) -> Requested {
    let mut r = Requested { chains: vec![], methods: vec![], events: vec![], other: vec![] };
    fn push(list: &mut Vec<(String, bool)>, item: &str, req: bool) {
        if let Some(e) = list.iter_mut().find(|(s, _)| s == item) { e.1 |= req; } else { list.push((item.to_string(), req)); }
    }
    for (ns, req) in [(required, true), (optional, false)] {
        let Some(map) = ns.as_object() else { continue };
        for (key, body) in map {
            let (space, key_chain) = match key.split_once(':') { Some((s, _)) => (s, Some(key.as_str())), None => (key.as_str(), None) };
            if space != "eip155" { push(&mut r.other, key, req); continue; }
            if let Some(c) = key_chain { push(&mut r.chains, c, req); }
            for c in body.get("chains").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                if c.starts_with("eip155:") { push(&mut r.chains, c, req); } else { push(&mut r.other, c, req); }
            }
            for m in body.get("methods").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) { push(&mut r.methods, m, req); }
            for e in body.get("events").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) { push(&mut r.events, e, req); }
        }
    }
    r.chains.sort_by_key(|(_, req)| !*req); // stable: required first, dApp order kept
    r
}

pub fn plan_session(required: &Value, optional: &Value) -> SessionPlan {
    let r = requested(required, optional);
    let mut plan = SessionPlan::default();
    for (caip, req) in &r.chains {
        let id = parse_caip2(caip);
        plan.chains.push(ChainOffer { caip: caip.clone(), id: id.unwrap_or(0), name: id.map(chain_name).unwrap_or_else(|| caip.clone()), supported: id.is_some_and(chain_allowed), required: *req });
    }
    for (m, req) in &r.methods {
        plan.methods.push(m.clone());
        if !SUPPORTED_METHODS.contains(&m.as_str()) {
            plan.refused_methods.push(m.clone());
            if *req { plan.required_refused_methods.push(m.clone()); }
        }
    }
    plan.other_namespaces = r.other.iter().map(|(s, _)| s.clone()).collect();
    let required_other: Vec<&str> = r.other.iter().filter(|(_, req)| *req).map(|(s, _)| s.as_str()).collect();
    let required_unsupported: Vec<&str> = plan.chains.iter().filter(|c| c.required && !c.supported).map(|c| c.name.as_str()).collect();
    plan.blocker = if !required_other.is_empty() {
        Some(format!("It requires {}, which this wallet does not support (Ethereum-compatible networks only).", required_other.join(", ")))
    } else if !required_unsupported.is_empty() {
        Some(format!("It requires {}, which your phone has no reviewed profile for.", required_unsupported.join(", ")))
    } else if !plan.chains.iter().any(|c| c.supported) {
        Some("It didn't ask for any network your phone can sign for.".into())
    } else { None };
    plan
}

/// The namespaces to approve: the selected chains (each requested by the dApp, each on the
/// allow-list, every required chain included), the supported methods plus any required ones
/// (refused per call), and accounts built from the PAIRED address.
pub fn build_namespaces(required: &Value, optional: &Value, selected: &[u64], paired: &str) -> Result<Value, String> {
    let plan = plan_session(required, optional);
    if let Some(b) = plan.blocker { return Err(b); }
    if selected.is_empty() { return Err("choose at least one network".into()); }
    let mut chains: Vec<u64> = vec![];
    for &id in selected {
        if !chain_allowed(id) { return Err(format!("your phone has no reviewed profile for chain {id}")); }
        if !plan.chains.iter().any(|c| c.id == id) { return Err(format!("the dApp did not ask for chain {id}")); }
        if !chains.contains(&id) { chains.push(id); }
    }
    if let Some(missing) = plan.chains.iter().find(|c| c.required && !chains.contains(&c.id)) {
        return Err(format!("the dApp requires {}; it must be included", missing.name));
    }
    let r = requested(required, optional);
    let mut methods: Vec<String> = SUPPORTED_METHODS.iter().map(|s| s.to_string()).collect();
    for (m, req) in &r.methods { if *req && !methods.contains(m) { methods.push(m.clone()); } }
    let mut events: Vec<String> = EVENTS.iter().map(|s| s.to_string()).collect();
    for (e, req) in &r.events { if *req && !events.contains(e) { events.push(e.clone()); } }
    let address = verify::checksum(paired);
    Ok(json!({"eip155": {
        "chains": chains.iter().map(|c| format!("eip155:{c}")).collect::<Vec<_>>(),
        "methods": methods,
        "events": events,
        "accounts": chains.iter().map(|c| format!("eip155:{c}:{address}")).collect::<Vec<_>>(),
    }}))
}

/// Add one allow-listed chain (and the paired account on it) to approved namespaces.
pub fn add_chain(namespaces: &Value, chain: u64, paired: &str) -> Result<Value, String> {
    if !chain_allowed(chain) { return Err(format!("your phone has no reviewed profile for chain {chain}")); }
    let mut ns = namespaces.clone();
    let eip = ns.get_mut("eip155").and_then(Value::as_object_mut).ok_or("the session has no eip155 namespace")?;
    let caip = format!("eip155:{chain}");
    let account = format!("{caip}:{}", verify::checksum(paired));
    for (key, item) in [("chains", caip), ("accounts", account)] {
        let list = eip.entry(key).or_insert_with(|| json!([])).as_array_mut().ok_or("malformed namespace")?;
        if !list.iter().any(|v| v.as_str() == Some(item.as_str())) { list.push(Value::String(item)); }
    }
    Ok(ns)
}

/// True when every account in the session's namespaces is the paired address.
pub fn session_matches(namespaces: &Value, paired: &str) -> bool {
    let mut any = false;
    for body in namespaces.as_object().into_iter().flat_map(|m| m.values()) {
        for acc in body.get("accounts").and_then(Value::as_array).into_iter().flatten() {
            let Some(a) = acc.as_str() else { return false };
            match a.rsplit_once(':') { Some((_, addr)) if addr.eq_ignore_ascii_case(paired) => any = true, _ => return false }
        }
    }
    any
}

// ---------------------------------------------------------------- requests

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Note { pub level: &'static str, pub text: String }
fn note(level: &'static str, text: impl Into<String>) -> Note { Note { level, text: text.into() } }

/// `eth_sendTransaction` parameters after validation, before the node fills the gaps.
#[derive(Debug, Clone, PartialEq)]
pub struct TxDraft {
    pub to: String, pub value: u128, pub data: String,
    pub gas: Option<u128>, pub max_fee: Option<u128>, pub max_priority: Option<u128>, pub nonce: Option<u128>,
    pub notes: Vec<Note>,
}

const TX_KEYS: [&str; 14] = ["from", "to", "value", "data", "input", "gas", "gasLimit", "maxFeePerGas", "maxPriorityFeePerGas", "gasPrice", "nonce", "chainId", "type", "accessList"];

pub fn normalize_tx(params: &Value, paired: &str, chain: u64) -> Result<TxDraft, RpcError> {
    let list = params.as_array().ok_or_else(|| bad("params must be an array"))?;
    if list.len() != 1 { return Err(bad("eth_sendTransaction takes exactly one transaction object")); }
    let tx: &Map<String, Value> = list[0].as_object().ok_or_else(|| bad("the transaction must be an object"))?;
    let unknown: Vec<&str> = tx.keys().map(String::as_str).filter(|k| !TX_KEYS.contains(k)).collect();
    if !unknown.is_empty() { return Err(bad(format!("unsupported transaction fields: {}", unknown.join(", ")))); }
    let field = |k: &str| tx.get(k).filter(|v| !v.is_null());
    let mut notes = vec![];

    match field("from") {
        Some(v) => {
            let from = dapp_address(v.as_str().ok_or_else(|| bad("from must be an address"))?, "from")?;
            if from != paired.to_ascii_lowercase() { return Err(rpc_err(UNAUTHORIZED, format!("from {} is not the account this wallet connected ({})", verify::checksum(&from), verify::checksum(paired)))); }
        }
        None => notes.push(note("info", "The dApp did not name the sending account; your paired phone's address is used.")),
    }
    if let Some(v) = field("chainId") {
        let c = dapp_quantity(v, "chainId")?;
        if c != chain as u128 { return Err(bad(format!("the transaction is for chain {c}, but this request came on {} ({chain})", chain_name(chain)))); }
    }
    if let Some(t) = field("type") {
        let t = dapp_quantity(t, "type")?;
        if t != 0 && t != 2 { return Err(bad(format!("transaction type {t} is not supported (EIP-1559 only)"))); }
    }
    if let Some(a) = field("accessList") {
        if !a.as_array().is_some_and(|l| l.is_empty()) { return Err(bad("access lists are not supported: the phone signs with an empty access list")); }
    }
    let to = match field("to") {
        Some(v) => dapp_address(v.as_str().ok_or_else(|| bad("to must be an address"))?, "to")?,
        None => return Err(bad("contract deployment (no `to`) is not supported")),
    };
    if to[2..].bytes().all(|b| b == b'0') { return Err(bad("refusing the zero address as recipient")); }
    let value = field("value").map(|v| dapp_quantity(v, "value")).transpose()?.unwrap_or(0);
    let data = match (field("data"), field("input")) {
        (Some(d), Some(i)) => { let (d, i) = (dapp_bytes(d, "data")?, dapp_bytes(i, "input")?); if d != i { return Err(bad("data and input differ")); } d }
        (Some(d), None) | (None, Some(d)) => dapp_bytes(d, "data")?,
        (None, None) => "0x".into(),
    };
    let gas = match (field("gas"), field("gasLimit")) {
        (Some(a), Some(b)) => { let (a, b) = (dapp_quantity(a, "gas")?, dapp_quantity(b, "gasLimit")?); if a != b { return Err(bad("gas and gasLimit differ")); } Some(a) }
        (Some(a), None) | (None, Some(a)) => Some(dapp_quantity(a, "gas")?),
        (None, None) => None,
    };
    if let Some(g) = gas { if !(21_000..=MAX_GAS).contains(&g) { return Err(bad(format!("gas limit {g} is outside 21000…{MAX_GAS}"))); } }
    let max_fee = field("maxFeePerGas").map(|v| dapp_quantity(v, "maxFeePerGas")).transpose()?;
    let max_priority = field("maxPriorityFeePerGas").map(|v| dapp_quantity(v, "maxPriorityFeePerGas")).transpose()?;
    if let (Some(f), Some(p)) = (max_fee, max_priority) { if p > f { return Err(bad("maxPriorityFeePerGas exceeds maxFeePerGas")); } }
    if field("gasPrice").is_some() {
        if max_fee.is_some() || max_priority.is_some() { return Err(bad("gasPrice cannot be combined with EIP-1559 fee fields")); }
        dapp_quantity(field("gasPrice").unwrap(), "gasPrice")?;
        notes.push(note("info", "The dApp suggested a legacy gas price; fees are quoted from your node instead (EIP-1559)."));
    }
    let nonce = field("nonce").map(|v| dapp_quantity(v, "nonce")).transpose()?;
    Ok(TxDraft { to, value, data, gas, max_fee, max_priority, nonce, notes })
}

/// What the calldata is, for the Mac card. The phone does its own, stricter decoding.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct CallInfo {
    /// "transfer" | "token_transfer" | "token_approve" | "contract_call"
    pub kind: &'static str,
    pub selector: Option<String>,
    pub data_bytes: usize,
    /// token recipient / spender (checksummed)
    pub party: Option<String>,
    /// raw token amount: decimal, or "unlimited" for max uint256
    pub amount: Option<String>,
    /// whether the phone's current transaction review accepts this shape
    pub phone_supported: bool,
}

pub fn call_info(data: &str, value: u128) -> CallInfo {
    let body = data.trim_start_matches("0x");
    let bytes = body.len() / 2;
    if body.is_empty() { return CallInfo { kind: "transfer", selector: None, data_bytes: 0, party: None, amount: None, phone_supported: true }; }
    let selector = body.get(..8).map(|s| format!("0x{s}"));
    let token = match selector.as_deref() { Some("0xa9059cbb") => Some("token_transfer"), Some("0x095ea7b3") => Some("token_approve"), _ => None };
    if let (Some(kind), 68) = (token, bytes) {
        let word = &body[8..72];
        let amount_hex = &body[72..136];
        let party = verify::checksum(&format!("0x{}", &word[24..]));
        let amount = if amount_hex.bytes().all(|b| b == b'f') { "unlimited".to_string() }
            else if amount_hex[..32].bytes().all(|b| b == b'0') { u128::from_str_radix(&amount_hex[32..], 16).map(|v| v.to_string()).unwrap_or_default() }
            else { format!("0x{}", amount_hex.trim_start_matches('0')) };
        let clean_pad = word[..24].bytes().all(|b| b == b'0');
        return CallInfo { kind, selector, data_bytes: bytes, party: Some(party), amount: Some(amount), phone_supported: clean_pad && value == 0 };
    }
    CallInfo { kind: "contract_call", selector, data_bytes: bytes, party: None, amount: None, phone_supported: false }
}

/// `personal_sign` params → (0x hex bytes to sign, text if the bytes are UTF-8).
/// Canonical order is [message, address]; the reversed order some dApps send is accepted only when
/// it is unambiguous (first param is the paired address, second is not an address).
pub fn personal_sign_params(params: &Value, paired: &str) -> Result<(String, Option<String>), RpcError> {
    let list = params.as_array().ok_or_else(|| bad("params must be an array"))?;
    if list.len() < 2 || list.len() > 3 { return Err(bad("personal_sign takes [message, address]")); }
    let a = list[0].as_str().ok_or_else(|| bad("message must be a string"))?;
    let b = list[1].as_str().ok_or_else(|| bad("address must be a string"))?;
    let paired_l = paired.to_ascii_lowercase();
    let (msg, addr) = if is_address(b) { (a, b) } else if is_address(a) && a.eq_ignore_ascii_case(&paired_l) { (b, a) } else { return Err(bad("personal_sign takes [message, address]")); };
    if dapp_address(addr, "address")? != paired_l { return Err(rpc_err(UNAUTHORIZED, format!("the message is for {}, not the account this wallet connected", verify::checksum(addr)))); }
    let bytes = match msg.strip_prefix("0x") {
        Some(h) if h.len() % 2 == 0 && h.bytes().all(|c| c.is_ascii_hexdigit()) => hex::decode(h).map_err(|_| bad("bad hex message"))?,
        _ => msg.as_bytes().to_vec(),
    };
    if bytes.is_empty() { return Err(bad("the message is empty")); }
    if bytes.len() > message::MAX_MESSAGE_BYTES { return Err(bad(format!("the message is {} bytes; the phone's limit is {}", bytes.len(), message::MAX_MESSAGE_BYTES))); }
    let text = String::from_utf8(bytes.clone()).ok();
    Ok((format!("0x{}", hex::encode(&bytes)), text))
}

#[derive(Serialize, Debug, Clone, PartialEq, Default)]
pub struct TypedSummary {
    pub primary_type: String, pub domain_name: Option<String>, pub domain_version: Option<String>,
    pub domain_chain: Option<u64>, pub verifying_contract: Option<String>,
}

/// `eth_signTypedData_v4` params [address, typedData] → (typed data JSON text, summary). The text
/// must pass the same strict parser the phone uses, so a request the phone would refuse never
/// reaches it.
pub fn typed_data_params(params: &Value, paired: &str) -> Result<(String, TypedSummary), RpcError> {
    let list = params.as_array().ok_or_else(|| bad("params must be an array"))?;
    if list.len() != 2 { return Err(bad("eth_signTypedData_v4 takes [address, typedData]")); }
    let addr = list[0].as_str().ok_or_else(|| bad("address must be a string"))?;
    if dapp_address(addr, "address")? != paired.to_ascii_lowercase() { return Err(rpc_err(UNAUTHORIZED, format!("the data is for {}, not the account this wallet connected", verify::checksum(addr)))); }
    let text = match &list[1] {
        Value::String(s) => s.clone(),
        v @ Value::Object(_) => serde_json::to_string(v).map_err(|e| bad(e.to_string()))?,
        _ => return Err(bad("typedData must be a JSON string or object")),
    };
    if text.len() > message::MAX_TYPED_DATA_BYTES { return Err(bad(format!("typed data is {} bytes; the phone's limit is {}", text.len(), message::MAX_TYPED_DATA_BYTES))); }
    message::typed_data_digest(&text).map_err(|e| bad(format!("typed data refused: {}", e.0)))?;
    let v: Value = serde_json::from_str(&text).map_err(|_| bad("typed data is not JSON"))?;
    let d = &v["domain"];
    let chain = match &d["chainId"] { Value::Number(n) => n.as_u64(), Value::String(s) => if let Some(h) = s.strip_prefix("0x") { u64::from_str_radix(h, 16).ok() } else { s.parse().ok() }, _ => None };
    Ok((text, TypedSummary {
        primary_type: v["primaryType"].as_str().unwrap_or("").to_string(),
        domain_name: d["name"].as_str().map(str::to_string), domain_version: d["version"].as_str().map(str::to_string),
        domain_chain: chain, verifying_contract: d["verifyingContract"].as_str().map(verify::checksum),
    }))
}

/// What the UI should do with a request. Anything not listed becomes an `RpcError`.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)] // one short-lived value per request, serialized at once
pub enum Prepared {
    /// Answer at once, no phone involved (eth_chainId, eth_accounts).
    Answer { result: Value },
    /// Same quote the Send flow uses; goes through send::sign_start → verify → broadcast_verified.
    Transaction { chain_id: u64, quote: Quote, call: CallInfo, notes: Vec<Note> },
    /// Goes through signing::sign_message (hex) → verified signature.
    PersonalSign { chain_id: u64, message_hex: String, text: Option<String>, notes: Vec<Note> },
    /// Goes through signing::sign_typed_data → verified signature.
    TypedData { chain_id: u64, typed_data: String, summary: TypedSummary, notes: Vec<Note> },
    /// Ask the user; on yes the UI adds the chain (wc_add_chain) and answers null.
    SwitchChain { chain_id: u64, name: String, in_session: bool },
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self { Prepared::Answer { .. } => "Answer", Prepared::Transaction { .. } => "Transaction", Prepared::PersonalSign { .. } => "PersonalSign", Prepared::TypedData { .. } => "TypedData", Prepared::SwitchChain { .. } => "SwitchChain" };
        write!(f, "Prepared::{kind}")
    }
}

/// Method routing that needs no node: everything except filling a transaction.
pub fn route(method: &str, params: &Value, chain: u64, session_chains: &[u64], paired: &str) -> Result<Prepared, RpcError> {
    match method {
        "eth_chainId" => Ok(Prepared::Answer { result: json!(verify::to_quantity(chain as u128)) }),
        "eth_accounts" | "eth_requestAccounts" => Ok(Prepared::Answer { result: json!([verify::checksum(paired)]) }),
        "personal_sign" => {
            let (message_hex, text) = personal_sign_params(params, paired)?;
            let mut notes = vec![];
            if text.is_none() { notes.push(note("danger", "This is not readable text. Sign only if you know exactly what it is.")); }
            else if message_hex.len() == 66 { notes.push(note("warn", "32 bytes, the size of a hash.")); }
            Ok(Prepared::PersonalSign { chain_id: chain, message_hex, text, notes })
        }
        "eth_signTypedData_v4" => {
            let (typed_data, summary) = typed_data_params(params, paired)?;
            let mut notes = vec![];
            match summary.domain_chain {
                Some(c) if c != chain => notes.push(note("danger", format!("The data names chain {c} ({}), but the dApp is connected on {}.", chain_name(c), chain_name(chain)))),
                None => notes.push(note("warn", "The data does not name a chain, so it could be valid on any network.")),
                _ => {}
            }
            if summary.primary_type.to_ascii_lowercase().contains("permit") { notes.push(note("danger", "This is a permit: it lets someone move your tokens without another transaction.")); }
            Ok(Prepared::TypedData { chain_id: chain, typed_data, summary, notes })
        }
        "wallet_switchEthereumChain" => {
            let target = params.as_array().and_then(|l| l.first()).and_then(|o| o.get("chainId")).ok_or_else(|| bad("wallet_switchEthereumChain takes [{chainId}]"))?;
            let id = dapp_quantity(target, "chainId")?;
            let id = u64::try_from(id).map_err(|_| rpc_err(UNRECOGNIZED_CHAIN, "unrecognized chain"))?;
            if !chain_allowed(id) { return Err(rpc_err(UNRECOGNIZED_CHAIN, format!("Unrecognized chain {id}: your phone has no reviewed profile for it"))); }
            Ok(Prepared::SwitchChain { chain_id: id, name: chain_name(id), in_session: session_chains.contains(&id) })
        }
        "eth_sign" => Err(rpc_err(UNSUPPORTED_METHOD, "eth_sign is refused: it signs an opaque hash that nobody can review. Use personal_sign or eth_signTypedData_v4.")),
        "eth_signTransaction" => Err(rpc_err(UNSUPPORTED_METHOD, "eth_signTransaction is refused: this wallet only returns transactions it broadcast itself. Use eth_sendTransaction.")),
        "eth_sendTransaction" => Err(rpc_err(INTERNAL, "eth_sendTransaction needs a node")), // handled by prepare_tx
        m => Err(rpc_err(UNSUPPORTED_METHOD, format!("{m} is not supported by Phone Vault"))),
    }
}

// ---------------------------------------------------------------- node

/// Minimal JSON-RPC call for the dApp's gas estimate. Not `eth::Rpc::estimate_gas_data`, so that
/// the node's own refusal text reaches the dApp unprefixed and the answer is parsed with the
/// strict `dapp_quantity` rather than `eth::Rpc`'s lenient hex parse.
fn node_call(url: &str, method: &str, params: Value) -> Result<Value, String> {
    if !url.starts_with("https://") { return Err("the node URL must use https://".into()); }
    let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(20)).redirect(reqwest::redirect::Policy::none()).build().map_err(|e| e.to_string())?;
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let http = client.post(url).json(&body).send().map_err(|e| eth::transport_error(&e))?;
    let bytes = eth::read_capped(http, eth::MAX_RESPONSE)?;
    let resp: Value = serde_json::from_slice(&bytes).map_err(|e| format!("node returned non-JSON: {e}"))?;
    if let Some(e) = resp.get("error") { return Err(e.get("message").and_then(Value::as_str).unwrap_or("node error").to_string()); }
    resp.get("result").cloned().ok_or_else(|| format!("node returned no result for {method}"))
}

/// Gas limit for a call: the node's estimate, +20 % headroom for anything but a plain transfer.
pub fn gas_with_headroom(estimate: u128, plain_transfer: bool) -> u128 {
    if plain_transfer && estimate == 21_000 { 21_000 } else { estimate.saturating_mul(6).div_ceil(5) }
}

fn prepare_tx(rpc_url: &str, chain: u64, params: &Value, paired: &str) -> Result<Prepared, RpcError> {
    let draft = normalize_tx(params, paired, chain)?;
    let mut notes = draft.notes.clone();
    let node = |e: eth::EthError| rpc_err(INTERNAL, e.0);
    let rpc = eth::Rpc::new(rpc_url).map_err(node)?;
    let node_chain = rpc.chain_id().map_err(node)?;
    if node_chain != chain as u128 { return Err(rpc_err(INTERNAL, format!("the node for {} answers for chain {node_chain}; check the node in Settings", chain_name(chain)))); }
    let pending = rpc.nonce(paired).map_err(node)?;
    let nonce = match draft.nonce {
        Some(n) if n != pending => { notes.push(note("warn", format!("The dApp set nonce {n}; your next nonce is {pending}. A different nonce can replace or wait behind another transaction."))); n }
        Some(n) => n,
        None => pending,
    };
    let (priority, max_fee) = match (draft.max_priority, draft.max_fee) {
        (Some(p), Some(f)) => { notes.push(note("info", "Fees as suggested by the dApp.")); (p, f) }
        (p, f) => {
            let (np, nf) = rpc.fees().map_err(node)?;
            let p = p.unwrap_or(np);
            let f = f.unwrap_or(nf).max(p);
            (p, f)
        }
    };
    let gas = match draft.gas {
        Some(g) => g,
        None => {
            let call = json!({"from": paired, "to": draft.to, "value": verify::to_quantity(draft.value), "data": draft.data});
            let est = node_call(rpc_url, "eth_estimateGas", json!([call])).map_err(|e| rpc_err(TX_REJECTED, format!("the node expects this transaction to fail: {e}")))?;
            let est = dapp_quantity(&est, "gas estimate")?;
            gas_with_headroom(est, draft.data == "0x")
        }
    };
    if gas > MAX_GAS { return Err(bad(format!("gas limit {gas} exceeds {MAX_GAS}"))); }
    let balance = rpc.balance(paired).map_err(node)?;
    let max_cost = gas.checked_mul(max_fee).ok_or_else(|| bad("fee overflow"))?;
    let total = draft.value.checked_add(max_cost).ok_or_else(|| bad("total overflow"))?;
    if total > balance { return Err(rpc_err(TX_REJECTED, format!("insufficient funds: up to {} needed, {} available", eth::format_eth(total), eth::format_eth(balance)))); }
    let call = call_info(&draft.data, draft.value);
    match call.kind {
        "contract_call" => notes.push(note("danger", "This calls a contract. Your phone currently signs only plain transfers and token transfer/approve calls, so it will refuse this.")),
        "token_approve" if call.amount.as_deref() == Some("unlimited") => notes.push(note("danger", "Unlimited approval: the spender can move all of this token, now and later.")),
        "token_approve" => notes.push(note("warn", "Token approval: the spender can move up to this amount of the token.")),
        _ => {}
    }
    if !call.phone_supported && call.kind != "contract_call" { notes.push(note("warn", "This token call is not in the canonical form your phone accepts; it will refuse it.")); }
    let quote = Quote {
        chain_id: verify::to_quantity(chain as u128), nonce: verify::to_quantity(nonce), max_priority_fee_per_gas: verify::to_quantity(priority),
        max_fee_per_gas: verify::to_quantity(max_fee), gas_limit: verify::to_quantity(gas), to: draft.to.clone(),
        value: verify::to_quantity(draft.value), data: draft.data.clone(),
        amount_eth: eth::format_eth(draft.value), max_fee_eth: eth::format_eth(max_cost), total_eth: eth::format_eth(total),
        balance_eth: eth::format_eth(balance), network: crate::network_name(chain as u128),
        // dApp calldata is passed through as-is; verify.rs checks it byte-for-byte, not as a token send
        token: None, replaces: None,
    };
    Ok(Prepared::Transaction { chain_id: chain, quote, call, notes })
}

fn paired_or_err() -> Result<String, RpcError> {
    pairing::load().map_err(|e| rpc_err(UNAUTHORIZED, e.0))?.ok_or_else(|| rpc_err(UNAUTHORIZED, "this wallet is not paired with a phone"))
}

// ---------------------------------------------------------------- commands

#[tauri::command]
pub fn wc_plan_session(required: Value, optional: Value) -> SessionPlan { plan_session(&required, &optional) }

#[tauri::command]
pub fn wc_session_namespaces(required: Value, optional: Value, selected: Vec<u64>) -> Result<Value, String> {
    let paired = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
    build_namespaces(&required, &optional, &selected, &paired)
}

#[tauri::command]
pub fn wc_add_chain(namespaces: Value, chain_id: u64) -> Result<Value, String> {
    let paired = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
    add_chain(&namespaces, chain_id, &paired)
}

#[tauri::command]
pub fn wc_session_matches(namespaces: Value) -> bool {
    matches!(pairing::load(), Ok(Some(p)) if session_matches(&namespaces, &p))
}

/// Validate and map one dApp request. `chain` is the request's CAIP-2 chain; `session_chains` the
/// chains the session was approved for; `rpc_url` the user's node for that chain.
///
/// `origin`: the site that asked, only when it is trusted: the browser-reported origin (extension)
/// or WalletConnect Verify's origin when it says VALID. It is what a sign-in (EIP-4361) message is
/// checked against; without one a sign-in is only warned about.
#[tauri::command]
pub async fn wc_prepare(rpc_url: Option<String>, chain: String, session_chains: Vec<String>, method: String, params: Value, origin: Option<String>) -> Result<Prepared, RpcError> {
    tauri::async_runtime::spawn_blocking(move || {
        let paired = paired_or_err()?;
        let origin = trusted_origin(origin.as_deref());
        let id = parse_caip2(&chain).ok_or_else(|| rpc_err(CHAIN_DISCONNECTED, format!("{chain} is not an EVM chain")))?;
        let session: Vec<u64> = session_chains.iter().filter_map(|c| parse_caip2(c)).collect();
        if !session.contains(&id) { return Err(rpc_err(CHAIN_DISCONNECTED, format!("{} is not part of this session", chain_name(id)))); }
        if !chain_allowed(id) { return Err(rpc_err(CHAIN_DISCONNECTED, format!("your phone has no reviewed profile for chain {id}"))); }
        if method == "eth_sendTransaction" {
            let url = rpc_url.ok_or_else(|| rpc_err(INTERNAL, "no node configured for this chain"))?;
            return prepare_tx(&url, id, &params, &paired);
        }
        let mut prep = route(&method, &params, id, &session, &paired)?;
        sign_in_gate(&mut prep, origin.as_deref())?;
        Ok(prep)
    }).await.map_err(|e| rpc_err(INTERNAL, e.to_string()))?
}

/// A site origin the webview passed, in the bridge's normal form; anything malformed is dropped
/// (and then treated as unverified).
pub fn trusted_origin(origin: Option<&str>) -> Option<String> {
    origin.filter(|o| !o.is_empty()).and_then(|o| crate::bridge::normalize_origin(o).ok())
}

/// Sign-In with Ethereum: refuse a sign-in message for another site than the one asking; warn
/// when it is not known which site is asking.
pub fn sign_in_gate(prep: &mut Prepared, origin: Option<&str>) -> Result<(), RpcError> {
    let Prepared::PersonalSign { text: Some(text), notes, .. } = prep else { return Ok(()) };
    match crate::siwe::check(text, origin) {
        crate::siwe::Check::NotSignIn => {}
        crate::siwe::Check::Mismatch { domain, site } => return Err(rpc_err(UNAUTHORIZED, crate::siwe::blocked_message(&site, &domain))),
        crate::siwe::Check::Unverified { domain } => notes.insert(0, note("danger", format!(
            "This signs you in to {domain}, but which site is asking could not be verified. Sign only if you opened {domain} yourself."))),
        crate::siwe::Check::Matches { domain } => notes.push(note("info", format!("Signs you in to {domain}, the site that is asking."))),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const ME: &str = "0x7a3b9c1d2e4f5061728394a5b6c7d8e9f0a1b2c3";
    const TO: &str = "0x1111111111111111111111111111111111111111";

    fn tx(obj: Value) -> Result<TxDraft, RpcError> { normalize_tx(&json!([obj]), ME, 8453) }

    #[test]
    fn sign_in_messages_are_checked_against_the_asking_site() {
        let siwe = |domain: &str| format!("0x{}", hex::encode(format!("{domain} wants you to sign in with your Ethereum account:\n{ME}\n\nURI: https://{domain}\nVersion: 1\nChain ID: 1\nNonce: 1\nIssued At: 2021-09-30T16:25:24Z")));
        let prep = |domain: &str, origin: Option<&str>| -> Result<Prepared, RpcError> {
            let mut p = route("personal_sign", &json!([siwe(domain), ME]), 1, &[1], ME)?;
            sign_in_gate(&mut p, trusted_origin(origin).as_deref())?;
            Ok(p)
        };
        let notes = |p: Prepared| match p { Prepared::PersonalSign { notes, .. } => notes, _ => panic!() };
        // matching site: an info note
        let n = notes(prep("app.uniswap.org", Some("https://app.uniswap.org")).unwrap());
        assert!(n.iter().any(|n| n.level == "info" && n.text.contains("app.uniswap.org")), "{n:?}");
        // another site: refused with a message naming both
        let e = prep("opensea.io", Some("https://evil.example")).unwrap_err();
        assert_eq!(e.code, UNAUTHORIZED);
        assert!(e.message.starts_with("Blocked: evil.example asked you to sign in to opensea.io"), "{}", e.message);
        // no trusted origin (WalletConnect Verify not VALID), or a malformed one: a danger note first
        for o in [None, Some("not an origin"), Some("http://evil.example")] {
            let n = notes(prep("opensea.io", o).unwrap());
            assert_eq!(n[0].level, "danger", "{o:?}");
            assert!(n[0].text.contains("could not be verified"));
        }
        // ordinary messages are untouched
        let mut p = route("personal_sign", &json!(["0x68656c6c6f", ME]), 1, &[1], ME).unwrap();
        sign_in_gate(&mut p, Some("https://evil.example")).unwrap();
        assert!(notes(p).is_empty());
    }

    #[test]
    fn quantities_accept_hex_only() {
        assert_eq!(dapp_quantity(&json!("0x0"), "v").unwrap(), 0);
        assert_eq!(dapp_quantity(&json!("0x00"), "v").unwrap(), 0);
        assert_eq!(dapp_quantity(&json!("0x0de0b6b3a7640000"), "v").unwrap(), 1_000_000_000_000_000_000);
        assert_eq!(dapp_quantity(&json!("0X1A"), "v").unwrap(), 26);
        assert!(dapp_quantity(&json!("0x"), "v").is_err());
        assert!(dapp_quantity(&json!("100"), "v").is_err(), "decimal strings are refused");
        assert!(dapp_quantity(&json!(100), "v").is_err(), "JSON numbers are refused");
        assert!(dapp_quantity(&json!("0xzz"), "v").is_err());
        assert!(dapp_quantity(&json!(format!("0x1{}", "0".repeat(32))), "v").is_err(), "more than 128 bits");
        assert_eq!(dapp_quantity(&json!(format!("0x{}1", "0".repeat(63))), "v").unwrap(), 1, "64 digits with leading zeros");
        assert!(dapp_quantity(&json!(format!("0x{}", "0".repeat(65))), "v").is_err());
    }

    #[test]
    fn plain_transfer_fills_defaults() {
        let d = tx(json!({"from": ME, "to": TO, "value": "0x2386f26fc10000"})).unwrap();
        assert_eq!(d.to, TO);
        assert_eq!(d.value, 10_000_000_000_000_000);
        assert_eq!(d.data, "0x");
        assert_eq!((d.gas, d.max_fee, d.max_priority, d.nonce), (None, None, None, None));
        assert!(d.notes.is_empty());
    }

    #[test]
    fn missing_from_uses_paired_with_a_note_and_other_from_is_refused() {
        let d = tx(json!({"to": TO})).unwrap();
        assert_eq!(d.value, 0);
        assert_eq!(d.notes.len(), 1);
        let e = tx(json!({"from": TO, "to": TO})).unwrap_err();
        assert_eq!(e.code, UNAUTHORIZED);
        // same address, other case: fine
        assert!(tx(json!({"from": ME.to_ascii_uppercase().replace("0X", "0x"), "to": TO})).is_ok());
        // mixed case with a bad checksum: refused
        assert_eq!(tx(json!({"from": "0x7A3b9C1d2E4f5061728394A5b6C7d8E9f0A1B2c4", "to": TO})).unwrap_err().code, INVALID_PARAMS);
    }

    #[test]
    fn chain_id_must_match_the_request_chain() {
        assert!(tx(json!({"to": TO, "chainId": "0x2105"})).is_ok());
        let e = tx(json!({"to": TO, "chainId": "0x1"})).unwrap_err();
        assert_eq!(e.code, INVALID_PARAMS);
        assert!(e.message.contains("chain 1"));
    }

    #[test]
    fn data_and_input_rules() {
        let data = format!("0xa9059cbb{:0>64}{:0>64}", &TO[2..], "64");
        assert_eq!(tx(json!({"to": TO, "data": data})).unwrap().data, data);
        assert_eq!(tx(json!({"to": TO, "input": data})).unwrap().data, data);
        assert!(tx(json!({"to": TO, "data": data, "input": data})).is_ok());
        assert!(tx(json!({"to": TO, "data": data, "input": "0x"})).is_err());
        assert!(tx(json!({"to": TO, "data": "0xabc"})).is_err(), "odd length");
        assert!(tx(json!({"to": TO, "data": "abcd"})).is_err(), "no 0x");
        let big = format!("0x{}", "00".repeat(MAX_DATA_BYTES + 1));
        assert!(tx(json!({"to": TO, "data": big})).unwrap_err().message.contains("limit"));
        let ok = format!("0x{}", "00".repeat(MAX_DATA_BYTES));
        assert!(tx(json!({"to": TO, "data": ok})).is_ok());
        assert_eq!(tx(json!({"to": TO, "data": "0xABCD"})).unwrap().data, "0xabcd");
    }

    #[test]
    fn structural_refusals() {
        assert!(tx(json!({"from": ME})).unwrap_err().message.contains("deployment"));
        assert!(tx(json!({"to": "0x0000000000000000000000000000000000000000"})).is_err());
        assert!(tx(json!({"to": TO, "authorizationList": []})).unwrap_err().message.contains("authorizationList"));
        assert!(tx(json!({"to": TO, "type": "0x4"})).is_err());
        assert!(tx(json!({"to": TO, "type": "0x2"})).is_ok());
        assert!(tx(json!({"to": TO, "accessList": []})).is_ok());
        assert!(tx(json!({"to": TO, "accessList": [{"address": TO, "storageKeys": []}]})).is_err());
        assert!(normalize_tx(&json!([]), ME, 8453).is_err());
        assert!(normalize_tx(&json!([{"to": TO}, {"to": TO}]), ME, 8453).is_err());
        assert!(normalize_tx(&json!({"to": TO}), ME, 8453).is_err());
    }

    #[test]
    fn gas_and_fee_rules() {
        let d = tx(json!({"to": TO, "gas": "0x5208", "maxFeePerGas": "0x3b9aca00", "maxPriorityFeePerGas": "0x0f4240", "nonce": "0x07"})).unwrap();
        assert_eq!((d.gas, d.max_fee, d.max_priority, d.nonce), (Some(21000), Some(1_000_000_000), Some(1_000_000), Some(7)));
        assert!(tx(json!({"to": TO, "gas": "0x5208", "gasLimit": "0x5209"})).is_err());
        assert!(tx(json!({"to": TO, "gas": "0x1"})).is_err(), "below 21000");
        assert!(tx(json!({"to": TO, "gas": "0x2000000"})).is_err(), "above the cap");
        assert!(tx(json!({"to": TO, "maxFeePerGas": "0x1", "maxPriorityFeePerGas": "0x2"})).is_err());
        let legacy = tx(json!({"from": ME, "to": TO, "gasPrice": "0x3b9aca00"})).unwrap();
        assert_eq!(legacy.max_fee, None);
        assert_eq!(legacy.notes.len(), 1);
        assert!(tx(json!({"to": TO, "gasPrice": "0x1", "maxFeePerGas": "0x1"})).is_err());
        assert_eq!(gas_with_headroom(21_000, true), 21_000);
        assert_eq!(gas_with_headroom(50_000, false), 60_000);
        assert_eq!(gas_with_headroom(21_001, true), 25_202);
    }

    #[test]
    fn call_shapes() {
        assert_eq!(call_info("0x", 5).kind, "transfer");
        let transfer = format!("0xa9059cbb{:0>64}{:0>64}", &TO[2..], "3e8");
        let c = call_info(&transfer, 0);
        assert_eq!((c.kind, c.amount.as_deref(), c.phone_supported), ("token_transfer", Some("1000"), true));
        assert_eq!(c.party.as_deref(), Some(TO));
        assert!(!call_info(&transfer, 1).phone_supported, "token call with native value");
        let approve = format!("0x095ea7b3{:0>64}{}", &TO[2..], "f".repeat(64));
        assert_eq!(call_info(&approve, 0).amount.as_deref(), Some("unlimited"));
        let swap = "0x3593564c0000";
        let s = call_info(swap, 0);
        assert_eq!((s.kind, s.selector.as_deref(), s.phone_supported), ("contract_call", Some("0x3593564c"), false));
    }

    #[test]
    fn method_routing() {
        let r = |m: &str, p: Value| route(m, &p, 8453, &[8453, 1], ME);
        assert!(matches!(r("eth_chainId", json!([])), Ok(Prepared::Answer { result }) if result == json!("0x2105")));
        assert!(matches!(r("eth_accounts", json!([])), Ok(Prepared::Answer { result }) if result == json!([verify::checksum(ME)])));
        assert!(matches!(r("eth_requestAccounts", json!([])), Ok(Prepared::Answer { .. })));
        for m in ["eth_sign", "eth_signTransaction", "eth_signTypedData", "eth_signTypedData_v3", "wallet_addEthereumChain", "eth_getEncryptionPublicKey", "wallet_sendCalls", "personal_ecRecover"] {
            assert_eq!(r(m, json!([])).unwrap_err().code, UNSUPPORTED_METHOD, "{m}");
        }
        assert!(matches!(r("wallet_switchEthereumChain", json!([{"chainId": "0xa"}])), Ok(Prepared::SwitchChain { chain_id: 10, in_session: false, .. })));
        assert!(matches!(r("wallet_switchEthereumChain", json!([{"chainId": "0x1"}])), Ok(Prepared::SwitchChain { chain_id: 1, in_session: true, .. })));
        assert_eq!(r("wallet_switchEthereumChain", json!([{"chainId": "0x38"}])).unwrap_err().code, UNRECOGNIZED_CHAIN);
    }

    #[test]
    fn personal_sign_mapping() {
        let (hex, text) = personal_sign_params(&json!(["0x48656c6c6f", ME]), ME).unwrap();
        assert_eq!((hex.as_str(), text.as_deref()), ("0x48656c6c6f", Some("Hello")));
        let (hex, _) = personal_sign_params(&json!(["Hello", ME]), ME).unwrap();
        assert_eq!(hex, "0x48656c6c6f", "plain text is signed as its UTF-8 bytes");
        assert!(personal_sign_params(&json!([ME, "Hello"]), ME).is_ok(), "unambiguous reversed order");
        assert_eq!(personal_sign_params(&json!(["Hello", TO]), ME).unwrap_err().code, UNAUTHORIZED);
        assert!(personal_sign_params(&json!(["", ME]), ME).is_err());
        assert!(personal_sign_params(&json!([format!("0x{}", "61".repeat(8193)), ME]), ME).is_err());
        let (_, t) = personal_sign_params(&json!(["0xff00", ME]), ME).unwrap();
        assert_eq!(t, None);
        assert!(matches!(route("personal_sign", &json!(["0xff00", ME]), 1, &[1], ME), Ok(Prepared::PersonalSign { notes, .. }) if notes[0].level == "danger"));
    }

    fn mail(chain: u64) -> Value {
        json!({"types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"}],
            "Mail": [{"name": "contents", "type": "string"}]}, "primaryType": "Mail",
            "domain": {"name": "Ether Mail", "chainId": chain}, "message": {"contents": "Hello"}})
    }

    #[test]
    fn typed_data_mapping() {
        let (text, s) = typed_data_params(&json!([ME, mail(8453).to_string()]), ME).unwrap();
        assert!(text.contains("Ether Mail"));
        assert_eq!((s.primary_type.as_str(), s.domain_chain), ("Mail", Some(8453)));
        assert!(typed_data_params(&json!([ME, mail(8453)]), ME).is_ok(), "object form");
        assert_eq!(typed_data_params(&json!([TO, mail(8453)]), ME).unwrap_err().code, UNAUTHORIZED);
        assert!(typed_data_params(&json!([ME, "{\"types\":{}}"]), ME).unwrap_err().message.contains("refused"));
        match route("eth_signTypedData_v4", &json!([ME, mail(1)]), 8453, &[8453], ME).unwrap() {
            Prepared::TypedData { notes, .. } => assert_eq!(notes[0].level, "danger"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn session_planning() {
        let req = json!({"eip155": {"chains": ["eip155:8453"], "methods": ["eth_sendTransaction", "eth_sign"], "events": ["chainChanged"]}});
        let opt = json!({"eip155": {"chains": ["eip155:1", "eip155:56"], "methods": ["personal_sign", "wallet_getCapabilities"], "events": []}});
        let p = plan_session(&req, &opt);
        assert!(p.blocker.is_none());
        assert_eq!(p.chains.iter().map(|c| (c.id, c.supported, c.required)).collect::<Vec<_>>(), vec![(8453, true, true), (1, true, false), (56, false, false)]);
        assert_eq!(p.required_refused_methods, vec!["eth_sign"]);
        assert!(p.refused_methods.contains(&"wallet_getCapabilities".to_string()));

        let ns = build_namespaces(&req, &opt, &[8453, 1], ME).unwrap();
        let eip = &ns["eip155"];
        assert_eq!(eip["chains"], json!(["eip155:8453", "eip155:1"]));
        assert_eq!(eip["accounts"], json!([format!("eip155:8453:{}", verify::checksum(ME)), format!("eip155:1:{}", verify::checksum(ME))]));
        let methods: Vec<&str> = eip["methods"].as_array().unwrap().iter().map(|m| m.as_str().unwrap()).collect();
        assert!(methods.contains(&"eth_sign"), "required method approved so the session can exist (refused per call)");
        assert!(!methods.contains(&"wallet_getCapabilities"), "optional unsupported methods are not approved");
        assert!(build_namespaces(&req, &opt, &[1], ME).unwrap_err().contains("requires"), "required chain missing");
        assert!(build_namespaces(&req, &opt, &[8453, 56], ME).is_err(), "not on the allow-list");
        assert!(build_namespaces(&req, &opt, &[8453, 10], ME).is_err(), "not requested");
        assert!(build_namespaces(&req, &opt, &[], ME).is_err());

        // chain-specific namespace key
        let p2 = plan_session(&json!({"eip155:10": {"methods": ["personal_sign"], "events": []}}), &json!({}));
        assert_eq!(p2.chains[0].id, 10);
        // required unsupported chain / non-EVM namespace block approval
        assert!(plan_session(&json!({"eip155": {"chains": ["eip155:56"], "methods": [], "events": []}}), &json!({})).blocker.is_some());
        assert!(plan_session(&json!({"solana": {"chains": ["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"], "methods": [], "events": []}}), &opt).blocker.is_some());
        assert!(plan_session(&json!({}), &json!({"solana": {"chains": ["solana:x"], "methods": [], "events": []}})).blocker.is_some());
    }

    #[test]
    fn adding_a_chain_and_matching_sessions() {
        let ns = build_namespaces(&json!({}), &json!({"eip155": {"chains": ["eip155:8453"], "methods": [], "events": []}}), &[8453], ME).unwrap();
        let more = add_chain(&ns, 10, ME).unwrap();
        assert_eq!(more["eip155"]["chains"], json!(["eip155:8453", "eip155:10"]));
        assert_eq!(add_chain(&more, 10, ME).unwrap(), more, "idempotent");
        assert!(add_chain(&ns, 56, ME).is_err());
        assert!(session_matches(&more, ME));
        assert!(!session_matches(&more, TO));
        assert!(!session_matches(&json!({}), ME));
    }

    #[test]
    fn allow_list_matches_the_phone() {
        let java = include_str!("../../../app/src/main/java/dev/phonevault/signer/Eip1559Request.java");
        let body = java.split("static boolean supportedChain(long id) {").nth(1).unwrap().split('}').next().unwrap();
        let mut ids: Vec<u64> = body.split("id == ").skip(1).map(|t| t.trim_start().split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap()).collect();
        ids.sort();
        let mut ours = ALLOWED_CHAINS.to_vec(); ours.sort();
        assert_eq!(ids, ours, "wc::ALLOWED_CHAINS must equal Eip1559Request.supportedChain");
    }

    #[test]
    fn caip2() {
        assert_eq!(parse_caip2("eip155:8453"), Some(8453));
        assert_eq!(parse_caip2("eip155:01"), None);
        assert_eq!(parse_caip2("solana:1"), None);
        assert_eq!(parse_caip2("eip155:"), None);
    }
}
