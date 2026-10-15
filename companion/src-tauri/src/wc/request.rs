//! Request mapping: the method allow-list, parameter normalization and the prepared request.

use super::*;
use crate::{message, verify, Quote};
use serde_json::{json, Map, Value};

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Note {
    pub level: &'static str,
    pub text: String,
}
pub(super) fn note(level: &'static str, text: impl Into<String>) -> Note {
    Note { level, text: text.into() }
}

/// `eth_sendTransaction` parameters after validation, before the node fills the gaps.
#[derive(Debug, Clone, PartialEq)]
pub struct TxDraft {
    pub to: String,
    pub value: u128,
    pub data: String,
    pub gas: Option<u128>,
    pub max_fee: Option<u128>,
    pub max_priority: Option<u128>,
    pub nonce: Option<u128>,
    pub notes: Vec<Note>,
}

const TX_KEYS: [&str; 14] = [
    "from",
    "to",
    "value",
    "data",
    "input",
    "gas",
    "gasLimit",
    "maxFeePerGas",
    "maxPriorityFeePerGas",
    "gasPrice",
    "nonce",
    "chainId",
    "type",
    "accessList",
];

pub fn normalize_tx(params: &Value, paired: &str, chain: u64) -> Result<TxDraft, RpcError> {
    let list = params.as_array().ok_or_else(|| bad("params must be an array"))?;
    if list.len() != 1 {
        return Err(bad("eth_sendTransaction takes exactly one transaction object"));
    }
    let tx: &Map<String, Value> = list[0].as_object().ok_or_else(|| bad("the transaction must be an object"))?;
    let unknown: Vec<&str> = tx.keys().map(String::as_str).filter(|k| !TX_KEYS.contains(k)).collect();
    if !unknown.is_empty() {
        return Err(bad(format!("unsupported transaction fields: {}", unknown.join(", "))));
    }
    let field = |k: &str| tx.get(k).filter(|v| !v.is_null());
    let mut notes = vec![];

    match field("from") {
        Some(v) => {
            let from = dapp_address(v.as_str().ok_or_else(|| bad("from must be an address"))?, "from")?;
            if from != paired.to_ascii_lowercase() {
                return Err(rpc_err(
                    UNAUTHORIZED,
                    format!(
                        "from {} is not the account this wallet connected ({})",
                        verify::checksum(&from),
                        verify::checksum(paired)
                    ),
                ));
            }
        }
        None => notes
            .push(note("info", "The site did not name the sending account, so your paired phone's address is used.")),
    }
    if let Some(v) = field("chainId") {
        let c = dapp_quantity(v, "chainId")?;
        if c != chain as u128 {
            return Err(bad(format!(
                "the transaction is for chain {c}, but this request came on {} ({chain})",
                chain_name(chain)
            )));
        }
    }
    if let Some(t) = field("type") {
        let t = dapp_quantity(t, "type")?;
        if t != 0 && t != 2 {
            return Err(bad(format!("transaction type {t} is not supported (EIP-1559 only)")));
        }
    }
    if let Some(a) = field("accessList") {
        if !a.as_array().is_some_and(Vec::is_empty) {
            return Err(bad("access lists are not supported: the phone signs with an empty access list"));
        }
    }
    let to = match field("to") {
        Some(v) => dapp_address(v.as_str().ok_or_else(|| bad("to must be an address"))?, "to")?,
        None => return Err(bad("contract deployment (no `to`) is not supported")),
    };
    if to[2..].bytes().all(|b| b == b'0') {
        return Err(bad("refusing the zero address as recipient"));
    }
    let value = field("value").map(|v| dapp_quantity(v, "value")).transpose()?.unwrap_or(0);
    let data = match (field("data"), field("input")) {
        (Some(d), Some(i)) => {
            let (d, i) = (dapp_bytes(d, "data")?, dapp_bytes(i, "input")?);
            if d != i {
                return Err(bad("data and input differ"));
            }
            d
        }
        (Some(d), None) | (None, Some(d)) => dapp_bytes(d, "data")?,
        (None, None) => "0x".into(),
    };
    let gas = match (field("gas"), field("gasLimit")) {
        (Some(a), Some(b)) => {
            let (a, b) = (dapp_quantity(a, "gas")?, dapp_quantity(b, "gasLimit")?);
            if a != b {
                return Err(bad("gas and gasLimit differ"));
            }
            Some(a)
        }
        (Some(a), None) | (None, Some(a)) => Some(dapp_quantity(a, "gas")?),
        (None, None) => None,
    };
    if let Some(g) = gas {
        if !(21_000..=MAX_GAS).contains(&g) {
            return Err(bad(format!("gas limit {g} is outside 21000…{MAX_GAS}")));
        }
    }
    let max_fee = field("maxFeePerGas").map(|v| dapp_quantity(v, "maxFeePerGas")).transpose()?;
    let max_priority = field("maxPriorityFeePerGas").map(|v| dapp_quantity(v, "maxPriorityFeePerGas")).transpose()?;
    if let (Some(f), Some(p)) = (max_fee, max_priority) {
        if p > f {
            return Err(bad("maxPriorityFeePerGas exceeds maxFeePerGas"));
        }
    }
    if field("gasPrice").is_some() {
        if max_fee.is_some() || max_priority.is_some() {
            return Err(bad("gasPrice cannot be combined with EIP-1559 fee fields"));
        }
        dapp_quantity(field("gasPrice").unwrap(), "gasPrice")?;
        notes.push(note(
            "info",
            "The site suggested an old-style gas price. Fees are quoted from your node instead (EIP-1559).",
        ));
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
    if body.is_empty() {
        return CallInfo {
            kind: "transfer",
            selector: None,
            data_bytes: 0,
            party: None,
            amount: None,
            phone_supported: true,
        };
    }
    let selector = body.get(..8).map(|s| format!("0x{s}"));
    let token = match body.get(..8) {
        Some(crate::abi::SEL_TRANSFER) => Some("token_transfer"),
        Some(crate::abi::SEL_APPROVE) => Some("token_approve"),
        _ => None,
    };
    if let (Some(kind), 68) = (token, bytes) {
        let word = &body[8..72];
        let amount_hex = &body[72..136];
        let party = verify::checksum(&format!("0x{}", &word[24..]));
        let amount = if amount_hex.bytes().all(|b| b == b'f') {
            "unlimited".to_string()
        } else if amount_hex[..32].bytes().all(|b| b == b'0') {
            u128::from_str_radix(&amount_hex[32..], 16).map(|v| v.to_string()).unwrap_or_default()
        } else {
            format!("0x{}", amount_hex.trim_start_matches('0'))
        };
        let clean_pad = word[..24].bytes().all(|b| b == b'0');
        return CallInfo {
            kind,
            selector,
            data_bytes: bytes,
            party: Some(party),
            amount: Some(amount),
            phone_supported: clean_pad && value == 0,
        };
    }
    CallInfo { kind: "contract_call", selector, data_bytes: bytes, party: None, amount: None, phone_supported: false }
}

/// `personal_sign` params → (0x hex bytes to sign, text if the bytes are UTF-8).
/// Canonical order is [message, address]; the reversed order some dApps send is accepted only when
/// it is unambiguous (first param is the paired address, second is not an address).
pub fn personal_sign_params(params: &Value, paired: &str) -> Result<(String, Option<String>), RpcError> {
    let list = params.as_array().ok_or_else(|| bad("params must be an array"))?;
    if list.len() < 2 || list.len() > 3 {
        return Err(bad("personal_sign takes [message, address]"));
    }
    let a = list[0].as_str().ok_or_else(|| bad("message must be a string"))?;
    let b = list[1].as_str().ok_or_else(|| bad("address must be a string"))?;
    let paired_l = paired.to_ascii_lowercase();
    let (msg, addr) = if verify::is_address(b) {
        (a, b)
    } else if verify::is_address(a) && a.eq_ignore_ascii_case(&paired_l) {
        (b, a)
    } else {
        return Err(bad("personal_sign takes [message, address]"));
    };
    if dapp_address(addr, "address")? != paired_l {
        return Err(rpc_err(
            UNAUTHORIZED,
            format!("the message is for {}, not the account this wallet connected", verify::checksum(addr)),
        ));
    }
    let bytes = match msg.strip_prefix("0x") {
        Some(h) if h.len() % 2 == 0 && h.bytes().all(|c| c.is_ascii_hexdigit()) => {
            hex::decode(h).map_err(|_| bad("bad hex message"))?
        }
        _ => msg.as_bytes().to_vec(),
    };
    if bytes.is_empty() {
        return Err(bad("the message is empty"));
    }
    if bytes.len() > message::MAX_MESSAGE_BYTES {
        return Err(bad(format!(
            "the message is {} bytes; the phone's limit is {}",
            bytes.len(),
            message::MAX_MESSAGE_BYTES
        )));
    }
    let text = String::from_utf8(bytes.clone()).ok();
    Ok((format!("0x{}", hex::encode(&bytes)), text))
}

#[derive(Serialize, Debug, Clone, PartialEq, Default)]
pub struct TypedSummary {
    pub primary_type: String,
    pub domain_name: Option<String>,
    pub domain_version: Option<String>,
    pub domain_chain: Option<u64>,
    pub verifying_contract: Option<String>,
}

/// `eth_signTypedData_v4` params [address, typedData] → (typed data JSON text, summary). The text
/// must pass the same strict parser the phone uses, so a request the phone would refuse never
/// reaches it.
pub fn typed_data_params(params: &Value, paired: &str) -> Result<(String, TypedSummary), RpcError> {
    let list = params.as_array().ok_or_else(|| bad("params must be an array"))?;
    if list.len() != 2 {
        return Err(bad("eth_signTypedData_v4 takes [address, typedData]"));
    }
    let addr = list[0].as_str().ok_or_else(|| bad("address must be a string"))?;
    if dapp_address(addr, "address")? != paired.to_ascii_lowercase() {
        return Err(rpc_err(
            UNAUTHORIZED,
            format!("the data is for {}, not the account this wallet connected", verify::checksum(addr)),
        ));
    }
    let text = match &list[1] {
        Value::String(s) => s.clone(),
        v @ Value::Object(_) => serde_json::to_string(v).map_err(|e| bad(e.to_string()))?,
        _ => return Err(bad("typedData must be a JSON string or object")),
    };
    if text.len() > message::MAX_TYPED_DATA_BYTES {
        return Err(bad(format!(
            "typed data is {} bytes; the phone's limit is {}",
            text.len(),
            message::MAX_TYPED_DATA_BYTES
        )));
    }
    message::typed_data_digest(&text).map_err(|e| bad(format!("typed data refused: {}", e.0)))?;
    let v: Value = serde_json::from_str(&text).map_err(|_| bad("typed data is not JSON"))?;
    let d = &v["domain"];
    let chain = match &d["chainId"] {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => {
            if let Some(h) = s.strip_prefix("0x") {
                u64::from_str_radix(h, 16).ok()
            } else {
                s.parse().ok()
            }
        }
        _ => None,
    };
    Ok((
        text,
        TypedSummary {
            primary_type: v["primaryType"].as_str().unwrap_or("").to_string(),
            domain_name: d["name"].as_str().map(str::to_string),
            domain_version: d["version"].as_str().map(str::to_string),
            domain_chain: chain,
            verifying_contract: d["verifyingContract"].as_str().map(verify::checksum),
        },
    ))
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
        let kind = match self {
            Prepared::Answer { .. } => "Answer",
            Prepared::Transaction { .. } => "Transaction",
            Prepared::PersonalSign { .. } => "PersonalSign",
            Prepared::TypedData { .. } => "TypedData",
            Prepared::SwitchChain { .. } => "SwitchChain",
        };
        write!(f, "Prepared::{kind}")
    }
}

/// Method routing that needs no node: everything except filling a transaction.
pub fn route(
    method: &str,
    params: &Value,
    chain: u64,
    session_chains: &[u64],
    paired: &str,
) -> Result<Prepared, RpcError> {
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
                Some(c) if c != chain => notes.push(note("danger", format!("The data names chain {c} ({}), but the site is connected on {}.", chain_name(c), chain_name(chain)))),
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
        "eth_signTransaction" => Err(rpc_err(UNSUPPORTED_METHOD, "eth_signTransaction is refused: this wallet only returns transactions it sent to the network itself. Use eth_sendTransaction.")),
        "eth_sendTransaction" => Err(rpc_err(INTERNAL, "eth_sendTransaction needs a node")), // handled by prepare_tx
        m => Err(rpc_err(UNSUPPORTED_METHOD, format!("{m} is not supported by Phone Vault"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wc::node::gas_with_headroom;
    use crate::wc::tests::{ME, TO};

    fn tx(obj: Value) -> Result<TxDraft, RpcError> {
        normalize_tx(&json!([obj]), ME, 8453)
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
        assert_eq!(
            tx(json!({"from": "0x7A3b9C1d2E4f5061728394A5b6C7d8E9f0A1B2c4", "to": TO})).unwrap_err().code,
            INVALID_PARAMS
        );
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
        assert_eq!(
            (d.gas, d.max_fee, d.max_priority, d.nonce),
            (Some(21000), Some(1_000_000_000), Some(1_000_000), Some(7))
        );
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
        assert!(
            matches!(r("eth_accounts", json!([])), Ok(Prepared::Answer { result }) if result == json!([verify::checksum(ME)]))
        );
        assert!(matches!(r("eth_requestAccounts", json!([])), Ok(Prepared::Answer { .. })));
        for m in [
            "eth_sign",
            "eth_signTransaction",
            "eth_signTypedData",
            "eth_signTypedData_v3",
            "wallet_addEthereumChain",
            "eth_getEncryptionPublicKey",
            "wallet_sendCalls",
            "personal_ecRecover",
        ] {
            assert_eq!(r(m, json!([])).unwrap_err().code, UNSUPPORTED_METHOD, "{m}");
        }
        assert!(matches!(
            r("wallet_switchEthereumChain", json!([{"chainId": "0xa"}])),
            Ok(Prepared::SwitchChain { chain_id: 10, in_session: false, .. })
        ));
        assert!(matches!(
            r("wallet_switchEthereumChain", json!([{"chainId": "0x1"}])),
            Ok(Prepared::SwitchChain { chain_id: 1, in_session: true, .. })
        ));
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
        assert!(
            matches!(route("personal_sign", &json!(["0xff00", ME]), 1, &[1], ME), Ok(Prepared::PersonalSign { notes, .. }) if notes[0].level == "danger")
        );
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
}
