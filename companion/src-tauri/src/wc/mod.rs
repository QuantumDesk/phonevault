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
//!
//! Layout: this file holds the error codes and dApp value parsing; `session` the session plan,
//! `request` the request mapping, `node` the node-filled transaction, `commands` the Tauri commands.

mod commands;
mod node;
mod request;
mod session;

pub use commands::*;
pub use request::{normalize_tx, personal_sign_params, route, Prepared};

use crate::verify;
use serde::Serialize;
use serde_json::Value;

/// Methods a session is offered. Everything else is refused per request.
pub const SUPPORTED_METHODS: [&str; 7] = [
    "eth_sendTransaction",
    "personal_sign",
    "eth_signTypedData_v4",
    "eth_chainId",
    "eth_accounts",
    "eth_requestAccounts",
    "wallet_switchEthereumChain",
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
pub struct RpcError {
    pub code: i64,
    pub message: String,
}
fn rpc_err(code: i64, message: impl Into<String>) -> RpcError {
    RpcError { code, message: message.into() }
}
fn bad(message: impl Into<String>) -> RpcError {
    rpc_err(INVALID_PARAMS, message)
}

/// Chains the phone has a reviewed profile for (Eip1559Request.supportedChain; tested below).
pub fn chain_allowed(id: u64) -> bool {
    crate::chains::allowed(id)
}

/// A chain's name in dApp-facing text.
pub fn chain_name(id: u64) -> String {
    match crate::chains::get(id) {
        Some(c) => c.dapp_name.into(),
        None => format!("Chain {id}"),
    }
}

/// "eip155:8453" → 8453. Anything else (other namespaces, junk) → None.
pub fn parse_caip2(s: &str) -> Option<u64> {
    let id = s.strip_prefix("eip155:")?;
    if id.is_empty()
        || id.len() > 19
        || !id.bytes().all(|b| b.is_ascii_digit())
        || (id.len() > 1 && id.starts_with('0'))
    {
        return None;
    }
    id.parse().ok()
}

/// Address from a dApp: 0x + 40 hex; if written in mixed case it must be a valid EIP-55 checksum.
pub fn dapp_address(s: &str, what: &str) -> Result<String, RpcError> {
    verify::parse_address(s, verify::Case::ChecksumIfMixed).map_err(|e| match e {
        verify::AddressError::Shape => bad(format!("{what} must be a 0x address with 40 hex characters")),
        verify::AddressError::Checksum => bad(format!("{what} fails its EIP-55 checksum")),
    })
}

/// Hex quantity from a dApp: "0x" + 1…64 hex digits. Leading zeros are tolerated (JSON-RPC
/// clients differ) but the value must fit in 128 bits. Decimal strings and JSON numbers are refused.
pub fn dapp_quantity(v: &Value, what: &str) -> Result<u128, RpcError> {
    let s = v.as_str().ok_or_else(|| bad(format!("{what} must be a 0x hex string")))?;
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| bad(format!("{what} must be 0x-prefixed hex, got {s:?}")))?;
    if body.is_empty() || body.len() > 64 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad(format!("{what} is not a hex quantity: {s:?}")));
    }
    let digits = body.trim_start_matches('0');
    if digits.len() > 32 {
        return Err(bad(format!("{what} is too large")));
    }
    if digits.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(digits, 16).map_err(|_| bad(format!("{what} is not a hex quantity")))
}

fn dapp_bytes(v: &Value, what: &str) -> Result<String, RpcError> {
    let s = v.as_str().ok_or_else(|| bad(format!("{what} must be a 0x hex string")))?;
    let body = s.strip_prefix("0x").ok_or_else(|| bad(format!("{what} must be 0x-prefixed hex")))?;
    if body.len() % 2 != 0 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad(format!("{what} must be even-length hex")));
    }
    if body.len() / 2 > MAX_DATA_BYTES {
        return Err(bad(format!("{what} is {} bytes; the limit is {MAX_DATA_BYTES}", body.len() / 2)));
    }
    Ok(format!("0x{}", body.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    pub(super) const ME: &str = "0x7a3b9c1d2e4f5061728394a5b6c7d8e9f0a1b2c3";
    pub(super) const TO: &str = "0x1111111111111111111111111111111111111111";

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
        assert_eq!(
            dapp_quantity(&json!(format!("0x{}1", "0".repeat(63))), "v").unwrap(),
            1,
            "64 digits with leading zeros"
        );
        assert!(dapp_quantity(&json!(format!("0x{}", "0".repeat(65))), "v").is_err());
    }

    #[test]
    fn allow_list_matches_the_phone() {
        let java = include_str!("../../../../app/src/main/java/dev/phonevault/signer/Eip1559Request.java");
        let body = java.split("static boolean supportedChain(long id) {").nth(1).unwrap().split('}').next().unwrap();
        let mut ids: Vec<u64> = body
            .split("id == ")
            .skip(1)
            .map(|t| t.trim_start().split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap())
            .collect();
        ids.sort();
        let mut ours = crate::chains::IDS.to_vec();
        ours.sort();
        assert_eq!(ids, ours, "chains::CHAINS must equal Eip1559Request.supportedChain");
    }

    #[test]
    fn caip2() {
        assert_eq!(parse_caip2("eip155:8453"), Some(8453));
        assert_eq!(parse_caip2("eip155:01"), None);
        assert_eq!(parse_caip2("solana:1"), None);
        assert_eq!(parse_caip2("eip155:"), None);
    }
}
