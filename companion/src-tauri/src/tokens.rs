//! ERC-20 support: the SAME token list the phone ships (`app/src/main/res/raw/tokens.json`,
//! compiled in here byte for byte), token balances via `balanceOf`, and token-transfer quotes.
//!
//! The list is pinned by SHA-256 here and in the phone's `TokenList.java`; a mismatch refuses it.
//! Tests check both pins against the file, so the Mac and the phone cannot disagree about which
//! contract is "USDC" or how many decimals it has. The node is untrusted: balances are display
//! only, and a transfer is built here from the list entry, re-checked in `send::sign_start`, and
//! re-decoded from the signed bytes by `verify::check_erc20_transfer` before it can be broadcast.

use crate::{blocking, eth, pairing, verify, CmdResult, Quote};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// SHA-256 of `app/src/main/res/raw/tokens.json`. Must equal `TokenList.PINNED_SHA256` (tested).
pub const PINNED_SHA256: &str = "1021c5c5be1393df34c089d79e48aada223c6517ab03e70035efd0132e081506";
const LIST_BYTES: &[u8] = include_bytes!("../../../app/src/main/res/raw/tokens.json");
pub const ALLOWED_CHAINS: [u64; 6] = [1, 11155111, 8453, 10, 42161, 137];

const SEL_TRANSFER: &str = "a9059cbb";
const SEL_BALANCE_OF: &str = "70a08231";

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Token { pub chain_id: u64, pub address: String, pub symbol: String, pub name: String, pub decimals: u32 }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListFile { version: u64, tokens: Vec<Token> }

/// Parse and check a list with the same rules as the phone (TokenList.parse).
fn parse_list(bytes: &[u8]) -> Result<Vec<Token>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "token list is not UTF-8".to_string())?;
    let file: ListFile = serde_json::from_str(text).map_err(|e| format!("token list is not strict JSON: {e}"))?;
    if file.version != 1 { return Err("unsupported token list version".into()); }
    if file.tokens.is_empty() { return Err("token list is empty".into()); }
    let mut seen = std::collections::HashSet::new();
    for (i, t) in file.tokens.iter().enumerate() {
        let w = format!("token #{i}");
        if !ALLOWED_CHAINS.contains(&t.chain_id) { return Err(format!("{w}: chain {} is not in the phone's allow-list", t.chain_id)); }
        let a = &t.address;
        if a.len() != 42 || !a.starts_with("0x") || !a[2..].bytes().all(|b| b.is_ascii_hexdigit()) || a[2..].bytes().all(|b| b == b'0') {
            return Err(format!("{w}: bad address"));
        }
        if verify::checksum(a) != *a { return Err(format!("{w}: address is not in EIP-55 checksum casing")); }
        if t.symbol.is_empty() || t.symbol.len() > 11 || !t.symbol.bytes().all(|b| b.is_ascii_alphanumeric()) { return Err(format!("{w}: bad symbol")); }
        if t.name.is_empty() || t.name.len() > 64 || !t.name.bytes().all(|b| (0x20..=0x7e).contains(&b)) || t.name.trim() != t.name { return Err(format!("{w}: bad name")); }
        if t.decimals > 36 { return Err(format!("{w}: too many decimals")); }
        if !seen.insert(format!("{}:{}", t.chain_id, a.to_ascii_lowercase())) { return Err(format!("{w}: duplicate address on chain {}", t.chain_id)); }
        if !seen.insert(format!("{}:sym:{}", t.chain_id, t.symbol.to_ascii_uppercase())) { return Err(format!("{w}: duplicate symbol on chain {}", t.chain_id)); }
    }
    Ok(file.tokens)
}

pub fn sha256_hex(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

fn load_pinned(bytes: &[u8]) -> Result<Vec<Token>, String> {
    let actual = sha256_hex(bytes);
    if actual != PINNED_SHA256 { return Err(format!("token list hash {actual} does not match the pinned {PINNED_SHA256}")); }
    parse_list(bytes)
}

/// The built-in list, or why it was refused.
pub fn list() -> Result<&'static [Token], String> {
    static LIST: OnceLock<Result<Vec<Token>, String>> = OnceLock::new();
    LIST.get_or_init(|| load_pinned(LIST_BYTES)).as_ref().map(|v| v.as_slice()).map_err(|e| e.clone())
}

pub fn lookup(chain_id: u64, address: &str) -> Option<&'static Token> {
    list().ok()?.iter().find(|t| t.chain_id == chain_id && t.address.eq_ignore_ascii_case(address))
}

// ---------------------------------------------------------------- units and calldata

/// Exact decimal text for `raw` base units: trailing fractional zeros trimmed, nothing rounded.
pub fn format_units(raw: u128, decimals: u32) -> String {
    let s = raw.to_string();
    let d = decimals as usize;
    if d == 0 { return s; }
    let padded = if s.len() <= d { format!("{}{}", "0".repeat(d + 1 - s.len()), s) } else { s };
    let (whole, frac) = padded.split_at(padded.len() - d);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() { whole.to_string() } else { format!("{whole}.{frac}") }
}

/// Decimal text → base units, exact: at most `decimals` fractional digits, no signs or exponents.
pub fn parse_units(text: &str, decimals: u32) -> Result<u128, String> {
    let t = text.trim();
    if t.is_empty() { return Err("enter an amount".into()); }
    let (whole, frac) = t.split_once('.').unwrap_or((t, ""));
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) || (whole.is_empty() && frac.is_empty()) {
        return Err("amount must be a plain decimal number, like 12.5".into());
    }
    if frac.len() > decimals as usize { return Err(format!("this token has {decimals} decimals; use at most {decimals} digits after the dot")); }
    let digits = format!("{whole}{frac}{}", "0".repeat(decimals as usize - frac.len()));
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() { return Ok(0); }
    digits.parse::<u128>().map_err(|_| "amount too large".to_string())
}

fn word_address(address: &str) -> Result<String, String> {
    let a = address.trim().to_ascii_lowercase();
    if a.len() != 42 || !a.starts_with("0x") || !a[2..].bytes().all(|b| b.is_ascii_hexdigit()) { return Err("bad address".into()); }
    Ok(format!("{:0>64}", &a[2..]))
}

/// `transfer(address,uint256)` calldata, lower-case 0x hex (exactly the phone's canonical form).
pub fn transfer_calldata(recipient: &str, amount: u128) -> Result<String, String> {
    Ok(format!("0x{SEL_TRANSFER}{}{:064x}", word_address(recipient)?, amount))
}

pub fn balance_of_calldata(owner: &str) -> Result<String, String> {
    Ok(format!("0x{SEL_BALANCE_OF}{}", word_address(owner)?))
}

/// A `balanceOf` answer: exactly one 32-byte word that fits in u128 (anything else is refused).
pub fn parse_balance_word(ret: &[u8]) -> Result<u128, String> {
    if ret.len() != 32 { return Err(format!("balanceOf returned {} bytes, expected 32", ret.len())); }
    if ret[..16].iter().any(|&b| b != 0) { return Err("balance is too large to display".into()); }
    Ok(u128::from_be_bytes(ret[16..].try_into().unwrap()))
}

// ---------------------------------------------------------------- what the UI sent: re-checked

/// The token part of a quote. Travels UI → Rust; `check_quote` re-derives everything from the list.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TokenIntent {
    pub contract: String, pub symbol: String, pub name: String, pub decimals: u32,
    pub recipient: String, pub amount_raw: String, pub amount: String,
}

/// Re-check a token quote against the built-in list before it goes to the phone: the contract is
/// listed on the quote's chain with the same symbol/decimals, `to` is that contract, no native
/// value, and `data` is exactly transfer(recipient, amount). Returns (contract, recipient, amount).
pub fn check_quote(quote: &Quote, t: &TokenIntent) -> Result<(String, String, u128), String> {
    let chain = verify::quantity(&quote.chain_id).map_err(|e| e.0)?;
    let chain = u64::try_from(chain).map_err(|_| "chain id out of range".to_string())?;
    let listed = lookup(chain, &t.contract).ok_or("the token is not in the built-in list for this network")?;
    if listed.symbol != t.symbol || listed.decimals != t.decimals || listed.name != t.name { return Err("token details differ from the built-in list".into()); }
    let contract = listed.address.to_ascii_lowercase();
    if quote.to.to_ascii_lowercase() != contract { return Err("the transaction is not addressed to the token contract".into()); }
    if verify::quantity(&quote.value).map_err(|e| e.0)? != 0 { return Err("a token transfer must not send ETH".into()); }
    let amount: u128 = t.amount_raw.parse().map_err(|_| "bad token amount".to_string())?;
    if amount == 0 || format_units(amount, listed.decimals) != t.amount { return Err("token amount text differs from the base units".into()); }
    let recipient = t.recipient.to_ascii_lowercase();
    if quote.data.to_ascii_lowercase() != transfer_calldata(&recipient, amount)? { return Err("calldata is not exactly transfer(recipient, amount)".into()); }
    Ok((contract, recipient, amount))
}

// ---------------------------------------------------------------- commands

#[tauri::command]
pub(crate) fn token_list() -> CmdResult<Vec<Token>> { list().map(|l| l.to_vec()) }

#[derive(Serialize)]
pub struct TokenBalance { address: String, symbol: String, name: String, decimals: u32, raw: Option<String>, amount: Option<String>, error: Option<String> }
#[derive(Serialize)]
pub struct TokenBalances { chain_id: u128, balances: Vec<TokenBalance> }

/// balanceOf(paired address) for every listed token on the node's chain. Display only.
#[tauri::command]
pub(crate) async fn token_balances(rpc_url: String) -> CmdResult<TokenBalances> {
    blocking(move || {
        let owner = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let chain = rpc.chain_id().map_err(|e| e.0)?;
        let data = balance_of_calldata(&owner)?;
        let balances = list()?.iter().filter(|t| t.chain_id as u128 == chain).map(|t| {
            let r = rpc.eth_call(&t.address, &data).map_err(|e| e.0).and_then(|ret| parse_balance_word(&ret));
            let (raw, amount, error) = match r { Ok(v) => (Some(v.to_string()), Some(format_units(v, t.decimals)), None), Err(e) => (None, None, Some(e)) };
            TokenBalance { address: t.address.clone(), symbol: t.symbol.clone(), name: t.name.clone(), decimals: t.decimals, raw, amount, error }
        }).collect();
        Ok(TokenBalances { chain_id: chain, balances })
    }).await
}

/// Same recipient rules as `quote` (lib.rs).
fn check_recipient(to: &str) -> Result<String, String> {
    let t = to.trim();
    if t.len() != 42 || !t.starts_with("0x") || !t[2..].bytes().all(|b| b.is_ascii_hexdigit()) { return Err("recipient must be a 0x address with 40 hex characters".into()); }
    if t[2..].bytes().all(|b| b == b'0') { return Err("refusing the zero address".into()); }
    if t[2..].bytes().any(|b| b.is_ascii_uppercase()) && t[2..].bytes().any(|b| b.is_ascii_lowercase()) && verify::checksum(t) != t {
        return Err("recipient address fails its checksum — one character is wrong".into());
    }
    Ok(t.to_ascii_lowercase())
}

/// Quote an ERC-20 transfer of `amount` (token units) of the listed `token` to `to`.
#[tauri::command]
pub(crate) async fn token_quote(rpc_url: String, token: String, to: String, amount: String) -> CmdResult<Quote> {
    blocking(move || {
        let from = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
        let recipient = check_recipient(&to)?;
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let chain = rpc.chain_id().map_err(|e| e.0)?;
        let chain64 = u64::try_from(chain).map_err(|_| "chain id out of range".to_string())?;
        if !ALLOWED_CHAINS.contains(&chain64) { return Err(format!("the phone has no reviewed profile for chain {chain}")); }
        let t = lookup(chain64, &token).ok_or("that token is not in the built-in list for this network")?;
        let contract = t.address.to_ascii_lowercase();
        if recipient == contract || lookup(chain64, &recipient).is_some() { return Err("the recipient is a token contract; tokens sent there are usually lost".into()); }
        let value = parse_units(&amount, t.decimals)?;
        if value == 0 { return Err("amount must be more than zero".into()); }
        let held = parse_balance_word(&rpc.eth_call(&contract, &balance_of_calldata(&from)?).map_err(|e| e.0)?)?;
        if value > held { return Err(format!("not enough {}: {} {} available", t.symbol, format_units(held, t.decimals), t.symbol)); }
        let data = transfer_calldata(&recipient, value)?;
        let eth_balance = rpc.balance(&from).map_err(|e| e.0)?;
        let nonce = rpc.nonce(&from).map_err(|e| e.0)?;
        let (priority, max_fee) = rpc.fees().map_err(|e| e.0)?;
        let estimate = rpc.estimate_gas_data(&from, &contract, 0, &data).map_err(|e| format!("the node says this transfer would fail: {}", e.0))?;
        // token transfers vary a little with state; 25 % headroom (unused gas is not charged)
        let gas = estimate.saturating_mul(5) / 4;
        let gas = gas.max(21_000);
        let max_cost = gas.checked_mul(max_fee).ok_or("fee overflow")?;
        if max_cost > eth_balance { return Err(format!("not enough ETH for the network fee: {} needed at most, {} available", eth::format_eth(max_cost), eth::format_eth(eth_balance))); }
        let token_amount = format_units(value, t.decimals);
        Ok(Quote {
            chain_id: verify::to_quantity(chain), nonce: verify::to_quantity(nonce), max_priority_fee_per_gas: verify::to_quantity(priority),
            max_fee_per_gas: verify::to_quantity(max_fee), gas_limit: verify::to_quantity(gas), to: contract.clone(),
            value: "0x0".into(), data,
            amount_eth: "0".into(), max_fee_eth: eth::format_eth(max_cost), total_eth: eth::format_eth(max_cost),
            balance_eth: eth::format_eth(eth_balance), network: crate::network_name(chain),
            token: Some(TokenIntent { contract, symbol: t.symbol.clone(), name: t.name.clone(), decimals: t.decimals, recipient, amount_raw: value.to_string(), amount: token_amount }), replaces: None,
        })
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHONE_TOKEN_LIST_JAVA: &str = include_str!("../../../app/src/main/java/dev/phonevault/signer/TokenList.java");

    #[test]
    fn the_shared_list_matches_both_pins_and_loads() {
        // One file, compiled into both: the bytes the phone packages are the bytes here.
        let on_disk = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../app/src/main/res/raw/tokens.json")).unwrap();
        assert_eq!(on_disk, LIST_BYTES, "companion copy differs from the phone's res/raw/tokens.json");
        assert_eq!(sha256_hex(LIST_BYTES), PINNED_SHA256);
        let java_pin = PHONE_TOKEN_LIST_JAVA.split("PINNED_SHA256 = \"").nth(1).and_then(|s| s.split('"').next()).unwrap();
        assert_eq!(java_pin, PINNED_SHA256, "phone and companion pins differ");
        let l = list().unwrap();
        assert_eq!(l.len(), 30);
        for chain in ALLOWED_CHAINS { assert!(l.iter().any(|t| t.chain_id == chain && t.symbol == "USDC" && t.decimals == 6), "USDC on {chain}"); }
        let usdc = lookup(1, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        assert_eq!((usdc.symbol.as_str(), usdc.decimals), ("USDC", 6));
        assert!(lookup(137, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").is_none(), "lookups are per chain");
    }

    #[test]
    fn a_changed_list_is_refused() {
        let tampered = String::from_utf8(LIST_BYTES.to_vec()).unwrap().replacen("\"decimals\": 6", "\"decimals\": 18", 1);
        assert!(load_pinned(tampered.as_bytes()).unwrap_err().contains("does not match the pinned"));
        let usdc = r#"{"chainId": 1, "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "symbol": "USDC", "name": "USD Coin", "decimals": 6}"#;
        let wrap = |t: &str| format!(r#"{{"version": 1, "tokens": [{t}]}}"#);
        assert!(parse_list(wrap(usdc).as_bytes()).is_ok());
        for bad in [
            wrap(&usdc.replace("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")),
            wrap(&usdc.replace("\"chainId\": 1", "\"chainId\": 56")),
            wrap(&usdc.replace("\"decimals\": 6", "\"decimals\": 37")),
            wrap(&usdc.replace("\"USDC\"", "\"USD₮\"")),
            wrap(&usdc.replace("\"decimals\": 6}", "\"decimals\": 6, \"logo\": \"x\"}")),
            wrap(&usdc.replace("\"decimals\": 6}", "\"decimals\": 6, \"decimals\": 6}")),
            wrap(&format!("{usdc}, {usdc}")),
            r#"{"version": 1, "tokens": []}"#.to_string(),
        ] { assert!(parse_list(bad.as_bytes()).is_err(), "accepted {bad}"); }
    }

    #[test]
    fn units_are_exact() {
        assert_eq!(format_units(50_000_000, 6), "50");
        assert_eq!(format_units(1, 6), "0.000001");
        assert_eq!(format_units(0, 6), "0");
        assert_eq!(format_units(1, 18), "0.000000000000000001");
        assert_eq!(format_units(1_234_567_890_123_456_789, 18), "1.234567890123456789");
        assert_eq!(format_units(u128::MAX, 0), u128::MAX.to_string());
        assert_eq!(parse_units("50", 6).unwrap(), 50_000_000);
        assert_eq!(parse_units("0.000001", 6).unwrap(), 1);
        assert_eq!(parse_units(".5", 6).unwrap(), 500_000);
        assert_eq!(parse_units("1.234567890123456789", 18).unwrap(), 1_234_567_890_123_456_789);
        assert_eq!(parse_units("0", 6).unwrap(), 0);
        for bad in ["", ".", "0.0000001", "1e6", "-1", "1,5", " 1 2", "0x10", "340282366920938463463374607431768211456"] {
            assert!(parse_units(bad, 6).is_err(), "accepted {bad:?}");
        }
        for (raw, d) in [(1u128, 6u32), (123_456_789, 8), (10u128.pow(30), 18), (7, 0)] {
            assert_eq!(parse_units(&format_units(raw, d), d).unwrap(), raw);
        }
    }

    #[test]
    fn transfer_calldata_is_canonical() {
        let data = transfer_calldata("0x7F3A9C04e2b16d58a41C0f9E6b2D7a8c5e1f4B93", 50_000_000).unwrap();
        assert_eq!(data, "0xa9059cbb0000000000000000000000007f3a9c04e2b16d58a41c0f9e6b2d7a8c5e1f4b93\
                          0000000000000000000000000000000000000000000000000000000002faf080");
        assert_eq!(data.len(), 2 + 68 * 2);
        assert_eq!(verify::decode_erc20_transfer(&data).unwrap(), ("0x7f3a9c04e2b16d58a41c0f9e6b2d7a8c5e1f4b93".to_string(), 50_000_000));
        assert_eq!(balance_of_calldata("0x1111111111111111111111111111111111111111").unwrap(),
            "0x70a082310000000000000000000000001111111111111111111111111111111111111111");
        assert!(transfer_calldata("0x1234", 1).is_err());
    }

    #[test]
    fn balance_words_are_strict() {
        let mut w = [0u8; 32]; w[31] = 7;
        assert_eq!(parse_balance_word(&w).unwrap(), 7);
        assert!(parse_balance_word(&w[..31]).is_err());
        assert!(parse_balance_word(&[0u8; 64]).is_err());
        let mut big = [0u8; 32]; big[0] = 1;
        assert!(parse_balance_word(&big).is_err());
    }

    fn token_quote_fixture() -> (Quote, TokenIntent) {
        let recipient = "0x7f3a9c04e2b16d58a41c0f9e6b2d7a8c5e1f4b93".to_string();
        let t = TokenIntent { contract: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(), symbol: "USDC".into(), name: "USD Coin".into(), decimals: 6,
            recipient: recipient.clone(), amount_raw: "50000000".into(), amount: "50".into() };
        let q = Quote { chain_id: "0x1".into(), nonce: "0x0".into(), max_priority_fee_per_gas: "0x1".into(), max_fee_per_gas: "0x2".into(), gas_limit: "0xfde8".into(),
            to: t.contract.clone(), value: "0x0".into(), data: transfer_calldata(&recipient, 50_000_000).unwrap(),
            amount_eth: "0".into(), max_fee_eth: "0".into(), total_eth: "0".into(), balance_eth: "0".into(), network: "Ethereum Mainnet".into(), token: Some(t.clone()), replaces: None };
        (q, t)
    }

    #[test]
    fn check_quote_refuses_any_drift_from_the_list_or_the_calldata() {
        let (q, t) = token_quote_fixture();
        assert_eq!(check_quote(&q, &t).unwrap().2, 50_000_000);
        let mut x = q.clone(); x.to = "0xdac17f958d2ee523a2206206994597c13d831ec7".into(); assert!(check_quote(&x, &t).is_err());
        let mut x = q.clone(); x.value = "0x1".into(); assert!(check_quote(&x, &t).is_err());
        let mut x = q.clone(); x.data = transfer_calldata(&t.recipient, 50_000_001).unwrap(); assert!(check_quote(&x, &t).is_err());
        let mut x = q.clone(); x.data.push_str("00"); assert!(check_quote(&x, &t).is_err());
        let mut x = q.clone(); x.chain_id = "0x89".into(); assert!(check_quote(&x, &t).is_err(), "Ethereum USDC address is not listed on Polygon");
        let mut y = t.clone(); y.decimals = 18; assert!(check_quote(&q, &y).is_err());
        let mut y = t.clone(); y.symbol = "USDT".into(); assert!(check_quote(&q, &y).is_err());
        let mut y = t.clone(); y.amount = "5".into(); assert!(check_quote(&q, &y).is_err());
        let mut y = t.clone(); y.recipient = "0x1111111111111111111111111111111111111111".into(); assert!(check_quote(&q, &y).is_err());
    }
}
