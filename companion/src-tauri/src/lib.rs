//! Phone Vault Companion (macOS): the host side of the signer. It never sees a key. It pairs with
//! the phone, reads balances and fees from a node, hands a transaction to the phone for review,
//! verifies what comes back independently, and broadcasts only what the user approved on the phone.

mod aoa;
mod eth;
mod pairing;
mod verify;
// redesigned UI: honest send flow, local history, fiat display
mod history;
mod price;
mod send;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

type CmdResult<T> = Result<T, String>;

fn blocking<T: Send + 'static>(f: impl FnOnce() -> CmdResult<T> + Send + 'static) -> impl std::future::Future<Output = CmdResult<T>> {
    async move { tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())? }
}

#[derive(Serialize)]
struct Status { phone: aoa::Presence, paired: Option<String>, paired_checksum: Option<String>, pairing_path: String }

#[tauri::command]
async fn device_status() -> CmdResult<Status> {
    blocking(|| {
        let phone = aoa::presence().map_err(|e| e.to_string())?;
        let paired = pairing::load().map_err(|e| e.0)?;
        Ok(Status { paired_checksum: paired.as_deref().map(verify::checksum), paired, phone, pairing_path: pairing::path().map(|p| p.display().to_string()).unwrap_or_default() })
    }).await
}

fn ask_phone(request: Value, timeout: Duration) -> CmdResult<Value> {
    let mut session = aoa::Session::connect().map_err(|e| e.to_string())?;
    session.exchange(&request, timeout).map_err(|e| e.to_string())
}

/// Ask the phone for its address. Nothing is pinned until the user confirms it against the phone's screen.
#[tauri::command]
async fn read_address() -> CmdResult<String> {
    blocking(|| {
        let request = json!({"id": uuid::Uuid::new_v4().to_string(), "method": "getAddress"});
        let response = ask_phone(request.clone(), Duration::from_secs(30))?;
        let obj = response.as_object().ok_or("malformed response")?;
        if obj.get("status").and_then(Value::as_str) == Some("error") {
            return Err(format!("phone: {}", obj.get("error").and_then(Value::as_str).unwrap_or("error")));
        }
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect(); keys.sort();
        if keys != ["address", "id", "status"] || obj["status"] != "ok" { return Err("malformed address response".into()); }
        let addr = obj["address"].as_str().ok_or("no address")?;
        if addr.len() != 42 || !addr.starts_with("0x") || !addr[2..].bytes().all(|b| b.is_ascii_hexdigit()) { return Err("invalid address from phone".into()); }
        Ok(verify::checksum(addr))
    }).await
}

#[tauri::command]
async fn confirm_pairing(address: String) -> CmdResult<String> {
    blocking(move || pairing::save(&address).map(|p| p.display().to_string()).map_err(|e| e.0)).await
}

#[tauri::command]
async fn forget_pairing() -> CmdResult<()> { blocking(|| pairing::forget().map_err(|e| e.0)).await }

#[derive(Serialize)]
struct Wallet { address: String, balance_wei: String, balance_eth: String, chain_id: u128, block: u128 }

#[tauri::command]
async fn wallet(rpc_url: String) -> CmdResult<Wallet> {
    blocking(move || {
        let address = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let balance = rpc.balance(&address).map_err(|e| e.0)?;
        Ok(Wallet { address: verify::checksum(&address), balance_wei: balance.to_string(), balance_eth: eth::format_eth(balance), chain_id: rpc.chain_id().map_err(|e| e.0)?, block: rpc.block_number().map_err(|e| e.0)? })
    }).await
}

/// Everything the phone will be asked to sign, quoted from the node, in the phone's exact wire format.
#[derive(Serialize, Deserialize, Clone)]
struct Quote {
    chain_id: String, nonce: String, max_priority_fee_per_gas: String, max_fee_per_gas: String, gas_limit: String,
    to: String, value: String, data: String,
    // display
    amount_eth: String, max_fee_eth: String, total_eth: String, balance_eth: String, network: String,
}

fn network_name(chain: u128) -> String {
    match chain { 1 => "Ethereum Mainnet".into(), 11155111 => "Sepolia Testnet".into(), 8453 => "Base".into(), 10 => "Optimism".into(), 42161 => "Arbitrum One".into(), 137 => "Polygon".into(), c => format!("chain {c}") }
}

#[tauri::command]
async fn quote(rpc_url: String, to: String, amount_eth: String) -> CmdResult<Quote> {
    blocking(move || {
        let from = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
        let to_l = to.trim().to_string();
        if to_l.len() != 42 || !to_l.starts_with("0x") || !to_l[2..].bytes().all(|b| b.is_ascii_hexdigit()) { return Err("recipient must be a 0x address with 40 hex characters".into()); }
        if to_l[2..].bytes().all(|b| b == b'0') { return Err("refusing the zero address".into()); }
        // If the recipient is written with mixed case, it must be a valid EIP-55 checksum (typo guard).
        if to_l[2..].bytes().any(|b| b.is_ascii_uppercase()) && to_l[2..].bytes().any(|b| b.is_ascii_lowercase()) && verify::checksum(&to_l) != to_l {
            return Err("recipient address fails its checksum — one character is wrong".into());
        }
        let value = eth::parse_eth(&amount_eth).map_err(|e| e.0)?;
        if value == 0 { return Err("amount must be more than zero".into()); }
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let chain = rpc.chain_id().map_err(|e| e.0)?;
        if !matches!(chain, 1 | 11155111 | 8453 | 10 | 42161 | 137) { return Err(format!("the phone has no reviewed profile for chain {chain}")); }
        let balance = rpc.balance(&from).map_err(|e| e.0)?;
        let nonce = rpc.nonce(&from).map_err(|e| e.0)?;
        let (priority, max_fee) = rpc.fees().map_err(|e| e.0)?;
        let gas = rpc.estimate_gas(&from, &to_l, value).unwrap_or(21_000).max(21_000);
        let max_cost = gas.checked_mul(max_fee).ok_or("fee overflow")?;
        let total = value.checked_add(max_cost).ok_or("total overflow")?;
        if total > balance { return Err(format!("not enough balance: {} ETH needed at most, {} ETH available", eth::format_eth(total), eth::format_eth(balance))); }
        Ok(Quote {
            chain_id: verify::to_quantity(chain), nonce: verify::to_quantity(nonce), max_priority_fee_per_gas: verify::to_quantity(priority),
            max_fee_per_gas: verify::to_quantity(max_fee), gas_limit: verify::to_quantity(gas), to: to_l.to_ascii_lowercase(),
            value: verify::to_quantity(value), data: "0x".into(),
            amount_eth: eth::format_eth(value), max_fee_eth: eth::format_eth(max_cost), total_eth: eth::format_eth(total),
            balance_eth: eth::format_eth(balance), network: network_name(chain),
        })
    }).await
}

#[derive(Serialize)]
struct SignedTx { raw: String, hash: String, signer: String }

/// Hand the quote to the phone. The user reviews and approves ON THE PHONE; this waits up to 3 minutes.
#[tauri::command]
async fn sign(q: Quote) -> CmdResult<SignedTx> {
    blocking(move || {
        let pinned = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
        let request = json!({
            "id": uuid::Uuid::new_v4().to_string(), "method": "signEip1559",
            "chainId": q.chain_id, "nonce": q.nonce, "maxPriorityFeePerGas": q.max_priority_fee_per_gas,
            "maxFeePerGas": q.max_fee_per_gas, "gasLimit": q.gas_limit, "to": q.to, "value": q.value, "data": q.data,
        });
        let response = ask_phone(request.clone(), Duration::from_secs(300))?;
        let v = verify::validate_signature(&request, &response, &pinned).map_err(|e| e.0)?;
        Ok(SignedTx { raw: v.raw_hex, hash: v.tx_hash, signer: verify::checksum(&v.signer) })
    }).await
}

#[tauri::command]
async fn broadcast(rpc_url: String, raw: String, expected_hash: String) -> CmdResult<String> {
    blocking(move || {
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let hash = rpc.send_raw(&raw).map_err(|e| e.0)?;
        if hash.to_ascii_lowercase() != expected_hash.to_ascii_lowercase() { return Err(format!("node returned hash {hash}, expected {expected_hash}")); }
        Ok(hash)
    }).await
}

#[derive(Serialize)]
struct Receipt { mined: bool, success: bool, block: u128 }

#[tauri::command]
async fn receipt(rpc_url: String, hash: String) -> CmdResult<Receipt> {
    blocking(move || {
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        Ok(match rpc.receipt_status(&hash).map_err(|e| e.0)? { None => Receipt { mined: false, success: false, block: 0 }, Some((ok, block)) => Receipt { mined: true, success: ok, block } })
    }).await
}

#[tauri::command]
fn default_rpc() -> String { eth::DEFAULT_RPC.to_string() }

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .manage(send::SendState::default())
        .invoke_handler(tauri::generate_handler![device_status, read_address, confirm_pairing, forget_pairing, wallet, quote, sign, broadcast, receipt, default_rpc,
            send::sign_start, send::sign_cancel, send::broadcast_verified, send::fee_estimate, send::max_sendable, send::check_address,
            history::history_list, history::history_mark, history::history_add_incoming, price::spot_usd])
        .run(tauri::generate_context!())
        .expect("error while running Phone Vault Companion");
}
