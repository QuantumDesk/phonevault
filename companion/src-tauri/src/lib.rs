//! Phone Vault Companion (macOS): the host side of the signer. It never sees a key. It pairs with
//! the phone, reads balances and fees from a node, hands a transaction to the phone for review,
//! verifies what comes back independently, and broadcasts only what the user approved on the phone.

mod aoa;
// device attestation: is the phone genuine Phone Vault hardware + firmware + app?
pub mod attest;
mod eth;
mod message;
mod pairing;
mod signing;
mod verify;
// send flow with progress and cancel, local history, fiat display
mod history;
mod price;
mod send;
// simulate every transaction on the user's node before it goes to the phone (shown as the Mac's claim)
mod sim;
// speed up / cancel a stuck transaction: a new transaction with the same nonce, reviewed on the phone
mod replace;
// background: balances, incoming transfers, pending settlement, notifications; menu-bar item; NFTs
mod nft;
mod tray;
mod watcher;
// ERC-20: the phone's built-in token list, balances, token sends
mod tokens;
// WalletConnect: request policy only; signing goes through send/signing above
mod wc;
// Sign-In with Ethereum: refuse a sign-in message for another site than the one asking
mod siwe;
// Browser extension: another dApp transport over native messaging; policy reuses wc.rs
pub mod bridge;
// Bitcoin: watch-only xpub accounts, Esplora, PSBT build → phone → independent verification
mod btc;
// Settings / setup: open the bundled blank backup card (no secrets on this Mac)
mod backup_card;
// security-audit proof tests (test builds only)
#[cfg(test)]
mod audit_proofs;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

type CmdResult<T> = Result<T, String>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> CmdResult<T> + Send + 'static) -> CmdResult<T> { tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())? }

/// One paired account as the UI shows it.
#[derive(Serialize)]
struct PairedAccount { address: String, checksum: String, label: String, wallet: Option<String>, account: Option<u32>, active: bool }

#[derive(Serialize)]
struct Status {
    phone: aoa::Presence,
    /// The ACTIVE paired address (what the UI shows and every request is pinned to).
    paired: Option<String>, paired_checksum: Option<String>, paired_label: Option<String>,
    accounts: Vec<PairedAccount>,
    pairing_path: String,
}

fn accounts_view(p: &pairing::Pairings) -> Vec<PairedAccount> {
    p.accounts.iter().map(|a| PairedAccount {
        address: a.address.clone(), checksum: verify::checksum(&a.address), label: a.label.clone(), wallet: a.wallet.clone(), account: a.account,
        active: p.active.as_deref() == Some(a.address.as_str()),
    }).collect()
}

#[tauri::command]
async fn device_status() -> CmdResult<Status> {
    blocking(|| {
        let phone = aoa::presence().map_err(|e| e.to_string())?;
        attest::note_presence(phone);
        let p = pairing::list().map_err(|e| e.0)?;
        let paired = p.active.clone();
        Ok(Status {
            paired_checksum: paired.as_deref().map(verify::checksum), paired_label: p.active_account().map(|a| a.label.clone()),
            accounts: accounts_view(&p), paired, phone, pairing_path: pairing::path().map(|p| p.display().to_string()).unwrap_or_default(),
        })
    }).await
}

/// Every signing request names the account it is pinned to: the phone refuses it ("Switch to the
/// right account on the phone") when another account is active there, before any review.
pub(crate) fn pinned_request(mut request: Value, pinned: &str) -> Value {
    if let Some(o) = request.as_object_mut() { o.insert("from".into(), Value::from(pinned.to_ascii_lowercase())); }
    request
}

fn ask_phone(request: Value, timeout: Duration) -> CmdResult<Value> {
    // One conversation with the phone at a time: wait for any other request to finish.
    let _turn = aoa::take_turn(|| {}, || false).map_err(|e| e.to_string())?;
    let mut session = aoa::Session::connect().map_err(|e| e.to_string())?;
    session.exchange(&request, timeout).map_err(|e| e.to_string())
}

/// The phone's ACTIVE account, as getAddress reports it.
#[derive(Serialize, Debug, PartialEq)]
pub(crate) struct PhoneAccount { address: String, account: Option<u32>, wallet: Option<String>, label: String }

/// Strict parse of a getAddress answer: `{id,status,address}` from older apps, plus
/// `account` ("1".."20") and `wallet` ("standard" | "passphrase") from apps with accounts.
pub(crate) fn parse_address_response(request: &Value, response: &Value) -> CmdResult<(String, Option<u32>, Option<String>)> {
    let obj = response.as_object().ok_or("malformed response")?;
    if obj.get("id") != request.get("id") { return Err("the phone's answer is for a different request".into()); }
    if obj.get("status").and_then(Value::as_str) == Some("error") {
        return Err(format!("phone: {}", obj.get("error").and_then(Value::as_str).unwrap_or("error")));
    }
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect(); keys.sort();
    let with_account = keys == ["account", "address", "id", "status", "wallet"];
    if !(keys == ["address", "id", "status"] || with_account) || obj["status"] != "ok" { return Err("malformed address response".into()); }
    let addr = obj["address"].as_str().ok_or("no address")?;
    if addr.len() != 42 || !addr.starts_with("0x") || !addr[2..].bytes().all(|b| b.is_ascii_hexdigit()) { return Err("invalid address from phone".into()); }
    if !with_account { return Ok((addr.to_ascii_lowercase(), None, None)); }
    let n = obj["account"].as_str().and_then(|s| if s.starts_with('0') { None } else { s.parse::<u32>().ok() }).filter(|n| (1..=20).contains(n)).ok_or("malformed account number")?;
    let w = obj["wallet"].as_str().filter(|w| *w == "standard" || *w == "passphrase").ok_or("malformed wallet kind")?;
    Ok((addr.to_ascii_lowercase(), Some(n), Some(w.to_string())))
}

/// Ask the phone for its ACTIVE account. Nothing is pinned until the user confirms it against the phone's screen.
#[tauri::command]
async fn read_address() -> CmdResult<PhoneAccount> {
    blocking(|| {
        let request = json!({"id": uuid::Uuid::new_v4().to_string(), "method": "getAddress"});
        let response = ask_phone(request.clone(), Duration::from_secs(30))?;
        let (addr, account, wallet) = parse_address_response(&request, &response)?;
        let existing = pairing::list().map_err(|e| e.0)?;
        let label = existing.find(&addr).map(|p| p.label.clone()).unwrap_or_else(|| pairing::default_label(&existing, account, wallet.as_deref()));
        Ok(PhoneAccount { address: verify::checksum(&addr), account, wallet, label })
    }).await
}

/// Pair one account (and make it the one the Mac shows). Several accounts can be paired.
#[tauri::command]
async fn confirm_pairing(address: String, label: Option<String>, account: Option<u32>, wallet: Option<String>) -> CmdResult<String> {
    // Only an address that a phone which passed the device check attested to in this connection.
    blocking(move || attest::require_pairable(&address)
        .and_then(|_| pairing::add(&address, label.as_deref(), wallet.as_deref(), account).map_err(|e| e.0))
        .map(|p| p.display().to_string())).await
}

/// Show (and pin new requests to) another paired account.
#[tauri::command]
async fn select_account(address: String) -> CmdResult<()> {
    blocking(move || { pairing::select(&address).map_err(|e| e.0)?; watcher::WAKE.store(true, std::sync::atomic::Ordering::SeqCst); Ok(()) }).await
}

#[tauri::command]
async fn rename_account(address: String, label: String) -> CmdResult<()> { blocking(move || pairing::rename(&address, &label).map(|_| ()).map_err(|e| e.0)).await }

/// Unpair one account (its local history file stays on disk).
#[tauri::command]
async fn forget_account(address: String) -> CmdResult<()> { blocking(move || pairing::remove(&address).map(|_| ()).map_err(|e| e.0)).await }

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
    /// Set for an ERC-20 transfer (tokens::token_quote); re-checked against the list before signing.
    #[serde(default)]
    token: Option<tokens::TokenIntent>,
    /// Set for a speed-up/cancel (replace::replacement_quote); re-checked against history before signing.
    #[serde(default)]
    replaces: Option<replace::Replacement>,
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
            balance_eth: eth::format_eth(balance), network: network_name(chain), token: None, replaces: None,
        })
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let browser_bridge = bridge::create();
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .manage(send::SendState::default())
        .manage(browser_bridge.clone())
        .invoke_handler(tauri::generate_handler![device_status, read_address, confirm_pairing, forget_pairing, select_account, rename_account, forget_account, wallet, quote, receipt,
            send::sign_start, send::sign_cancel, sim::simulate, send::broadcast_verified, send::fee_estimate, send::max_sendable, send::check_address,
            history::history_list, history::history_mark, history::history_reconcile, price::prices_usd,
            replace::replacement_quote,
            watcher::watch_configure, watcher::watch_scan_status, nft::nft_list, nft::nft_scan, nft::nft_add_contract, nft::nft_metadata, nft::dapp_icon,
            signing::sign_message, signing::sign_typed_data,
            attest::attest_phone, attest::attestation_cached, attest::developer_mode, attest::set_developer_mode,
            tokens::token_list, tokens::token_balances, tokens::token_quote,
            wc::wc_plan_session, wc::wc_session_namespaces, wc::wc_add_chain, wc::wc_session_matches, wc::wc_prepare,
            bridge::bridge_status, bridge::bridge_pending, bridge::bridge_respond, bridge::bridge_approve_connect,
            bridge::bridge_update_site, bridge::bridge_revoke, bridge::bridge_set_nodes, bridge::bridge_install, bridge::bridge_uninstall,
            backup_card::open_backup_card,
            btc::btc_accounts, btc::btc_read_account, btc::btc_show_address, btc::btc_confirm_account, btc::btc_select, btc::btc_rename, btc::btc_forget,
            btc::btc_set_server, btc::btc_wallet, btc::btc_refresh, btc::btc_check_address, btc::btc_fees, btc::btc_quote, btc::btc_bump_quote,
            btc::btc_sign_start, btc::btc_sign_cancel, btc::btc_broadcast, btc::btc_tx_status, btc::btc_export, btc::btc_save_export])
        .setup(move |app| {
            // browser-extension bridge (native-messaging relay socket)
            bridge::start(app.handle(), &browser_bridge);
            // menu-bar item + the background watcher (balances, incoming transfers, notifications)
            tray::setup(app.handle())?;
            watcher::start(app.handle().clone());
            btc::watch::start(app.handle().clone());
            Ok(())
        })
        // Closing the window hides it: the app keeps running in the menu bar (Quit is in its menu).
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building Phone Vault Companion")
        .run(|app, event| {
            // clicking the Dock icon brings the window back
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = event { tray::show_main(app); }
            // no Dock elsewhere: nothing to handle
            #[cfg(not(target_os = "macos"))]
            let _ = (app, event);
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";

    #[test]
    fn address_answers_from_old_and_new_phone_apps() {
        let req = json!({"id": "a-1", "method": "getAddress"});
        assert_eq!(parse_address_response(&req, &json!({"id": "a-1", "status": "ok", "address": ADDR})).unwrap(), (ADDR.into(), None, None));
        assert_eq!(parse_address_response(&req, &json!({"id": "a-1", "status": "ok", "address": ADDR, "account": "2", "wallet": "passphrase"})).unwrap(),
            (ADDR.into(), Some(2), Some("passphrase".into())));
        for bad in [
            json!({"id": "a-1", "status": "ok", "address": ADDR, "account": "2"}),
            json!({"id": "a-1", "status": "ok", "address": ADDR, "account": "0", "wallet": "standard"}),
            json!({"id": "a-1", "status": "ok", "address": ADDR, "account": "21", "wallet": "standard"}),
            json!({"id": "a-1", "status": "ok", "address": ADDR, "account": "02", "wallet": "standard"}),
            json!({"id": "a-1", "status": "ok", "address": ADDR, "account": "2", "wallet": "hidden"}),
            json!({"id": "a-1", "status": "ok", "address": ADDR, "account": 2, "wallet": "standard"}),
            json!({"id": "a-2", "status": "ok", "address": ADDR}),
            json!({"id": "a-1", "status": "ok", "address": "0x12"}),
        ] { assert!(parse_address_response(&req, &bad).is_err(), "accepted {bad}"); }
    }

    /// The command list in build.rs (the ACL: anything missing cannot be invoked), the
    /// app-commands permission set, and generate_handler! must name the same commands.
    #[test]
    fn every_registered_command_is_permitted_and_nothing_else() {
        fn quoted(s: &str) -> Vec<String> { s.split('"').skip(1).step_by(2).map(str::to_string).collect() }
        let lib = include_str!("lib.rs");
        let handler = lib.split("generate_handler![").nth(1).unwrap().split("])").next().unwrap();
        let mut registered: Vec<String> = handler.split(',').map(|x| x.trim().rsplit("::").next().unwrap().to_string()).filter(|x| !x.is_empty()).collect();
        let build = include_str!("../build.rs");
        let mut listed = quoted(build.split("COMMANDS: &[&str] = &[").nth(1).unwrap().split("];").next().unwrap());
        let set = include_str!("../permissions/app-commands.toml");
        let mut permitted: Vec<String> = quoted(set.split("permissions = [").nth(1).unwrap())
            .into_iter().map(|p| p.strip_prefix("allow-").expect("allow- only").replace('-', "_")).collect();
        registered.sort(); listed.sort(); permitted.sort();
        assert_eq!(registered, listed, "build.rs COMMANDS vs generate_handler!");
        assert_eq!(registered, permitted, "permissions/app-commands.toml vs generate_handler!");
        let cap: Value = serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        assert_eq!(cap["windows"], json!(["main"]));
        assert!(cap["permissions"].as_array().unwrap().contains(&json!("app-commands")));
        assert!(cap.get("remote").is_none(), "no remote origin may call commands");
    }

    #[test]
    fn pinned_request_names_the_account() {
        let r = pinned_request(json!({"id": "x", "method": "personal_sign", "chainId": "0x1", "message": "0x68"}), &ADDR.to_ascii_uppercase().replace("0X", "0x"));
        assert_eq!(r["from"], ADDR);
        assert_eq!(r.as_object().unwrap().len(), 5);
    }
}
