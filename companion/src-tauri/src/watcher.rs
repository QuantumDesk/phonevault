//! Background watcher: runs in Rust whether the window is open, hidden or closed to the menu bar.
//!
//! For every network, on a schedule (the selected one every 20 s, the others every 90 s):
//! * reads the native balance at a known block and tells the UI and the menu-bar item;
//! * on an increase, looks through the blocks since the last reading for plain transfers to this
//!   address and records them with their real hashes; if the gap is too wide (or the money came
//!   from inside a contract call, which no block body shows), records a balance increase without a
//!   hash, as before;
//! * searches `Transfer` logs of the built-in token list to this address (eth_getLogs over a
//!   bounded, recent block window, continued from where it stopped) and records incoming token
//!   transfers with their hashes;
//! * settles pending transactions sent from here (history::reconcile);
//! * notifies once per new incoming transfer, if notifications are on.
//!
//! Everything comes from the user's own nodes (Settings → Node). No explorer, no third party.

use crate::{eth, history, pairing, price, tokens, verify, CmdResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};

pub const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// (chain id, name, native symbol, default node, initial log window in blocks ≈ the last day or
/// what public nodes still serve without an archive token)
pub const NETWORKS: [(u64, &str, &str, &str, u128); 6] = [
    (8453, "Base", "ETH", "https://mainnet.base.org", 21_600),
    (1, "Ethereum", "ETH", "https://ethereum-rpc.publicnode.com", 7_200),
    (10, "Optimism", "ETH", "https://optimism-rpc.publicnode.com", 9_000),
    (42161, "Arbitrum One", "ETH", "https://arbitrum-one-rpc.publicnode.com", 20_000),
    (137, "Polygon", "POL", "https://polygon-bor-rpc.publicnode.com", 2_000),
    (11155111, "Sepolia", "ETH", "https://ethereum-sepolia-rpc.publicnode.com", 7_200),
];
pub fn network(chain: u64) -> Option<(u64, &'static str, &'static str, &'static str, u128)> { NETWORKS.iter().copied().find(|n| n.0 == chain) }

/// Blocks a native-transfer search may read after a balance increase (full block bodies).
const MAX_NATIVE_SCAN_BLOCKS: u128 = 40;
const SELECTED_EVERY: Duration = Duration::from_secs(20);
const OTHERS_EVERY: Duration = Duration::from_secs(90);

// ---------------------------------------------------------------- settings and persisted state

#[derive(Serialize, Deserialize, Clone, Default)]
struct ChainState {
    /// last native balance reading (wei, block)
    #[serde(default)]
    last: Option<(String, u128)>,
    /// token logs searched up to this block
    #[serde(default)]
    cursor: Option<u128>,
    #[serde(default)]
    scan: Option<ScanStatus>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Persisted {
    owner: Option<String>,
    rpcs: HashMap<String, String>,
    notify: bool,
    chain_id: u64,
    chains: HashMap<String, ChainState>,
}
impl Default for Persisted {
    fn default() -> Self { Persisted { owner: None, rpcs: HashMap::new(), notify: true, chain_id: 8453, chains: HashMap::new() } }
}

/// How far back transfer logs were searched on a network, or why it failed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ScanStatus { pub chain_id: u64, pub from_block: Option<u128>, pub to_block: Option<u128>, pub error: Option<String> }

static STATE: Mutex<Option<Persisted>> = Mutex::new(None);

fn state_path() -> Result<PathBuf, String> { Ok(pairing::path().map_err(|e| e.0)?.with_file_name("watch-state.json")) }

fn with_state<T>(f: impl FnOnce(&mut Persisted) -> T) -> Result<T, String> {
    let mut g = STATE.lock().map_err(|_| "watch state poisoned".to_string())?;
    if g.is_none() {
        let loaded = state_path().ok().and_then(|p| fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        *g = Some(loaded);
    }
    Ok(f(g.as_mut().unwrap()))
}

fn persist() -> Result<(), String> {
    let snapshot = with_state(|s| serde_json::to_vec_pretty(s))?.map_err(|e| e.to_string())?;
    let p = state_path()?;
    if let Some(dir) = p.parent() { fs::create_dir_all(dir).map_err(|e| e.to_string())?; }
    let tmp = p.with_extension("json.tmp");
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
    f.write_all(&snapshot).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &p).map_err(|e| e.to_string())
}

pub fn rpc_for(chain: u64) -> Option<String> {
    let custom = with_state(|s| s.rpcs.get(&chain.to_string()).cloned()).ok().flatten();
    custom.or_else(|| network(chain).map(|n| n.3.to_string()))
}
pub fn selected_chain() -> u64 { with_state(|s| s.chain_id).unwrap_or(8453) }

/// The UI pushes its settings: custom nodes per chain, notifications on/off, selected network.
#[tauri::command]
pub(crate) fn watch_configure(rpcs: HashMap<String, String>, notify: bool, chain_id: u64) -> CmdResult<()> {
    let rpcs: HashMap<String, String> = rpcs.into_iter().filter(|(k, v)| v.starts_with("https://") && k.parse::<u64>().is_ok()).collect();
    with_state(|s| { s.rpcs = rpcs; s.notify = notify; if network(chain_id).is_some() { s.chain_id = chain_id; } })?;
    persist()?;
    WAKE.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
pub(crate) fn watch_scan_status() -> CmdResult<Vec<ScanStatus>> {
    with_state(|s| s.chains.values().filter_map(|c| c.scan.clone()).collect())
}

// ---------------------------------------------------------------- log search (shared with nft.rs)

/// Topic word for an address (32 bytes, left-padded).
pub fn topic_address(addr: &str) -> String { format!("0x{:0>64}", addr.trim_start_matches("0x").to_ascii_lowercase()) }

/// Search logs in [from, to], newest chunk first. Public nodes refuse wide ranges and old blocks
/// ("archive requests need a token") in different ways, so a refused chunk is retried smaller
/// and the search stops at the first chunk that is refused even at the smallest size.
/// Returns (logs, lowest block searched, the refusal if the window was not fully searched).
pub fn search_logs(rpc: &eth::Rpc, from: u128, to: u128, address: Option<Value>, topics: Value) -> (Vec<Value>, Option<u128>, Option<String>) {
    let mut logs = Vec::new();
    let mut chunk: u128 = 2_000;
    let mut hi = to;
    let mut covered = None;
    let mut requests = 0;
    while hi >= from && requests < 40 {
        let lo = hi.saturating_sub(chunk - 1).max(from);
        requests += 1;
        match rpc.logs(lo, hi, address.clone(), topics.clone()) {
            Ok(mut l) => { logs.append(&mut l); covered = Some(lo); if lo == 0 || lo == from { break; } hi = lo - 1; }
            // a rate limit is not about the range: stop and try again next round
            Err(e) if e.0.contains("limit reached") || e.0.contains("HTTP 429") || e.0.to_ascii_lowercase().contains("rate limit") => return (logs, covered, Some(e.0)),
            Err(_) if chunk > 64 => { chunk = (chunk / 4).max(64); }
            Err(e) => return (logs, covered, Some(e.0)),
        }
    }
    let incomplete = covered.map_or(true, |c| c > from);
    (logs, covered, incomplete.then(|| "searched as far back as the node allows".to_string()))
}

/// An ERC-20 Transfer log to `owner`: (contract, from, amount). None for anything else (ERC-721
/// has a fourth topic; zero amounts are address-poisoning noise).
fn parse_erc20_in(log: &Value, owner_topic: &str) -> Option<(String, String, u128)> {
    if log.get("removed").and_then(Value::as_bool) == Some(true) { return None; }
    let topics = log.get("topics")?.as_array()?;
    if topics.len() != 3 || topics[0].as_str()? != TRANSFER_TOPIC || !topics[2].as_str()?.eq_ignore_ascii_case(owner_topic) { return None; }
    let data = log.get("data")?.as_str()?.trim_start_matches("0x");
    if data.len() != 64 || !data[..32].bytes().all(|b| b == b'0') { return None; }
    let amount = u128::from_str_radix(&data[32..], 16).ok().filter(|a| *a > 0)?;
    let from = format!("0x{}", &topics[1].as_str()?.trim_start_matches("0x")[24..]);
    Some((log.get("address")?.as_str()?.to_ascii_lowercase(), from, amount))
}

// ---------------------------------------------------------------- one pass over one network

struct Found { incoming: Vec<history::Entry>, changed: bool }

fn notify(app: &AppHandle, body: &str) {
    use tauri_plugin_notification::NotificationExt;
    let _ = app.notification().builder().title("Phone Vault").body(body).show();
}

fn check_chain(app: &AppHandle, chain: u64, owner: &str) -> Result<Found, String> {
    let url = rpc_for(chain).ok_or("unknown network")?;
    let rpc = eth::Rpc::new(&url).map_err(|e| e.0)?;
    let node_chain = rpc.chain_id().map_err(|e| e.0)?;
    if node_chain != chain as u128 { return Err(format!("the node for chain {chain} is on chain {node_chain}")); }
    let block = rpc.block_number().map_err(|e| e.0)?;
    let balance = rpc.balance_at(owner, block).map_err(|e| e.0)?;
    let _ = app.emit("watch-balance", json!({"chain_id": chain, "balance_wei": balance.to_string(), "balance_eth": eth::format_eth(balance), "block": block}));
    if chain == selected_chain() { crate::tray::set_balance(app, chain, balance); }

    let mut found = Found { incoming: Vec::new(), changed: false };
    let key = chain.to_string();
    let prev = with_state(|s| s.chains.get(&key).and_then(|c| c.last.clone()))?;
    with_state(|s| s.chains.entry(key.clone()).or_default().last = Some((balance.to_string(), block)))?;

    // native: a balance increase since the last reading
    if let Some((prev_wei, prev_block)) = prev {
        let prev_wei: u128 = prev_wei.parse().unwrap_or(balance);
        if balance > prev_wei && block > prev_block {
            let delta = balance - prev_wei;
            let mut items = Vec::new();
            if block - prev_block <= MAX_NATIVE_SCAN_BLOCKS {
                for b in (prev_block + 1)..=block {
                    let Ok(body) = rpc.block_with_txs(b) else { items.clear(); break; };
                    for tx in body.get("transactions").and_then(Value::as_array).into_iter().flatten() {
                        let to = tx.get("to").and_then(Value::as_str).unwrap_or("");
                        if !to.eq_ignore_ascii_case(owner) { continue; }
                        let value = tx.get("value").and_then(|v| eth::Rpc::parse_quantity(v, "value").ok()).unwrap_or(0);
                        if value == 0 { continue; }
                        items.push(history::Incoming {
                            hash: tx.get("hash").and_then(Value::as_str).unwrap_or_default().to_string(), chain_id: chain as u128,
                            from: tx.get("from").and_then(Value::as_str).map(str::to_string), amount_eth: eth::format_eth(value),
                            token: None, log_index: None, block: Some(b),
                        });
                    }
                }
            }
            if items.iter().any(|i| i.hash.is_empty()) { items.clear(); }
            if items.is_empty() {
                let entries = history::record_balance_increase(chain as u128, delta)?;
                found.incoming.extend(entries.into_iter().take(1));
            } else {
                found.incoming.extend(history::record_incoming(items)?);
            }
            found.changed = true;
        }
    }

    // ERC-20 from the built-in list: Transfer logs to this address since the cursor
    let listed: Vec<&tokens::Token> = tokens::list().map(|l| l.iter().filter(|t| t.chain_id == chain).collect()).unwrap_or_default();
    if !listed.is_empty() {
        let window = network(chain).map(|n| n.4).unwrap_or(5_000);
        let cursor = with_state(|s| s.chains.get(&key).and_then(|c| c.cursor))?;
        let first = cursor.is_none() || block.saturating_sub(cursor.unwrap_or(0)) > window;
        let from = if first { block.saturating_sub(window - 1) } else { cursor.unwrap_or(block) + 1 };
        if from <= block {
            let owner_topic = topic_address(owner);
            let addresses = Value::Array(listed.iter().map(|t| Value::String(t.address.to_ascii_lowercase())).collect());
            let (logs, covered, error) = search_logs(&rpc, from, block, Some(addresses), json!([TRANSFER_TOPIC, Value::Null, owner_topic]));
            let mut items = Vec::new();
            for log in &logs {
                let Some((contract, sender, amount)) = parse_erc20_in(log, &owner_topic) else { continue };
                let Some(t) = listed.iter().find(|t| t.address.eq_ignore_ascii_case(&contract)) else { continue };
                items.push(history::Incoming {
                    hash: log.get("transactionHash").and_then(Value::as_str).unwrap_or_default().to_string(), chain_id: chain as u128,
                    from: Some(sender), amount_eth: "0".into(), token: Some((t.symbol.clone(), tokens::format_units(amount, t.decimals), t.address.clone())),
                    log_index: log.get("logIndex").and_then(|v| eth::Rpc::parse_quantity(v, "logIndex").ok()).map(|v| v as u64),
                    block: log.get("blockNumber").and_then(|v| eth::Rpc::parse_quantity(v, "blockNumber").ok()),
                });
            }
            items.retain(|i| !i.hash.is_empty());
            let added = history::record_incoming(items)?;
            if !added.is_empty() { found.changed = true; }
            // the first (backfill) search fills history quietly; later ones notify
            if !first { found.incoming.extend(added); }
            with_state(|s| {
                let c = s.chains.entry(key.clone()).or_default();
                let prev = c.scan.clone();
                let prev_from = prev.as_ref().and_then(|x| x.from_block);
                // advance when the newest chunk was searched; otherwise retry next time
                if covered.is_some() { c.cursor = Some(block); }
                let error = if covered.is_none() { Some(error.clone().unwrap_or_else(|| "the node refused the log search".into())) }
                    else if first || prev_from.is_none() { error.clone() }
                    else { prev.and_then(|x| x.error) };
                let from_block = if first || prev_from.is_none() { covered } else { prev_from };
                c.scan = Some(ScanStatus { chain_id: chain, from_block, to_block: Some(block), error });
            })?;
        }
    }

    if history::reconcile(&rpc, chain as u128, owner)? { found.changed = true; }
    Ok(found)
}

fn describe(e: &history::Entry) -> String {
    let net = network(e.chain_id as u64);
    let (name, symbol) = net.map(|n| (n.1, n.2)).unwrap_or(("this network", "ETH"));
    let what = match (&e.token_symbol, &e.token_amount) { (Some(s), Some(a)) => format!("{a} {s}"), _ => format!("{} {symbol}", e.amount_eth) };
    match &e.counterparty { Some(from) => format!("Received {what} on {name} from {}…{}.", &from[..6], &from[from.len() - 4..]), None => format!("Received {what} on {name}.") }
}

pub static WAKE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Start the watcher thread (once, from setup).
pub fn start(app: AppHandle) {
    std::thread::Builder::new().name("watcher".into()).spawn(move || {
        let mut due: HashMap<u64, Instant> = HashMap::new();
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let woke = WAKE.swap(false, std::sync::atomic::Ordering::SeqCst);
            let Ok(Some(owner)) = pairing::load() else { crate::tray::set_unpaired(&app); continue };
            // a different wallet starts from scratch
            let reset = with_state(|s| { if s.owner.as_deref() != Some(owner.as_str()) { s.owner = Some(owner.clone()); s.chains.clear(); true } else { false } }).unwrap_or(false);
            if reset { due.clear(); crate::tray::set_address(&app, &verify::checksum(&owner)); }
            let selected = selected_chain();
            let mut any = false;
            for (chain, ..) in NETWORKS {
                if woke && chain == selected { due.remove(&chain); }
                if due.get(&chain).is_some_and(|t| t.elapsed() < if chain == selected { SELECTED_EVERY } else { OTHERS_EVERY }) { continue; }
                due.insert(chain, Instant::now());
                match check_chain(&app, chain, &owner) {
                    Ok(f) => {
                        if f.changed { any = true; }
                        if with_state(|s| s.notify).unwrap_or(true) {
                            for e in f.incoming.iter().take(3) { notify(&app, &describe(e)); }
                            if f.incoming.len() > 3 { notify(&app, &format!("{} more incoming transfers. Open Phone Vault for details.", f.incoming.len() - 3)); }
                        }
                    }
                    Err(_) => { /* node unreachable: try again on the next round */ }
                }
            }
            if any { let _ = app.emit("history-changed", ()); }
            let _ = persist();
            let _ = price::spot("ETH"); // keeps the menu-bar USD figure warm (cached 60 s)
        }
    }).expect("watcher thread");
}

#[cfg(test)]
mod tests {
    use super::*;
    const ME: &str = "0x7a3b9c1d2e4f5061728394a5b6c7d8e9f0a1b2c3";

    fn log(topics: Vec<&str>, data: &str) -> Value {
        json!({"address": "0x833589FCD6EDB6E08F4C7C32D4F71B54BDA02913", "topics": topics, "data": data, "transactionHash": "0xab", "logIndex": "0x3", "blockNumber": "0x10"})
    }

    #[test]
    fn erc20_transfer_logs_are_parsed_strictly() {
        let me = topic_address(ME);
        let from = topic_address("0x51ea0b8f1a0c6f3f0c1b2e5a6d7c8b9a0e1f2d3c");
        let amount = format!("{:064x}", 125_500_000u128); // 125.5 USDC
        let (contract, sender, value) = parse_erc20_in(&log(vec![TRANSFER_TOPIC, &from, &me], &format!("0x{amount}")), &me).unwrap();
        assert_eq!(contract, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913");
        assert_eq!(sender, "0x51ea0b8f1a0c6f3f0c1b2e5a6d7c8b9a0e1f2d3c");
        assert_eq!(value, 125_500_000);
        // zero-value transfers (address poisoning), ERC-721 (4 topics), other recipients, removed logs: ignored
        assert!(parse_erc20_in(&log(vec![TRANSFER_TOPIC, &from, &me], &format!("0x{:0>64}", "0")), &me).is_none());
        assert!(parse_erc20_in(&log(vec![TRANSFER_TOPIC, &from, &me, &format!("0x{:0>64}", "1")], "0x"), &me).is_none());
        assert!(parse_erc20_in(&log(vec![TRANSFER_TOPIC, &me, &from], &format!("0x{amount}")), &me).is_none());
        let mut removed = log(vec![TRANSFER_TOPIC, &from, &me], &format!("0x{amount}"));
        removed["removed"] = json!(true);
        assert!(parse_erc20_in(&removed, &me).is_none());
        // amounts beyond u128 are not shown rather than wrapped
        assert!(parse_erc20_in(&log(vec![TRANSFER_TOPIC, &from, &me], &format!("0x1{:0>63}", "")), &me).is_none());
    }

    /// Live check against the default public nodes (network access): `cargo test -- --ignored live_`
    #[test]
    #[ignore]
    fn live_log_search_on_public_nodes() {
        let busy = "0x28c6c06298d514db089934071355e5743bf21d60"; // a busy exchange address on Ethereum
        let rpc = eth::Rpc::new(network(1).unwrap().3).unwrap();
        let head = rpc.block_number().unwrap();
        let usdc = json!(["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "0xdac17f958d2ee523a2206206994597c13d831ec7"]);
        let (logs, covered, err) = search_logs(&rpc, head - 7_199, head, Some(usdc), json!([TRANSFER_TOPIC, Value::Null, topic_address(busy)]));
        println!("ethereum token search: {} logs, from {covered:?} (head {head}), {err:?}", logs.len());
        assert!(covered.is_some() && !logs.is_empty());
        let me = topic_address(busy);
        assert!(logs.iter().filter_map(|l| parse_erc20_in(l, &me)).count() > 0);
        // wallet-wide (no contract) searches: public nodes refuse them; the error must say so
        let (_, c2, e2) = search_logs(&rpc, head - 1_999, head, None, json!([TRANSFER_TOPIC, Value::Null, topic_address(busy)]));
        println!("ethereum wallet-wide search: from {c2:?}, {e2:?}");
        for chain in [10u64, 137, 42161, 8453] {
            let rpc = eth::Rpc::new(network(chain).unwrap().3).unwrap();
            let Ok(head) = rpc.block_number() else { println!("{chain}: node unreachable"); continue };
            let toks = Value::Array(tokens::list().unwrap().iter().filter(|t| t.chain_id == chain).map(|t| json!(t.address.to_ascii_lowercase())).collect());
            let (logs, covered, err) = search_logs(&rpc, head - (network(chain).unwrap().4 - 1), head, Some(toks), json!([TRANSFER_TOPIC, Value::Null, topic_address(busy)]));
            println!("{chain}: {} logs, covered from {covered:?} of {}..{head}, {err:?}", logs.len(), head - (network(chain).unwrap().4 - 1));
        }
    }

    #[test]
    fn every_network_has_a_window_and_https_node() {
        for (id, _, _, rpc, window) in NETWORKS {
            assert!(rpc.starts_with("https://"));
            assert!(window >= 1_000);
            assert!(tokens::ALLOWED_CHAINS.contains(&id));
        }
    }
}
