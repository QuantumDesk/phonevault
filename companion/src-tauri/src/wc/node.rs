//! `eth_sendTransaction`: missing fields filled from the user's node, giving the Send flow's `Quote`.

use super::request::{call_info, note};
use super::*;
use crate::{eth, pairing, verify, Quote};
use serde_json::{json, Value};
use std::time::Duration;

/// Minimal JSON-RPC call for the dApp's gas estimate. Not `eth::Rpc::estimate_gas_data`, so that
/// the node's own refusal text reaches the dApp unprefixed and the answer is parsed with the
/// strict `dapp_quantity` rather than `eth::Rpc`'s lenient hex parse.
fn node_call(url: &str, method: &str, params: Value) -> Result<Value, String> {
    if !url.starts_with("https://") {
        return Err("the node URL must use https://".into());
    }
    let client = crate::http::client(Duration::from_secs(20), crate::http::Policy::none())?;
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let http = client.post(url).json(&body).send().map_err(|e| eth::transport_error(&e))?;
    let bytes = eth::read_capped(http, eth::MAX_RESPONSE)?;
    let resp: Value = serde_json::from_slice(&bytes).map_err(|e| format!("node returned non-JSON: {e}"))?;
    if let Some(e) = resp.get("error") {
        return Err(e.get("message").and_then(Value::as_str).unwrap_or("node error").to_string());
    }
    resp.get("result").cloned().ok_or_else(|| format!("node returned no result for {method}"))
}

/// Gas limit for a call: the node's estimate, +20 % headroom for anything but a plain transfer.
pub fn gas_with_headroom(estimate: u128, plain_transfer: bool) -> u128 {
    if plain_transfer && estimate == 21_000 {
        21_000
    } else {
        estimate.saturating_mul(6).div_ceil(5)
    }
}

pub(super) fn prepare_tx(rpc_url: &str, chain: u64, params: &Value, paired: &str) -> Result<Prepared, RpcError> {
    let draft = normalize_tx(params, paired, chain)?;
    let mut notes = draft.notes.clone();
    let node = |e: eth::EthError| rpc_err(INTERNAL, e.0);
    let rpc = eth::Rpc::new(rpc_url).map_err(node)?;
    let node_chain = rpc.chain_id().map_err(node)?;
    if node_chain != chain as u128 {
        return Err(rpc_err(
            INTERNAL,
            format!("the node for {} answers for chain {node_chain}; check the node in Settings", chain_name(chain)),
        ));
    }
    let pending = rpc.nonce(paired).map_err(node)?;
    let nonce = match draft.nonce {
        Some(n) if n != pending => {
            notes.push(note("warn", format!("The site set nonce {n}, but your next nonce is {pending}. A different nonce can replace or wait behind another transaction.")));
            n
        }
        Some(n) => n,
        None => pending,
    };
    let (priority, max_fee) = match (draft.max_priority, draft.max_fee) {
        (Some(p), Some(f)) => {
            notes.push(note("info", "Fees as suggested by the site."));
            (p, f)
        }
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
            let call =
                json!({"from": paired, "to": draft.to, "value": verify::to_quantity(draft.value), "data": draft.data});
            let est = node_call(rpc_url, "eth_estimateGas", json!([call]))
                .map_err(|e| rpc_err(TX_REJECTED, format!("the node expects this transaction to fail: {e}")))?;
            let est = dapp_quantity(&est, "gas estimate")?;
            gas_with_headroom(est, draft.data == "0x")
        }
    };
    if gas > MAX_GAS {
        return Err(bad(format!("gas limit {gas} exceeds {MAX_GAS}")));
    }
    let balance = rpc.balance(paired).map_err(node)?;
    let max_cost = gas.checked_mul(max_fee).ok_or_else(|| bad("fee overflow"))?;
    let total = draft.value.checked_add(max_cost).ok_or_else(|| bad("total overflow"))?;
    if total > balance {
        return Err(rpc_err(
            TX_REJECTED,
            format!(
                "insufficient funds: up to {} needed, {} available",
                eth::format_eth(total),
                eth::format_eth(balance)
            ),
        ));
    }
    let call = call_info(&draft.data, draft.value);
    match call.kind {
        "contract_call" => notes.push(note("danger", "This calls a contract. Your phone signs only calls it can explain (transfers, token and NFT approvals, Uniswap swaps) and refuses anything else.")),
        "token_approve" if call.amount.as_deref() == Some("unlimited") => notes.push(note("danger", "Unlimited approval: the spender can move all of this token, now and later.")),
        "token_approve" => notes.push(note("warn", "Token approval: the spender can move up to this amount of the token.")),
        _ => {}
    }
    if !call.phone_supported && call.kind != "contract_call" {
        notes.push(note("warn", "This token call is not in the canonical form your phone accepts; it will refuse it."));
    }
    let quote = Quote {
        chain_id: verify::to_quantity(chain as u128),
        nonce: verify::to_quantity(nonce),
        max_priority_fee_per_gas: verify::to_quantity(priority),
        max_fee_per_gas: verify::to_quantity(max_fee),
        gas_limit: verify::to_quantity(gas),
        to: draft.to.clone(),
        value: verify::to_quantity(draft.value),
        data: draft.data.clone(),
        amount_eth: eth::format_eth(draft.value),
        max_fee_eth: eth::format_eth(max_cost),
        total_eth: eth::format_eth(total),
        balance_eth: eth::format_eth(balance),
        network: crate::network_name(chain as u128),
        // dApp calldata is passed through as-is; verify.rs checks it byte-for-byte, not as a token send
        token: None,
        replaces: None,
    };
    Ok(Prepared::Transaction { chain_id: chain, quote, call, notes })
}

pub(super) fn paired_or_err() -> Result<String, RpcError> {
    pairing::load()
        .map_err(|e| rpc_err(UNAUTHORIZED, e.0))?
        .ok_or_else(|| rpc_err(UNAUTHORIZED, "This wallet isn't paired with a phone yet."))
}
