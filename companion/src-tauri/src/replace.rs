//! Speed up or cancel a transaction that is stuck pending. Both are ordinary, complete new
//! transactions with the SAME nonce and higher fees, built here and then sent through the normal
//! pipeline: the phone reviews them like any other transaction, `verify::validate_signature`
//! checks what it signed, and only a verified transaction can be broadcast.
//!
//! * Speed up: the same `to`, `value`, `data` and gas limit as the original.
//! * Cancel: a 0-value transfer to your own address (21,000 gas), so the nonce is used up by a
//!   transaction that does nothing.
//!
//! Fees: both maxFeePerGas and maxPriorityFeePerGas at least 12.5 % above the highest ones already
//! sent for that nonce (nodes require +10 %), or the current network fee if that is higher.
//! Whichever transaction of the nonce group gets mined first wins; history marks the rest dropped.

use crate::{blocking, eth, history, pairing, tokens, verify, CmdResult, Quote};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Replacement {
    /// The pending transaction this one replaces.
    pub hash: String,
    /// "speedup" | "cancel"
    pub kind: String,
    /// The highest fees already sent for this nonce, for display ("was … now …").
    #[serde(default)]
    pub previous_max_fee_per_gas: Option<String>,
    #[serde(default)]
    pub previous_max_priority_fee_per_gas: Option<String>,
}

/// ⌈x × 1.125⌉, and always at least x + 1.
pub fn bump(x: u128) -> u128 { (x.saturating_mul(1125).saturating_add(999) / 1000).max(x.saturating_add(1)) }

/// New (priority, maxFee): each bumped from the previous, or the current network value if higher.
pub fn new_fees(previous: (u128, u128), current: (u128, u128)) -> (u128, u128) {
    let priority = bump(previous.0).max(current.0);
    let max_fee = bump(previous.1).max(current.1).max(priority);
    (priority, max_fee)
}

fn q(v: &str, what: &str) -> Result<u128, String> { verify::quantity(v).map_err(|e| format!("{what}: {}", e.0)) }

/// The highest fees among the transactions this Mac sent for (chain, nonce), if any were recorded.
fn group_fees(entries: &[history::Entry], chain_id: u128, nonce: u128) -> Result<Option<(u128, u128)>, String> {
    let mut best: Option<(u128, u128)> = None;
    for t in entries.iter().filter(|x| x.kind == "out" && x.chain_id == chain_id && x.nonce == Some(nonce)).filter_map(|x| x.tx.as_ref()) {
        let f = (q(&t.max_priority_fee_per_gas, "priority fee")?, q(&t.max_fee_per_gas, "max fee")?);
        best = Some(best.map_or(f, |b| (b.0.max(f.0), b.1.max(f.1))));
    }
    Ok(best)
}

fn pending_original(hash: &str) -> Result<(history::Entry, Vec<history::Entry>), String> {
    let all = history::list()?;
    let e = all.iter().find(|x| x.hash.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(hash))).cloned()
        .ok_or("this transaction is not in this Mac's history")?;
    if e.kind != "out" { return Err("only a transaction sent from this Mac can be sped up or cancelled".into()); }
    if e.status != "pending" { return Err(format!("this transaction is no longer pending ({})", e.status)); }
    if e.nonce.is_none() { return Err("this transaction has no recorded nonce".into()); }
    Ok((e, all))
}

/// Rebuild the token intent of a recorded token transfer from the built-in list and its calldata.
fn token_intent(chain_id: u128, contract: &str, data: &str) -> Result<tokens::TokenIntent, String> {
    let t = tokens::lookup(u64::try_from(chain_id).map_err(|_| "chain id out of range")?, contract).ok_or("the token is not in the built-in list for this network")?;
    let (recipient, amount) = verify::decode_erc20_transfer(data).map_err(|e| e.0)?;
    Ok(tokens::TokenIntent {
        contract: t.address.to_ascii_lowercase(), symbol: t.symbol.clone(), name: t.name.clone(), decimals: t.decimals,
        recipient, amount_raw: amount.to_string(), amount: tokens::format_units(amount, t.decimals),
    })
}

/// Quote a speed-up or cancel for a pending transaction sent from this Mac.
#[tauri::command]
pub(crate) async fn replacement_quote(rpc_url: String, hash: String, kind: String) -> CmdResult<Quote> {
    if !matches!(kind.as_str(), "speedup" | "cancel") { return Err("kind must be speedup or cancel".into()); }
    blocking(move || {
        let owner = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
        let (e, all) = pending_original(&hash)?;
        let nonce = e.nonce.unwrap_or_default();
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let chain = rpc.chain_id().map_err(|e| e.0)?;
        if chain != e.chain_id { return Err(format!("this transaction is on chain {}, but the selected node is on chain {chain}; switch to that network", e.chain_id)); }
        if rpc.receipt_status(&hash).map_err(|e| e.0)?.is_some() || rpc.nonce_latest(&owner).map_err(|e| e.0)? > nonce {
            return Err("it was already included in a block (or another transaction used its nonce), so there is nothing to replace".into());
        }
        let previous = match group_fees(&all, chain, nonce)? {
            Some(f) => f,
            None => rpc.tx_fees(&hash).map_err(|e| e.0)?.ok_or("the node doesn't know the original transaction's fees; it may already have been dropped")?,
        };
        let (priority, max_fee) = new_fees(previous, rpc.fees().map_err(|e| e.0)?);
        let (to, value, data, gas, token) = if kind == "speedup" {
            let t = e.tx.as_ref().ok_or("this transaction was sent before this app kept its details, so it can only be cancelled")?;
            let token = match &e.token_contract { Some(c) => Some(token_intent(chain, c, &t.data)?), None => None };
            (t.to.to_ascii_lowercase(), q(&t.value, "value")?, t.data.to_ascii_lowercase(), q(&t.gas_limit, "gas limit")?, token)
        } else {
            (owner.clone(), 0, "0x".to_string(), 21_000, None)
        };
        let balance = rpc.balance(&owner).map_err(|e| e.0)?;
        let max_cost = gas.checked_mul(max_fee).ok_or("fee overflow")?;
        let total = value.checked_add(max_cost).ok_or("total overflow")?;
        if total > balance { return Err(format!("not enough balance for the higher fee: {} ETH needed at most, {} ETH available", eth::format_eth(total), eth::format_eth(balance))); }
        Ok(Quote {
            chain_id: verify::to_quantity(chain), nonce: verify::to_quantity(nonce), max_priority_fee_per_gas: verify::to_quantity(priority),
            max_fee_per_gas: verify::to_quantity(max_fee), gas_limit: verify::to_quantity(gas), to, value: verify::to_quantity(value), data,
            amount_eth: eth::format_eth(value), max_fee_eth: eth::format_eth(max_cost), total_eth: eth::format_eth(total),
            balance_eth: eth::format_eth(balance), network: crate::network_name(chain), token,
            replaces: Some(Replacement {
                hash: e.hash.clone().unwrap_or_default(), kind,
                previous_max_fee_per_gas: Some(verify::to_quantity(previous.1)), previous_max_priority_fee_per_gas: Some(verify::to_quantity(previous.0)),
            }),
        })
    }).await
}

/// Before a replacement goes to the phone: it really replaces a pending transaction from this
/// Mac (same chain and nonce), its fees are bumped, and a speed-up changes nothing else while a
/// cancel is a 0-value self-transfer. Otherwise the "Replacement for tx …" label would be a lie.
pub fn check(quote: &Quote, owner: &str) -> Result<(), String> {
    let Some(r) = &quote.replaces else { return Ok(()) };
    let (e, all) = pending_original(&r.hash)?;
    check_against(quote, r, &e, &all, owner)
}

fn check_against(quote: &Quote, r: &Replacement, e: &history::Entry, all: &[history::Entry], owner: &str) -> Result<(), String> {
    let chain = q(&quote.chain_id, "chainId")?;
    if chain != e.chain_id { return Err("the replacement is for a different network than the original".into()); }
    let nonce = q(&quote.nonce, "nonce")?;
    if Some(nonce) != e.nonce { return Err("the replacement does not use the original's nonce".into()); }
    if let Some((p, m)) = group_fees(all, chain, nonce)? {
        if q(&quote.max_priority_fee_per_gas, "priority fee")? < bump(p) || q(&quote.max_fee_per_gas, "max fee")? < bump(m) {
            return Err("the replacement's fees are not at least 12.5 % above the original's".into());
        }
    }
    let (to, value, data) = (quote.to.to_ascii_lowercase(), q(&quote.value, "value")?, quote.data.to_ascii_lowercase());
    match r.kind.as_str() {
        "speedup" => {
            let t = e.tx.as_ref().ok_or("the original's details are not recorded")?;
            if to != t.to.to_ascii_lowercase() || value != q(&t.value, "value")? || data != t.data.to_ascii_lowercase() || quote.gas_limit != t.gas_limit {
                return Err("a speed-up must send exactly what the original sent".into());
            }
        }
        "cancel" => {
            if to != owner.to_ascii_lowercase() || value != 0 || data != "0x" || quote.token.is_some() {
                return Err("a cancel must be a 0-value transfer to your own address".into());
            }
        }
        _ => return Err("unknown replacement kind".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const ME: &str = "0x7a3b9c1d2e4f5061728394a5b6c7d8e9f0a1b2c3";
    const TO: &str = "0x1111111111111111111111111111111111111111";

    #[test]
    fn bumps_are_at_least_twelve_and_a_half_percent() {
        assert_eq!(bump(1000), 1125);
        assert_eq!(bump(1001), 1127, "rounded up");
        assert_eq!(bump(0), 1);
        assert_eq!(bump(1), 2);
        // current fee higher than the bump wins, per field
        assert_eq!(new_fees((1_000, 10_000), (5_000, 2_000)), (5_000, 11_250));
        assert_eq!(new_fees((1_000, 10_000), (100, 50_000)), (1_125, 50_000));
        // max fee never below the priority fee
        assert_eq!(new_fees((10_000, 10_000), (90_000, 1)), (90_000, 90_000));
    }

    fn original() -> history::Entry {
        let mut e: history::Entry = serde_json::from_value(serde_json::json!({
            "kind": "out", "hash": "0xaa", "chain_id": 8453, "counterparty": TO, "amount_eth": "0.01", "fee_max_eth": null,
            "nonce": 7, "time": 1, "status": "pending", "block": null })).unwrap();
        e.tx = Some(history::TxParams { to: TO.into(), value: "0x2386f26fc10000".into(), data: "0x".into(), gas_limit: "0x5208".into(),
            max_fee_per_gas: "0x3e8".into(), max_priority_fee_per_gas: "0x64".into() });
        e
    }

    fn quote(to: &str, value: &str, nonce: &str, prio: &str, max: &str, kind: &str) -> (Quote, Replacement) {
        let r = Replacement { hash: "0xaa".into(), kind: kind.into(), previous_max_fee_per_gas: None, previous_max_priority_fee_per_gas: None };
        (Quote { chain_id: "0x2105".into(), nonce: nonce.into(), max_priority_fee_per_gas: prio.into(), max_fee_per_gas: max.into(), gas_limit: "0x5208".into(),
            to: to.into(), value: value.into(), data: "0x".into(), amount_eth: "0".into(), max_fee_eth: "0".into(), total_eth: "0".into(),
            balance_eth: "0".into(), network: "Base".into(), token: None, replaces: Some(r.clone()) }, r)
    }

    #[test]
    fn replacements_must_really_replace() {
        let e = original();
        let all = vec![e.clone()];
        // speed-up: same tx, fees ≥ +12.5 % (0x64=100 → 113 = 0x71; 0x3e8=1000 → 1125 = 0x465)
        let (q1, r1) = quote(TO, "0x2386f26fc10000", "0x7", "0x71", "0x465", "speedup");
        assert!(check_against(&q1, &r1, &e, &all, ME).is_ok());
        let (q2, r2) = quote(TO, "0x2386f26fc10000", "0x7", "0x70", "0x465", "speedup");
        assert!(check_against(&q2, &r2, &e, &all, ME).is_err(), "priority bumped by less than 12.5 %");
        let (q3, r3) = quote(ME, "0x2386f26fc10000", "0x7", "0x71", "0x465", "speedup");
        assert!(check_against(&q3, &r3, &e, &all, ME).is_err(), "a speed-up cannot change the recipient");
        let (q4, r4) = quote(TO, "0x2386f26fc10000", "0x8", "0x71", "0x465", "speedup");
        assert!(check_against(&q4, &r4, &e, &all, ME).is_err(), "other nonce");
        // cancel: 0 to self only
        let (q5, r5) = quote(ME, "0x0", "0x7", "0x71", "0x465", "cancel");
        assert!(check_against(&q5, &r5, &e, &all, ME).is_ok());
        let (q6, r6) = quote(TO, "0x0", "0x7", "0x71", "0x465", "cancel");
        assert!(check_against(&q6, &r6, &e, &all, ME).is_err());
        let (q7, r7) = quote(ME, "0x1", "0x7", "0x71", "0x465", "cancel");
        assert!(check_against(&q7, &r7, &e, &all, ME).is_err());
        // a second replacement must beat the highest fee already sent for the nonce
        let mut first_speedup = original();
        first_speedup.hash = Some("0xbb".into());
        first_speedup.tx.as_mut().unwrap().max_fee_per_gas = "0x465".into();
        first_speedup.tx.as_mut().unwrap().max_priority_fee_per_gas = "0x71".into();
        let all2 = vec![e.clone(), first_speedup];
        assert!(check_against(&q5, &r5, &e, &all2, ME).is_err(), "not above the first speed-up");
        let (q8, r8) = quote(ME, "0x0", "0x7", "0x80", "0x4f2", "cancel");
        assert!(check_against(&q8, &r8, &e, &all2, ME).is_ok());
    }
}
