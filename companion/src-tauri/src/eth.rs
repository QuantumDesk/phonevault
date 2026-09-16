//! Ethereum node access over JSON-RPC: balance, nonce, fee quote, broadcast, receipt.
//! The node is untrusted data: everything it feeds into a transaction is shown to the user here
//! AND on the phone before anything is signed.

use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct EthError(pub String);
fn err(m: impl Into<String>) -> EthError { EthError(m.into()) }

pub struct Rpc { url: String, client: reqwest::blocking::Client }

pub const DEFAULT_RPC: &str = "https://ethereum-rpc.publicnode.com";

impl Rpc {
    pub fn new(url: &str) -> Result<Rpc, EthError> {
        if !url.starts_with("https://") { return Err(err("the node URL must use https://")); }
        let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(20)).build().map_err(|e| err(e.to_string()))?;
        Ok(Rpc { url: url.to_string(), client })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, EthError> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let resp: Value = self.client.post(&self.url).json(&body).send().map_err(|e| err(format!("node unreachable: {e}")))?
            .json().map_err(|e| err(format!("node returned non-JSON: {e}")))?;
        if let Some(e) = resp.get("error") { return Err(err(format!("node error for {method}: {}", e.get("message").and_then(Value::as_str).unwrap_or("unknown")))); }
        resp.get("result").cloned().ok_or_else(|| err(format!("node returned no result for {method}")))
    }

    fn hex_u128(v: &Value, what: &str) -> Result<u128, EthError> {
        let s = v.as_str().ok_or_else(|| err(format!("{what}: expected hex string")))?;
        u128::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|_| err(format!("{what}: bad hex {s}")))
    }

    pub fn chain_id(&self) -> Result<u128, EthError> { Self::hex_u128(&self.call("eth_chainId", json!([]))?, "chainId") }
    pub fn block_number(&self) -> Result<u128, EthError> { Self::hex_u128(&self.call("eth_blockNumber", json!([]))?, "blockNumber") }
    pub fn balance(&self, address: &str) -> Result<u128, EthError> { Self::hex_u128(&self.call("eth_getBalance", json!([address, "latest"]))?, "balance") }
    pub fn nonce(&self, address: &str) -> Result<u128, EthError> { Self::hex_u128(&self.call("eth_getTransactionCount", json!([address, "pending"]))?, "nonce") }

    /// (maxPriorityFeePerGas, maxFeePerGas) in wei. Priority from the node's suggestion, max fee =
    /// 2 × next base fee + priority, so the transaction survives a few blocks of fee growth.
    pub fn fees(&self) -> Result<(u128, u128), EthError> {
        let history = self.call("eth_feeHistory", json!(["0x5", "latest", [50]]))?;
        let base_next = history.get("baseFeePerGas").and_then(Value::as_array).and_then(|a| a.last()).map(|v| Self::hex_u128(v, "baseFee")).transpose()?
            .ok_or_else(|| err("fee history without base fees"))?;
        let priority = match self.call("eth_maxPriorityFeePerGas", json!([])) {
            Ok(v) => Self::hex_u128(&v, "priorityFee")?,
            Err(_) => 1_000_000_000, // 1 gwei fallback
        };
        let priority = priority.max(100_000_000); // never below 0.1 gwei
        Ok((priority, base_next.saturating_mul(2).saturating_add(priority)))
    }

    pub fn estimate_gas(&self, from: &str, to: &str, value_wei: u128) -> Result<u128, EthError> {
        let v = self.call("eth_estimateGas", json!([{"from": from, "to": to, "value": crate::verify::to_quantity(value_wei)}]))?;
        Self::hex_u128(&v, "gas")
    }

    pub fn send_raw(&self, raw_hex: &str) -> Result<String, EthError> {
        let v = self.call("eth_sendRawTransaction", json!([raw_hex]))?;
        v.as_str().map(str::to_string).ok_or_else(|| err("broadcast returned no hash"))
    }

    /// None while pending; Some(true) mined OK; Some(false) reverted.
    pub fn receipt_status(&self, hash: &str) -> Result<Option<(bool, u128)>, EthError> {
        let v = self.call("eth_getTransactionReceipt", json!([hash]))?;
        if v.is_null() { return Ok(None); }
        let ok = Self::hex_u128(v.get("status").unwrap_or(&json!("0x0")), "status")? == 1;
        let block = Self::hex_u128(v.get("blockNumber").unwrap_or(&json!("0x0")), "blockNumber")?;
        Ok(Some((ok, block)))
    }
}

/// Wei → decimal ETH string with up to 8 fractional digits (display only).
pub fn format_eth(wei: u128) -> String {
    let whole = wei / 1_000_000_000_000_000_000u128;
    let frac = wei % 1_000_000_000_000_000_000u128;
    let mut s = format!("{whole}.{:018}", frac);
    while s.ends_with('0') { s.pop(); }
    if s.ends_with('.') { s.push('0'); }
    // trim to 8 decimals for the eye; the wei value is what gets signed
    if let Some(dot) = s.find('.') { if s.len() - dot - 1 > 8 { s.truncate(dot + 9); } }
    s
}

/// Decimal ETH string → wei, exact (no floats).
pub fn parse_eth(text: &str) -> Result<u128, EthError> {
    let t = text.trim();
    if t.is_empty() { return Err(err("enter an amount")); }
    let (whole, frac) = match t.split_once('.') { Some((w, f)) => (w, f), None => (t, "") };
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) || frac.len() > 18 || (whole.is_empty() && frac.is_empty()) {
        return Err(err("amount must be a decimal number of ETH with at most 18 decimals"));
    }
    let whole_v: u128 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| err("amount too large"))? };
    let mut frac_s = frac.to_string();
    while frac_s.len() < 18 { frac_s.push('0'); }
    let frac_v: u128 = if frac_s.is_empty() { 0 } else { frac_s.parse().map_err(|_| err("bad amount"))? };
    whole_v.checked_mul(1_000_000_000_000_000_000).and_then(|w| w.checked_add(frac_v)).ok_or_else(|| err("amount too large"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eth_round_trip() {
        assert_eq!(parse_eth("0.5").unwrap(), 500_000_000_000_000_000);
        assert_eq!(parse_eth("2").unwrap(), 2_000_000_000_000_000_000);
        assert_eq!(format_eth(500_000_000_000_000_000), "0.5");
        assert_eq!(format_eth(420_000_000_000_000), "0.00042");
        assert!(parse_eth("1e3").is_err());
        assert!(parse_eth("-1").is_err());
    }
}
