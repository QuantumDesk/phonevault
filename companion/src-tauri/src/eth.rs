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

/// The most this reads of one node answer (a full block with its transactions fits easily).
pub const MAX_RESPONSE: u64 = 16 * 1024 * 1024;

/// Read a body, refusing one longer than `max` bytes instead of buffering all of it. A read error
/// is described by its kind only: an HTTP client's error text can carry the request URL.
pub fn read_capped(r: impl std::io::Read, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    r.take(max.saturating_add(1)).read_to_end(&mut bytes).map_err(|e| format!("the answer could not be read ({:?})", e.kind()))?;
    if bytes.len() as u64 > max { return Err(format!("the answer is larger than {} bytes, refused", max)); }
    Ok(bytes)
}

/// Why a request to a node failed, WITHOUT the node URL: node URLs routinely carry the user's
/// provider API key (Infura/Alchemy/QuickNode paths), and these messages reach the UI, connected
/// sites (bridge.rs) and WalletConnect dApps (wc.rs). reqwest's own Display includes the URL.
pub fn transport_error(e: &reqwest::Error) -> String {
    let what = if e.is_timeout() { "timed out" } else if e.is_connect() { "could not connect" } else if e.is_redirect() { "redirect refused" } else { "request failed" };
    format!("node unreachable: {what}")
}

/// HTTP client for nodes: bounded time, and no redirects (the node is the URL the user set, not
/// wherever it points to).
fn node_client() -> Result<reqwest::blocking::Client, EthError> {
    reqwest::blocking::Client::builder().timeout(Duration::from_secs(20)).redirect(reqwest::redirect::Policy::none())
        .build().map_err(|e| err(e.to_string()))
}

impl Rpc {
    pub fn new(url: &str) -> Result<Rpc, EthError> {
        if !url.starts_with("https://") { return Err(err("the node URL must use https://")); }
        Ok(Rpc { url: url.to_string(), client: node_client()? })
    }

    /// POST one JSON-RPC request and parse the answer, reading at most MAX_RESPONSE bytes.
    /// `Err` when the node cannot be reached, answers too much, or does not answer JSON.
    fn post(&self, method: &str, params: Value) -> Result<Value, EthError> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let http = self.client.post(&self.url).json(&body).send().map_err(|e| err(transport_error(&e)))?;
        let code = http.status();
        let bytes = read_capped(http, MAX_RESPONSE).map_err(|e| err(format!("node answer to {method}: {e}")))?;
        // Public nodes answer refusals (rate limits, "archive requests need a token") with an HTTP
        // error and a JSON-RPC error body: keep the node's own words.
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => Ok(v),
            Err(_) if !code.is_success() => Err(err(format!("node refused {method}: HTTP {code}"))),
            Err(e2) => Err(err(format!("node returned non-JSON: {e2}"))),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, EthError> {
        let resp = self.post(method, params)?;
        if let Some(e) = resp.get("error") { return Err(err(format!("node error for {method}: {}", e.get("message").and_then(Value::as_str).unwrap_or("unknown")))); }
        resp.get("result").cloned().ok_or_else(|| err(format!("node returned no result for {method}")))
    }

    /// The whole JSON-RPC response (`result` or `error` with its code and revert `data`), for the
    /// simulation, which needs a node's refusal in detail rather than as text. Errs only when the
    /// node cannot be reached or does not answer JSON-RPC.
    pub fn call_raw(&self, method: &str, params: Value) -> Result<Value, EthError> {
        let resp = self.post(method, params)?;
        if resp.get("result").is_none() && resp.get("error").is_none() { return Err(err(format!("node returned no result for {method}"))); }
        Ok(resp)
    }

    /// (number, baseFeePerGas) of the latest block, read together.
    pub fn latest_header(&self) -> Result<(u128, u128), EthError> {
        let b = self.call("eth_getBlockByNumber", json!(["latest", false]))?;
        let number = Self::hex_u128(b.get("number").unwrap_or(&Value::Null), "number")?;
        let base = match b.get("baseFeePerGas") { Some(v) if !v.is_null() => Self::hex_u128(v, "baseFeePerGas")?, _ => 0 };
        Ok((number, base))
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

    /// Gas for a call with calldata (token transfers). An error usually means it would revert.
    pub fn estimate_gas_data(&self, from: &str, to: &str, value_wei: u128, data: &str) -> Result<u128, EthError> {
        let v = self.call("eth_estimateGas", json!([{"from": from, "to": to, "value": crate::verify::to_quantity(value_wei), "data": data}]))?;
        Self::hex_u128(&v, "gas")
    }

    /// Read-only `eth_call` at the latest block; returns the raw return bytes.
    pub fn eth_call(&self, to: &str, data: &str) -> Result<Vec<u8>, EthError> {
        let v = self.call("eth_call", json!([{"to": to, "data": data}, "latest"]))?;
        let s = v.as_str().ok_or_else(|| err("eth_call: expected hex string"))?;
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| err("eth_call: bad hex"))
    }

    pub fn send_raw(&self, raw_hex: &str) -> Result<String, EthError> {
        let v = self.call("eth_sendRawTransaction", json!([raw_hex]))?;
        v.as_str().map(str::to_string).ok_or_else(|| err("broadcast returned no hash"))
    }

    /// Transactions mined from `address` so far (the next nonce not yet in a block).
    pub fn nonce_latest(&self, address: &str) -> Result<u128, EthError> { Self::hex_u128(&self.call("eth_getTransactionCount", json!([address, "latest"]))?, "nonce") }

    /// Balance at a given block (so a balance and the block it belongs to are read together).
    pub fn balance_at(&self, address: &str, block: u128) -> Result<u128, EthError> {
        Self::hex_u128(&self.call("eth_getBalance", json!([address, crate::verify::to_quantity(block)]))?, "balance")
    }

    /// (maxPriorityFeePerGas, maxFeePerGas) of a transaction the node knows, if it is EIP-1559.
    pub fn tx_fees(&self, hash: &str) -> Result<Option<(u128, u128)>, EthError> {
        let v = self.call("eth_getTransactionByHash", json!([hash]))?;
        if v.is_null() { return Ok(None); }
        match (v.get("maxPriorityFeePerGas"), v.get("maxFeePerGas")) {
            (Some(p), Some(m)) => Ok(Some((Self::hex_u128(p, "priorityFee")?, Self::hex_u128(m, "maxFee")?))),
            _ => Ok(None),
        }
    }

    /// `eth_getLogs` between two blocks (inclusive). `address` may be one contract, several, or none.
    pub fn logs(&self, from: u128, to: u128, address: Option<Value>, topics: Value) -> Result<Vec<Value>, EthError> {
        let mut filter = json!({"fromBlock": crate::verify::to_quantity(from), "toBlock": crate::verify::to_quantity(to), "topics": topics});
        if let Some(a) = address { filter["address"] = a; }
        match self.call("eth_getLogs", json!([filter]))? { Value::Array(a) => Ok(a), _ => Err(err("eth_getLogs: expected an array")) }
    }

    /// A block with its full transactions (for finding incoming native transfers).
    pub fn block_with_txs(&self, number: u128) -> Result<Value, EthError> {
        self.call("eth_getBlockByNumber", json!([crate::verify::to_quantity(number), true]))
    }

    pub fn parse_quantity(v: &Value, what: &str) -> Result<u128, EthError> { Self::hex_u128(v, what) }

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
    fn node_answers_are_capped() {
        assert_eq!(read_capped(&b"{}"[..], 2).unwrap(), b"{}");
        assert!(read_capped(&b"{} "[..], 2).is_err());
        assert!(read_capped(std::io::repeat(b' '), 1024).is_err(), "an endless body stops at the cap");
    }

    /// A failed request's error text must not include the node URL (which can carry the user's
    /// provider API key): it reaches the UI and, through wc.rs, WalletConnect dApps.
    #[test]
    fn node_errors_never_contain_the_node_url() {
        let rpc = Rpc::new("https://127.0.0.1:9/v3/SECRET-API-KEY-1234").unwrap();
        let e = rpc.chain_id().unwrap_err().0;
        assert!(e.starts_with("node unreachable"), "{e}");
        assert!(!e.contains("SECRET") && !e.contains("127.0.0.1"), "{e}");
    }

    /// One-shot local HTTP server answering every request with `reply`.
    fn serve(reply: String) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for s in listener.incoming().take(3) {
                let mut s = s.unwrap();
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let _ = s.write_all(reply.replace("{port}", &port.to_string()).as_bytes());
            }
        });
        format!("http://127.0.0.1:{port}/")
    }

    #[test]
    fn redirects_are_not_followed_and_big_answers_refused() {
        // Rpc::new insists on https; the transport under test is the same client.
        let url = serve("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{port}/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into());
        let rpc = Rpc { url, client: node_client().unwrap() };
        let e = rpc.chain_id().unwrap_err().0;
        assert!(e.contains("307"), "followed the redirect? {e}");

        let big = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x{}\"}}", "0".repeat(MAX_RESPONSE as usize));
        let url = serve(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{big}", big.len()));
        let rpc = Rpc { url, client: node_client().unwrap() };
        let e = rpc.chain_id().unwrap_err().0;
        assert!(e.contains("larger than"), "{e}");

        let url = serve("HTTP/1.1 200 OK\r\nContent-Length: 40\r\nConnection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"} ".into());
        assert_eq!(Rpc { url, client: node_client().unwrap() }.chain_id().unwrap(), 1);
    }

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
