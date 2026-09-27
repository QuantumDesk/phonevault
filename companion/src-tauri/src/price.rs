//! Spot price in USD for the native coin, for display only (never part of anything signed).
//! One public, key-less source (Coinbase), cached for 60 s. Failure just means no dollar figures.

use crate::{blocking, CmdResult};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(60);
static CACHE: Mutex<Option<HashMap<String, (Instant, f64)>>> = Mutex::new(None);

fn fetch(symbol: &str) -> Result<f64, String> {
    let url = format!("https://api.coinbase.com/v2/prices/{symbol}-USD/spot");
    let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(6)).build().map_err(|e| e.to_string())?;
    let v: Value = client.get(url).send().map_err(|e| e.to_string())?.error_for_status().map_err(|e| e.to_string())?.json().map_err(|e| e.to_string())?;
    parse(&v)
}

fn parse(v: &Value) -> Result<f64, String> {
    let amount = v.pointer("/data/amount").and_then(Value::as_str).ok_or("no price in response")?;
    let p: f64 = amount.parse().map_err(|_| "price is not a number".to_string())?;
    if !(p.is_finite() && p > 0.0) { return Err("implausible price".into()); }
    Ok(p)
}

/// USD per coin. `symbol` is limited to the native coins of the networks the app knows.
#[tauri::command]
pub(crate) async fn spot_usd(symbol: String) -> CmdResult<f64> {
    let symbol = symbol.to_ascii_uppercase();
    if !matches!(symbol.as_str(), "ETH" | "POL") { return Err(format!("no price source for {symbol}")); }
    blocking(move || {
        if let Some((at, p)) = CACHE.lock().map_err(|_| "cache poisoned")?.as_ref().and_then(|m| m.get(&symbol)).copied() {
            if at.elapsed() < TTL { return Ok(p); }
        }
        let p = fetch(&symbol)?;
        CACHE.lock().map_err(|_| "cache poisoned")?.get_or_insert_with(HashMap::new).insert(symbol, (Instant::now(), p));
        Ok(p)
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_coinbase_shape() {
        let v: Value = serde_json::from_str(r#"{"data":{"amount":"3456.78","base":"ETH","currency":"USD"}}"#).unwrap();
        assert_eq!(parse(&v).unwrap(), 3456.78);
        assert!(parse(&serde_json::json!({"data":{"amount":"-1"}})).is_err());
        assert!(parse(&serde_json::json!({})).is_err());
    }
}
