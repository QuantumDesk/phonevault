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
    let client =
        reqwest::blocking::Client::builder().timeout(Duration::from_secs(6)).build().map_err(|e| e.to_string())?;
    let v: Value = client
        .get(url)
        .send()
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .map_err(|e| e.to_string())?;
    parse(&v)
}

fn parse(v: &Value) -> Result<f64, String> {
    let amount = v.pointer("/data/amount").and_then(Value::as_str).ok_or("no price in response")?;
    let p: f64 = amount.parse().map_err(|_| "price is not a number".to_string())?;
    if !(p.is_finite() && p > 0.0) {
        return Err("implausible price".into());
    }
    Ok(p)
}

/// Cached spot price for ETH, POL or BTC (the only symbols fetched).
pub fn spot(symbol: &str) -> Result<f64, String> {
    let symbol = symbol.to_ascii_uppercase();
    if !matches!(symbol.as_str(), "ETH" | "POL" | "BTC") {
        return Err(format!("no price source for {symbol}"));
    }
    if let Some((at, p)) = CACHE.lock().map_err(|_| "cache poisoned")?.as_ref().and_then(|m| m.get(&symbol)).copied() {
        if at.elapsed() < TTL {
            return Ok(p);
        }
    }
    let p = fetch(&symbol)?;
    CACHE.lock().map_err(|_| "cache poisoned")?.get_or_insert_with(HashMap::new).insert(symbol, (Instant::now(), p));
    Ok(p)
}

#[derive(serde::Serialize)]
#[allow(non_snake_case)]
pub struct Prices {
    ETH: Option<f64>,
    POL: Option<f64>,
    BTC: Option<f64>,
}

/// Every price the UI uses for totals, each null when unavailable.
#[tauri::command]
pub(crate) async fn prices_usd() -> CmdResult<Prices> {
    blocking(|| Ok(Prices { ETH: spot("ETH").ok(), POL: spot("POL").ok(), BTC: spot("BTC").ok() })).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How a listed token is valued, without a price feed per token: USD stablecoins are $1 by
    /// definition (a depeg is not shown), wrapped ETH is the ETH price, wrapped BTC the BTC price.
    /// Anything else has no USD figure. The UI applies this (tokens.ts usdBasis); this copy keeps
    /// the built-in token list covered.
    fn token_basis(symbol: &str) -> Option<&'static str> {
        match symbol {
            "USDC" | "USDT" | "USDT0" | "DAI" => Some("USD"),
            "WETH" => Some("ETH"),
            "WBTC" | "cbBTC" => Some("BTC"),
            _ => None,
        }
    }

    #[test]
    fn parses_coinbase_shape() {
        let v: Value = serde_json::from_str(r#"{"data":{"amount":"3456.78","base":"ETH","currency":"USD"}}"#).unwrap();
        assert_eq!(parse(&v).unwrap(), 3456.78);
        assert!(parse(&serde_json::json!({"data":{"amount":"-1"}})).is_err());
        assert!(parse(&serde_json::json!({})).is_err());
    }
    #[test]
    fn token_bases_cover_the_listed_tokens() {
        assert_eq!(token_basis("USDC"), Some("USD"));
        assert_eq!(token_basis("USDT0"), Some("USD"));
        assert_eq!(token_basis("WETH"), Some("ETH"));
        assert_eq!(token_basis("cbBTC"), Some("BTC"));
        assert_eq!(token_basis("XYZ"), None);
        // every symbol in the built-in list has a basis
        for t in crate::tokens::list().unwrap() {
            assert!(token_basis(&t.symbol).is_some(), "{}", t.symbol);
        }
    }
}
