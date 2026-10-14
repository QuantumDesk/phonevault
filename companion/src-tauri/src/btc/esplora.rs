//! Esplora REST client (the API of mempool.space, blockstream.info, and an Esplora/electrs or
//! mempool instance of your own). The server is untrusted input: everything it says is parsed
//! strictly, every coin is checked against its previous transaction (hashed here to its txid)
//! before it is spent, and nothing it says can change what the phone signs or what `verify.rs`
//! accepts. It does learn which addresses are yours: see the privacy note in Settings.
//!
//! Defaults: mempool.space, with blockstream.info as the fallback on Bitcoin and Testnet. A server
//! you set yourself is used alone (no fallback that would leak your addresses elsewhere).

use super::wallet::Net;
use serde::Deserialize;
use std::io::Read;
use std::time::Duration;

const MAX_BODY: u64 = 4 * 1024 * 1024;

/// Default servers per network (first is primary).
pub fn defaults(net: Net) -> &'static [&'static str] {
    match net {
        Net::Bitcoin => &["https://mempool.space/api", "https://blockstream.info/api"],
        // Testnet4 (testnet3 is being retired; the phone's "testnet" keys and tb1 addresses are the same)
        Net::Testnet => &["https://mempool.space/testnet4/api"],
        Net::Signet => &["https://mempool.space/signet/api"],
    }
}

/// Where the user looks a transaction up (display only; opened in the browser on click).
pub fn explorer_tx(net: Net, txid: &str) -> String {
    match net {
        Net::Bitcoin => format!("https://mempool.space/tx/{txid}"),
        Net::Testnet => format!("https://mempool.space/testnet4/tx/{txid}"),
        Net::Signet => format!("https://mempool.space/signet/tx/{txid}"),
    }
}

/// A server URL the user typed: https, or http only to this Mac / the local network (an own node).
pub fn check_server(url: &str) -> Result<String, String> {
    let u = url.trim().trim_end_matches('/');
    let rest = if let Some(r) = u.strip_prefix("https://") {
        r
    } else if let Some(r) = u.strip_prefix("http://") {
        let host = r.split(['/', ':']).next().unwrap_or("");
        let local = host == "localhost"
            || host.ends_with(".local")
            || host.starts_with("127.")
            || host.starts_with("10.")
            || host.starts_with("192.168.")
            || host
                .strip_prefix("172.")
                .and_then(|x| x.split('.').next())
                .and_then(|x| x.parse::<u8>().ok())
                .is_some_and(|x| (16..=31).contains(&x));
        if !local {
            return Err("Use https://, or http:// only for a server on this Mac or your local network".into());
        }
        r
    } else {
        return Err("The server URL starts with https://".into());
    };
    if rest.is_empty()
        || rest.len() > 200
        || rest.chars().any(|c| c.is_whitespace() || c == '?' || c == '#' || c == '@')
    {
        return Err("That is not a server URL".into());
    }
    Ok(u.to_string())
}

#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Stats {
    pub funded_txo_count: u64,
    pub funded_txo_sum: u64,
    pub spent_txo_count: u64,
    pub spent_txo_sum: u64,
    pub tx_count: u64,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct AddressInfo {
    pub address: String,
    pub chain_stats: Stats,
    pub mempool_stats: Stats,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
pub struct TxStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub block_time: Option<u64>,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: TxStatus,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct Vout {
    pub scriptpubkey: String,
    #[serde(default)]
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct Vin {
    pub txid: String,
    pub vout: u32,
    #[serde(default)]
    pub prevout: Option<Vout>,
    #[serde(default)]
    pub is_coinbase: bool,
    #[serde(default)]
    pub sequence: u32,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct Tx {
    pub txid: String,
    pub vin: Vec<Vin>,
    pub vout: Vec<Vout>,
    #[serde(default)]
    pub weight: u64,
    #[serde(default)]
    pub fee: u64,
    pub status: TxStatus,
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn parse_address(body: &str, expected: &str) -> Result<AddressInfo, String> {
    let a: AddressInfo = serde_json::from_str(body).map_err(|e| format!("server: unexpected address answer ({e})"))?;
    if a.address != expected {
        return Err("server answered for a different address".into());
    }
    // (mempool stats may spend confirmed coins, so only the confirmed side must balance on its own)
    if a.chain_stats.spent_txo_sum > a.chain_stats.funded_txo_sum {
        return Err("server: spent more than funded".into());
    }
    Ok(a)
}

pub fn parse_utxos(body: &str) -> Result<Vec<Utxo>, String> {
    let u: Vec<Utxo> = serde_json::from_str(body).map_err(|e| format!("server: unexpected utxo answer ({e})"))?;
    if u.iter().any(|x| !hex64(&x.txid) || x.value == 0 || x.value > 21_000_000 * 100_000_000) {
        return Err("server: malformed utxo".into());
    }
    Ok(u)
}

pub fn parse_txs(body: &str) -> Result<Vec<Tx>, String> {
    let t: Vec<Tx> = serde_json::from_str(body).map_err(|e| format!("server: unexpected transaction list ({e})"))?;
    if t.iter().any(|x| !hex64(&x.txid) || x.vout.len() > 100_000) {
        return Err("server: malformed transaction".into());
    }
    Ok(t)
}

/// `/fee-estimates`: {"1": 87.88, "6": 21.3, "144": 1.02, …} (sat/vB per confirmation target).
pub fn parse_fees(body: &str) -> Result<std::collections::BTreeMap<u32, f64>, String> {
    let m: std::collections::HashMap<String, f64> =
        serde_json::from_str(body).map_err(|e| format!("server: unexpected fee answer ({e})"))?;
    let out: std::collections::BTreeMap<u32, f64> = m
        .into_iter()
        .filter_map(|(k, v)| Some((k.parse().ok()?, v)))
        .filter(|(_, v)| v.is_finite() && *v > 0.0 && *v < 100_000.0)
        .collect();
    if out.is_empty() {
        return Err("server gave no fee estimates".into());
    }
    Ok(out)
}

/// The fee rate for a target in blocks: the server's estimate for the nearest target at or above it.
pub fn rate_for(fees: &std::collections::BTreeMap<u32, f64>, target: u32) -> Option<f64> {
    fees.range(target..).next().or_else(|| fees.iter().next_back()).map(|(_, v)| *v)
}

pub struct Client {
    bases: Vec<String>,
    http: reqwest::blocking::Client,
}

impl Client {
    pub fn new(net: Net, custom: Option<&str>) -> Result<Client, String> {
        let bases = match custom {
            Some(c) => vec![check_server(c)?],
            None => defaults(net).iter().map(ToString::to_string).collect(),
        };
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("PhoneVault")
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Client { bases, http })
    }
    pub fn host(&self) -> String {
        self.bases.first().map(|b| b.split('/').nth(2).unwrap_or(b).to_string()).unwrap_or_default()
    }

    fn read(resp: reqwest::blocking::Response) -> Result<String, String> {
        let status = resp.status();
        let mut body = String::new();
        resp.take(MAX_BODY).read_to_string(&mut body).map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("HTTP {}: {}", status.as_u16(), body.chars().take(200).collect::<String>()));
        }
        Ok(body)
    }

    /// GET with fallback to the next server on transport errors and 5xx/429 (not on 4xx answers).
    pub fn get(&self, path: &str) -> Result<String, String> {
        let mut last = String::new();
        for base in &self.bases {
            match self.http.get(format!("{base}{path}")).send() {
                Ok(r) => match Self::read(r) {
                    Ok(b) => return Ok(b),
                    Err(e) if e.starts_with("HTTP 5") || e.starts_with("HTTP 429") => last = e,
                    Err(e) => return Err(e),
                },
                Err(e) => {
                    last = if e.is_timeout() {
                        "the server timed out".into()
                    } else {
                        format!("the server is unreachable ({})", base.split('/').nth(2).unwrap_or(base))
                    }
                }
            }
        }
        Err(last)
    }

    pub fn address(&self, a: &str) -> Result<AddressInfo, String> {
        parse_address(&self.get(&format!("/address/{a}"))?, a)
    }
    pub fn utxos(&self, a: &str) -> Result<Vec<Utxo>, String> {
        parse_utxos(&self.get(&format!("/address/{a}/utxo"))?)
    }
    pub fn txs(&self, a: &str) -> Result<Vec<Tx>, String> {
        parse_txs(&self.get(&format!("/address/{a}/txs"))?)
    }
    pub fn fees(&self) -> Result<std::collections::BTreeMap<u32, f64>, String> {
        parse_fees(&self.get("/fee-estimates")?)
    }
    pub fn tip(&self) -> Result<u64, String> {
        self.get("/blocks/tip/height")?.trim().parse().map_err(|_| "server: bad tip height".to_string())
    }
    pub fn tx_status(&self, txid: &str) -> Result<TxStatus, String> {
        serde_json::from_str(&self.get(&format!("/tx/{txid}/status"))?).map_err(|e| format!("server: {e}"))
    }
    /// A raw transaction; the caller checks it hashes to the txid it asked for.
    pub fn tx_hex(&self, txid: &str) -> Result<String, String> {
        let h = self.get(&format!("/tx/{txid}/hex"))?;
        let h = h.trim().to_string();
        if h.len() % 2 != 0 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("server: malformed transaction hex".into());
        }
        Ok(h)
    }
    /// POST /tx to the first server only (a broadcast is not retried elsewhere behind the user's back).
    pub fn broadcast(&self, hex: &str) -> Result<String, String> {
        let base = self.bases.first().ok_or("no server")?;
        let r = self
            .http
            .post(format!("{base}/tx"))
            .header("content-type", "text/plain")
            .body(hex.to_string())
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    "the server timed out".to_string()
                } else {
                    "the server is unreachable".to_string()
                }
            })?;
        Ok(Self::read(r)?.trim().to_string())
    }
}

#[cfg(test)]
pub mod fixtures {
    // Shapes copied from mempool.space / blockstream.info answers (values shortened).
    pub const ADDRESS: &str = r#"{"address":"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu","chain_stats":{"funded_txo_count":3,"funded_txo_sum":250000,"spent_txo_count":1,"spent_txo_sum":100000,"tx_count":4},"mempool_stats":{"funded_txo_count":1,"funded_txo_sum":5000,"spent_txo_count":0,"spent_txo_sum":0,"tx_count":1}}"#;
    pub const UTXOS: &str = r#"[{"txid":"6e9d0c5bea2cda99f3e5c76fb2740cdf8793d1d363422cd065d22bf0a2bb5bad","vout":1,"status":{"confirmed":true,"block_height":860001,"block_hash":"00000000000000000001a3c4","block_time":1726000000},"value":150000},{"txid":"a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90","vout":0,"status":{"confirmed":false},"value":5000}]"#;
    pub const FEES: &str = r#"{"1":21.104,"2":18.2,"3":15.5,"6":9.07,"10":7.1,"144":1.98,"504":1.0,"1008":1.0}"#;
    pub const TXS: &str = r#"[{"txid":"a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90","version":2,"locktime":0,"vin":[{"txid":"0f9e8d7c6b5a49382716051f2e3d4c5b6a79880f9e8d7c6b5a49382716051f2e","vout":0,"prevout":{"scriptpubkey":"0014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","scriptpubkey_asm":"OP_0 OP_PUSHBYTES_20 aa","scriptpubkey_type":"v0_p2wpkh","scriptpubkey_address":"bc1q42424242424242424242424242424242xyz","value":20000},"scriptsig":"","scriptsig_asm":"","witness":["30","02"],"is_coinbase":false,"sequence":4294967293}],"vout":[{"scriptpubkey":"0014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2","scriptpubkey_asm":"OP_0","scriptpubkey_type":"v0_p2wpkh","scriptpubkey_address":"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu","value":5000},{"scriptpubkey":"0014bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","scriptpubkey_address":"bc1qother","value":14800}],"size":222,"weight":561,"sigops":1,"fee":200,"status":{"confirmed":false}},{"txid":"6e9d0c5bea2cda99f3e5c76fb2740cdf8793d1d363422cd065d22bf0a2bb5bad","version":2,"locktime":859999,"vin":[{"txid":"1111111111111111111111111111111111111111111111111111111111111111","vout":3,"prevout":{"scriptpubkey":"0014cccccccccccccccccccccccccccccccccccccccc","scriptpubkey_address":"bc1qsender","value":400000},"is_coinbase":false,"sequence":4294967295}],"vout":[{"scriptpubkey":"0014dddddddddddddddddddddddddddddddddddddddd","scriptpubkey_address":"bc1qelse","value":249000},{"scriptpubkey":"0014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2","scriptpubkey_address":"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu","value":150000}],"weight":561,"fee":1000,"status":{"confirmed":true,"block_height":860001,"block_hash":"0000","block_time":1726000000}}]"#;
}

#[cfg(test)]
mod tests {
    use super::*;
    use fixtures::*;

    #[test]
    fn parses_server_answers() {
        let a = parse_address(ADDRESS, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu").unwrap();
        assert_eq!(
            (
                a.chain_stats.tx_count,
                a.chain_stats.funded_txo_sum - a.chain_stats.spent_txo_sum,
                a.mempool_stats.funded_txo_sum
            ),
            (4, 150_000, 5_000)
        );
        assert!(
            parse_address(ADDRESS, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g").is_err(),
            "answer for another address"
        );
        let u = parse_utxos(UTXOS).unwrap();
        assert_eq!(u.len(), 2);
        assert_eq!((u[0].value, u[0].status.confirmed, u[0].status.block_height), (150_000, true, Some(860_001)));
        assert!(!u[1].status.confirmed);
        assert!(parse_utxos(r#"[{"txid":"zz","vout":0,"value":1,"status":{"confirmed":true}}]"#).is_err());
        assert!(parse_utxos(r#"[{"txid":"6e9d0c5bea2cda99f3e5c76fb2740cdf8793d1d363422cd065d22bf0a2bb5bad","vout":0,"value":-5,"status":{"confirmed":true}}]"#).is_err());
        let t = parse_txs(TXS).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].vin[0].prevout.as_ref().unwrap().value, 20_000);
        assert_eq!(t[1].status.block_height, Some(860_001));
        assert!(parse_txs("{\"error\":1}").is_err());
        let f = parse_fees(FEES).unwrap();
        assert_eq!(rate_for(&f, 1), Some(21.104));
        assert_eq!(rate_for(&f, 4), Some(9.07));
        assert_eq!(rate_for(&f, 144), Some(1.98));
        assert_eq!(rate_for(&f, 5000), Some(1.0));
        assert!(parse_fees("{}").is_err());
        assert!(parse_fees(r#"{"1":-3}"#).is_err());
    }

    /// Live check against the default servers (network): `cargo test -- --ignored live_esplora`
    #[test]
    #[ignore]
    fn live_esplora_mainnet() {
        let c = Client::new(Net::Bitcoin, None).unwrap();
        let f = c.fees().unwrap();
        println!("fees: {f:?}, tip {}", c.tip().unwrap());
        let a = c.address("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu").unwrap();
        println!("BIP-84 vector address: {a:?}");
        let txs = c.txs("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu").unwrap();
        if let Some(t) = txs.first() {
            let hex = c.tx_hex(&t.txid).unwrap();
            let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&::hex::decode(hex).unwrap()).unwrap();
            assert_eq!(tx.compute_txid().to_string(), t.txid);
        }
    }

    #[test]
    fn server_urls() {
        assert_eq!(check_server("https://mempool.space/api/").unwrap(), "https://mempool.space/api");
        assert!(check_server("http://umbrel.local:3006/api").is_ok());
        assert!(check_server("http://192.168.1.20:3002/api").is_ok());
        assert!(check_server("http://172.20.0.2/api").is_ok());
        assert!(check_server("http://example.com/api").is_err());
        assert!(check_server("http://172.40.0.2/api").is_err());
        assert!(check_server("ftp://x").is_err());
        assert!(check_server("https://user@host/api").is_err());
        assert!(check_server("https://").is_err());
        assert!(defaults(Net::Bitcoin)[0].starts_with("https://mempool.space"));
    }
}
