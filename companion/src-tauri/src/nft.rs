//! ERC-721 holdings, found without any indexer: `Transfer` logs to this address in the recent
//! block window of the user's node (the 4-topic form, where the token id is indexed), then
//! `ownerOf` for each candidate so only tokens still held are shown, `name`/`symbol` by eth_call.
//!
//! Many public nodes only answer log searches that name a contract; then the scan says so and the
//! user can add a collection by its contract address (balanceOf + ERC-721 Enumerable, or the same
//! log search restricted to that contract).
//!
//! Metadata and images are fetched only when the user asks, by this Rust side, https only (ipfs://
//! through the public ipfs.io gateway), no redirects, no private/loopback hosts, 256 KiB of JSON and
//! 2 MiB of image at most; the image comes back as a data: URL, so the page never loads it itself.

use crate::{blocking, eth, pairing, verify, watcher, CmdResult};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Mutex;
use std::time::Duration;

const MAX_CANDIDATES: usize = 120;
const MAX_JSON: u64 = 256 * 1024;
const MAX_IMAGE: u64 = 2 * 1024 * 1024;
const SEL_OWNER_OF: &str = "6352211e";
const SEL_NAME: &str = "06fdde03";
const SEL_SYMBOL: &str = "95d89b41";
const SEL_TOKEN_URI: &str = "c87b56dd";
const SEL_BALANCE_OF: &str = "70a08231";
const SEL_TOKEN_OF_OWNER_BY_INDEX: &str = "2f745c59";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Nft { pub chain_id: u64, pub contract: String, pub token_id: String, pub name: Option<String>, pub symbol: Option<String>, pub owned: Option<bool>, pub checked_at: u64 }

#[derive(Serialize)]
pub struct Scan { chain_id: u64, nfts: Vec<Nft>, from_block: Option<u128>, to_block: Option<u128>, error: Option<String> }

#[derive(Serialize)]
pub struct Meta { name: Option<String>, description: Option<String>, image: Option<String>, error: Option<String> }

#[derive(Serialize, Deserialize, Default)]
struct Store { owner: Option<String>, nfts: Vec<Nft> }
static LOCK: Mutex<()> = Mutex::new(());

/// One store per paired account (`nfts-<address>.json`).
fn store_path(owner: &str) -> Result<std::path::PathBuf, String> { pairing::account_file("nfts", owner).map_err(|e| e.0) }
/// The single store of versions before accounts; read for the address it belonged to.
fn legacy_store_path() -> Result<std::path::PathBuf, String> { Ok(pairing::path().map_err(|e| e.0)?.with_file_name("nfts.json")) }

fn load(owner: &str) -> Vec<Nft> {
    let read = |p: std::path::PathBuf| -> Option<Store> { fs::read_to_string(p).ok().and_then(|t| serde_json::from_str(&t).ok()) };
    let s = store_path(owner).ok().and_then(read).or_else(|| legacy_store_path().ok().and_then(read)).unwrap_or_default();
    if s.owner.as_deref().is_some_and(|o| o.eq_ignore_ascii_case(owner)) { s.nfts } else { Vec::new() }
}

fn save(owner: &str, nfts: &[Nft]) -> Result<(), String> {
    let p = store_path(owner)?;
    let tmp = p.with_extension("json.tmp");
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
    f.write_all(&serde_json::to_vec_pretty(&Store { owner: Some(owner.into()), nfts: nfts.to_vec() }).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &p).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- ABI helpers

fn word_u256_hex(id: &str) -> Result<String, String> {
    let v: u128 = id.parse().map_err(|_| "token id out of range".to_string())?;
    Ok(format!("{v:064x}"))
}

/// A returned `string` (or a legacy `bytes32`), printable characters only, capped.
pub fn decode_string(ret: &[u8]) -> Option<String> {
    let raw: Vec<u8> = if ret.len() == 32 {
        ret.iter().copied().take_while(|b| *b != 0).collect()
    } else {
        if ret.len() < 64 { return None; }
        let off = u128::from_be_bytes(ret[16..32].try_into().ok()?) as usize;
        if off + 32 > ret.len() || ret[off..off + 16].iter().any(|b| *b != 0) { return None; }
        let len = u128::from_be_bytes(ret[off + 16..off + 32].try_into().ok()?) as usize;
        if len > 4096 || off + 32 + len > ret.len() { return None; }
        ret[off + 32..off + 32 + len].to_vec()
    };
    let s = String::from_utf8(raw).ok()?;
    let s: String = s.chars().filter(|c| !c.is_control()).take(200).collect();
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn address_word(ret: &[u8]) -> Option<String> {
    (ret.len() == 32 && ret[..12].iter().all(|b| *b == 0)).then(|| format!("0x{}", hex::encode(&ret[12..])))
}

fn uint_word(ret: &[u8]) -> Option<u128> {
    (ret.len() == 32 && ret[..16].iter().all(|b| *b == 0)).then(|| u128::from_be_bytes(ret[16..].try_into().unwrap()))
}

fn owns(rpc: &eth::Rpc, contract: &str, id: &str, owner: &str) -> Option<bool> {
    let ret = rpc.eth_call(contract, &format!("0x{SEL_OWNER_OF}{}", word_u256_hex(id).ok()?)).ok()?;
    address_word(&ret).map(|a| a.eq_ignore_ascii_case(owner))
}

fn label(rpc: &eth::Rpc, contract: &str) -> (Option<String>, Option<String>) {
    let s = |sel: &str| rpc.eth_call(contract, &format!("0x{sel}")).ok().and_then(|r| decode_string(&r));
    (s(SEL_NAME), s(SEL_SYMBOL))
}

/// Merge candidates into the stored list for this chain and re-check ownership of all of them.
fn refresh(rpc: &eth::Rpc, chain: u64, owner: &str, candidates: Vec<(String, String)>) -> Result<Vec<Nft>, String> {
    let _g = LOCK.lock().map_err(|_| "nft lock poisoned".to_string())?;
    let mut all = load(owner);
    for (contract, id) in candidates {
        if !all.iter().any(|n| n.chain_id == chain && n.contract.eq_ignore_ascii_case(&contract) && n.token_id == id) {
            all.push(Nft { chain_id: chain, contract: verify::checksum(&contract), token_id: id, name: None, symbol: None, owned: None, checked_at: 0 });
        }
    }
    let mut labels: std::collections::HashMap<String, (Option<String>, Option<String>)> = std::collections::HashMap::new();
    let now = crate::history::now();
    for n in all.iter_mut().filter(|n| n.chain_id == chain).take(MAX_CANDIDATES) {
        n.owned = owns(rpc, &n.contract, &n.token_id, owner);
        n.checked_at = now;
        if n.name.is_none() && n.symbol.is_none() {
            let l = labels.entry(n.contract.to_ascii_lowercase()).or_insert_with(|| label(rpc, &n.contract)).clone();
            n.name = l.0; n.symbol = l.1;
        }
    }
    // tokens sent away stay out of the list
    all.retain(|n| n.chain_id != chain || n.owned != Some(false));
    save(owner, &all)?;
    Ok(all.into_iter().filter(|n| n.chain_id == chain).collect())
}

/// ERC-721 Transfer logs (to, id indexed) → (contract, decimal token id).
fn erc721_candidates(logs: &[Value], owner_topic: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for l in logs {
        let Some(t) = l.get("topics").and_then(Value::as_array) else { continue };
        if t.len() != 4 || t[0].as_str() != Some(watcher::TRANSFER_TOPIC) || !t[2].as_str().is_some_and(|x| x.eq_ignore_ascii_case(owner_topic)) { continue; }
        let Some(id_hex) = t[3].as_str().map(|s| s.trim_start_matches("0x")) else { continue };
        if id_hex.len() != 64 || !id_hex[..32].bytes().all(|b| b == b'0') { continue; } // ids beyond u128 are not shown
        let Ok(id) = u128::from_str_radix(&id_hex[32..], 16) else { continue };
        let Some(c) = l.get("address").and_then(Value::as_str) else { continue };
        let item = (c.to_ascii_lowercase(), id.to_string());
        if !out.contains(&item) { out.push(item); }
    }
    out
}

fn connect(rpc_url: &str) -> Result<(eth::Rpc, u64, String, u128), String> {
    let owner = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
    let rpc = eth::Rpc::new(rpc_url).map_err(|e| e.0)?;
    let chain = u64::try_from(rpc.chain_id().map_err(|e| e.0)?).map_err(|_| "chain id out of range")?;
    let block = rpc.block_number().map_err(|e| e.0)?;
    Ok((rpc, chain, owner, block))
}

#[tauri::command]
pub(crate) async fn nft_list(chain_id: u64) -> CmdResult<Vec<Nft>> {
    blocking(move || {
        let owner = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
        Ok(load(&owner).into_iter().filter(|n| n.chain_id == chain_id).collect())
    }).await
}

/// Search the recent window for ERC-721 transfers to this address (any contract).
#[tauri::command]
pub(crate) async fn nft_scan(rpc_url: String) -> CmdResult<Scan> {
    blocking(move || {
        let (rpc, chain, owner, block) = connect(&rpc_url)?;
        let window = watcher::network(chain).map(|n| n.4).unwrap_or(5_000);
        let owner_topic = watcher::topic_address(&owner);
        let (logs, covered, error) = watcher::search_logs(&rpc, block.saturating_sub(window - 1), block, None, json!([watcher::TRANSFER_TOPIC, Value::Null, owner_topic]));
        let error = error.map(|e| if covered.is_none() && e.to_ascii_lowercase().contains("address") { format!("this node only answers log searches for specific contracts ({e}); add a collection by its contract address, or use your own node") } else { e });
        let nfts = refresh(&rpc, chain, &owner, erc721_candidates(&logs, &owner_topic))?;
        Ok(Scan { chain_id: chain, nfts, from_block: covered, to_block: Some(block), error })
    }).await
}

/// Add a collection by contract: ERC-721 Enumerable when available, else its transfer logs.
#[tauri::command]
pub(crate) async fn nft_add_contract(rpc_url: String, contract: String) -> CmdResult<Scan> {
    blocking(move || {
        let c = contract.trim().to_ascii_lowercase();
        if c.len() != 42 || !c.starts_with("0x") || !c[2..].bytes().all(|b| b.is_ascii_hexdigit()) { return Err("a contract address is 0x followed by 40 hex characters".into()); }
        let (rpc, chain, owner, block) = connect(&rpc_url)?;
        let owner_word = format!("{:0>64}", owner.trim_start_matches("0x"));
        let count = rpc.eth_call(&c, &format!("0x{SEL_BALANCE_OF}{owner_word}")).ok().and_then(|r| uint_word(&r))
            .ok_or("that contract doesn't answer balanceOf like an ERC-721 collection on this network")?;
        let mut candidates = Vec::new();
        for i in 0..count.min(50) {
            match rpc.eth_call(&c, &format!("0x{SEL_TOKEN_OF_OWNER_BY_INDEX}{owner_word}{i:064x}")).ok().and_then(|r| uint_word(&r)) {
                Some(id) => candidates.push((c.clone(), id.to_string())),
                None => break,
            }
        }
        let (mut from, mut error) = (None, None);
        if candidates.len() < count.min(50) as usize {
            let window = watcher::network(chain).map(|n| n.4).unwrap_or(5_000);
            let owner_topic = watcher::topic_address(&owner);
            let (logs, covered, e) = watcher::search_logs(&rpc, block.saturating_sub(window - 1), block, Some(json!(c)), json!([watcher::TRANSFER_TOPIC, Value::Null, owner_topic]));
            candidates.extend(erc721_candidates(&logs, &owner_topic));
            from = covered; error = e;
            if candidates.is_empty() && count > 0 { error = Some(format!("you hold {count} from this collection, but it doesn't list them and none arrived in the recent block window")); }
        }
        let nfts = refresh(&rpc, chain, &owner, candidates)?;
        Ok(Scan { chain_id: chain, nfts, from_block: from, to_block: Some(block), error })
    }).await
}

// ---------------------------------------------------------------- metadata, on request only

fn safe_url(url: &str) -> Result<reqwest::Url, String> {
    let u = if let Some(rest) = url.strip_prefix("ipfs://") { format!("https://ipfs.io/ipfs/{}", rest.trim_start_matches("ipfs/")) } else { url.to_string() };
    let parsed = reqwest::Url::parse(&u).map_err(|_| "not a URL".to_string())?;
    if parsed.scheme() != "https" { return Err("only https:// (and ipfs://) links are fetched".into()); }
    let host = parsed.host_str().ok_or("no host")?.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".localhost") { return Err("refusing a local address".into()); }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let private = match ip {
            std::net::IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast() || v.octets()[0] == 100 && (64..128).contains(&v.octets()[1]),
            std::net::IpAddr::V6(v) => v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
        };
        if private { return Err("refusing a private network address".into()); }
    }
    Ok(parsed)
}

fn fetch(url: &str, cap: u64) -> Result<(Vec<u8>, String), String> {
    let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(12)).redirect(reqwest::redirect::Policy::none()).build().map_err(|e| e.to_string())?;
    let resp = client.get(safe_url(url)?).header("accept", "application/json, image/*").send().map_err(|e| format!("fetch failed: {e}"))?;
    if !resp.status().is_success() { return Err(format!("the server answered HTTP {}", resp.status())); }
    let ctype = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    let mut body = Vec::new();
    resp.take(cap + 1).read_to_end(&mut body).map_err(|e| e.to_string())?;
    if body.len() as u64 > cap { return Err(format!("larger than {} KiB; not loaded", cap / 1024)); }
    Ok((body, ctype))
}

/// data: URLs are decoded locally (base64 or percent-free utf8 text).
fn data_url(url: &str) -> Option<(Vec<u8>, String)> {
    let rest = url.strip_prefix("data:")?;
    let (head, body) = rest.split_once(',')?;
    let ctype = head.split(';').next().unwrap_or("").to_ascii_lowercase();
    let bytes = if head.ends_with(";base64") { base64::engine::general_purpose::STANDARD.decode(body.trim()).ok()? } else { body.as_bytes().to_vec() };
    Some((bytes, ctype))
}

const IMAGE_TYPES: [&str; 5] = ["image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml"];

fn image_data_url(url: &str) -> Result<String, String> {
    let (bytes, ctype) = match data_url(url) { Some(d) => d, None => fetch(url, MAX_IMAGE)? };
    if bytes.len() as u64 > MAX_IMAGE { return Err("image larger than 2 MiB; not loaded".into()); }
    let ctype = ctype.split(';').next().unwrap_or("").trim().to_string();
    if !IMAGE_TYPES.contains(&ctype.as_str()) { return Err(format!("not a supported image type ({})", if ctype.is_empty() { "unknown" } else { &ctype })); }
    Ok(format!("data:{ctype};base64,{}", base64::engine::general_purpose::STANDARD.encode(bytes)))
}

#[tauri::command]
pub(crate) async fn nft_metadata(rpc_url: String, contract: String, token_id: String) -> CmdResult<Meta> {
    blocking(move || {
        let rpc = eth::Rpc::new(&rpc_url).map_err(|e| e.0)?;
        let c = contract.trim().to_ascii_lowercase();
        if c.len() != 42 || !c.starts_with("0x") { return Err("bad contract".into()); }
        let empty = |e: String| Meta { name: None, description: None, image: None, error: Some(e) };
        let Some(uri) = rpc.eth_call(&c, &format!("0x{SEL_TOKEN_URI}{}", word_u256_hex(&token_id)?)).ok().and_then(|r| decode_string(&r)) else {
            return Ok(empty("the contract has no tokenURI for this token".into()));
        };
        let uri = uri.replace("{id}", &format!("{:064x}", token_id.parse::<u128>().unwrap_or(0)));
        let json_bytes = match data_url(&uri) { Some((b, _)) => b, None => match fetch(&uri, MAX_JSON) { Ok((b, _)) => b, Err(e) => return Ok(empty(e)) } };
        let Ok(v) = serde_json::from_slice::<Value>(&json_bytes) else { return Ok(empty("the metadata is not JSON".into())) };
        let text = |k: &str| v.get(k).and_then(Value::as_str).map(|s| s.chars().filter(|c| !c.is_control() || *c == '\n').take(500).collect::<String>());
        let (image, error) = match text("image").or_else(|| text("image_url")) {
            Some(u) => match image_data_url(&u) { Ok(d) => (Some(d), None), Err(e) => (None, Some(e)) },
            None => (None, Some("no image in the metadata".into())),
        };
        Ok(Meta { name: text("name"), description: text("description"), image, error })
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_decode_abi_and_bytes32() {
        let mut abi = vec![0u8; 96];
        abi[31] = 32; abi[63] = 5; abi[64..69].copy_from_slice(b"Pixel");
        assert_eq!(decode_string(&abi).as_deref(), Some("Pixel"));
        let mut b32 = [0u8; 32]; b32[..3].copy_from_slice(b"MKR");
        assert_eq!(decode_string(&b32).as_deref(), Some("MKR"));
        abi[63] = 200; // length past the end
        assert!(decode_string(&abi).is_none());
    }

    #[test]
    fn erc721_logs_become_candidates_once() {
        let me = watcher::topic_address("0x7a3b9c1d2e4f5061728394a5b6c7d8e9f0a1b2c3");
        let other = watcher::topic_address("0x1111111111111111111111111111111111111111");
        let id = format!("0x{:064x}", 4211u128);
        let l = |to: &str| json!({"address": "0xAbC0000000000000000000000000000000000001", "topics": [watcher::TRANSFER_TOPIC, other, to, id]});
        let erc20 = json!({"address": "0xabc", "topics": [watcher::TRANSFER_TOPIC, other, me], "data": "0x01"});
        let c = erc721_candidates(&[l(&me), l(&me), l(&other), erc20], &me);
        assert_eq!(c, vec![("0xabc0000000000000000000000000000000000001".to_string(), "4211".to_string())]);
    }

    #[test]
    fn only_public_https_is_fetched() {
        assert!(safe_url("https://example.com/a.json").is_ok());
        assert_eq!(safe_url("ipfs://bafyabc/1.json").unwrap().as_str(), "https://ipfs.io/ipfs/bafyabc/1.json");
        assert!(safe_url("http://example.com/a.json").is_err());
        assert!(safe_url("https://localhost/a").is_err());
        assert!(safe_url("https://127.0.0.1/a").is_err());
        assert!(safe_url("https://192.168.1.10/a").is_err());
        assert!(safe_url("https://[::1]/a").is_err());
        assert!(safe_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn images_must_be_images() {
        let png = format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode([0x89, b'P', b'N', b'G']));
        assert!(image_data_url(&png).unwrap().starts_with("data:image/png;base64,"));
        assert!(image_data_url("data:text/html;base64,PGgxPg==").is_err());
    }
}
