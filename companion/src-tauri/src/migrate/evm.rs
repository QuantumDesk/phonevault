//! Read-only EVM scan of an old address on one network, from the user's node: the native balance,
//! every token of the built-in list, ERC-721 NFTs, and ERC-20 / NFT approvals still in force.
//!
//! Like the NFT screen, this uses no indexer: NFTs and approvals are found in the logs the node
//! serves (a recent block window, searched newest first), so older ones can be missed; the report
//! says which blocks were searched. Items found once are kept in the session and re-checked
//! directly (`ownerOf`, `allowance`, `isApprovedForAll`) on every re-scan, window or not.
//! TODO(erc1155): ERC-1155 balances are not found (they need TransferSingle/TransferBatch logs).
//!
//! Node answers are untrusted: every word is shape-checked (abi.rs), nothing is indexed unchecked.

#![deny(clippy::indexing_slicing)]

use super::Status;
use crate::abi::{self, SEL_BALANCE_OF, SEL_NAME, SEL_OWNER_OF, SEL_SYMBOL};
use crate::{chains, eth, tokens, verify, watcher};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// `allowance(address,address)` (ERC-20).
pub const SEL_ALLOWANCE: &str = "dd62ed3e";
/// `decimals()` (ERC-20).
pub const SEL_DECIMALS: &str = "313ce567";
/// `isApprovedForAll(address,address)` (ERC-721 / ERC-1155).
pub const SEL_IS_APPROVED_FOR_ALL: &str = "e985e9c5";
/// keccak256("Approval(address,address,uint256)"): ERC-20 (3 topics) and ERC-721 (4 topics).
pub const APPROVAL_TOPIC: &str = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
/// keccak256("ApprovalForAll(address,address,bool)").
pub const APPROVAL_FOR_ALL_TOPIC: &str = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31";

/// How far back logs are searched (blocks); `watcher::search_logs` also stops after 40 requests.
pub const LOG_BLOCKS: u128 = 80_000;
/// Distinct NFTs / approvals checked per scan at most.
const MAX_CANDIDATES: usize = 120;
/// Native balance below this (0.00001 of the coin) counts as emptied: what a "send max" leaves.
pub const NATIVE_DUST_WEI: u128 = 10_000_000_000_000;

/// The node, as this scan uses it (a fake in tests).
pub trait Node {
    fn chain_id(&self) -> Result<u128, String>;
    fn block_number(&self) -> Result<u128, String>;
    fn balance(&self, address: &str) -> Result<u128, String>;
    fn call(&self, to: &str, data: &str) -> Result<Vec<u8>, String>;
    /// Logs in [from, to], newest first: (logs, lowest block searched, why it stopped early).
    fn logs(&self, from: u128, to: u128, topics: Value) -> (Vec<Value>, Option<u128>, Option<String>);
}

impl Node for eth::Rpc {
    fn chain_id(&self) -> Result<u128, String> {
        eth::Rpc::chain_id(self).map_err(String::from)
    }
    fn block_number(&self) -> Result<u128, String> {
        eth::Rpc::block_number(self).map_err(String::from)
    }
    fn balance(&self, address: &str) -> Result<u128, String> {
        eth::Rpc::balance(self, address).map_err(String::from)
    }
    fn call(&self, to: &str, data: &str) -> Result<Vec<u8>, String> {
        self.eth_call(to, data).map_err(String::from)
    }
    fn logs(&self, from: u128, to: u128, topics: Value) -> (Vec<Value>, Option<u128>, Option<String>) {
        watcher::search_logs(self, from, to, None, topics)
    }
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Item {
    pub key: String,
    pub symbol: String,
    pub name: String,
    /// None for the native coin
    pub contract: Option<String>,
    pub decimals: u32,
    pub raw: String,
    pub amount: String,
    /// what the Phone Vault account holds of it (display; None when it could not be read)
    pub destination_amount: Option<String>,
    pub status: Status,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct NftItem {
    pub key: String,
    pub contract: String,
    pub token_id: String,
    pub name: Option<String>,
    pub symbol: Option<String>,
    pub status: Status,
    /// ownerOf says the Phone Vault account holds it now
    pub on_phone_vault: bool,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Approval {
    pub key: String,
    /// "token" (ERC-20 allowance) or "collection" (an operator for every NFT of a collection)
    pub kind: &'static str,
    pub contract: String,
    pub symbol: Option<String>,
    pub spender: String,
    /// "unlimited", an amount in token units, or "all NFTs"
    pub amount: String,
    pub status: Status,
}

/// The block range a log search covered.
#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub struct Window {
    pub searched: bool,
    pub from_block: Option<u128>,
    pub to_block: Option<u128>,
    pub error: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Report {
    pub chain_id: u64,
    pub network: &'static str,
    pub address: String,
    pub destination: String,
    pub native: Item,
    pub tokens: Vec<Item>,
    /// listed tokens whose balance the node could not read (symbols)
    pub unreadable_tokens: Vec<String>,
    pub nfts: Vec<NftItem>,
    pub nft_window: Window,
    pub approvals: Vec<Approval>,
    pub approval_window: Window,
}

fn data_owner(sel: &str, a: &str) -> String {
    format!("0x{sel}{}", abi::address_word_hex(a))
}
fn data_two(sel: &str, a: &str, b: &str) -> String {
    format!("0x{sel}{}{}", abi::address_word_hex(a), abi::address_word_hex(b))
}

/// A uint256 return word: Some(u128) when it fits, None when larger (an "unlimited" allowance).
/// Err for anything that is not exactly one word.
fn u256_word(ret: &[u8]) -> Result<Option<u128>, String> {
    if ret.len() != 32 {
        return Err("the contract's answer is not one 32-byte word".into());
    }
    Ok(abi::u128_of_word(ret))
}

fn label(node: &dyn Node, contract: &str) -> (Option<String>, Option<String>) {
    let s = |sel: &str| node.call(contract, &format!("0x{sel}")).ok().and_then(|r| abi::decode_string(&r));
    (s(SEL_NAME), s(SEL_SYMBOL))
}

/// Everything about `old` on the node's chain. `found`: keys seen with a balance before (the
/// session); new ones are added to it. `deep`: also search the logs for NFTs and approvals.
pub fn scan(
    node: &dyn Node,
    old: &str,
    dest: &str,
    found: &mut BTreeSet<String>,
    deep: bool,
) -> Result<Report, String> {
    let chain = u64::try_from(node.chain_id()?).map_err(|_| "chain id out of range")?;
    let c = chains::get(chain).ok_or_else(|| format!("the phone has no reviewed profile for chain {chain}"))?;
    let block = node.block_number()?;
    let base = format!("evm:{chain}:{old}");

    // native coin
    let raw = node.balance(old)?;
    let key = format!("{base}:native");
    let native = Item {
        status: Status::of(raw >= NATIVE_DUST_WEI, &key, found),
        key,
        symbol: c.symbol.into(),
        name: c.symbol.into(),
        contract: None,
        decimals: 18,
        raw: raw.to_string(),
        amount: tokens::format_units(raw, 18),
        destination_amount: node.balance(dest).ok().map(|v| tokens::format_units(v, 18)),
    };

    // the built-in token list
    let (mut items, mut unreadable) = (Vec::new(), Vec::new());
    for t in tokens::list()?.iter().filter(|t| t.chain_id == chain) {
        let key = format!("{base}:{}", t.address.to_ascii_lowercase());
        let read = |owner: &str| {
            node.call(&t.address, &data_owner(SEL_BALANCE_OF, owner)).and_then(|r| tokens::parse_balance_word(&r))
        };
        let raw = match read(old) {
            Ok(v) => v,
            Err(_) => {
                unreadable.push(t.symbol.clone());
                continue;
            }
        };
        let status = Status::of(raw > 0, &key, found);
        if status == Status::Empty {
            continue;
        }
        items.push(Item {
            status,
            key,
            symbol: t.symbol.clone(),
            name: t.name.clone(),
            contract: Some(verify::checksum(&t.address)),
            decimals: t.decimals,
            raw: raw.to_string(),
            amount: tokens::format_units(raw, t.decimals),
            destination_amount: read(dest).ok().map(|v| tokens::format_units(v, t.decimals)),
        });
    }

    let from = block.saturating_sub(LOG_BLOCKS - 1);
    let owner_topic = watcher::topic_address(old);

    // NFTs: the ones found before, plus (deep) ERC-721 transfers to the old address in the window
    let nft_prefix = format!("{base}:nft:");
    let mut candidates: Vec<(String, String)> = found
        .iter()
        .filter_map(|k| k.strip_prefix(&nft_prefix)?.split_once(':'))
        .map(|(c, id)| (c.to_string(), id.to_string()))
        .collect();
    let mut nft_window = Window::default();
    if deep {
        let (logs, covered, error) = node.logs(from, block, json!([abi::TRANSFER_TOPIC, Value::Null, owner_topic]));
        nft_window = Window { searched: true, from_block: covered, to_block: Some(block), error };
        for cand in crate::nft::erc721_candidates(&logs, &owner_topic) {
            if !candidates.contains(&cand) {
                candidates.push(cand);
            }
        }
    }
    let mut nfts = Vec::new();
    let mut labels: std::collections::HashMap<String, (Option<String>, Option<String>)> = Default::default();
    for (contract, id) in candidates.into_iter().take(MAX_CANDIDATES) {
        let Ok(idn) = id.parse::<u128>() else { continue };
        let owner =
            node.call(&contract, &format!("0x{SEL_OWNER_OF}{idn:064x}")).ok().and_then(|r| abi::address_of_word(&r));
        let key = format!("{nft_prefix}{contract}:{id}");
        let held = owner.as_deref() == Some(old);
        let on_pv = owner.as_deref() == Some(dest);
        let mut status = Status::of(held, &key, found);
        if status == Status::Moved && !on_pv {
            status = Status::Gone;
        }
        if status == Status::Empty {
            continue;
        }
        let (name, symbol) = labels.entry(contract.clone()).or_insert_with(|| label(node, &contract)).clone();
        nfts.push(NftItem {
            key,
            contract: verify::checksum(&contract),
            token_id: id,
            name,
            symbol,
            status,
            on_phone_vault: on_pv,
        });
    }

    // approvals: the ones found before, plus (deep) Approval / ApprovalForAll logs by the old address
    let ap_prefix = format!("{base}:approve:");
    let all_prefix = format!("{base}:approveall:");
    let mut erc20: Vec<(String, String)> = found
        .iter()
        .filter_map(|k| k.strip_prefix(&ap_prefix)?.split_once(':'))
        .map(|(c, s)| (c.to_string(), s.to_string()))
        .collect();
    let mut for_all: Vec<(String, String)> = found
        .iter()
        .filter_map(|k| k.strip_prefix(&all_prefix)?.split_once(':'))
        .map(|(c, s)| (c.to_string(), s.to_string()))
        .collect();
    let mut approval_window = Window::default();
    if deep {
        let (logs, covered, error) =
            node.logs(from, block, json!([[APPROVAL_TOPIC, APPROVAL_FOR_ALL_TOPIC], owner_topic]));
        approval_window = Window { searched: true, from_block: covered, to_block: Some(block), error };
        for (kind, contract, spender) in approval_candidates(&logs, &owner_topic) {
            let list = if kind == "token" { &mut erc20 } else { &mut for_all };
            if !list.contains(&(contract.clone(), spender.clone())) {
                list.push((contract, spender));
            }
        }
    }
    let mut approvals = Vec::new();
    for (contract, spender) in erc20.into_iter().take(MAX_CANDIDATES) {
        let Ok(word) = node.call(&contract, &data_two(SEL_ALLOWANCE, old, &spender)).and_then(|r| u256_word(&r)) else {
            continue;
        };
        let key = format!("{ap_prefix}{contract}:{spender}");
        let status = Status::of(word != Some(0), &key, found);
        if status == Status::Empty {
            continue;
        }
        let listed = tokens::lookup(chain, &contract);
        let symbol = listed.map(|t| t.symbol.clone()).or_else(|| label(node, &contract).1);
        let decimals = listed.map(|t| t.decimals).or_else(|| {
            node.call(&contract, &format!("0x{SEL_DECIMALS}"))
                .ok()
                .and_then(|r| u256_word(&r).ok().flatten())
                .and_then(|d| u32::try_from(d).ok())
                .filter(|d| *d <= 36)
        });
        let amount = match (word, decimals) {
            (None, _) => "unlimited".to_string(),
            (Some(v), _) if v >= u128::MAX / 2 => "unlimited".to_string(),
            (Some(v), Some(d)) => tokens::format_units(v, d),
            (Some(v), None) => format!("{v} base units"),
        };
        approvals.push(Approval {
            key,
            kind: "token",
            contract: verify::checksum(&contract),
            symbol,
            spender: verify::checksum(&spender),
            amount,
            status,
        });
    }
    for (contract, operator) in for_all.into_iter().take(MAX_CANDIDATES) {
        let Ok(word) =
            node.call(&contract, &data_two(SEL_IS_APPROVED_FOR_ALL, old, &operator)).and_then(|r| u256_word(&r))
        else {
            continue;
        };
        let key = format!("{all_prefix}{contract}:{operator}");
        let status = Status::of(word == Some(1), &key, found);
        if status == Status::Empty {
            continue;
        }
        approvals.push(Approval {
            key,
            kind: "collection",
            contract: verify::checksum(&contract),
            symbol: label(node, &contract).1,
            spender: verify::checksum(&operator),
            amount: "all NFTs".into(),
            status,
        });
    }

    Ok(Report {
        chain_id: chain,
        network: c.watch_name,
        address: verify::checksum(old),
        destination: verify::checksum(dest),
        native,
        tokens: items,
        unreadable_tokens: unreadable,
        nfts,
        nft_window,
        approvals,
        approval_window,
    })
}

/// Approval / ApprovalForAll logs where `owner` approved someone: ("token" | "collection",
/// contract, spender), lowercase. ERC-721 single-token approvals (4 topics) are left out: they end
/// when the NFT moves. ApprovalForAll logs that revoke (data = false) are left out too.
pub fn approval_candidates(logs: &[Value], owner_topic: &str) -> Vec<(&'static str, String, String)> {
    let mut out = Vec::new();
    for l in logs {
        if l.get("removed").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let Some(t) = l.get("topics").and_then(Value::as_array) else { continue };
        let [t0, t1, t2] = t.as_slice() else { continue };
        if !t1.as_str().is_some_and(|x| x.eq_ignore_ascii_case(owner_topic)) {
            continue;
        }
        let Some(spender) = t2.as_str().and_then(watcher::address_of_topic) else { continue };
        let Some(contract) = l.get("address").and_then(Value::as_str).filter(|c| verify::is_address(c)) else {
            continue;
        };
        let kind = match t0.as_str() {
            Some(x) if x.eq_ignore_ascii_case(APPROVAL_TOPIC) => "token",
            Some(x) if x.eq_ignore_ascii_case(APPROVAL_FOR_ALL_TOPIC) => {
                let data = l.get("data").and_then(Value::as_str).and_then(|d| d.strip_prefix("0x"));
                if data.and_then(abi::u128_of_word_hex) != Some(1) {
                    continue;
                }
                "collection"
            }
            _ => continue,
        };
        let item = (kind, contract.to_ascii_lowercase(), spender);
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::verify::keccak256;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const OLD: &str = "0x1111111111111111111111111111111111111111";
    const DEST: &str = "0x2222222222222222222222222222222222222222";
    const SPENDER: &str = "0x3333333333333333333333333333333333333333";
    const NFT: &str = "0x4444444444444444444444444444444444444444";
    const ODD: &str = "0x5555555555555555555555555555555555555555";

    #[test]
    fn selectors_and_topics_are_the_signatures_hashes() {
        let sel = |sig: &str| hex::encode(&keccak256(sig.as_bytes())[..4]);
        assert_eq!(sel("allowance(address,address)"), SEL_ALLOWANCE);
        assert_eq!(sel("decimals()"), SEL_DECIMALS);
        assert_eq!(sel("isApprovedForAll(address,address)"), SEL_IS_APPROVED_FOR_ALL);
        assert_eq!(format!("0x{}", hex::encode(keccak256(b"Approval(address,address,uint256)"))), APPROVAL_TOPIC);
        assert_eq!(
            format!("0x{}", hex::encode(keccak256(b"ApprovalForAll(address,address,bool)"))),
            APPROVAL_FOR_ALL_TOPIC
        );
    }

    fn word(v: u128) -> Vec<u8> {
        let mut w = vec![0u8; 16];
        w.extend_from_slice(&v.to_be_bytes());
        w
    }
    fn addr_word(a: &str) -> Vec<u8> {
        hex::decode(abi::address_word_hex(a)).unwrap()
    }
    fn string_ret(s: &str) -> Vec<u8> {
        let mut r = word(32);
        r.extend(word(s.len() as u128));
        let mut b = s.as_bytes().to_vec();
        b.resize(32, 0);
        r.extend(b);
        r
    }

    /// A pretend node on Base: balances, eth_call answers by (contract, calldata), logs.
    struct Fake {
        balances: HashMap<String, u128>,
        calls: HashMap<(String, String), Vec<u8>>,
        logs: Vec<Value>,
        log_searches: RefCell<u32>,
    }
    impl Node for Fake {
        fn chain_id(&self) -> Result<u128, String> {
            Ok(8453)
        }
        fn block_number(&self) -> Result<u128, String> {
            Ok(30_000_000)
        }
        fn balance(&self, a: &str) -> Result<u128, String> {
            Ok(self.balances.get(a).copied().unwrap_or(0))
        }
        fn call(&self, to: &str, data: &str) -> Result<Vec<u8>, String> {
            self.calls
                .get(&(to.to_ascii_lowercase(), data.to_string()))
                .cloned()
                .ok_or_else(|| "execution reverted".to_string())
        }
        fn logs(&self, _from: u128, to: u128, topics: Value) -> (Vec<Value>, Option<u128>, Option<String>) {
            *self.log_searches.borrow_mut() += 1;
            let t0 = &topics[0];
            let wanted: Vec<&str> = match t0 {
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                v => v.as_str().into_iter().collect(),
            };
            let logs =
                self.logs.iter().filter(|l| wanted.contains(&l["topics"][0].as_str().unwrap_or(""))).cloned().collect();
            (logs, Some(to - 1000), Some("searched as far back as the node allows".into()))
        }
    }

    fn usdc() -> &'static tokens::Token {
        tokens::list()
            .unwrap()
            .iter()
            .find(|t| t.chain_id == 8453 && t.symbol == "USDC")
            .expect("USDC on Base in the list")
    }

    fn fake() -> Fake {
        let usdc = usdc().address.to_ascii_lowercase();
        let mut calls = HashMap::new();
        calls.insert((usdc.clone(), data_owner(SEL_BALANCE_OF, OLD)), word(25_000_000)); // 25 USDC
        calls.insert((usdc.clone(), data_owner(SEL_BALANCE_OF, DEST)), word(0));
        calls.insert((usdc.clone(), data_two(SEL_ALLOWANCE, OLD, SPENDER)), vec![0xff; 32]); // unlimited
        calls.insert((NFT.into(), format!("0x{SEL_OWNER_OF}{:064x}", 7u128)), addr_word(OLD));
        calls.insert((NFT.into(), format!("0x{SEL_NAME}")), string_ret("Pixel Cats"));
        calls.insert((NFT.into(), format!("0x{SEL_SYMBOL}")), string_ret("PXC"));
        calls.insert((NFT.into(), data_two(SEL_IS_APPROVED_FOR_ALL, OLD, SPENDER)), word(1));
        // a hostile contract: allowance answers 31 bytes
        calls.insert((ODD.into(), data_two(SEL_ALLOWANCE, OLD, SPENDER)), vec![1; 31]);
        let me = watcher::topic_address(OLD);
        let sp = watcher::topic_address(SPENDER);
        let logs = vec![
            json!({"address": NFT, "topics": [abi::TRANSFER_TOPIC, watcher::topic_address(ODD), me, format!("0x{:064x}", 7)]}),
            json!({"address": usdc, "topics": [APPROVAL_TOPIC, me, sp], "data": format!("0x{}", "ff".repeat(32))}),
            json!({"address": ODD, "topics": [APPROVAL_TOPIC, me, sp], "data": "0x"}),
            json!({"address": NFT, "topics": [APPROVAL_FOR_ALL_TOPIC, me, sp], "data": format!("0x{:064x}", 1)}),
            // noise: a single-NFT approval (4 topics), someone else's approval, a malformed topic list
            json!({"address": NFT, "topics": [APPROVAL_TOPIC, me, sp, format!("0x{:064x}", 7)]}),
            json!({"address": usdc, "topics": [APPROVAL_TOPIC, sp, me]}),
            json!({"address": usdc, "topics": "nonsense"}),
        ];
        Fake {
            balances: HashMap::from([(OLD.into(), 3 * 10u128.pow(17)), (DEST.into(), 0)]),
            calls,
            logs,
            log_searches: RefCell::new(0),
        }
    }

    #[test]
    fn first_scan_finds_coins_tokens_nfts_and_approvals() {
        let f = fake();
        let mut found = BTreeSet::new();
        let r = scan(&f, OLD, DEST, &mut found, true).unwrap();
        assert_eq!((r.chain_id, r.network), (8453, "Base"));
        assert_eq!((r.native.amount.as_str(), r.native.status), ("0.3", Status::Move));
        assert_eq!(r.native.destination_amount.as_deref(), Some("0"));
        assert_eq!(r.tokens.len(), 1, "only tokens with a balance: {:?}", r.tokens);
        assert_eq!(
            (r.tokens[0].symbol.as_str(), r.tokens[0].amount.as_str(), r.tokens[0].status),
            ("USDC", "25", Status::Move)
        );
        assert_eq!(r.nfts.len(), 1);
        assert_eq!(
            (r.nfts[0].token_id.as_str(), r.nfts[0].name.as_deref(), r.nfts[0].status),
            ("7", Some("Pixel Cats"), Status::Move)
        );
        assert_eq!(r.approvals.len(), 2, "{:?}", r.approvals);
        let a = &r.approvals[0];
        assert_eq!(
            (a.kind, a.amount.as_str(), a.symbol.as_deref(), a.status),
            ("token", "unlimited", Some("USDC"), Status::Move)
        );
        let b = &r.approvals[1];
        assert_eq!((b.kind, b.amount.as_str(), b.symbol.as_deref()), ("collection", "all NFTs", Some("PXC")));
        assert!(r.nft_window.searched && r.nft_window.from_block.is_some());
        assert_eq!(*f.log_searches.borrow(), 2);
        assert_eq!(found.len(), 5, "native, USDC, the NFT, two approvals: {found:?}");
    }

    #[test]
    fn rescan_ticks_off_what_moved_without_searching_logs() {
        let mut f = fake();
        let mut found = BTreeSet::new();
        scan(&f, OLD, DEST, &mut found, true).unwrap();
        // the user moved everything and revoked the token approval; the NFT went to Phone Vault
        let usdc = usdc().address.to_ascii_lowercase();
        f.balances.insert(OLD.into(), 21_000 * 300_000_000); // dust left after the max send
        f.balances.insert(DEST.into(), 29 * 10u128.pow(16));
        f.calls.insert((usdc.clone(), data_owner(SEL_BALANCE_OF, OLD)), word(0));
        f.calls.insert((usdc.clone(), data_owner(SEL_BALANCE_OF, DEST)), word(25_000_000));
        f.calls.insert((usdc, data_two(SEL_ALLOWANCE, OLD, SPENDER)), word(0));
        f.calls.insert((NFT.into(), format!("0x{SEL_OWNER_OF}{:064x}", 7u128)), addr_word(DEST));
        f.logs.clear();
        *f.log_searches.borrow_mut() = 0;
        let r = scan(&f, OLD, DEST, &mut found, false).unwrap();
        assert_eq!(*f.log_searches.borrow(), 0, "a quick re-scan reads no logs");
        assert_eq!(r.native.status, Status::Moved);
        assert_eq!(r.native.destination_amount.as_deref(), Some("0.29"));
        assert_eq!((r.tokens[0].status, r.tokens[0].destination_amount.as_deref()), (Status::Moved, Some("25")));
        assert_eq!((r.nfts[0].status, r.nfts[0].on_phone_vault), (Status::Moved, true));
        assert_eq!(r.approvals.iter().map(|a| a.status).collect::<Vec<_>>(), vec![Status::Moved, Status::Move]);
        assert!(!r.nft_window.searched);
    }

    #[test]
    fn hostile_log_shapes_are_skipped() {
        let me = watcher::topic_address(OLD);
        let sp = watcher::topic_address(SPENDER);
        let logs = vec![
            json!({"address": "0xnot", "topics": [APPROVAL_TOPIC, me, sp]}),
            json!({"address": NFT, "topics": [APPROVAL_TOPIC, me, "0x12"]}),
            json!({"address": NFT, "topics": [APPROVAL_FOR_ALL_TOPIC, me, sp], "data": format!("0x{:064x}", 0)}),
            json!({"address": NFT, "topics": [APPROVAL_FOR_ALL_TOPIC, me, sp], "data": "0x01"}),
            json!({"address": NFT, "topics": [APPROVAL_TOPIC, me, sp], "removed": true}),
            json!({"address": NFT, "topics": [1, 2, 3]}),
            json!({"address": NFT}),
            json!(null),
        ];
        assert!(approval_candidates(&logs, &me).is_empty());
        assert!(u256_word(&[0; 31]).is_err());
        assert_eq!(u256_word(&[0xff; 32]).unwrap(), None);
    }
}

/// Security-audit proof tests (adversarial): a node that errors (or is rate limited) on the
/// re-check calls must not make a still-live item look handled.
#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod audit_tests {
    use super::*;
    use std::collections::HashMap;

    const OLD: &str = "0x1111111111111111111111111111111111111111";
    const DEST: &str = "0x2222222222222222222222222222222222222222";
    const SPENDER: &str = "0x3333333333333333333333333333333333333333";
    const NFT: &str = "0x4444444444444444444444444444444444444444";
    const TOKEN: &str = "0x6666666666666666666666666666666666666666";

    /// Base; eth_call answered from `calls` (or every call fails, like a rate-limited node).
    struct Node2 {
        calls: HashMap<(String, String), Vec<u8>>,
        fail_calls: bool,
    }
    impl Node for Node2 {
        fn chain_id(&self) -> Result<u128, String> {
            Ok(8453)
        }
        fn block_number(&self) -> Result<u128, String> {
            Ok(30_000_000)
        }
        fn balance(&self, _a: &str) -> Result<u128, String> {
            Ok(0)
        }
        fn call(&self, to: &str, data: &str) -> Result<Vec<u8>, String> {
            if self.fail_calls {
                return Err("HTTP 429: rate limit".into());
            }
            self.calls.get(&(to.to_ascii_lowercase(), data.to_string())).cloned().ok_or_else(|| "reverted".into())
        }
        fn logs(&self, _f: u128, _t: u128, _x: Value) -> (Vec<Value>, Option<u128>, Option<String>) {
            (vec![], None, None)
        }
    }

    /// FINDING: an approval found active before vanishes from the report when the node fails the
    /// `allowance` / `isApprovedForAll` re-check (evm.rs:288-290, 322-326): no "couldn't check"
    /// marker, so the UI tally (migrate.ts:200, 211-215) can say "Everything found has moved" while an
    /// unlimited approval is still live.
    #[test]
    fn audit_failed_allowance_recheck_silently_drops_a_live_approval() {
        let mut found = BTreeSet::from([
            format!("evm:8453:{OLD}:approve:{TOKEN}:{SPENDER}"),
            format!("evm:8453:{OLD}:approveall:{NFT}:{SPENDER}"),
        ]);
        let node = Node2 { calls: HashMap::new(), fail_calls: true };
        let r = scan(&node, OLD, DEST, &mut found, false).unwrap();
        assert!(r.approvals.is_empty(), "the live approvals are simply not reported: {:?}", r.approvals);
        assert!(!r.approval_window.searched && r.approval_window.error.is_none(), "and nothing says the check failed");
    }

    /// FINDING: an NFT found before is reported as `Gone` ("Sent somewhere other than Phone Vault",
    /// counted as moved by the UI tally, migrate.ts:196) when the node merely fails `ownerOf`
    /// (evm.rs:237-245): an RPC error is read as "not held any more".
    #[test]
    fn audit_failed_owner_of_turns_a_held_nft_into_gone() {
        let mut found = BTreeSet::from([format!("evm:8453:{OLD}:nft:{NFT}:7")]);
        let node = Node2 { calls: HashMap::new(), fail_calls: true };
        let r = scan(&node, OLD, DEST, &mut found, false).unwrap();
        assert_eq!(r.nfts.len(), 1);
        assert_eq!(r.nfts[0].status, Status::Gone, "a rate-limited ownerOf reads as 'left the old wallet'");
        // contrast: listed tokens whose balanceOf fails ARE reported as unreadable (the right pattern)
        assert!(!r.unreadable_tokens.is_empty());
    }

    /// FINDING (DoS): candidate de-duplication is O(n^2) (`out.contains` in approval_candidates,
    /// evm.rs:388, and nft::erc721_candidates, nft.rs:181) over logs a hostile node controls (up to
    /// 40 x 16 MB answers, watcher.rs:198 / eth.rs:26). Prints timings; 4x the logs costs >6x time.
    #[test]
    fn audit_candidate_dedup_is_quadratic_in_hostile_logs() {
        let me = watcher::topic_address(OLD);
        let mk = |n: usize| -> Vec<Value> {
            (0..n)
                .map(|i| json!({"address": NFT, "topics": [APPROVAL_TOPIC, me, format!("0x{:064x}", i + 1)], "data": "0x"}))
                .collect()
        };
        let mut times = vec![];
        for n in [4_000usize, 8_000, 16_000] {
            let logs = mk(n);
            let t = std::time::Instant::now();
            let out = approval_candidates(&logs, &me);
            let el = t.elapsed();
            assert_eq!(out.len(), n);
            eprintln!("approval_candidates: {n} distinct logs -> {el:?}");
            times.push(el.as_secs_f64());
        }
        assert!(times[2] > times[0] * 6.0, "{times:?}");
    }
}
