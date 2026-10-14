//! Address discovery (BIP-44 gap limit 20 on the receive and change chains), balances and history,
//! from an Esplora server. Pure over a `Source`, so it is tested with fixtures.
//!
//! A full scan asks for every used address and 20 unused ones past the last used on each chain.
//! A light scan (the background watcher between full scans) asks only for addresses holding coins
//! or with unconfirmed activity, and a few around the next receive/change index, which is where new
//! payments land.

use super::esplora::{AddressInfo, Tx};
use super::store::{AddrState, Cache, Entry};
use super::wallet::{Account, MAX_INDEX};
use std::collections::{BTreeMap, BTreeSet};

pub const GAP: u32 = 20;
/// The esplora answer for one address's transactions (newest 50 unconfirmed + 25 confirmed).
pub trait Source {
    fn address(&self, a: &str) -> Result<AddressInfo, String>;
    fn txs(&self, a: &str) -> Result<Vec<Tx>, String>;
}

impl Source for super::esplora::Client {
    fn address(&self, a: &str) -> Result<AddressInfo, String> {
        super::esplora::Client::address(self, a)
    }
    fn txs(&self, a: &str) -> Result<Vec<Tx>, String> {
        super::esplora::Client::txs(self, a)
    }
}

fn state(chain: u32, index: u32, i: &AddressInfo) -> AddrState {
    AddrState {
        chain,
        index,
        chain_txs: i.chain_stats.tx_count,
        mempool_txs: i.mempool_stats.tx_count,
        confirmed: i.chain_stats.funded_txo_sum.saturating_sub(i.chain_stats.spent_txo_sum),
        mempool: i.mempool_stats.funded_txo_sum as i64 - i.mempool_stats.spent_txo_sum as i64,
    }
}

/// Scan, update `cache`, and return the transactions that are new incoming payments (only after
/// the first complete scan: the backfill fills history quietly).
pub fn scan(
    account: &Account,
    src: &dyn Source,
    cache: &mut Cache,
    full: bool,
    now: u64,
) -> Result<Vec<Entry>, String> {
    let mut changed: BTreeSet<String> = BTreeSet::new();
    let mut seen: BTreeMap<String, AddrState> = BTreeMap::new();
    let check = |chain: u32,
                 index: u32,
                 cache: &Cache,
                 changed: &mut BTreeSet<String>,
                 seen: &mut BTreeMap<String, AddrState>|
     -> Result<bool, String> {
        let a = account.derive(chain, index)?.address.to_string();
        let info = src.address(&a)?;
        let s = state(chain, index, &info);
        let used = s.chain_txs + s.mempool_txs > 0;
        let prev = cache.addrs.get(&a);
        if used && prev.is_none_or(|p| p.chain_txs != s.chain_txs || p.mempool_txs != s.mempool_txs) {
            changed.insert(a.clone());
        }
        if !used && prev.is_some() {
            changed.insert(a.clone());
        } // an unconfirmed payment vanished
        if used {
            seen.insert(a, s);
        }
        Ok(used)
    };
    let full = full || !cache.initial_done;
    let mut next = cache.next;
    if full {
        for chain in 0..=1u32 {
            let (mut gap, mut i, mut last) = (0, 0u32, None);
            while gap < GAP && i <= MAX_INDEX {
                if check(chain, i, cache, &mut changed, &mut seen)? {
                    gap = 0;
                    last = Some(i);
                } else {
                    gap += 1;
                }
                i += 1;
            }
            next[chain as usize] = last.map_or(0, |l| l + 1);
        }
        cache.addrs = seen;
        cache.full_scan_at = now;
    } else {
        let mut ask: BTreeSet<(u32, u32)> = cache
            .addrs
            .values()
            .filter(|s| s.confirmed > 0 || s.mempool != 0 || s.mempool_txs > 0)
            .map(|s| (s.chain, s.index))
            .collect();
        for i in cache.next[0].saturating_sub(3)..cache.next[0] + 5 {
            ask.insert((0, i));
        }
        for i in cache.next[1]..cache.next[1] + 2 {
            ask.insert((1, i));
        }
        for (chain, i) in ask {
            if check(chain, i, cache, &mut changed, &mut seen)? {
                next[chain as usize] = next[chain as usize].max(i + 1);
            }
        }
        // addresses not asked keep their state; asked ones are replaced (or dropped when unused now)
        for a in &changed {
            if !seen.contains_key(a) {
                cache.addrs.remove(a);
            }
        }
        for (a, s) in seen {
            cache.addrs.insert(a, s);
        }
        // a payment landed beyond what we looked at: the next full scan finds the rest
        if next != cache.next {
            cache.full_scan_at = 0;
        }
    }
    cache.next = next;

    // history for the addresses whose transaction count moved
    let mine: BTreeSet<String> = cache.addrs.keys().cloned().collect();
    let mut fetched: BTreeMap<String, Tx> = BTreeMap::new();
    for a in &changed {
        if !mine.contains(a) {
            continue;
        }
        for t in src.txs(a)? {
            fetched.insert(t.txid.clone(), t);
        }
    }
    let mut incoming = Vec::new();
    let notify = cache.initial_done;
    for t in fetched.values() {
        let e = entry(t, &mine, now);
        match cache.history.iter_mut().find(|x| x.txid == e.txid) {
            Some(x) => {
                let first = x.time;
                *x = e;
                if x.height.is_none() {
                    x.time = first;
                }
            }
            None => {
                if notify && e.net > 0 {
                    incoming.push(e.clone());
                }
                cache.history.push(e);
            }
        }
    }
    // a pending transaction that touched a changed address but is no longer listed: replaced or evicted
    for x in cache.history.iter_mut().filter(|x| x.status == "pending" && !fetched.contains_key(&x.txid)) {
        if x.addrs.iter().any(|a| changed.contains(a)) {
            x.status = "dropped".into();
        }
    }
    cache.scanned_at = now;
    cache.initial_done = true;
    cache.error = None;
    Ok(incoming)
}

/// A server transaction as seen from this account.
pub fn entry(t: &Tx, mine: &BTreeSet<String>, now: u64) -> Entry {
    let ours = |addr: &Option<String>| addr.as_ref().is_some_and(|a| mine.contains(a));
    let got: u64 = t.vout.iter().filter(|o| ours(&o.scriptpubkey_address)).map(|o| o.value).sum();
    let spent: u64 = t
        .vin
        .iter()
        .filter_map(|i| i.prevout.as_ref())
        .filter(|p| ours(&p.scriptpubkey_address))
        .map(|p| p.value)
        .sum();
    let net = got as i64 - spent as i64;
    let counterparty = if spent > 0 {
        t.vout.iter().find(|o| !ours(&o.scriptpubkey_address)).and_then(|o| o.scriptpubkey_address.clone())
    } else {
        t.vin
            .iter()
            .filter_map(|i| i.prevout.as_ref())
            .find(|p| !ours(&p.scriptpubkey_address))
            .and_then(|p| p.scriptpubkey_address.clone())
    };
    let mut addrs: BTreeSet<String> =
        t.vout.iter().filter_map(|o| o.scriptpubkey_address.clone()).filter(|a| mine.contains(a)).collect();
    addrs.extend(
        t.vin.iter().filter_map(|i| i.prevout.as_ref()?.scriptpubkey_address.clone()).filter(|a| mine.contains(a)),
    );
    Entry {
        txid: t.txid.clone(),
        net,
        fee: (spent > 0).then_some(t.fee),
        height: t.status.block_height.filter(|_| t.status.confirmed),
        time: t.status.block_time.filter(|_| t.status.confirmed).unwrap_or(now),
        counterparty,
        status: if t.status.confirmed { "confirmed".into() } else { "pending".into() },
        addrs: addrs.into_iter().collect(),
        rbf: t.vin.iter().any(|i| i.sequence < 0xffff_fffe),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc::esplora::{parse_txs, Stats, TxStatus, Vin, Vout};
    use crate::btc::wallet::{tests::account as test_account, Kind, Net};
    use std::cell::RefCell;

    /// A pretend server: which addresses have which transactions.
    struct Fake {
        txs: BTreeMap<String, Vec<Tx>>,
        asked: RefCell<Vec<String>>,
    }
    impl Source for Fake {
        fn address(&self, a: &str) -> Result<AddressInfo, String> {
            self.asked.borrow_mut().push(a.to_string());
            let list = self.txs.get(a).cloned().unwrap_or_default();
            let mut cs = Stats::default();
            let mut ms = Stats::default();
            for t in &list {
                let s = if t.status.confirmed { &mut cs } else { &mut ms };
                s.tx_count += 1;
                for o in t.vout.iter().filter(|o| o.scriptpubkey_address.as_deref() == Some(a)) {
                    s.funded_txo_count += 1;
                    s.funded_txo_sum += o.value;
                }
                for p in t
                    .vin
                    .iter()
                    .filter_map(|i| i.prevout.as_ref())
                    .filter(|p| p.scriptpubkey_address.as_deref() == Some(a))
                {
                    s.spent_txo_count += 1;
                    s.spent_txo_sum += p.value;
                }
            }
            Ok(AddressInfo { address: a.to_string(), chain_stats: cs, mempool_stats: ms })
        }
        fn txs(&self, a: &str) -> Result<Vec<Tx>, String> {
            Ok(self.txs.get(a).cloned().unwrap_or_default())
        }
    }

    fn vout(a: &str, v: u64) -> Vout {
        Vout { scriptpubkey: "00".into(), scriptpubkey_address: Some(a.into()), value: v }
    }
    fn tx(id: u8, ins: Vec<Vout>, outs: Vec<Vout>, height: Option<u64>) -> Tx {
        Tx {
            txid: format!("{id:064x}"),
            vin: ins
                .into_iter()
                .map(|p| Vin {
                    txid: "aa".repeat(32),
                    vout: 0,
                    prevout: Some(p),
                    is_coinbase: false,
                    sequence: 0xffff_fffd,
                })
                .collect(),
            vout: outs,
            weight: 561,
            fee: 200,
            status: TxStatus {
                confirmed: height.is_some(),
                block_height: height,
                block_time: height.map(|h| 1_700_000_000 + h),
            },
        }
    }

    #[test]
    fn gap_limit_discovery_balances_and_history() {
        let (a, _) = test_account(Net::Bitcoin, Kind::P2wpkh, 1);
        let r = |i| a.derive(0, i).unwrap().address.to_string();
        let c = |i| a.derive(1, i).unwrap().address.to_string();
        let mut f = Fake { txs: BTreeMap::new(), asked: RefCell::new(vec![]) };
        // receive 0 funded, receive 19 funded (inside the gap), receive 40 funded (beyond it: not found)
        let t1 = tx(
            1,
            vec![vout("bc1qsender", 300_000)],
            vec![vout(&r(0), 200_000), vout("bc1qsenderchange", 99_800)],
            Some(800_000),
        );
        let t2 = tx(2, vec![vout("bc1qsender", 60_000)], vec![vout(&r(19), 50_000)], Some(800_010));
        let t3 = tx(3, vec![vout("bc1qsender", 60_000)], vec![vout(&r(40), 50_000)], Some(800_011));
        // a send from receive 0 with change to change 0
        let t4 = tx(4, vec![vout(&r(0), 200_000)], vec![vout("bc1qshop", 120_000), vout(&c(0), 79_800)], Some(800_020));
        for (addr, t) in [(r(0), &t1), (r(19), &t2), (r(40), &t3), (r(0), &t4), (c(0), &t4)] {
            f.txs.entry(addr).or_default().push(t.clone());
        }
        let mut cache = Cache::default();
        let inc = scan(&a, &f, &mut cache, true, 1_800_000_000).unwrap();
        assert!(inc.is_empty(), "the first scan backfills quietly");
        assert_eq!(cache.next, [20, 1]);
        assert_eq!(f.asked.borrow().len(), 40 + 21, "receive 0..=39 (gap after 19), change 0..=20");
        assert_eq!(cache.confirmed(), 50_000 + 79_800);
        assert_eq!(cache.history.len(), 3);
        let e4 = cache.history.iter().find(|e| e.txid == t4.txid).unwrap();
        assert_eq!((e4.net, e4.fee, e4.counterparty.as_deref()), (-120_200, Some(200), Some("bc1qshop")));
        let e1 = cache.history.iter().find(|e| e.txid == t1.txid).unwrap();
        assert_eq!(
            (e1.net, e1.fee, e1.counterparty.as_deref(), e1.status.as_str()),
            (200_000, None, Some("bc1qsender"), "confirmed")
        );

        // an unconfirmed payment to the next receive address: a light scan finds it and reports it
        let t5 = tx(5, vec![vout("bc1qfriend", 30_000)], vec![vout(&r(20), 25_000)], None);
        f.txs.entry(r(20)).or_default().push(t5.clone());
        f.asked.borrow_mut().clear();
        let inc = scan(&a, &f, &mut cache, false, 1_800_000_100).unwrap();
        assert!(f.asked.borrow().len() < 15, "light scan asks little: {}", f.asked.borrow().len());
        assert_eq!(inc.len(), 1);
        assert_eq!((inc[0].net, inc[0].status.as_str()), (25_000, "pending"));
        assert_eq!(cache.unconfirmed(), 25_000);
        assert_eq!(cache.next[0], 21);
        // it gets replaced (RBF) by the sender and vanishes: marked dropped, balance back
        f.txs.get_mut(&r(20)).unwrap().clear();
        scan(&a, &f, &mut cache, false, 1_800_000_200).unwrap();
        assert_eq!(cache.history.iter().find(|e| e.txid == t5.txid).unwrap().status, "dropped");
        assert_eq!(cache.unconfirmed(), 0);
    }

    /// The scan trusts the Esplora server's "used" answers: one that reports change addresses
    /// 0..=899 as used moves `next[1]` (the change index btc_quote builds with, mod.rs) to 900, far
    /// past what an honest gap-20 scan reaches. This pins that behaviour: the change index the
    /// Mac proposes is only as honest as the server, so it must not be trusted on its own.
    #[test]
    fn lying_server_pushes_change_index_far_past_the_gap_limit() {
        struct Liar {
            used: BTreeSet<String>,
        }
        impl Source for Liar {
            fn address(&self, a: &str) -> Result<AddressInfo, String> {
                let mut cs = Stats::default();
                if self.used.contains(a) {
                    cs.tx_count = 1;
                }
                Ok(AddressInfo { address: a.to_string(), chain_stats: cs, mempool_stats: Stats::default() })
            }
            fn txs(&self, _a: &str) -> Result<Vec<Tx>, String> {
                Ok(vec![])
            }
        }
        let (a, _) = test_account(Net::Bitcoin, Kind::P2wpkh, 1);
        let used: BTreeSet<String> = (0..900).map(|i| a.derive(1, i).unwrap().address.to_string()).collect();
        let mut cache = Cache::default();
        scan(&a, &Liar { used }, &mut cache, true, 1_800_000_000).unwrap();
        assert_eq!(cache.next[1], 900, "the next change address is index 900");
        // an honest server afterwards: the gap-20 scan stops at change index 19
        let mut honest = Cache::default();
        scan(&a, &Liar { used: BTreeSet::new() }, &mut honest, true, 1_800_000_000).unwrap();
        assert_eq!(honest.next[1], 0);
        const { assert!(900 > GAP) };
    }

    #[test]
    fn entries_from_the_fixture() {
        let t = parse_txs(crate::btc::esplora::fixtures::TXS).unwrap();
        let mine = BTreeSet::from(["bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu".to_string()]);
        let e0 = entry(&t[0], &mine, 5);
        assert_eq!((e0.net, e0.status.as_str(), e0.time, e0.rbf), (5_000, "pending", 5, true));
        let e1 = entry(&t[1], &mine, 5);
        assert_eq!(
            (e1.net, e1.height, e1.time, e1.rbf, e1.counterparty.as_deref()),
            (150_000, Some(860_001), 1_726_000_000, false, Some("bc1qsender"))
        );
    }
}
