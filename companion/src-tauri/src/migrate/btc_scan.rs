//! Read-only Bitcoin scan of an old wallet: the balance behind an extended public key (gap limit
//! 20, per script type) or one address, from the user's Esplora server (Settings → Bitcoin). Pure
//! over `btc::scan::Source`, so it is tested with a pretend server.
//!
//! The server is untrusted: sums are checked (no wrap, never more than 21 M BTC), and a server that
//! calls every address "used" cannot keep the scan going: it stops after `MAX_ADDRESSES` per key.
//!
//! Addresses are derived by `btc::wallet::address_for`, the same code as for paired accounts
//! (Native SegWit, Taproot, Nested SegWit, Legacy).

#![deny(clippy::indexing_slicing)]

use super::source::BtcType;
use crate::btc::esplora::AddressInfo;
use crate::btc::scan::{Source, GAP};
use crate::btc::wallet::{address_for, Kind, Net};
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::key::Secp256k1;
use serde::Serialize;

/// Addresses asked about per extended key at most (all types, both chains).
pub const MAX_ADDRESSES: u32 = 600;
/// Below this an amount is dust (the standard P2PKH dust limit): too little to move.
pub const DUST_SATS: u64 = 546;
const MAX_SATS: u64 = 21_000_000 * 100_000_000;

/// The address at receive (0) or change (1) `index` of an account key, as `t`.
pub fn derive(x: &Xpub, t: BtcType, net: Net, chain: u32, index: u32) -> Result<String, String> {
    let secp = Secp256k1::verification_only();
    let path = [
        ChildNumber::from_normal_idx(chain).map_err(|e| e.to_string())?,
        ChildNumber::from_normal_idx(index).map_err(|e| e.to_string())?,
    ];
    let pk = x.derive_pub(&secp, &path).map_err(|e| e.to_string())?.public_key;
    Ok(address_for(&secp, kind_of(t), net, pk).to_string())
}

/// The paired-account type with the same script.
pub fn kind_of(t: BtcType) -> Kind {
    match t {
        BtcType::Legacy => Kind::P2pkh,
        BtcType::Nested => Kind::P2shP2wpkh,
        BtcType::Native => Kind::P2wpkh,
        BtcType::Taproot => Kind::P2tr,
    }
}

/// What one script type of an old key holds.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct TypeTotal {
    pub btc_type: BtcType,
    pub name: &'static str,
    pub looks: &'static str,
    pub confirmed_sats: u64,
    pub unconfirmed_sats: i64,
    pub used_addresses: u32,
    pub checked_addresses: u32,
    pub first_address: String,
}

#[derive(Default)]
struct Sums {
    confirmed: u64,
    mempool: i64,
}

impl Sums {
    fn add(&mut self, i: &AddressInfo) -> Result<bool, String> {
        let c = &i.chain_stats;
        let m = &i.mempool_stats;
        let confirmed = c.funded_txo_sum.checked_sub(c.spent_txo_sum).ok_or("server: spent more than funded")?;
        let funded = i64::try_from(m.funded_txo_sum).map_err(|_| "server: amount out of range")?;
        let spent = i64::try_from(m.spent_txo_sum).map_err(|_| "server: amount out of range")?;
        self.confirmed = self.confirmed.checked_add(confirmed).filter(|v| *v <= MAX_SATS).ok_or(TOO_MUCH)?;
        self.mempool = funded.checked_sub(spent).and_then(|d| self.mempool.checked_add(d)).ok_or(TOO_MUCH)?;
        if self.mempool.unsigned_abs() > MAX_SATS {
            return Err(TOO_MUCH.into());
        }
        Ok(c.tx_count.saturating_add(m.tx_count) > 0)
    }
}
const TOO_MUCH: &str = "server: reported more bitcoin than exists";

/// Gap-limit scan of one script type: the receive chain until 20 unused in a row, then the change
/// chain the same way, but only when the receive chain was used at all (a wallet makes change only
/// when spending what it received, so an unused type costs 20 requests, not 40).
pub fn scan_type(x: &Xpub, t: BtcType, net: Net, src: &dyn Source, budget: &mut u32) -> Result<TypeTotal, String> {
    let mut sums = Sums::default();
    let (mut used, mut checked) = (0u32, 0u32);
    for chain in 0..=1u32 {
        if chain == 1 && used == 0 {
            break;
        }
        let (mut gap, mut i) = (0u32, 0u32);
        while gap < GAP {
            if *budget == 0 {
                return Err(format!(
                    "stopped after {MAX_ADDRESSES} addresses: the server reports more activity than this check follows"
                ));
            }
            *budget -= 1;
            let a = derive(x, t, net, chain, i)?;
            let info = src.address(&a)?;
            checked += 1;
            if sums.add(&info)? {
                used += 1;
                gap = 0;
            } else {
                gap += 1;
            }
            i = i.checked_add(1).ok_or("address index out of range")?;
        }
    }
    Ok(TypeTotal {
        btc_type: t,
        name: t.name(),
        looks: t.looks(),
        confirmed_sats: sums.confirmed,
        unconfirmed_sats: sums.mempool,
        used_addresses: used,
        checked_addresses: checked,
        first_address: derive(x, t, net, 0, 0)?,
    })
}

/// Every type of an extended key. Types without any use are left out unless none was used.
pub fn scan_key(x: &Xpub, types: &[BtcType], net: Net, src: &dyn Source) -> Result<Vec<TypeTotal>, String> {
    let mut budget = MAX_ADDRESSES;
    let mut out = Vec::new();
    for t in types {
        out.push(scan_type(x, *t, net, src, &mut budget)?);
    }
    if out.iter().any(|t| t.used_addresses > 0) {
        out.retain(|t| t.used_addresses > 0);
    }
    Ok(out)
}

/// One address.
pub fn scan_address(a: &str, src: &dyn Source) -> Result<(u64, i64, bool), String> {
    let info = src.address(a)?;
    let mut sums = Sums::default();
    let used = sums.add(&info)?;
    Ok((sums.confirmed, sums.mempool, used))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::btc::esplora::{Stats, Tx};
    use crate::migrate::source::{parse, xpub_of, Source as Entry};
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    /// The account xpub at `path` of the BIP-39 test seed ("abandon … about").
    fn account(path: &str) -> Xpub {
        let secp = Secp256k1::new();
        let seed = hex::decode(crate::btc::wallet::tests::SEED).unwrap();
        let master = Xpriv::new_master(bitcoin::NetworkKind::Main, &seed).unwrap();
        let k = master.derive_priv(&secp, &DerivationPath::from_str(path).unwrap()).unwrap();
        Xpub::from_priv(&secp, &k)
    }

    #[test]
    fn derivation_matches_the_bip_test_vectors() {
        assert_eq!(
            derive(&account("m/44'/0'/0'"), BtcType::Legacy, Net::Bitcoin, 0, 0).unwrap(),
            "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
        );
        assert_eq!(
            derive(&account("m/49'/0'/0'"), BtcType::Nested, Net::Bitcoin, 0, 0).unwrap(),
            "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
        );
        assert_eq!(
            derive(&account("m/84'/0'/0'"), BtcType::Native, Net::Bitcoin, 0, 0).unwrap(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            derive(&account("m/86'/0'/0'"), BtcType::Taproot, Net::Bitcoin, 0, 0).unwrap(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        // the same addresses as a paired account of that type (btc::wallet) derives
        for (t, path) in [
            (BtcType::Legacy, "m/44'/0'/0'"),
            (BtcType::Nested, "m/49'/0'/0'"),
            (BtcType::Native, "m/84'/0'/0'"),
            (BtcType::Taproot, "m/86'/0'/0'"),
        ] {
            let (a, _) = crate::btc::wallet::tests::account(Net::Bitcoin, kind_of(t), 1);
            assert_eq!(a.xpub, account(path));
            for (chain, i) in [(0, 0), (0, 7), (1, 3)] {
                assert_eq!(
                    derive(&a.xpub, t, Net::Bitcoin, chain, i).unwrap(),
                    a.derive(chain, i).unwrap().address.to_string()
                );
            }
        }
        // the zpub of the same account, through the parser
        assert_eq!(xpub_of(ZPUB).unwrap(), account("m/84'/0'/0'"));
        assert!(matches!(parse(ZPUB).unwrap(), Entry::Xpub { .. }));
    }

    /// A pretend Esplora server: address → (confirmed sats, transaction count, unconfirmed sats).
    struct Fake {
        coins: BTreeMap<String, (u64, u64, i64)>,
        asked: RefCell<u32>,
        everything_used: bool,
    }
    impl Source for Fake {
        fn address(&self, a: &str) -> Result<AddressInfo, String> {
            *self.asked.borrow_mut() += 1;
            let (c, n, m) = self.coins.get(a).copied().unwrap_or((0, u64::from(self.everything_used), 0));
            let chain_stats = Stats { funded_txo_sum: c, tx_count: n, funded_txo_count: n, ..Stats::default() };
            let mempool_stats = if m >= 0 {
                Stats { funded_txo_sum: m as u64, tx_count: u64::from(m != 0), ..Stats::default() }
            } else {
                Stats { spent_txo_sum: m.unsigned_abs(), tx_count: 1, ..Stats::default() }
            };
            Ok(AddressInfo { address: a.to_string(), chain_stats, mempool_stats })
        }
        fn txs(&self, _a: &str) -> Result<Vec<Tx>, String> {
            Ok(vec![])
        }
    }

    #[test]
    fn gap_limit_per_type_and_chain() {
        let x = account("m/84'/0'/0'");
        let r = |i| derive(&x, BtcType::Native, Net::Bitcoin, 0, i).unwrap();
        let c = |i| derive(&x, BtcType::Native, Net::Bitcoin, 1, i).unwrap();
        let mut coins = BTreeMap::new();
        coins.insert(r(0), (0, 2, 0)); // used, emptied
        coins.insert(r(19), (50_000, 1, 0)); // inside the gap
        coins.insert(r(45), (70_000, 1, 0)); // beyond it: not found
        coins.insert(c(3), (12_000, 1, 1_000));
        let f = Fake { coins, asked: RefCell::new(0), everything_used: false };
        let mut budget = MAX_ADDRESSES;
        let t = scan_type(&x, BtcType::Native, Net::Bitcoin, &f, &mut budget).unwrap();
        assert_eq!((t.confirmed_sats, t.unconfirmed_sats, t.used_addresses), (62_000, 1_000, 3));
        assert_eq!(t.checked_addresses, 40 + 24, "receive 0..=39, change 0..=23");
        assert_eq!(t.first_address, r(0));

        // an unused type: the receive chain only
        let mut budget = MAX_ADDRESSES;
        let t = scan_type(&x, BtcType::Legacy, Net::Bitcoin, &f, &mut budget).unwrap();
        assert_eq!((t.used_addresses, t.checked_addresses), (0, 20));

        // an xpub scanned as every type keeps only the types that were used
        let all =
            scan_key(&x, &[BtcType::Native, BtcType::Taproot, BtcType::Legacy, BtcType::Nested], Net::Bitcoin, &f)
                .unwrap();
        assert_eq!(all.iter().map(|t| t.btc_type).collect::<Vec<_>>(), vec![BtcType::Native]);
        // nothing used anywhere: every type is reported (all zero)
        let empty = Fake { coins: BTreeMap::new(), asked: RefCell::new(0), everything_used: false };
        assert_eq!(scan_key(&x, &[BtcType::Native, BtcType::Taproot], Net::Bitcoin, &empty).unwrap().len(), 2);
        assert_eq!(*empty.asked.borrow(), 40);
    }

    #[test]
    fn a_lying_server_cannot_run_the_scan_forever_or_overflow() {
        let x = account("m/84'/0'/0'");
        let liar = Fake { coins: BTreeMap::new(), asked: RefCell::new(0), everything_used: true };
        let e = scan_key(&x, &[BtcType::Native, BtcType::Taproot], Net::Bitcoin, &liar).unwrap_err();
        assert!(e.contains("stopped after"), "{e}");
        assert_eq!(*liar.asked.borrow(), MAX_ADDRESSES);

        let a = derive(&x, BtcType::Native, Net::Bitcoin, 0, 0).unwrap();
        let rich = Fake {
            coins: BTreeMap::from([(a.clone(), (MAX_SATS + 1, 1, 0))]),
            asked: RefCell::new(0),
            everything_used: false,
        };
        assert!(scan_address(&a, &rich).unwrap_err().contains("more bitcoin than exists"));
        let ok = Fake {
            coins: BTreeMap::from([(a.clone(), (1_000, 1, -400))]),
            asked: RefCell::new(0),
            everything_used: false,
        };
        assert_eq!(scan_address(&a, &ok).unwrap(), (1_000, -400, true));
        // spent more than funded on the confirmed side
        struct Odd;
        impl Source for Odd {
            fn address(&self, a: &str) -> Result<AddressInfo, String> {
                Ok(AddressInfo {
                    address: a.into(),
                    chain_stats: Stats { funded_txo_sum: 1, spent_txo_sum: 2, tx_count: 1, ..Stats::default() },
                    mempool_stats: Stats { funded_txo_sum: u64::MAX, ..Stats::default() },
                })
            }
            fn txs(&self, _: &str) -> Result<Vec<Tx>, String> {
                Ok(vec![])
            }
        }
        assert!(scan_address(&a, &Odd).is_err());
    }
}
