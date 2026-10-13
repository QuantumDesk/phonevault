//! Building a Bitcoin send: coin selection, size and fee, and the unsigned PSBT (v0) the phone
//! signs. Everything here is deterministic given its inputs (except the input/output order, which
//! is shuffled for privacy) and is what `verify.rs` later holds the phone's answer to.
//!
//! * Transaction: nVersion 2, nLockTime 0, every nSequence 0xfffffffd (opts in to RBF, BIP-125).
//! * Inputs carry `witness_utxo` and their BIP-32 origin (PSBT_IN_BIP32_DERIVATION for P2WPKH;
//!   PSBT_IN_TAP_INTERNAL_KEY + PSBT_IN_TAP_BIP32_DERIVATION for P2TR), P2WPKH inputs also the
//!   full previous transaction (`non_witness_utxo`) while the request stays under the phone's size
//!   limit. The change output carries its origin too, so the phone can prove it is ours.
//! * Coin selection: branch-and-bound for a change-less exact match, else largest-first with a
//!   change output; change too small to be worth spending goes to the fee instead (no dust change).

use super::wallet::{Account, Derived, Kind};
use bitcoin::absolute::LockTime;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use std::collections::BTreeMap;

/// BIP-125 opt-in (any value below 0xfffffffe), the value Bitcoin Core uses.
pub const RBF_SEQUENCE: u32 = 0xffff_fffd;
/// Below this an output is dust for every standard script type (P2PKH: 546).
pub const RECIPIENT_DUST: u64 = 546;
/// Fee rates the Mac will build with (sat/kvB): 0.1 … 2000 sat/vB.
pub const MIN_RATE_KVB: u64 = 100;
pub const MAX_RATE_KVB: u64 = 2_000_000;
/// Largest PSBT this Mac sends. The phone takes a PSBT of up to 200 KiB (Psbt.MAX_BYTES) in a
/// btcSignPsbt line of up to 288 KiB (AccessoryTransport.MAX_PSBT_REQUEST_BYTES; base64 of 180 KiB
/// is 240 KiB) and sends it back with the signatures added (about 110 bytes per input), which must
/// fit verify::MAX_RESPONSE_PSBT and the USB response cap for btcSignPsbt (aoa.rs).
pub const MAX_PSBT_BYTES: usize = 180 * 1024;
/// The phone signs transactions with at most 100 inputs and 100 outputs (BtcTx.MAX_IO).
pub const MAX_INPUTS: usize = 100;
/// The phone parses a previous transaction (non_witness_utxo) of at most 10 000 inputs/outputs
/// (BtcTx.MAX_PREV_IO).
pub const MAX_PREV_IO: usize = 10_000;

/// A coin of this account, as the server listed it — value and script checked against the
/// previous transaction (`prev_tx`, whose txid is hashed here) before it is used.
#[derive(Clone, Debug)]
pub struct Coin {
    pub outpoint: OutPoint,
    pub value: u64,
    pub derived: Derived,
    pub confirmed: bool,
    pub prev_tx: Option<Transaction>,
}

/// One planned output.
#[derive(Clone, Debug)]
pub struct Out { pub address: Address, pub value: u64, pub change: Option<Derived> }

/// A built, unsigned send: what the phone is asked to sign and what its answer must match.
#[derive(Clone, Debug)]
pub struct Built {
    pub account: Account,
    pub psbt: Psbt,
    pub inputs: Vec<Coin>,
    /// in transaction order
    pub outputs: Vec<Out>,
    pub recipient: Address,
    pub amount: u64,
    pub fee: u64,
    pub rate_kvb: u64,
    /// estimated (upper bound) virtual size
    pub vsize: u64,
    /// RBF: the txid this transaction replaces
    pub replaces: Option<String>,
}

impl Built {
    pub fn change(&self) -> Option<&Out> { self.outputs.iter().find(|o| o.change.is_some()) }
    pub fn input_total(&self) -> u64 { self.inputs.iter().map(|c| c.value).sum() }
    pub fn prevouts(&self) -> Vec<TxOut> { self.inputs.iter().map(|c| TxOut { value: Amount::from_sat(c.value), script_pubkey: c.derived.script.clone() }).collect() }
}

fn varint_len(n: u64) -> u64 { match n { 0..=0xfc => 1, 0xfd..=0xffff => 3, 0x10000..=0xffff_ffff => 5, _ => 9 } }

/// Weight of a segwit transaction spending `n_in` inputs of `kind` to outputs with these script lengths.
pub fn weight(kind: Kind, n_in: usize, out_script_lens: &[u64]) -> u64 {
    let outs: u64 = out_script_lens.iter().map(|l| 8 + varint_len(*l) + l).sum();
    let base = 4 + 4 + varint_len(n_in as u64) + varint_len(out_script_lens.len() as u64) + 41 * n_in as u64 + outs;
    base * 4 + 2 + kind.input_witness_weight() * n_in as u64
}

pub fn vsize(weight: u64) -> u64 { weight.div_ceil(4) }
pub fn fee_for(vbytes: u64, rate_kvb: u64) -> u64 { (vbytes * rate_kvb).div_ceil(1000) }
fn input_vbytes(kind: Kind) -> u64 { (41 * 4 + kind.input_witness_weight()).div_ceil(4) }

/// "12.5" sat/vB → 12_500 sat/kvB (at most 3 decimals), within the allowed range.
pub fn parse_rate(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    if w.is_empty() || w.len() > 6 || f.len() > 3 || !w.bytes().all(|b| b.is_ascii_digit()) || !f.bytes().all(|b| b.is_ascii_digit()) { return Err("Fee rate: use a number of sat/vB, like 12 or 3.5".into()); }
    let v = w.parse::<u64>().map_err(|_| "bad fee rate")? * 1000 + format!("{f:0<3}").parse::<u64>().map_err(|_| "bad fee rate")?;
    if v < MIN_RATE_KVB { return Err("Fee rate is below 0.1 sat/vB; nodes won't relay it".into()); }
    if v > MAX_RATE_KVB { return Err("Fee rate above 2000 sat/vB refused (typo guard)".into()); }
    Ok(v)
}

/// "0.0005" BTC → 50_000 sat. At most 8 decimals; no signs, no exponents.
pub fn parse_btc(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    if (w.is_empty() && f.is_empty()) || w.len() > 8 || f.len() > 8 || !w.bytes().all(|b| b.is_ascii_digit()) || !f.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Amount: use digits and one dot, at most 8 decimals".into());
    }
    let whole = if w.is_empty() { 0 } else { w.parse::<u64>().map_err(|_| "bad amount")? };
    let frac = if f.is_empty() { 0 } else { format!("{f:0<8}").parse::<u64>().map_err(|_| "bad amount")? };
    let sats = whole.checked_mul(100_000_000).and_then(|x| x.checked_add(frac)).ok_or("amount too large")?;
    if sats > 21_000_000 * 100_000_000 { return Err("amount too large".into()); }
    Ok(sats)
}

/// 50_000 → "0.0005" (exact, trailing zeros trimmed).
pub fn format_btc(sats: u64) -> String {
    let s = format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

#[derive(Debug, PartialEq)]
pub struct Selection { pub picked: Vec<usize>, pub change: u64, pub fee: u64, pub vsize: u64 }

/// The smallest change worth creating at this fee rate: at least 1000 sat, and at least what
/// spending it later would cost at today's rate (else it is dust in all but name).
pub fn min_change(kind: Kind, rate_kvb: u64) -> u64 { 1000u64.max(fee_for(input_vbytes(kind), rate_kvb)) }

/// Pick coins for `amount` to a recipient script of `recipient_len` bytes, or everything for
/// `amount = None` ("send all", no change). Confirmed coins are preferred; unconfirmed ones (our own
/// unconfirmed change, incoming payments in the mempool) only when the confirmed ones are not enough.
pub fn select(kind: Kind, coins: &[(u64, bool)], amount: Option<u64>, recipient_len: u64, rate_kvb: u64) -> Result<Selection, String> {
    let in_fee = fee_for(input_vbytes(kind), rate_kvb);
    let usable: Vec<usize> = (0..coins.len()).filter(|&i| coins[i].0 > in_fee).collect();
    let Some(amount) = amount else {
        if usable.is_empty() { return Err("nothing to send: every coin is worth less than the fee to spend it".into()); }
        let vs = vsize(weight(kind, usable.len(), &[recipient_len]));
        let fee = fee_for(vs, rate_kvb);
        let total: u64 = usable.iter().map(|&i| coins[i].0).sum();
        if total < fee + RECIPIENT_DUST { return Err("the balance does not cover the fee at this rate".into()); }
        return Ok(Selection { picked: usable, change: 0, fee, vsize: vs });
    };
    if amount < RECIPIENT_DUST { return Err(format!("amount below {RECIPIENT_DUST} sat is dust: nodes won't relay it")); }
    let no_change = |n: usize| vsize(weight(kind, n, &[recipient_len]));
    let with_change = |n: usize| vsize(weight(kind, n, &[recipient_len, kind.script_len()]));
    let change_cost = fee_for(with_change(1) - no_change(1), rate_kvb) + in_fee; // create it now + spend it later
    // 1. branch and bound over confirmed coins, then all: a set whose effective value lands within
    //    `change_cost` above the target needs no change output (the small excess goes to the fee).
    for pool in [usable.iter().copied().filter(|&i| coins[i].1).collect::<Vec<_>>(), usable.clone()] {
        if let Some(picked) = bnb(&pool, coins, amount, in_fee, change_cost, |n| fee_for(no_change(n) - n as u64 * input_vbytes(kind), rate_kvb)) {
            let vs = no_change(picked.len());
            let total: u64 = picked.iter().map(|&i| coins[i].0).sum();
            return Ok(Selection { fee: total - amount, picked, change: 0, vsize: vs });
        }
    }
    // 2. largest first (confirmed before unconfirmed), with change; too-small change goes to the fee.
    let mut order = usable.clone();
    order.sort_by(|&a, &b| coins[b].1.cmp(&coins[a].1).then(coins[b].0.cmp(&coins[a].0)));
    let floor = min_change(kind, rate_kvb);
    let mut picked = Vec::new();
    let mut total = 0u64;
    for i in order {
        picked.push(i);
        total += coins[i].0;
        let fee_c = fee_for(with_change(picked.len()), rate_kvb);
        if total >= amount + fee_c + floor { return Ok(Selection { change: total - amount - fee_c, fee: fee_c, vsize: with_change(picked.len()), picked }); }
        let fee_n = fee_for(no_change(picked.len()), rate_kvb);
        if total >= amount + fee_n {
            // enough without change, but not for a change output worth keeping: the rest is fee
            // (bounded: less than the cost of a change output plus the minimum change).
            return Ok(Selection { change: 0, fee: total - amount, vsize: no_change(picked.len()), picked });
        }
    }
    let have: u64 = usable.iter().map(|&i| coins[i].0).sum();
    Err(format!("not enough bitcoin: {} BTC plus the fee needed, {} BTC spendable", format_btc(amount), format_btc(have)))
}

/// Depth-first search for a subset with target ≤ Σ effective value ≤ target + window (Bitcoin
/// Core's branch and bound, without the waste metric: the first fit with the least excess found
/// within the try budget wins).
fn bnb(pool: &[usize], coins: &[(u64, bool)], amount: u64, in_fee: u64, window: u64, base_fee: impl Fn(usize) -> u64) -> Option<Vec<usize>> {
    let mut eff: Vec<(usize, u64)> = pool.iter().map(|&i| (i, coins[i].0 - in_fee)).collect();
    eff.sort_by_key(|e| std::cmp::Reverse(e.1));
    if eff.is_empty() || eff.len() > 64 { return None; }
    let target = amount + base_fee(1); // the fixed part of the fee (version, counts, outputs)
    let mut best: Option<(u64, Vec<usize>)> = None;
    let mut tries = 0u32;
    let mut remaining: Vec<u64> = vec![0; eff.len() + 1];
    for i in (0..eff.len()).rev() { remaining[i] = remaining[i + 1] + eff[i].1; }
    #[allow(clippy::too_many_arguments)]
    fn go(i: usize, sum: u64, chosen: &mut Vec<usize>, eff: &[(usize, u64)], remaining: &[u64], target: u64, window: u64, best: &mut Option<(u64, Vec<usize>)>, tries: &mut u32) {
        *tries += 1;
        if *tries > 100_000 { return; }
        if sum > target + window { return; }
        if sum >= target {
            let excess = sum - target;
            if best.as_ref().is_none_or(|b| excess < b.0) { *best = Some((excess, chosen.clone())); }
            return;
        }
        if i == eff.len() || sum + remaining[i] < target { return; }
        chosen.push(eff[i].0);
        go(i + 1, sum + eff[i].1, chosen, eff, remaining, target, window, best, tries);
        chosen.pop();
        if best.as_ref().is_some_and(|b| b.0 == 0) { return; }
        go(i + 1, sum, chosen, eff, remaining, target, window, best, tries);
    }
    go(0, 0, &mut Vec::new(), &eff, &remaining, target, window, &mut best, &mut tries);
    best.map(|b| b.1)
}

/// Random order without a dependency: Fisher-Yates over the system RNG (ring is in the tree).
pub fn shuffle<T>(v: &mut [T]) {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    for i in (1..v.len()).rev() {
        let mut b = [0u8; 4];
        if rng.fill(&mut b).is_err() { return; }
        let j = (u32::from_le_bytes(b) as usize) % (i + 1);
        v.swap(i, j);
    }
}

/// Assemble the unsigned PSBT for a selection. `shuffle_order` is false only in tests.
#[allow(clippy::too_many_arguments)]
pub fn build(account: &Account, inputs: Vec<Coin>, recipient: Address, amount: u64, change: Option<(Derived, u64)>, fee: u64, rate_kvb: u64, vsize_est: u64, shuffle_order: bool) -> Result<Built, String> {
    if inputs.is_empty() { return Err("no inputs".into()); }
    if inputs.len() > MAX_INPUTS { return Err(format!("this would spend {} coins; the phone takes at most {MAX_INPUTS} per transaction. Send a smaller amount first", inputs.len())); }
    let mut inputs = inputs;
    let mut outputs = vec![Out { address: recipient.clone(), value: amount, change: None }];
    if let Some((d, v)) = change { outputs.push(Out { address: d.address.clone(), value: v, change: Some(d) }); }
    if shuffle_order { shuffle(&mut inputs); shuffle(&mut outputs); }
    let in_total: u64 = inputs.iter().map(|c| c.value).sum();
    let out_total: u64 = outputs.iter().map(|o| o.value).sum();
    if in_total != out_total + fee { return Err("internal: inputs ≠ outputs + fee".into()); }
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs.iter().map(|c| TxIn { previous_output: c.outpoint, script_sig: ScriptBuf::new(), sequence: Sequence(RBF_SEQUENCE), witness: Witness::new() }).collect(),
        output: outputs.iter().map(|o| TxOut { value: Amount::from_sat(o.value), script_pubkey: o.address.script_pubkey() }).collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| e.to_string())?;
    let fp = account.fingerprint;
    for (i, c) in inputs.iter().enumerate() {
        let inp = &mut psbt.inputs[i];
        inp.witness_utxo = Some(TxOut { value: Amount::from_sat(c.value), script_pubkey: c.derived.script.clone() });
        match account.kind {
            Kind::P2wpkh => { inp.bip32_derivation = BTreeMap::from([(c.derived.pubkey, (fp, c.derived.origin.clone()))]); }
            Kind::P2tr => {
                let x = c.derived.internal_key.ok_or("internal: no internal key")?;
                inp.tap_internal_key = Some(x);
                inp.tap_key_origins = BTreeMap::from([(x, (vec![], (fp, c.derived.origin.clone())))]);
            }
        }
    }
    for (i, o) in outputs.iter().enumerate() {
        let Some(d) = &o.change else { continue };
        let out = &mut psbt.outputs[i];
        match account.kind {
            Kind::P2wpkh => { out.bip32_derivation = BTreeMap::from([(d.pubkey, (fp, d.origin.clone()))]); }
            Kind::P2tr => {
                let x = d.internal_key.ok_or("internal: no internal key")?;
                out.tap_internal_key = Some(x);
                out.tap_key_origins = BTreeMap::from([(x, (vec![], (fp, d.origin.clone())))]);
            }
        }
    }
    // Full previous transactions for every P2WPKH input: the phone requires them (it checks each
    // input's amount against the txid it spends, so a lying server cannot inflate the fee). They
    // were fetched and hashed to their txids when the coins were listed (btc::checked_coin); they
    // are checked again here, and a coin without one is refused rather than sent without it.
    if account.kind == Kind::P2wpkh {
        for (i, c) in inputs.iter().enumerate() {
            let prev = c.prev_tx.as_ref().ok_or("internal: a coin's previous transaction is missing; refresh the wallet and try again")?;
            if prev.compute_txid() != c.outpoint.txid { return Err("a coin's previous transaction does not hash to the txid it spends".into()); }
            let out = prev.output.get(c.outpoint.vout as usize).ok_or("a coin's previous transaction does not have its output")?;
            if out.value.to_sat() != c.value || out.script_pubkey != c.derived.script { return Err("a coin's previous transaction does not pay it the listed amount".into()); }
            if prev.input.len() > MAX_PREV_IO || prev.output.len() > MAX_PREV_IO {
                return Err(format!("the coin {}:{} comes from a transaction with more than {MAX_PREV_IO} inputs or outputs, which the phone cannot check; spend other coins (send a smaller amount)", c.outpoint.txid, c.outpoint.vout));
            }
            psbt.inputs[i].non_witness_utxo = Some(prev.clone());
        }
    }
    let size = psbt.serialize().len();
    if size > MAX_PSBT_BYTES {
        return Err(format!("this transaction is too large for one request to the phone ({} KiB with the previous transactions the phone needs, at most {} KiB); send a smaller amount first, so fewer coins are spent", size.div_ceil(1024), MAX_PSBT_BYTES / 1024));
    }
    Ok(Built { account: account.clone(), psbt, inputs, outputs, recipient, amount, fee, rate_kvb, vsize: vsize_est, replaces: None })
}

/// Plan and build a send in one step.
pub fn plan(account: &Account, coins: Vec<Coin>, recipient: Address, amount: Option<u64>, change: Derived, rate_kvb: u64, shuffle_order: bool) -> Result<Built, String> {
    let values: Vec<(u64, bool)> = coins.iter().map(|c| (c.value, c.confirmed)).collect();
    let sel = select(account.kind, &values, amount, recipient.script_pubkey().len() as u64, rate_kvb)?;
    let total: u64 = sel.picked.iter().map(|&i| coins[i].value).sum();
    let send = amount.unwrap_or(total - sel.fee);
    let inputs: Vec<Coin> = sel.picked.iter().map(|&i| coins[i].clone()).collect();
    let change = (sel.change > 0).then_some((change, sel.change));
    build(account, inputs, recipient, send, change, sel.fee, rate_kvb, sel.vsize, shuffle_order)
}

/// Speed up (RBF, BIP-125) a transaction this Mac built: same inputs and recipient, the extra fee
/// taken from the change output. The new fee pays the new rate on the whole transaction and at
/// least 1 sat/vB more than the old absolute fee (BIP-125 rules 3 and 4).
pub fn bump(old: &Built, rate_kvb: u64) -> Result<Built, String> {
    let ch = old.change().ok_or("this transaction has no change output to take a higher fee from (a \"send all\" can't be sped up here)")?;
    let new_fee = fee_for(old.vsize, rate_kvb).max(old.fee + old.vsize);
    let extra = new_fee.saturating_sub(old.fee);
    if ch.value < extra + min_change(old.account.kind, rate_kvb) { return Err("the change is too small to pay that fee".into()); }
    let change_d = ch.change.clone().ok_or("internal")?;
    let mut b = build(&old.account, old.inputs.clone(), old.recipient.clone(), old.amount, Some((change_d, ch.value - extra)), new_fee, rate_kvb, old.vsize, true)?;
    b.replaces = Some(old.psbt.unsigned_tx.compute_txid().to_string());
    Ok(b)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::btc::wallet::{test_account, Net};
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;
    use std::str::FromStr;

    /// A coin paying `value` to `d`, with a previous transaction that really contains it.
    pub fn coin(d: &Derived, value: u64, n: u8) -> Coin {
        let prev = Transaction {
            version: Version::TWO, lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_byte_array([n; 32]), vout: 0 }, ..Default::default() }],
            output: vec![TxOut { value: Amount::from_sat(1234), script_pubkey: ScriptBuf::new() }, TxOut { value: Amount::from_sat(value), script_pubkey: d.script.clone() }],
        };
        Coin { outpoint: OutPoint { txid: prev.compute_txid(), vout: 1 }, value, derived: d.clone(), confirmed: true, prev_tx: Some(prev) }
    }

    #[test]
    fn sizes_match_real_transactions() {
        // 1-in 2-out P2WPKH: 141 vB with 72-byte signatures (the well-known 140.5 → 141)
        assert_eq!(vsize(weight(Kind::P2wpkh, 1, &[22, 22])), 141);
        // 1-in 1-out P2TR key path: 111 vB
        assert_eq!(vsize(weight(Kind::P2tr, 1, &[34])), 111);
        // 2-in 2-out P2TR: 211 vB
        assert_eq!(vsize(weight(Kind::P2tr, 2, &[34, 34])), 212);
        assert_eq!(fee_for(141, 1000), 141);
        assert_eq!(fee_for(141, 12_500), 1763); // 1762.5 rounds up
    }

    #[test]
    fn amounts_and_rates_parse_exactly() {
        assert_eq!(parse_btc("0.0005").unwrap(), 50_000);
        assert_eq!(parse_btc("1").unwrap(), 100_000_000);
        assert_eq!(parse_btc(".5").unwrap(), 50_000_000);
        assert_eq!(parse_btc("0.00000001").unwrap(), 1);
        for bad in ["", ".", "1e3", "-1", "0.000000001", "1,5", "21000001"] { assert!(parse_btc(bad).is_err(), "{bad}"); }
        assert_eq!(format_btc(50_000), "0.0005");
        assert_eq!(format_btc(100_000_000), "1");
        assert_eq!(format_btc(0), "0");
        assert_eq!(parse_rate("12").unwrap(), 12_000);
        assert_eq!(parse_rate("3.5").unwrap(), 3_500);
        assert_eq!(parse_rate("0.1").unwrap(), 100);
        for bad in ["0.05", "2001", "abc", "", "1.2345", "-3"] { assert!(parse_rate(bad).is_err(), "{bad}"); }
    }

    #[test]
    fn selection_finds_an_exact_match_without_change() {
        // 100k + 50k + 30k; sending 80_000 at 1 sat/vB: 50k + 30k minus fees can't reach it,
        // 100k alone overshoots by more than a change output costs → largest-first with change.
        let coins = [(100_000, true), (50_000, true), (30_000, true)];
        let s = select(Kind::P2wpkh, &coins, Some(80_000), 22, 1000).unwrap();
        assert_eq!(s.picked, vec![0]);
        assert_eq!(s.change, 100_000 - 80_000 - s.fee);
        assert_eq!(s.vsize, 141);
        // an amount that 50k + 30k cover exactly (minus a 2-in-1-out fee of 178 sat): no change
        let s = select(Kind::P2wpkh, &coins, Some(80_000 - 178), 22, 1000).unwrap();
        assert_eq!((s.change, s.fee), (0, 178));
        let mut p = s.picked.clone(); p.sort();
        assert_eq!(p, vec![1, 2]);
    }

    #[test]
    fn selection_avoids_dust_change_and_prefers_confirmed() {
        // 10_500 sat for 10_000 at 2 sat/vB: change would be ~200 sat → none; the excess is fee.
        let s = select(Kind::P2wpkh, &[(10_500, true)], Some(10_000), 22, 2000).unwrap();
        assert_eq!(s.change, 0);
        assert_eq!(s.fee, 500);
        // the unconfirmed coin is used only when the confirmed one is not enough
        let s = select(Kind::P2wpkh, &[(500_000, false), (300_000, true)], Some(100_000), 22, 1000).unwrap();
        assert_eq!(s.picked, vec![1]);
        let s = select(Kind::P2wpkh, &[(500_000, false), (300_000, true)], Some(400_000), 22, 1000).unwrap();
        assert!(s.picked.contains(&0));
        // not enough
        assert!(select(Kind::P2wpkh, &[(5_000, true)], Some(10_000), 22, 1000).unwrap_err().contains("not enough"));
        // dust amounts refused
        assert!(select(Kind::P2wpkh, &[(5_000, true)], Some(100), 22, 1000).is_err());
        // coins worth less than their spend cost are ignored
        let s = select(Kind::P2wpkh, &[(60, true), (50_000, true)], Some(20_000), 22, 1000).unwrap();
        assert_eq!(s.picked, vec![1]);
    }

    #[test]
    fn send_all_spends_everything_without_change() {
        let s = select(Kind::P2tr, &[(40_000, true), (25_000, false)], None, 34, 5000).unwrap();
        assert_eq!(s.picked.len(), 2);
        assert_eq!(s.change, 0);
        assert_eq!(s.fee, fee_for(vsize(weight(Kind::P2tr, 2, &[34])), 5000));
    }

    #[test]
    fn psbt_carries_origins_utxos_and_rbf() {
        for kind in [Kind::P2wpkh, Kind::P2tr] {
            let (a, _) = test_account(Net::Bitcoin, kind, 1);
            let coins = vec![coin(&a.derive(0, 0).unwrap(), 120_000, 1), coin(&a.derive(0, 3).unwrap(), 30_000, 2)];
            let to = Address::from_str("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g").unwrap().assume_checked();
            let b = plan(&a, coins, to.clone(), Some(100_000), a.derive(1, 0).unwrap(), 2_000, false).unwrap();
            let tx = &b.psbt.unsigned_tx;
            assert_eq!(tx.version, Version::TWO);
            assert!(tx.input.iter().all(|i| i.sequence.0 == RBF_SEQUENCE && i.sequence.is_rbf()));
            assert_eq!(b.input_total(), tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>() + b.fee);
            assert_eq!(tx.output[0].script_pubkey, to.script_pubkey());
            assert_eq!(tx.output[0].value.to_sat(), 100_000);
            let ch = b.change().unwrap();
            assert_eq!(ch.address, a.derive(1, 0).unwrap().address);
            for (i, inp) in b.psbt.inputs.iter().enumerate() {
                assert_eq!(inp.witness_utxo.as_ref().unwrap().script_pubkey, b.inputs[i].derived.script);
                match kind {
                    Kind::P2wpkh => {
                        assert_eq!(inp.bip32_derivation.values().next().unwrap(), &(a.fingerprint, b.inputs[i].derived.origin.clone()));
                        assert!(inp.non_witness_utxo.is_some());
                        assert!(inp.tap_key_origins.is_empty());
                    }
                    Kind::P2tr => {
                        assert_eq!(inp.tap_internal_key, b.inputs[i].derived.internal_key);
                        assert!(inp.tap_key_origins.values().next().unwrap().0.is_empty());
                        assert!(inp.non_witness_utxo.is_none() && inp.bip32_derivation.is_empty());
                    }
                }
            }
            let ci = b.outputs.iter().position(|o| o.change.is_some()).unwrap();
            assert!(!b.psbt.outputs[ci].bip32_derivation.is_empty() || !b.psbt.outputs[ci].tap_key_origins.is_empty());
            let ri = 1 - ci;
            assert!(b.psbt.outputs[ri].bip32_derivation.is_empty() && b.psbt.outputs[ri].tap_key_origins.is_empty(), "the recipient carries no origin");
            // round trip through the wire format
            assert_eq!(Psbt::deserialize(&b.psbt.serialize()).unwrap(), b.psbt);
        }
    }

    /// `c` re-pointed at a previous transaction with `extra` more outputs before its own.
    fn with_big_prev(mut c: Coin, extra: usize) -> Coin {
        let mut prev = c.prev_tx.clone().unwrap();
        let own = prev.output[c.outpoint.vout as usize].clone();
        prev.output = (0..extra).map(|_| TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::from_bytes(vec![0x51; 22]) }).chain([own]).collect();
        c.outpoint = OutPoint { txid: prev.compute_txid(), vout: extra as u32 };
        c.prev_tx = Some(prev);
        c
    }

    #[test]
    fn every_p2wpkh_input_carries_its_previous_transaction() {
        let (a, _) = test_account(Net::Bitcoin, Kind::P2wpkh, 1);
        let d = a.derive(0, 0).unwrap();
        // a large previous transaction is included, not dropped
        let c = with_big_prev(coin(&d, 200_000, 7), 900);
        let b = plan(&a, vec![c.clone(), coin(&d, 30_000, 8)], d.address.clone(), Some(210_000), a.derive(1, 0).unwrap(), 1000, false).unwrap();
        assert!(b.psbt.inputs.iter().all(|i| i.non_witness_utxo.is_some()));
        for (i, inp) in b.psbt.inputs.iter().enumerate() {
            assert_eq!(inp.non_witness_utxo.as_ref().unwrap().compute_txid(), b.psbt.unsigned_tx.input[i].previous_output.txid);
        }
        assert!(b.psbt.serialize().len() > 22_000, "bigger than the old cap, still sent");
        assert!(b.psbt.serialize().len() <= MAX_PSBT_BYTES);

        let build1 = |c: Coin| plan(&a, vec![c], d.address.clone(), Some(50_000), a.derive(1, 0).unwrap(), 1000, false);
        // missing, or not the transaction the coin spends, or not paying it: refused
        let mut missing = coin(&d, 200_000, 7); missing.prev_tx = None;
        assert!(build1(missing).unwrap_err().contains("missing"));
        let mut other = coin(&d, 200_000, 7); other.prev_tx = coin(&d, 200_000, 9).prev_tx;
        assert!(build1(other).unwrap_err().contains("does not hash"));
        let mut lying = coin(&d, 200_000, 7); lying.value = 300_000;
        assert!(plan(&a, vec![lying], d.address.clone(), Some(250_000), a.derive(1, 0).unwrap(), 1000, false).unwrap_err().contains("listed amount"));
        // more than the phone parses in a previous transaction: refused with a reason
        assert!(build1(with_big_prev(coin(&d, 200_000, 7), MAX_PREV_IO)).unwrap_err().contains("cannot check"));
        // and a PSBT over the phone's request size: refused, never truncated
        let huge: Vec<Coin> = (0..8u8).map(|n| with_big_prev(coin(&d, 100_000, n), 1_200)).collect();
        let e = plan(&a, huge, d.address.clone(), Some(750_000), a.derive(1, 0).unwrap(), 1000, false).unwrap_err();
        assert!(e.contains("too large for one request"), "{e}");
        // Taproot inputs carry none (BIP-341 signs the amounts of all inputs)
        let (t, _) = test_account(Net::Bitcoin, Kind::P2tr, 1);
        let td = t.derive(0, 0).unwrap();
        let mut tc = coin(&td, 200_000, 7); tc.prev_tx = None;
        let b = plan(&t, vec![tc], td.address.clone(), Some(50_000), t.derive(1, 0).unwrap(), 1000, false).unwrap();
        assert!(b.psbt.inputs[0].non_witness_utxo.is_none());
    }

    #[test]
    fn size_limits_fit_the_phone_and_the_way_back() {
        // phone: PSBT ≤ 200 KiB, btcSignPsbt line ≤ 288 KiB (AccessoryTransport / Psbt.java)
        assert!(MAX_PSBT_BYTES <= 200 * 1024);
        let line = r#"{"id":"00000000-0000-0000-0000-000000000000","method":"btcSignPsbt","network":"testnet4","psbt":""}"#.len() + MAX_PSBT_BYTES.div_ceil(3) * 4 + 1;
        assert!(line <= 288 * 1024, "{line}");
        assert!(line <= crate::btc::MAX_REQUEST_BYTES);
        // back: the PSBT plus up to ~110 bytes of signature per input, as base64, in one USB response
        let back = (MAX_PSBT_BYTES + MAX_INPUTS * 120).div_ceil(3) * 4;
        assert!(back <= crate::btc::verify::MAX_RESPONSE_PSBT);
        assert!(back + 200 <= crate::aoa::MAX_PSBT_RESPONSE_BYTES);
    }

    #[test]
    fn rbf_bump_takes_the_fee_from_change() {
        let (a, _) = test_account(Net::Bitcoin, Kind::P2wpkh, 1);
        let to = Address::from_str("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g").unwrap().assume_checked();
        let b = plan(&a, vec![coin(&a.derive(0, 0).unwrap(), 120_000, 1)], to, Some(50_000), a.derive(1, 0).unwrap(), 2_000, false).unwrap();
        let n = bump(&b, 10_000).unwrap();
        assert_eq!(n.amount, 50_000);
        assert_eq!(n.inputs.len(), 1);
        assert_eq!(n.inputs[0].outpoint, b.inputs[0].outpoint);
        assert!(n.fee >= b.fee + b.vsize && n.fee >= fee_for(b.vsize, 10_000));
        assert_eq!(n.change().unwrap().value, b.change().unwrap().value - (n.fee - b.fee));
        assert_eq!(n.replaces.as_deref(), Some(b.psbt.unsigned_tx.compute_txid().to_string().as_str()));
        // send-all: nothing to take it from
        let all = plan(&a, vec![coin(&a.derive(0, 0).unwrap(), 120_000, 1)], a.derive(0, 5).unwrap().address, None, a.derive(1, 0).unwrap(), 2_000, false).unwrap();
        assert!(bump(&all, 10_000).is_err());
    }
}
