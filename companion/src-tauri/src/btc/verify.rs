//! What the phone returns is checked here before anything can be broadcast. The phone is trusted
//! to show the user what it signs; this Mac does not trust the phone's answer, the USB link or
//! the server, so the signed PSBT must prove, on its own:
//!
//! 1. **Same transaction.** The returned PSBT's unsigned transaction is byte-for-byte the one this
//!    Mac built (inputs, sequences, outputs, amounts, version, locktime). So the recipient, the
//!    amount, the change and the fee (Σ inputs − Σ outputs, with input amounts from this Mac's own
//!    records, never from the returned PSBT) are exactly what the user reviewed. Any
//!    `witness_utxo` the phone echoes must also be unchanged.
//! 2. **Our keys, valid signatures.** Each input has exactly one signature, by the key this Mac
//!    derives from the paired xpub for that input (P2WPKH: the BIP-32 child key; P2TR: its BIP-86
//!    tweaked output key, which must also be the key in the spent scriptPubKey). The ECDSA
//!    signature is checked against the BIP-143 sighash, the Schnorr signature against the BIP-341
//!    key-spend sighash over all prevouts; only SIGHASH_ALL (or DEFAULT for Taproot) is accepted.
//! 3. **Consensus.** The finalized transaction (witnesses assembled here from the checked
//!    signatures, not copied from the phone) is run through Bitcoin Core's script interpreter
//!    (`bitcoinconsensus`, with the spent outputs, Taproot included) for every input.
//!
//! Only a transaction that passes all three is kept (by txid) for the Broadcast click.

use super::tx::Built;
use super::wallet::{Account, Kind};
use base64::Engine;
use bitcoin::ecdsa;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{consensus, taproot, Amount, Transaction, Witness};

/// A signed transaction that passed every check.
#[derive(Clone, Debug)]
pub struct Verified {
    pub txid: String,
    pub hex: String,
    pub fee: u64,
    pub vsize: u64,
}

/// Base64 characters of the signed PSBT the phone returns (tx::MAX_PSBT_BYTES plus signatures).
pub(crate) const MAX_RESPONSE_PSBT: usize = 260 * 1024;

/// Strict parse of a btcSignPsbt answer → the base64 PSBT, or why there is none.
pub fn parse_sign_response(request: &serde_json::Value, response: &serde_json::Value) -> Result<String, String> {
    let obj = response.as_object().ok_or("malformed response")?;
    if obj.get("id") != request.get("id") { return Err("the phone's answer is for a different request".into()); }
    match obj.get("status").and_then(|v| v.as_str()) {
        Some("approved") => {}
        Some("rejected") => return Err("rejected on the phone".into()),
        Some("error") => return Err(format!("phone error: {}", obj.get("error").and_then(|v| v.as_str()).unwrap_or("unknown"))),
        _ => return Err("malformed response status".into()),
    }
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort();
    if keys != ["id", "psbt", "status"] { return Err("approved response has unexpected fields".into()); }
    Ok(obj["psbt"].as_str().ok_or("psbt must be a string")?.to_string())
}

pub fn psbt_base64(p: &Psbt) -> String { base64::engine::general_purpose::STANDARD.encode(p.serialize()) }

fn differences(a: &Transaction, b: &Transaction) -> String {
    let mut d = Vec::new();
    if a.version != b.version { d.push("version".to_string()); }
    if a.lock_time != b.lock_time { d.push("locktime".into()); }
    if a.input.len() != b.input.len() { d.push("number of inputs".into()); }
    else if a.input.iter().zip(&b.input).any(|(x, y)| x.previous_output != y.previous_output) { d.push("inputs".into()); }
    else if a.input.iter().zip(&b.input).any(|(x, y)| x.sequence != y.sequence) { d.push("sequence (RBF)".into()); }
    if a.output.len() != b.output.len() { d.push("number of outputs".into()); }
    else {
        for (i, (x, y)) in a.output.iter().zip(&b.output).enumerate() {
            if x.script_pubkey != y.script_pubkey { d.push(format!("output {i} address")); }
            if x.value != y.value { d.push(format!("output {i} amount (so the fee too)")); }
        }
    }
    if d.is_empty() { "unsigned transaction".into() } else { d.join(", ") }
}

/// Check the phone's signed PSBT against what was built, and finalize it.
pub fn verify_signed(built: &Built, returned_b64: &str) -> Result<Verified, String> {
    if returned_b64.len() > MAX_RESPONSE_PSBT { return Err("signed PSBT is too large".into()); }
    let bytes = base64::engine::general_purpose::STANDARD.decode(returned_b64.trim()).map_err(|_| "signed PSBT is not base64".to_string())?;
    let ret = Psbt::deserialize(&bytes).map_err(|e| format!("signed PSBT does not parse: {e}"))?;
    let expected = &built.psbt.unsigned_tx;
    // 1. the same transaction, field for field
    if ret.unsigned_tx != *expected { return Err(format!("the phone returned a different transaction ({} changed)", differences(expected, &ret.unsigned_tx))); }
    if ret.inputs.len() != built.inputs.len() || built.inputs.len() != expected.input.len() { return Err("input count mismatch".into()); }
    let prevouts = built.prevouts();
    for (i, c) in built.inputs.iter().enumerate() {
        if expected.input[i].previous_output != c.outpoint { return Err("internal: input order".into()); }
        if let Some(w) = &ret.inputs[i].witness_utxo { if *w != prevouts[i] { return Err(format!("input {i}: the phone changed the spent amount or script")); } }
    }
    let in_total: u64 = built.inputs.iter().map(|c| c.value).sum();
    let out_total: u64 = expected.output.iter().map(|o| o.value.to_sat()).sum();
    let fee = in_total.checked_sub(out_total).ok_or("outputs exceed inputs")?;
    if fee != built.fee { return Err(format!("fee is {fee} sat, expected {} sat", built.fee)); }
    if built.outputs.iter().zip(&expected.output).any(|(o, t)| o.value != t.value.to_sat() || o.address.script_pubkey() != t.script_pubkey) { return Err("internal: outputs".into()); }

    // 2. one valid signature per input, by our key, SIGHASH_ALL/DEFAULT
    let secp = Secp256k1::verification_only();
    let mut cache = SighashCache::new(expected);
    let mut witnesses = Vec::with_capacity(built.inputs.len());
    for (i, c) in built.inputs.iter().enumerate() {
        let inp = &ret.inputs[i];
        let value = Amount::from_sat(c.value);
        let w = match built.account.kind {
            Kind::P2wpkh => {
                if !inp.tap_script_sigs.is_empty() || inp.tap_key_sig.is_some() { return Err(format!("input {i}: unexpected Taproot signature")); }
                let ours = bitcoin::PublicKey::new(c.derived.pubkey);
                let sig: ecdsa::Signature = match (&inp.final_script_witness, inp.partial_sigs.len()) {
                    (Some(fw), 0) => {
                        let items: Vec<&[u8]> = fw.iter().collect();
                        if items.len() != 2 || items[1] != ours.to_bytes().as_slice() { return Err(format!("input {i}: final witness is not for this wallet's key")); }
                        ecdsa::Signature::from_slice(items[0]).map_err(|e| format!("input {i}: {e}"))?
                    }
                    (None, 1) => *inp.partial_sigs.get(&ours).ok_or_else(|| format!("input {i}: signed by a key that is not this wallet's"))?,
                    (None, 0) => return Err(format!("input {i} is not signed")),
                    _ => return Err(format!("input {i}: more than one signature")),
                };
                if sig.sighash_type != EcdsaSighashType::All { return Err(format!("input {i}: sighash type {} is not SIGHASH_ALL", sig.sighash_type)); }
                let sighash = cache.p2wpkh_signature_hash(i, &c.derived.script, value, EcdsaSighashType::All).map_err(|e| e.to_string())?;
                secp.verify_ecdsa(&Message::from_digest(sighash.to_byte_array_compat()), &sig.signature, &c.derived.pubkey)
                    .map_err(|_| format!("input {i}: the signature does not verify for this wallet's key"))?;
                Witness::p2wpkh(&sig, &c.derived.pubkey)
            }
            Kind::P2tr => {
                if !inp.partial_sigs.is_empty() || !inp.tap_script_sigs.is_empty() { return Err(format!("input {i}: unexpected signature kind")); }
                let sig: taproot::Signature = match (&inp.final_script_witness, inp.tap_key_sig) {
                    (Some(fw), None) => {
                        let items: Vec<&[u8]> = fw.iter().collect();
                        if items.len() != 1 { return Err(format!("input {i}: final witness is not a key-path spend")); }
                        taproot::Signature::from_slice(items[0]).map_err(|e| format!("input {i}: {e}"))?
                    }
                    (None, Some(s)) => s,
                    (None, None) => return Err(format!("input {i} is not signed")),
                    _ => return Err(format!("input {i}: two signatures")),
                };
                if !matches!(sig.sighash_type, TapSighashType::Default | TapSighashType::All) { return Err(format!("input {i}: sighash type {} is not SIGHASH_DEFAULT/ALL", sig.sighash_type)); }
                let internal = c.derived.internal_key.ok_or("internal: no internal key")?;
                let output_key = Account::output_key(&secp, internal);
                // the spent script is OP_1 <output key>: the key we check against is the one that locks the coin
                if c.derived.script.as_bytes().get(2..) != Some(&output_key.serialize()[..]) { return Err(format!("input {i}: internal key does not match the spent script")); }
                let sighash = cache.taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), sig.sighash_type).map_err(|e| e.to_string())?;
                secp.verify_schnorr(&sig.signature, &Message::from_digest(sighash.to_byte_array_compat()), &output_key)
                    .map_err(|_| format!("input {i}: the signature does not verify for this wallet's key"))?;
                Witness::p2tr_key_spend(&sig)
            }
        };
        witnesses.push(w);
    }

    // 3. finalize from what was checked, then let Bitcoin Core's interpreter run every input
    let mut tx = expected.clone();
    for (i, w) in witnesses.into_iter().enumerate() { tx.input[i].witness = w; }
    consensus_check(&tx, &prevouts)?;
    let weight = tx.weight().to_wu();
    let vsize = weight.div_ceil(4);
    if vsize > built.vsize { return Err(format!("signed transaction is {vsize} vB, larger than the {} vB it was priced for", built.vsize)); }
    Ok(Verified { txid: tx.compute_txid().to_string(), hex: consensus::encode::serialize_hex(&tx), fee, vsize })
}

/// libbitcoinconsensus (Bitcoin Core 26) over every input, with all spent outputs (needed for Taproot).
pub fn consensus_check(tx: &Transaction, prevouts: &[bitcoin::TxOut]) -> Result<(), String> {
    let bytes = consensus::encode::serialize(tx);
    let scripts: Vec<Vec<u8>> = prevouts.iter().map(|p| p.script_pubkey.to_bytes()).collect();
    let utxos: Vec<bitcoinconsensus::Utxo> = prevouts.iter().zip(&scripts).map(|(p, s)| bitcoinconsensus::Utxo {
        script_pubkey: s.as_ptr(), script_pubkey_len: s.len() as u32, value: p.value.to_sat() as i64,
    }).collect();
    let flags = bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT | bitcoinconsensus::VERIFY_TAPROOT;
    for (i, p) in prevouts.iter().enumerate() {
        bitcoinconsensus::verify_with_flags(&scripts[i], p.value.to_sat(), &bytes, Some(&utxos), i, flags)
            .map_err(|e| format!("input {i} fails consensus script verification ({e:?})"))?;
    }
    Ok(())
}

/// `to_byte_array` for both sighash types, without importing the hashes trait at every call site.
trait ByteArray { fn to_byte_array_compat(self) -> [u8; 32]; }
impl ByteArray for bitcoin::sighash::SegwitV0Sighash { fn to_byte_array_compat(self) -> [u8; 32] { use bitcoin::hashes::Hash; self.to_byte_array() } }
impl ByteArray for bitcoin::sighash::TapSighash { fn to_byte_array_compat(self) -> [u8; 32] { use bitcoin::hashes::Hash; self.to_byte_array() } }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc::tx::{plan, tests::coin};
    use crate::btc::wallet::{tests::account as test_account, Net};
    use bitcoin::bip32::Xpriv;
    use bitcoin::{Address, TxOut};
    use std::str::FromStr;

    /// The verified transaction itself, decoded from its hex.
    fn signed_tx(v: &Verified) -> Transaction { consensus::encode::deserialize_hex(&v.hex).unwrap() }

    fn built(kind: Kind) -> (Built, Xpriv) {
        let (a, master) = test_account(Net::Bitcoin, kind, 1);
        let coins = vec![coin(&a.derive(0, 0).unwrap(), 120_000, 1), coin(&a.derive(0, 4).unwrap(), 30_000, 2), coin(&a.derive(1, 2).unwrap(), 45_000, 3)];
        let to = Address::from_str("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g").unwrap().assume_checked();
        (plan(&a, coins, to, Some(180_000), a.derive(1, 7).unwrap(), 3_000, true).unwrap(), master)
    }

    /// The phone's part: sign the PSBT as given (rust-bitcoin's BIP-32 signer, like the app's).
    fn phone_sign(p: &Psbt, key: &Xpriv) -> Psbt {
        let mut p = p.clone();
        p.sign(key, &Secp256k1::new()).expect("signs");
        p
    }

    fn other_key() -> Xpriv { Xpriv::new_master(bitcoin::NetworkKind::Main, &[7u8; 32]).unwrap() }

    #[test]
    fn honest_signatures_verify_and_finalize() {
        for kind in [Kind::P2wpkh, Kind::P2tr] {
            let (b, key) = built(kind);
            assert!(b.inputs.len() >= 2, "multi-input case");
            let signed = phone_sign(&b.psbt, &key);
            let v = verify_signed(&b, &psbt_base64(&signed)).unwrap();
            assert_eq!(v.fee, b.fee);
            assert_eq!(v.txid, b.psbt.unsigned_tx.compute_txid().to_string(), "segwit: txid fixed before signing");
            assert!(v.vsize <= b.vsize && v.vsize + 3 >= b.vsize, "estimate is a tight upper bound ({} vs {})", v.vsize, b.vsize);
            // the result is a complete, valid transaction
            assert!(signed_tx(&v).input.iter().all(|i| !i.witness.is_empty()));
            consensus_check(&signed_tx(&v), &b.prevouts()).unwrap();
            // rust-bitcoin's own finalizer agrees with ours
            let mut f = signed.clone();
            for (i, inp) in f.inputs.iter_mut().enumerate() { inp.final_script_witness = Some(signed_tx(&v).input[i].witness.clone()); inp.partial_sigs.clear(); inp.tap_key_sig = None; }
            assert_eq!(f.extract_tx_unchecked_fee_rate(), signed_tx(&v));
        }
    }

    #[test]
    fn tampered_outputs_or_fees_are_refused() {
        for kind in [Kind::P2wpkh, Kind::P2tr] {
            let (b, key) = built(kind);
            let ri = b.outputs.iter().position(|o| o.change.is_none()).unwrap();
            let ci = 1 - ri;
            let attacker = Address::from_str("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el").unwrap().assume_checked();
            type Tamper = Box<dyn Fn(&mut Psbt)>;
            let cases: Vec<(&str, Tamper)> = vec![
                ("recipient address", Box::new(move |p: &mut Psbt| p.unsigned_tx.output[ri].script_pubkey = attacker.script_pubkey())),
                ("amount up", Box::new(move |p: &mut Psbt| p.unsigned_tx.output[ri].value += Amount::from_sat(1))),
                ("change down = higher fee", Box::new(move |p: &mut Psbt| p.unsigned_tx.output[ci].value -= Amount::from_sat(5_000))),
                ("extra output", Box::new(|p: &mut Psbt| { p.unsigned_tx.output.push(TxOut { value: Amount::from_sat(1000), script_pubkey: p.unsigned_tx.output[0].script_pubkey.clone() }); p.outputs.push(Default::default()); })),
                ("dropped input", Box::new(|p: &mut Psbt| { p.unsigned_tx.input.pop(); p.inputs.pop(); })),
                ("no RBF", Box::new(|p: &mut Psbt| p.unsigned_tx.input[0].sequence = bitcoin::Sequence::MAX)),
                ("locktime", Box::new(|p: &mut Psbt| p.unsigned_tx.lock_time = bitcoin::absolute::LockTime::from_height(900_000).unwrap())),
            ];
            for (what, f) in cases {
                // the phone signs the altered transaction (it would be valid for it), the Mac refuses it
                let mut p = b.psbt.clone();
                f(&mut p);
                let signed = phone_sign(&p, &key);
                let e = verify_signed(&b, &psbt_base64(&signed)).unwrap_err();
                assert!(e.contains("different transaction"), "{kind:?} {what}: {e}");
            }
        }
    }

    #[test]
    fn wrong_keys_sighash_types_and_bad_signatures_are_refused() {
        for kind in [Kind::P2wpkh, Kind::P2tr] {
            let (b, key) = built(kind);
            // signed by another wallet (with our derivation paths): no signature by our keys
            let mut foreign = b.psbt.clone();
            let ofp = other_key().fingerprint(&Secp256k1::new());
            for inp in foreign.inputs.iter_mut() {
                for v in inp.bip32_derivation.values_mut() { v.0 = ofp; }
                for v in inp.tap_key_origins.values_mut() { v.1 .0 = ofp; }
            }
            let mut s = foreign.clone();
            let _ = s.sign(&other_key(), &Secp256k1::new());
            // put our fingerprints back (as a lying phone would) — the signatures stay foreign
            for (i, inp) in s.inputs.iter_mut().enumerate() { inp.bip32_derivation = b.psbt.inputs[i].bip32_derivation.clone(); inp.tap_key_origins = b.psbt.inputs[i].tap_key_origins.clone(); }
            if kind == Kind::P2wpkh {
                // a foreign key's partial sig is not ours
                assert!(verify_signed(&b, &psbt_base64(&s)).is_err());
            } else {
                // tap_key_sig by another key: Schnorr check against our output key fails
                for inp in s.inputs.iter_mut() { if inp.tap_key_sig.is_none() { inp.tap_key_sig = phone_sign(&b.psbt, &other_key()).inputs[0].tap_key_sig; } }
                assert!(verify_signed(&b, &psbt_base64(&s)).is_err());
            }
            // a valid signature moved to another input
            let good = phone_sign(&b.psbt, &key);
            let mut swapped = good.clone();
            match kind {
                Kind::P2wpkh => {
                    let s0 = *good.inputs[0].partial_sigs.values().next().unwrap();
                    let k1 = *good.inputs[1].partial_sigs.keys().next().unwrap();
                    swapped.inputs[1].partial_sigs = std::collections::BTreeMap::from([(k1, s0)]);
                }
                Kind::P2tr => swapped.inputs[1].tap_key_sig = good.inputs[0].tap_key_sig,
            }
            assert!(verify_signed(&b, &psbt_base64(&swapped)).unwrap_err().contains("does not verify"));
            // SIGHASH_NONE / ALL|ANYONECANPAY: refused even though the signature is valid for it
            let mut p = b.psbt.clone();
            match kind {
                Kind::P2wpkh => for inp in p.inputs.iter_mut() { inp.sighash_type = Some(EcdsaSighashType::None.into()); },
                Kind::P2tr => for inp in p.inputs.iter_mut() { inp.sighash_type = Some(TapSighashType::AllPlusAnyoneCanPay.into()); },
            }
            assert!(verify_signed(&b, &psbt_base64(&phone_sign(&p, &key))).unwrap_err().contains("sighash"));
            // an unsigned input
            let mut half = good.clone();
            half.inputs[2].partial_sigs.clear();
            half.inputs[2].tap_key_sig = None;
            assert!(verify_signed(&b, &psbt_base64(&half)).unwrap_err().contains("not signed"));
            // the phone echoing a different spent amount
            let mut amt = good.clone();
            amt.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(1);
            assert!(verify_signed(&b, &psbt_base64(&amt)).is_err());
            // garbage
            assert!(verify_signed(&b, "not base64!").is_err());
            assert!(verify_signed(&b, &base64::engine::general_purpose::STANDARD.encode(b"psbt\xff")).is_err());
        }
    }

    #[test]
    fn finalized_witnesses_from_the_phone_are_checked_too() {
        for kind in [Kind::P2wpkh, Kind::P2tr] {
            let (b, key) = built(kind);
            let v = verify_signed(&b, &psbt_base64(&phone_sign(&b.psbt, &key))).unwrap();
            let mut fin = b.psbt.clone();
            for (i, inp) in fin.inputs.iter_mut().enumerate() { inp.final_script_witness = Some(signed_tx(&v).input[i].witness.clone()); }
            assert_eq!(verify_signed(&b, &psbt_base64(&fin)).unwrap().txid, v.txid);
            // a final witness for another key
            let mut bad = fin.clone();
            let mut w: Vec<Vec<u8>> = bad.inputs[0].final_script_witness.as_ref().unwrap().iter().map(<[u8]>::to_vec).collect();
            let last = w.len() - 1;
            w[last][5] ^= 1;
            bad.inputs[0].final_script_witness = Some(Witness::from_slice(&w));
            assert!(verify_signed(&b, &psbt_base64(&bad)).is_err());
        }
    }

    #[test]
    fn consensus_check_catches_a_broken_witness() {
        let (b, key) = built(Kind::P2wpkh);
        let v = verify_signed(&b, &psbt_base64(&phone_sign(&b.psbt, &key))).unwrap();
        let mut tx = signed_tx(&v);
        tx.output[0].value -= Amount::from_sat(1);
        assert!(consensus_check(&tx, &b.prevouts()).is_err());
        let mut wrong_amount = b.prevouts();
        wrong_amount[0].value += Amount::from_sat(1);
        assert!(consensus_check(&signed_tx(&v), &wrong_amount).is_err(), "BIP-143 commits to the amount");
    }

    #[test]
    fn sign_answers_are_parsed_strictly() {
        let req = serde_json::json!({"id": "p1"});
        assert_eq!(parse_sign_response(&req, &serde_json::json!({"id": "p1", "status": "approved", "psbt": "cHNidP8="})).unwrap(), "cHNidP8=");
        assert!(parse_sign_response(&req, &serde_json::json!({"id": "p1", "status": "rejected"})).unwrap_err().contains("rejected"));
        assert!(parse_sign_response(&req, &serde_json::json!({"id": "p1", "status": "error", "error": "missing witness_utxo"})).unwrap_err().contains("missing witness_utxo"));
        assert!(parse_sign_response(&req, &serde_json::json!({"id": "p1", "status": "approved", "psbt": "x", "txid": "y"})).is_err());
        assert!(parse_sign_response(&req, &serde_json::json!({"id": "p2", "status": "approved", "psbt": "x"})).is_err());
    }
}
