#!/usr/bin/env python3
"""Host side of the Bitcoin dev-device test (tools/dev-device/btctest.sh), using embit as an
implementation independent of the phone's Java code.

  make   --descriptor-json resp.json --out unsigned.psbt [--foreign] [--fee SATS]
         Build a PSBTv0 spending a FABRICATED coin at …/0/0 of the account the phone shared
         (btc-account answer: wpkh, tr, sh(wpkh) or pkh), paying an external test address with
         change to …/1/0. Nothing is broadcast; the coin does not exist. Every input but Taproot
         carries its previous transaction (non_witness_utxo); SegWit inputs their witness_utxo;
         P2SH-P2WPKH inputs (and change) their redeem script. --foreign names a different
         fingerprint on the input (the phone must refuse it).
  verify --unsigned unsigned.psbt --signed signed.psbt
         Check that the phone only ADDED a signature, that it verifies for the input's key and the
         sighash computed here (BIP-143 for P2WPKH and P2SH-P2WPKH, the legacy sighash for P2PKH,
         BIP-341 for P2TR), and print the finalized transaction.

Needs: embit==0.8.0 (dev host only; sdist sha256 8bf4b10073c67400370ce523fb16f035fe759f6fdd987c579bdcc268d75ed770).
"""
import argparse
import base64
import hashlib
import json
import sys

from embit import bip32, ec, script
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput, SIGHASH, Witness

# descriptor opening -> kind (longest first: "sh(wpkh(" before "wpkh(", "pkh(")
KINDS = (("sh(wpkh(", "shwpkh"), ("wpkh(", "wpkh"), ("tr(", "tr"), ("pkh(", "pkh"))


def load_psbt(path):
    raw = open(path, "rb").read()
    if not raw.startswith(b"psbt\xff"):
        raw = base64.b64decode(b"".join(raw.split()))
    return PSBT.parse(raw)


def kind_of(descriptor):
    for opening, kind in KINDS:
        if descriptor.startswith(opening):
            return kind
    raise SystemExit(f"unsupported descriptor {descriptor[:20]}…")


def spk_for(kind, pub):
    if kind == "tr":
        return script.p2tr(pub)
    if kind == "shwpkh":
        return script.p2sh(script.p2wpkh(pub))
    if kind == "pkh":
        return script.p2pkh(pub)
    return script.p2wpkh(pub)


def push(data):
    assert 0 < len(data) < 76
    return bytes([len(data)]) + data


def make(args):
    answer = json.load(open(args.descriptor_json))
    fp = bytes.fromhex(answer["fingerprint"])
    if args.foreign:
        fp = bytes(4 * [0x11])
    account = bip32.HDKey.from_string(answer["xpub"])
    path = [int(p.rstrip("'"), 10) + (0x80000000 if p.endswith("'") else 0) for p in answer["path"].split("/")[1:]]
    kind = kind_of(answer["descriptor"])
    recv, change = account.derive([0, 0]), account.derive([1, 0])

    def spk(k):
        return spk_for(kind, k.key)

    amount, send = 100_000, 60_000
    fee = args.fee
    # The fabricated coin is output 0 of a fabricated previous transaction, so the PSBT can carry
    # that transaction as non_witness_utxo (the phone requires it for every input but Taproot: it
    # proves the amount). Its txid depends on the spent script, so no two types share an outpoint
    # (the phone remembers each coin it signed for and refuses one later claimed with another script).
    seed = hashlib.sha256(b"phone-vault fabricated coin " + spk(recv).data).digest()
    prev = Transaction(version=2, vin=[TransactionInput(seed, 0)], vout=[TransactionOutput(amount, spk(recv))], locktime=0)
    vin = [TransactionInput(prev.txid(), 0, sequence=0xFFFFFFFD)]
    external = script.p2wpkh(ec.PrivateKey(bytes([42] * 32)).get_public_key())
    vout = [TransactionOutput(send, external), TransactionOutput(amount - send - fee, spk(change))]
    psbt = PSBT(Transaction(version=2, vin=vin, vout=vout, locktime=0))
    if kind != "pkh":
        psbt.inputs[0].witness_utxo = TransactionOutput(amount, spk(recv))
    if kind != "tr":
        psbt.inputs[0].non_witness_utxo = prev
    for scope, key, tail in ((psbt.inputs[0], recv, [0, 0]), (psbt.outputs[1], change, [1, 0])):
        der = DerivationPath(fp if scope is psbt.inputs[0] else bytes.fromhex(answer["fingerprint"]), path + tail)
        if kind == "tr":
            scope.taproot_bip32_derivations[key.key] = ([], der)
            scope.taproot_internal_key = key.key
        else:
            scope.bip32_derivations[key.key] = der
            if kind == "shwpkh":
                scope.redeem_script = script.p2wpkh(key.key)
    open(args.out, "w").write(psbt.to_string() + "\n")
    print(json.dumps({"kind": kind, "recipient_spk": external.data.hex(), "send": send, "fee": fee}))


def utxo_of(inp, txin):
    """The spent output: from the previous transaction when present (checked against the outpoint), else the witness UTXO."""
    if inp.non_witness_utxo is not None:
        if inp.non_witness_utxo.txid() != txin.txid:
            sys.exit("FAIL: non_witness_utxo does not match its outpoint")
        out = inp.non_witness_utxo.vout[txin.vout]
        if inp.witness_utxo is not None and (inp.witness_utxo.value != out.value or inp.witness_utxo.script_pubkey.data != out.script_pubkey.data):
            sys.exit("FAIL: witness_utxo and non_witness_utxo disagree")
        return out
    if inp.witness_utxo is None:
        sys.exit("FAIL: input without UTXO data")
    return inp.witness_utxo


def verify(args):
    before, after = load_psbt(args.unsigned), load_psbt(args.signed)
    if before.tx.serialize() != after.tx.serialize():
        sys.exit("FAIL: the transaction changed")
    tx = after.tx
    utxos = [utxo_of(i, t) for i, t in zip(after.inputs, tx.vin)]
    spks = [u.script_pubkey for u in utxos]
    vals = [u.value for u in utxos]
    kinds = []
    for n, (b, a) in enumerate(zip(before.inputs, after.inputs)):
        spk = spks[n]
        if spk.data[:1] == b"\x51":
            kinds.append("P2TR")
            # embit 0.8 keeps PSBT_IN_TAP_KEY_SIG (0x13) among the unknown fields
            sig = a.unknown.get(b"\x13")
            if sig is None and a.final_scriptwitness is not None:
                sig = a.final_scriptwitness.items[0]
            if sig is None or len(sig) not in (64, 65):
                sys.exit(f"FAIL: input {n} has no Taproot key signature")
            hashtype = sig[64] if len(sig) == 65 else SIGHASH.DEFAULT
            h = tx.sighash_taproot(n, spks, vals, hashtype)
            if not ec.PublicKey.from_xonly(spk.data[2:]).schnorr_verify(ec.SchnorrSig.parse(sig[:64]), h):
                sys.exit(f"FAIL: input {n} Schnorr signature does not verify")
            tx.vin[n].witness = Witness([sig])
            continue
        if len(a.partial_sigs) != len(b.partial_sigs) + 1:
            sys.exit(f"FAIL: input {n} should gain exactly one partial signature")
        if a.final_scriptsig is not None or a.final_scriptwitness is not None:
            sys.exit(f"FAIL: input {n} was finalized by the phone (it only adds partial signatures)")
        pub, sig = next((p, s) for p, s in a.partial_sigs.items() if p not in b.partial_sigs)
        if sig[-1] != SIGHASH.ALL:
            sys.exit(f"FAIL: input {n} sighash type is not SIGHASH_ALL")
        if spk.data == script.p2wpkh(pub).data:
            kinds.append("P2WPKH")
            h = tx.sighash_segwit(n, script.p2pkh(pub), vals[n], SIGHASH.ALL)
            tx.vin[n].witness = Witness([sig, pub.sec()])
        elif spk.data == script.p2sh(script.p2wpkh(pub)).data:
            kinds.append("P2SH-P2WPKH")
            if a.redeem_script is None or a.redeem_script.data != script.p2wpkh(pub).data:
                sys.exit(f"FAIL: input {n} redeem script is not the signing key's")
            h = tx.sighash_segwit(n, script.p2pkh(pub), vals[n], SIGHASH.ALL)
            tx.vin[n].witness = Witness([sig, pub.sec()])
            tx.vin[n].script_sig = script.Script(push(script.p2wpkh(pub).data))
        elif spk.data == script.p2pkh(pub).data:
            kinds.append("P2PKH")
            if a.non_witness_utxo is None:
                sys.exit(f"FAIL: legacy input {n} without its previous transaction")
            h = tx.sighash_legacy(n, spk, SIGHASH.ALL)
            tx.vin[n].script_sig = script.Script(push(sig) + push(pub.sec()))
        else:
            sys.exit(f"FAIL: input {n} signature is for another key")
        if not pub.verify(ec.Signature.parse(sig[:-1]), h):
            sys.exit(f"FAIL: input {n} ECDSA signature does not verify")
    print(json.dumps({"kinds": kinds, "txid": tx.txid().hex(), "final": tx.serialize().hex()}))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make")
    m.add_argument("--descriptor-json", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("--foreign", action="store_true")
    m.add_argument("--fee", type=int, default=2_000)
    v = sub.add_parser("verify")
    v.add_argument("--unsigned", required=True)
    v.add_argument("--signed", required=True)
    a = p.parse_args()
    make(a) if a.cmd == "make" else verify(a)


if __name__ == "__main__":
    main()
