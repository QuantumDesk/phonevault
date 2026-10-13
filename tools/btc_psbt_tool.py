#!/usr/bin/env python3
"""Host side of the Bitcoin dev-device test (tools/dev-device/btctest.sh), using embit as an
implementation independent of the phone's Java code.

  make   --descriptor-json resp.json --out unsigned.psbt [--foreign] [--fee SATS]
         Build a PSBTv0 spending a FABRICATED coin at …/0/0 of the account the phone shared
         (btc-account answer), paying an external test address with change to …/1/0. Nothing is
         broadcast; the coin does not exist. --foreign names a different fingerprint on the input
         (the phone must refuse it).
  verify --unsigned unsigned.psbt --signed signed.psbt
         Check that the phone only ADDED a signature, that it verifies for the input's key and the
         sighash computed here (BIP-143 / BIP-341), and print the finalized transaction.

Needs: pip install embit==0.8.0 (dev host only).
"""
import argparse
import base64
import hashlib
import json
import sys

from embit import bip32, ec, script
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput, SIGHASH, Witness


def load_psbt(path):
    raw = open(path, "rb").read()
    if not raw.startswith(b"psbt\xff"):
        raw = base64.b64decode(b"".join(raw.split()))
    return PSBT.parse(raw)


def make(args):
    answer = json.load(open(args.descriptor_json))
    fp = bytes.fromhex(answer["fingerprint"])
    if args.foreign:
        fp = bytes(4 * [0x11])
    account = bip32.HDKey.from_string(answer["xpub"])
    path = [int(p.rstrip("'"), 10) + (0x80000000 if p.endswith("'") else 0) for p in answer["path"].split("/")[1:]]
    taproot = answer["descriptor"].startswith("tr(")
    recv, change = account.derive([0, 0]), account.derive([1, 0])

    def spk(k):
        return script.p2tr(k.key) if taproot else script.p2wpkh(k.key)

    amount, send = 100_000, 60_000
    fee = args.fee
    # One fabricated outpoint per spent script: the phone remembers each coin it signed for
    # (outpoint → amount + script, the SegWit fee-attack guard) and refuses the same outpoint
    # later claimed with another script, so P2WPKH and P2TR must not share one.
    outpoint = hashlib.sha256(b"phone-vault fabricated coin " + spk(recv).data).digest()
    vin = [TransactionInput(outpoint, 0, sequence=0xFFFFFFFD)]
    external = script.p2wpkh(ec.PrivateKey(bytes([42] * 32)).get_public_key())
    vout = [TransactionOutput(send, external), TransactionOutput(amount - send - fee, spk(change))]
    psbt = PSBT(Transaction(version=2, vin=vin, vout=vout, locktime=0))
    psbt.inputs[0].witness_utxo = TransactionOutput(amount, spk(recv))
    for scope, key, tail in ((psbt.inputs[0], recv, [0, 0]), (psbt.outputs[1], change, [1, 0])):
        der = DerivationPath(fp if scope is psbt.inputs[0] else bytes.fromhex(answer["fingerprint"]), path + tail)
        if taproot:
            scope.taproot_bip32_derivations[key.key] = ([], der)
            scope.taproot_internal_key = key.key
        else:
            scope.bip32_derivations[key.key] = der
    open(args.out, "w").write(psbt.to_string() + "\n")
    print(json.dumps({"recipient_spk": external.data.hex(), "send": send, "fee": fee}))


def verify(args):
    before, after = load_psbt(args.unsigned), load_psbt(args.signed)
    if before.tx.serialize() != after.tx.serialize():
        sys.exit("FAIL: the transaction changed")
    tx = after.tx
    spks = [i.witness_utxo.script_pubkey for i in after.inputs]
    vals = [i.witness_utxo.value for i in after.inputs]
    for n, (b, a) in enumerate(zip(before.inputs, after.inputs)):
        spk = a.witness_utxo.script_pubkey
        if spk.data[:1] == b"\x51":
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
        else:
            if len(a.partial_sigs) != len(b.partial_sigs) + 1:
                sys.exit(f"FAIL: input {n} should gain exactly one partial signature")
            pub, sig = next((p, s) for p, s in a.partial_sigs.items() if p not in b.partial_sigs)
            if script.p2wpkh(pub).data != spk.data or sig[-1] != SIGHASH.ALL:
                sys.exit(f"FAIL: input {n} signature is for another key or sighash")
            h = tx.sighash_segwit(n, script.p2pkh(pub), vals[n], SIGHASH.ALL)
            if not pub.verify(ec.Signature.parse(sig[:-1]), h):
                sys.exit(f"FAIL: input {n} ECDSA signature does not verify")
            tx.vin[n].witness = Witness([sig, pub.sec()])
    print(json.dumps({"txid": tx.txid().hex(), "final": tx.serialize().hex()}))


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
