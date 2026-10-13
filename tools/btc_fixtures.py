#!/usr/bin/env python3
"""Generate app/src/test/resources/btc/psbt-e2e.json with an INDEPENDENT Bitcoin implementation
(embit, https://github.com/diybitcoinhardware/embit, pure Python / libsecp256k1).

For the throwaway "abandon … about" test mnemonic it builds unsigned PSBTv0s (P2WPKH, P2TR, a
testnet mix with OP_RETURN, and change to the wallet; every P2WPKH input carries its previous
transaction as non_witness_utxo, which the phone requires), then signs every input with embit:
ECDSA with RFC 6979 and NO low-R grinding (as the phone signs), BIP-340 with all-zero auxiliary
randomness (the phone's test seam). It records each expected signature and the finalized raw
transaction. BtcEndToEndTest signs the same unsigned PSBTs on the JVM and must produce the same
signatures byte for byte, and the same final transaction.

Usage (dev only; the JSON is committed):  python3 -m venv /tmp/v && /tmp/v/bin/pip install embit==0.8.0
                                          /tmp/v/bin/python tools/btc_fixtures.py
"""
import json
import os
import sys

from embit import bip32, bip39, ec, script
from embit.util import secp256k1
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput, SIGHASH, Witness

MNEMONIC = "abandon " * 11 + "about"
H = 0x80000000
SEED = bip39.mnemonic_to_seed(MNEMONIC)
ROOT = bip32.HDKey.from_seed(SEED)
FP = ROOT.my_fingerprint


def key(path):
    return ROOT.derive(path)


def fake_txid(n):
    # deterministic, distinct previous txids (display order)
    return bytes([n] * 32)


def prev_tx(value, spk, n):
    """A previous transaction paying `value` to `spk` at output 1 (for non_witness_utxo)."""
    tx = Transaction(version=2, vin=[TransactionInput(fake_txid(n), 0)], vout=[
        TransactionOutput(1000, script.p2wpkh(ec.PrivateKey(bytes([n + 1] * 32)).get_public_key())),
        TransactionOutput(value, spk)], locktime=0)
    return tx


def build(name, network, inputs, outputs, version=2, locktime=0, sequence=0xFFFFFFFD):
    """inputs: (kind 'wpkh'|'tr', path, value, with_non_witness); outputs: (spk, value, own_path or None, kind)."""
    vin, utxos, prevs = [], [], []
    for i, (kind, path, value, nwu) in enumerate(inputs):
        k = key(path)
        spk = script.p2wpkh(k.key.get_public_key()) if kind == "wpkh" else script.p2tr(k.key.get_public_key())
        if nwu:
            p = prev_tx(value, spk, 40 + i)
            txid, vout = p.txid(), 1
        else:
            p = None
            txid, vout = fake_txid(10 + i), i
        vin.append(TransactionInput(txid, vout, sequence=sequence))
        utxos.append((spk, value))
        prevs.append(p)
    vout = [TransactionOutput(v, s) for (s, v, _p, _k) in outputs]
    tx = Transaction(version=version, vin=vin, vout=vout, locktime=locktime)
    psbt = PSBT(tx)
    for i, (kind, path, value, nwu) in enumerate(inputs):
        k = key(path)
        inp = psbt.inputs[i]
        inp.witness_utxo = TransactionOutput(value, utxos[i][0])
        if prevs[i] is not None:
            inp.non_witness_utxo = prevs[i]
        der = DerivationPath(FP, bip32.parse_path(path))
        if kind == "wpkh":
            inp.bip32_derivations[k.key.get_public_key()] = der
        else:
            inp.taproot_bip32_derivations[k.key.get_public_key()] = ([], der)
            inp.taproot_internal_key = k.key.get_public_key()
    for j, (spk, value, own, kind) in enumerate(outputs):
        if own:
            k = key(own)
            der = DerivationPath(FP, bip32.parse_path(own))
            if kind == "wpkh":
                psbt.outputs[j].bip32_derivations[k.key.get_public_key()] = der
            else:
                psbt.outputs[j].taproot_bip32_derivations[k.key.get_public_key()] = ([], der)
                psbt.outputs[j].taproot_internal_key = k.key.get_public_key()
    unsigned = psbt.to_string()

    # sign independently
    stx = psbt.tx
    spks = [u[0] for u in utxos]
    vals = [u[1] for u in utxos]
    sigs, witnesses = [], []
    for i, (kind, path, value, nwu) in enumerate(inputs):
        k = key(path)
        if kind == "wpkh":
            sc = script.p2pkh(k.key.get_public_key())
            h = stx.sighash_segwit(i, sc, value, SIGHASH.ALL)
            der = k.key.sign(h, grind=False).serialize() + bytes([SIGHASH.ALL])
            sigs.append({"input": i, "type": "partial_sig", "pubkey": k.key.get_public_key().sec().hex(), "sig": der.hex()})
            witnesses.append(Witness([der, k.key.get_public_key().sec()]))
        else:
            h = stx.sighash_taproot(i, spks, vals, SIGHASH.DEFAULT)
            tweaked = k.key.taproot_tweak(b"")
            # explicit all-zero aux_rand32 (BIP-340), not embit's "no aux" default
            sig = secp256k1.schnorrsig_sign(h, tweaked.secret, None, bytes(32))
            assert tweaked.get_public_key().schnorr_verify(ec.SchnorrSig.parse(sig), h)
            sigs.append({"input": i, "type": "tap_key_sig", "sig": sig.hex()})
            witnesses.append(Witness([sig]))
    for i, w in enumerate(witnesses):
        stx.vin[i].witness = w
    net = NETWORKS["main" if network == "bitcoin" else "test"]

    def is_change(own_path):
        # The phone's rule: the change chain (/1/) of an account AND script type that this PSBT
        # spends from (index window not exercised here). Other own keys are shown with a WARNING.
        if not own_path:
            return False
        p = own_path.split("/")
        spent = {(ip.split("/")[1], ip.split("/")[3]) for (_k, ip, _v, _n) in inputs}
        return p[4] == "1" and (p[1], p[3]) in spent

    return {
        "name": name,
        "network": network,
        "psbt": unsigned,
        "signatures": sigs,
        "finalTx": stx.serialize().hex(),
        "txid": stx.txid().hex(),
        "fee": sum(vals) - sum(v for (_s, v, _p, _k) in outputs),
        "vsizeSigned": stx.vsize if hasattr(stx, "vsize") else None,
        "outputs": [{"address": (s.address(net) if s.data[:1] != b"\x6a" else None), "value": v, "own": p, "change": is_change(p)}
                    for (s, v, p, _k) in outputs],
    }


def ext_wpkh(n):
    return script.p2wpkh(ec.PrivateKey(bytes([n] * 32)).get_public_key())


def ext_tr(n):
    return script.p2tr(ec.PrivateKey(bytes([n] * 32)).get_public_key())


def own(kind, path):
    k = key(path)
    return script.p2wpkh(k.key.get_public_key()) if kind == "wpkh" else script.p2tr(k.key.get_public_key())


cases = [
    build("p2wpkh-send-with-change", "bitcoin",
          [("wpkh", "m/84h/0h/0h/0/0", 1_000_000, True), ("wpkh", "m/84h/0h/0h/0/1", 500_000, True)],
          [(ext_wpkh(7), 1_234_567, None, "wpkh"), (own("wpkh", "m/84h/0h/0h/1/0"), 263_000, "m/84h/0h/0h/1/0", "wpkh")]),
    build("p2tr-send-with-change", "bitcoin",
          [("tr", "m/86h/0h/0h/0/0", 2_000_000, False)],
          [(ext_tr(9), 1_500_000, None, "tr"), (own("tr", "m/86h/0h/0h/1/0"), 499_000, "m/86h/0h/0h/1/0", "tr")]),
    build("testnet-mixed-opreturn", "testnet",
          [("wpkh", "m/84h/1h/0h/0/3", 300_000, True), ("tr", "m/86h/1h/1h/0/2", 400_000, False)],
          [(ext_tr(11), 600_000, None, "tr"),
           (script.Script(bytes.fromhex("6a0b68656c6c6f20776f726c64")), 0, None, "data"),
           (own("wpkh", "m/84h/1h/0h/1/7"), 99_000, "m/84h/1h/0h/1/7", "wpkh")]),
    build("p2wpkh-account-2-legacy-recipients", "bitcoin",
          [("wpkh", "m/84h/0h/1h/0/5", 800_000, True)],
          [(script.p2pkh(ec.PrivateKey(bytes([3] * 32)).get_public_key()), 100_000, None, "pkh"),
           (script.p2sh(ext_wpkh(4)), 200_000, None, "sh"),
           (script.Script(b"\x00\x20" + bytes([5] * 32)), 300_000, None, "wsh"),
           (own("tr", "m/86h/0h/1h/1/0"), 199_000, "m/86h/0h/1h/1/0", "tr")]),
]

out = {
    "source": "tools/btc_fixtures.py (embit 0.8.0), mnemonic: abandon x11 about",
    "fingerprint": FP.hex(),
    "cases": cases,
}
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app", "src", "test", "resources", "btc", "psbt-e2e.json")
with open(path, "w") as f:
    json.dump(out, f, indent=1)
print("wrote", path, [c["name"] for c in cases], file=sys.stderr)
