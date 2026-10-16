#!/usr/bin/env python3
"""Generate app/src/test/resources/btc/psbt-e2e.json with an INDEPENDENT Bitcoin implementation
(embit, https://github.com/diybitcoinhardware/embit, pure Python / libsecp256k1).

For the throwaway "abandon … about" test mnemonic it builds unsigned PSBTv0s (P2WPKH, P2TR,
P2SH-P2WPKH (BIP-49), P2PKH (BIP-44), a testnet mix with OP_RETURN, a testnet mix of all four
input types, and change to the wallet; every input but Taproot carries its previous transaction as
non_witness_utxo, which the phone requires; P2SH-P2WPKH inputs carry their redeem script and P2PKH
inputs no witness_utxo, as BIP-174 says), then signs every input with embit: ECDSA with RFC 6979
and NO low-R grinding (as the phone signs) over the BIP-143 sighash (P2WPKH, P2SH-P2WPKH) or the
legacy sighash (P2PKH), BIP-340 with all-zero auxiliary randomness (the phone's test seam). It
records each expected signature and the finalized raw transaction. BtcPsbtTest signs the same
unsigned PSBTs on the JVM and must produce the same signatures byte for byte, and the same final
transaction.

Usage (dev only; the JSON is committed):
  pip download --no-binary :all: --no-deps embit==0.8.0   # sdist sha256 8bf4b10073c67400370ce523fb16f035fe759f6fdd987c579bdcc268d75ed770
  python3 -m venv /tmp/v && /tmp/v/bin/pip install embit-0.8.0.tar.gz
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
# kinds: "wpkh" (BIP-84), "tr" (BIP-86), "shwpkh" (BIP-49, P2SH-P2WPKH), "pkh" (BIP-44, P2PKH)


def key(path):
    return ROOT.derive(path)


def fake_txid(n):
    # deterministic, distinct previous txids (display order)
    return bytes([n] * 32)


def spk_for(kind, pub):
    if kind == "wpkh":
        return script.p2wpkh(pub)
    if kind == "tr":
        return script.p2tr(pub)
    if kind == "shwpkh":
        return script.p2sh(script.p2wpkh(pub))
    if kind == "pkh":
        return script.p2pkh(pub)
    raise ValueError(kind)


def prev_tx(value, spk, n):
    """A previous transaction paying `value` to `spk` at output 1 (for non_witness_utxo)."""
    tx = Transaction(version=2, vin=[TransactionInput(fake_txid(n), 0)], vout=[
        TransactionOutput(1000, script.p2wpkh(ec.PrivateKey(bytes([n + 1] * 32)).get_public_key())),
        TransactionOutput(value, spk)], locktime=0)
    return tx


def push(data):
    assert 0 < len(data) < 76
    return bytes([len(data)]) + data


def build(name, network, inputs, outputs, version=2, locktime=0, sequence=0xFFFFFFFD):
    """inputs: (kind, path, value, with_non_witness); outputs: (spk, value, own_path or None, kind)."""
    vin, utxos, prevs = [], [], []
    for i, (kind, path, value, nwu) in enumerate(inputs):
        k = key(path)
        spk = spk_for(kind, k.key.get_public_key())
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
        pub = k.key.get_public_key()
        inp = psbt.inputs[i]
        if kind != "pkh":
            inp.witness_utxo = TransactionOutput(value, utxos[i][0])
        if prevs[i] is not None:
            inp.non_witness_utxo = prevs[i]
        der = DerivationPath(FP, bip32.parse_path(path))
        if kind == "tr":
            inp.taproot_bip32_derivations[pub] = ([], der)
            inp.taproot_internal_key = pub
        else:
            inp.bip32_derivations[pub] = der
            if kind == "shwpkh":
                inp.redeem_script = script.p2wpkh(pub)
    for j, (spk, value, own, kind) in enumerate(outputs):
        if own:
            k = key(own)
            pub = k.key.get_public_key()
            der = DerivationPath(FP, bip32.parse_path(own))
            if kind == "tr":
                psbt.outputs[j].taproot_bip32_derivations[pub] = ([], der)
                psbt.outputs[j].taproot_internal_key = pub
            else:
                psbt.outputs[j].bip32_derivations[pub] = der
                if kind == "shwpkh":
                    psbt.outputs[j].redeem_script = script.p2wpkh(pub)
    unsigned = psbt.to_string()

    # sign independently
    stx = psbt.tx
    spks = [u[0] for u in utxos]
    vals = [u[1] for u in utxos]
    sigs, witnesses, script_sigs = [], [], []
    for i, (kind, path, value, nwu) in enumerate(inputs):
        k = key(path)
        pub = k.key.get_public_key()
        if kind == "tr":
            h = stx.sighash_taproot(i, spks, vals, SIGHASH.DEFAULT)
            tweaked = k.key.taproot_tweak(b"")
            # explicit all-zero aux_rand32 (BIP-340), not embit's "no aux" default
            sig = secp256k1.schnorrsig_sign(h, tweaked.secret, None, bytes(32))
            assert tweaked.get_public_key().schnorr_verify(ec.SchnorrSig.parse(sig), h)
            sigs.append({"input": i, "type": "tap_key_sig", "sig": sig.hex()})
            witnesses.append(Witness([sig]))
            script_sigs.append(b"")
            continue
        if kind == "pkh":
            h = stx.sighash_legacy(i, spks[i], SIGHASH.ALL)
        else:
            h = stx.sighash_segwit(i, script.p2pkh(pub), value, SIGHASH.ALL)
        der = k.key.sign(h, grind=False).serialize() + bytes([SIGHASH.ALL])
        sigs.append({"input": i, "type": "partial_sig", "pubkey": pub.sec().hex(), "sig": der.hex()})
        if kind == "pkh":
            witnesses.append(Witness([]))
            script_sigs.append(push(der) + push(pub.sec()))
        else:
            witnesses.append(Witness([der, pub.sec()]))
            script_sigs.append(push(script.p2wpkh(pub).data) if kind == "shwpkh" else b"")
    for i, w in enumerate(witnesses):
        stx.vin[i].witness = w
        stx.vin[i].script_sig = script.Script(script_sigs[i])
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
        "scriptSigs": [s.hex() for s in script_sigs],
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
    return spk_for(kind, key(path).key.get_public_key())


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
    # BIP-49 Nested SegWit (3…): two coins, change back to the same account's change chain
    build("p2sh-p2wpkh-send-with-change", "bitcoin",
          [("shwpkh", "m/49h/0h/0h/0/0", 700_000, True), ("shwpkh", "m/49h/0h/0h/0/1", 300_000, True)],
          [(ext_wpkh(12), 650_000, None, "wpkh"), (own("shwpkh", "m/49h/0h/0h/1/0"), 348_000, "m/49h/0h/0h/1/0", "shwpkh")]),
    # BIP-44 Legacy (1…): no witness at all in the final transaction
    build("p2pkh-send-with-change", "bitcoin",
          [("pkh", "m/44h/0h/0h/0/0", 400_000, True), ("pkh", "m/44h/0h/2h/0/3", 250_000, True)],
          [(script.p2pkh(ec.PrivateKey(bytes([13] * 32)).get_public_key()), 500_000, None, "pkh"),
           (own("pkh", "m/44h/0h/0h/1/0"), 148_000, "m/44h/0h/0h/1/0", "pkh")]),
    # every input type in one testnet transaction (a migration sweep), change to Native SegWit
    build("testnet-sweep-all-types", "testnet",
          [("pkh", "m/44h/1h/0h/0/0", 120_000, True), ("shwpkh", "m/49h/1h/0h/0/2", 130_000, True),
           ("wpkh", "m/84h/1h/0h/0/1", 140_000, True), ("tr", "m/86h/1h/0h/0/0", 150_000, False)],
          [(script.p2sh(ext_wpkh(14)), 300_000, None, "sh"),
           (own("wpkh", "m/84h/1h/0h/1/3"), 238_000, "m/84h/1h/0h/1/3", "wpkh")]),
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
