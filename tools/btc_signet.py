#!/usr/bin/env python3
"""Host side of the REAL signet round trip (tools/dev-device/btc-signet-e2e.sh), using embit as an
implementation independent of the phone's Java code and mempool.space's signet Esplora API.

SIGNET ONLY: the API base is hard-coded to mempool.space/signet and every command refuses a
mainnet (xpub) account. Nothing here touches a faucet; funding is done by a person.

  derive  --account acct.json [--index N] [--change 0|1]
          Print the P2WPKH address at …/change/index of the account the phone shared.
  wait-utxo --address A [--timeout S] [--interval S]
          Poll /address/A/utxo until a coin appears (exit 3 on timeout).
  build   --account acct.json --out unsigned.psbt --plan plan.json
          Spend EVERY coin at …/0/0 to …/0/1 (half) with change to …/1/0, at the recommended
          half-hour fee rate. Each input carries witness_utxo, non_witness_utxo (the full previous
          transaction, fetched and hash-checked) and its BIP-32 derivation; both outputs carry
          theirs, so the phone proves they are its own.
  finalize --account acct.json --plan plan.json --unsigned u.psbt --signed s.psbt --out tx.json
          The phone only added one signature per input, each verifies (btc_psbt_tool.verify, BIP-143)
          for a key derived HERE from the account xpub; the outputs and fee are exactly the plan.
          Writes {"txid", "final"} (finalized raw transaction).
  broadcast --tx tx.json
          POST the raw transaction to /signet/api/tx; the answered txid must equal ours.
  wait-confirm --txid T [--timeout S]
          Poll until mempool.space has the transaction (exit 0 once seen), and keep polling until
          it confirms or the timeout passes (exit 0 either way once seen; 3 if never seen).

Needs embit==0.8.0 (dev host only). Standard library HTTP (urllib).
"""
import argparse
import hashlib
import json
import math
import os
import sys
import time
import urllib.error
import urllib.request

from embit import bip32, script
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput, Witness

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import btc_psbt_tool  # noqa: E402  (verify(): the same independent signature check as btctest.sh)

API = "https://mempool.space/signet/api"
EXPLORER = "https://mempool.space/signet/tx/"
DUST = 294  # P2WPKH dust threshold
USER_AGENT = "phone-vault-signet-e2e/1"


def http(path, data=None, timeout=30):
    req = urllib.request.Request(API + path, data=data, headers={"User-Agent": USER_AGENT})
    if data is not None:
        req.add_header("Content-Type", "text/plain")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode()


def load_account(path):
    answer = json.load(open(path))
    if not answer["xpub"].startswith("tpub") or not answer["path"].startswith("m/84'/1'/"):
        sys.exit("refusing: not a test-network P2WPKH account (signet only, never mainnet)")
    if not answer["descriptor"].startswith("wpkh("):
        sys.exit("refusing: only the P2WPKH account is supported here")
    fp = bytes.fromhex(answer["fingerprint"])
    path = [int(p.rstrip("'"), 10) + (0x80000000 if p.endswith("'") else 0) for p in answer["path"].split("/")[1:]]
    return fp, path, bip32.HDKey.from_string(answer["xpub"])


def key_at(account, change, index):
    return account.derive([change, index])


_TEST = NETWORKS["test"]  # testnet and signet share address encodings (bech32 "tb")


def address_of(key):
    return script.p2wpkh(key.key).address(network=_TEST)


def vsize_of(raw):
    stripped = Transaction.parse(raw)
    for i in stripped.vin:
        i.witness = Witness([])
    return math.ceil((len(stripped.serialize()) * 3 + len(raw)) / 4)


def cmd_derive(a):
    _, _, account = load_account(a.account)
    print(address_of(key_at(account, a.change, a.index)))


def utxos(address):
    return json.loads(http(f"/address/{address}/utxo"))


def cmd_wait_utxo(a):
    deadline = time.time() + a.timeout
    last = None
    while True:
        try:
            found = utxos(a.address)
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            found, last = [], str(e)
        if found:
            print(json.dumps(found))
            return 0
        if time.time() > deadline:
            print(f"no coin at {a.address} after {a.timeout}s" + (f" (last error: {last})" if last else ""), file=sys.stderr)
            return 3
        time.sleep(a.interval)


def estimate_vsize(n_in, n_out):
    # version 4 + locktime 4 + counts 2 = 10 bytes; segwit marker/flag 0.5 vB; P2WPKH input
    # 41 bytes + witness (1 + 73 + 34) / 4 → 68 vB (rounded up); P2WPKH output 31 vB.
    return math.ceil(10.5 + 68 * n_in + 31 * n_out)


def cmd_build(a):
    fp, path, account = load_account(a.account)
    k0, k1, kc = key_at(account, 0, 0), key_at(account, 0, 1), key_at(account, 1, 0)
    addr0 = address_of(k0)
    coins = sorted(utxos(addr0), key=lambda u: (u["txid"], u["vout"]))
    if not coins:
        sys.exit(f"no coin at {addr0} yet")
    rates = json.loads(http("/v1/fees/recommended"))
    rate = max(1, int(rates.get("halfHourFee", 1)))
    vin, inputs_meta, total = [], [], 0
    for u in coins:
        raw = bytes.fromhex(http(f"/tx/{u['txid']}/hex").strip())
        prev = Transaction.parse(raw)
        if prev.txid().hex() != u["txid"]:
            sys.exit(f"previous transaction {u['txid']} does not hash to its id")
        out = prev.vout[u["vout"]]
        if out.value != u["value"] or out.script_pubkey.data != script.p2wpkh(k0.key).data:
            sys.exit(f"coin {u['txid']}:{u['vout']} is not {u['value']} sats at {addr0}")
        vin.append(TransactionInput(bytes.fromhex(u["txid"]), u["vout"], sequence=0xFFFFFFFD))
        inputs_meta.append((prev, out))
        total += out.value
    fee = rate * estimate_vsize(len(vin), 2)
    send = total // 2
    change = total - send - fee
    if send < DUST or change < DUST:
        sys.exit(f"coin too small to split: {total} sats at {rate} sat/vB (fee {fee})")
    vout = [TransactionOutput(send, script.p2wpkh(k1.key)), TransactionOutput(change, script.p2wpkh(kc.key))]
    psbt = PSBT(Transaction(version=2, vin=vin, vout=vout, locktime=0))
    for i, (prev, out) in enumerate(inputs_meta):
        psbt.inputs[i].witness_utxo = out
        psbt.inputs[i].non_witness_utxo = prev
        psbt.inputs[i].bip32_derivations[k0.key] = DerivationPath(fp, path + [0, 0])
    psbt.outputs[0].bip32_derivations[k1.key] = DerivationPath(fp, path + [0, 1])
    psbt.outputs[1].bip32_derivations[kc.key] = DerivationPath(fp, path + [1, 0])
    open(a.out, "w").write(psbt.to_string() + "\n")
    plan = {
        "network": "signet", "from": addr0, "inputs": [f"{u['txid']}:{u['vout']}" for u in coins],
        "total_in": total, "fee_rate": rate, "fee": fee,
        "outputs": [{"address": address_of(k1), "value": send, "path": "0/1"},
                    {"address": address_of(kc), "value": change, "path": "1/0 (change)"}],
        "unsigned_txid": psbt.tx.txid().hex(),
        "psbt_sha256": hashlib.sha256(psbt.serialize()).hexdigest(),
    }
    json.dump(plan, open(a.plan, "w"), indent=2)
    print(json.dumps(plan, indent=2))


def cmd_finalize(a):
    _, _, account = load_account(a.account)
    plan = json.load(open(a.plan))
    unsigned, signed = btc_psbt_tool.load_psbt(a.unsigned), btc_psbt_tool.load_psbt(a.signed)
    if hashlib.sha256(unsigned.serialize()).hexdigest() != plan["psbt_sha256"]:
        sys.exit("FAIL: the unsigned PSBT is not the one planned")
    tx = signed.tx
    got = [{"address": o.script_pubkey.address(network=_TEST), "value": o.value} for o in tx.vout]
    if got != [{"address": o["address"], "value": o["value"]} for o in plan["outputs"]]:
        sys.exit(f"FAIL: outputs differ from the plan: {got}")
    ins = [f"{i.txid.hex()}:{i.vout}" for i in tx.vin]
    if ins != plan["inputs"]:
        sys.exit("FAIL: inputs differ from the plan")
    total_in = sum(i.witness_utxo.value for i in signed.inputs)
    if total_in != plan["total_in"] or total_in - sum(o.value for o in tx.vout) != plan["fee"]:
        sys.exit("FAIL: fee differs from the plan")
    ours = key_at(account, 0, 0).key
    for n, (b, s) in enumerate(zip(unsigned.inputs, signed.inputs)):
        new = [p for p in s.partial_sigs if p not in b.partial_sigs]
        if new != [ours]:
            sys.exit(f"FAIL: input {n} is not signed by our key m/84'/1'/0'/0/0 (derived here from the xpub)")
    # Signature validity (BIP-143 sighash computed here) + finalization: the btctest.sh checker.
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        btc_psbt_tool.verify(argparse.Namespace(unsigned=a.unsigned, signed=a.signed))
    result = json.loads(buf.getvalue())
    final = Transaction.parse(bytes.fromhex(result["final"]))
    if final.txid().hex() != plan["unsigned_txid"]:
        sys.exit("FAIL: finalized txid differs from the planned one")
    vsize = vsize_of(bytes.fromhex(result["final"]))
    result["vsize"] = vsize
    result["fee_rate_actual"] = round(plan["fee"] / vsize, 2)
    json.dump(result, open(a.out, "w"))
    print(json.dumps({"txid": result["txid"], "vsize": vsize, "fee": plan["fee"], "fee_rate": result["fee_rate_actual"]}))


def cmd_broadcast(a):
    tx = json.load(open(a.tx))
    try:
        answered = http("/tx", data=tx["final"].encode(), timeout=60).strip()
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        if "already" in body.lower() or "txn-already-known" in body:
            answered = tx["txid"]
        else:
            sys.exit(f"broadcast refused: HTTP {e.code}: {body}")
    if answered != tx["txid"]:
        sys.exit(f"broadcast answered txid {answered}, expected {tx['txid']}")
    print(answered)


def cmd_wait_confirm(a):
    deadline = time.time() + a.timeout
    seen = False
    while True:
        try:
            status = json.loads(http(f"/tx/{a.txid}/status"))
            if not seen:
                print(f"seen by mempool.space: {EXPLORER}{a.txid}", flush=True)
            seen = True
            if status.get("confirmed"):
                print(json.dumps({"confirmed": True, "block_height": status.get("block_height"),
                                  "block_hash": status.get("block_hash")}))
                return 0
        except urllib.error.HTTPError as e:
            if e.code != 404:
                print(f"status query failed: HTTP {e.code}", file=sys.stderr)
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            print(f"status query failed: {e}", file=sys.stderr)
        if time.time() > deadline:
            print(json.dumps({"confirmed": False, "seen": seen}))
            return 0 if seen else 3
        time.sleep(a.interval)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("derive")
    d.add_argument("--account", required=True)
    d.add_argument("--change", type=int, choices=(0, 1), default=0)
    d.add_argument("--index", type=int, default=0)
    w = sub.add_parser("wait-utxo")
    w.add_argument("--address", required=True)
    w.add_argument("--timeout", type=int, default=1800)
    w.add_argument("--interval", type=int, default=20)
    b = sub.add_parser("build")
    b.add_argument("--account", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--plan", required=True)
    f = sub.add_parser("finalize")
    for n in ("--account", "--plan", "--unsigned", "--signed", "--out"):
        f.add_argument(n, required=True)
    br = sub.add_parser("broadcast")
    br.add_argument("--tx", required=True)
    c = sub.add_parser("wait-confirm")
    c.add_argument("--txid", required=True)
    c.add_argument("--timeout", type=int, default=1800)
    c.add_argument("--interval", type=int, default=30)
    a = p.parse_args()
    return {"derive": cmd_derive, "wait-utxo": cmd_wait_utxo, "build": cmd_build, "finalize": cmd_finalize,
            "broadcast": cmd_broadcast, "wait-confirm": cmd_wait_confirm}[a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main())
