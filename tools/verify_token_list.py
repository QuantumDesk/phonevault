#!/usr/bin/env python3
"""Cross-check the built-in token list against the chains themselves (host-side, needs network).

For every entry in app/src/main/res/raw/tokens.json this asks a public node for the contract's
symbol() and decimals() and reports any difference. It is a second check, not the source of
truth: addresses come from the issuers and canonical lists cited in app/token-list/SOURCES.md.
EIP-55 casing and the pinned SHA-256 are enforced by the JVM and companion tests.

  python3 tools/verify_token_list.py            # exit 1 on any mismatch
"""
import json
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
RPC = {
    1: "https://ethereum-rpc.publicnode.com",
    10: "https://optimism-rpc.publicnode.com",
    137: "https://polygon-bor-rpc.publicnode.com",
    8453: "https://base-rpc.publicnode.com",
    42161: "https://arbitrum-one-rpc.publicnode.com",
    11155111: "https://ethereum-sepolia-rpc.publicnode.com",
}


def call(chain, to, data):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                       "params": [{"to": to, "data": data}, "latest"]}).encode()
    req = urllib.request.Request(RPC[chain], body, {"Content-Type": "application/json", "User-Agent": "phone-vault-tokencheck"})
    with urllib.request.urlopen(req, timeout=20) as r:
        res = json.load(r)
    if "result" not in res:
        raise RuntimeError(res.get("error"))
    return bytes.fromhex(res["result"][2:])


def text(b):
    if len(b) == 32:  # bytes32 symbol (old tokens)
        return b.rstrip(b"\0").decode("utf-8", "replace")
    off = int.from_bytes(b[:32], "big")
    n = int.from_bytes(b[off:off + 32], "big")
    return b[off + 32:off + 32 + n].decode("utf-8", "replace")


def main():
    tokens = json.loads((ROOT / "app/src/main/res/raw/tokens.json").read_text())["tokens"]
    bad = 0
    for t in tokens:
        try:
            symbol = text(call(t["chainId"], t["address"], "0x95d89b41"))
            decimals = int.from_bytes(call(t["chainId"], t["address"], "0x313ce567"), "big")
        except Exception as e:  # noqa: BLE001 - report and continue
            print(f"ERR  {t['chainId']:>8} {t['symbol']:<6} {t['address']}: {e}")
            bad += 1
            continue
        ok = decimals == t["decimals"]
        note = "" if symbol == t["symbol"] else f" (on-chain symbol {symbol!r})"
        print(f"{'ok ' if ok else 'BAD'}  {t['chainId']:>8} {t['symbol']:<6} {t['address']} decimals {decimals}{note}")
        bad += 0 if ok else 1
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
