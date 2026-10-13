#!/usr/bin/env bash
# Bitcoin round trips on a THROWAWAY dev phone (TESTNET only; nothing is broadcast, the coins
# spent are fabricated): btcGetAccount (share screen, decline, remembered), btcShowAddress
# (compare screen), btcSignPsbt for P2WPKH and P2TR (review, sign, reject, refuse a foreign coin).
# Every approval is checked on the host with an implementation independent of the phone's Java
# code (embit, tools/btc_psbt_tool.py): the signed PSBT may only gain a signature, and that
# signature must verify for the input's key and the sighash computed on the host.
#
# Needs PV_HOST_PY (venv python with pyusb AND embit==0.8.0), PV_HOST_CLIENT (tools/aoa_client.py)
# and PV_BTC_TOOL (tools/btc_psbt_tool.py). Not part of CI; run by hand next to the other scripts.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
PY="${PV_HOST_PY:-/root/pv-host/.venv/bin/python}"
CLIENT="${PV_HOST_CLIENT:-/root/pv-host/tools/aoa_client.py}"
TOOL="${PV_BTC_TOOL:-/root/pv-host/tools/btc_psbt_tool.py}"
OUT="${PV_BTC_OUT:-/tmp/btctest}"
[[ -x "$PY" && -s "$CLIENT" && -s "$TOOL" ]] || die "host tools not staged ($PY / $CLIENT / $TOOL)"
"$PY" -c 'import embit, usb' 2>/dev/null || die "$PY needs pyusb and embit==0.8.0"
mkdir -p "$OUT"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# client <name> <args…>: run aoa_client in the background (adb is stopped while it owns USB)
start_client() {
  local name="$1"; shift
  usb_reset; unlock_if_locked; go_home
  "$A" kill-server; sleep 1
  "$PY" "$CLIENT" "$@" > "$OUT/$name.out" 2>&1 &
  CLIENT_PID=$!
  sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked
}

# wait_screen <title>: the request's screen appears (a PIN prompt for the seed key is answered)
wait_screen() {
  local i
  for i in $(seq 1 30); do
    sleep 2
    system_prompt_up && enter_system_pin
    has_text "$1" && return 0
    kill -0 "$CLIENT_PID" 2>/dev/null || break
  done
  kill "$CLIENT_PID" 2>/dev/null || true
  die "screen '$1' never appeared: $(texts 10)"
}

finish_client() { # finish_client <name> <expected exit>
  local rc=0; wait "$CLIENT_PID" || rc=$?
  [[ $rc -eq $2 ]] || { tail -5 "$OUT/$1.out"; die "$1: host client exited $rc, expected $2"; }
}

json_of() { "$PY" -c 'import json,sys; t=open(sys.argv[1]).read(); print(json.dumps(json.loads(t[t.index("{"):t.rindex("}")+1])))' "$1"; }

# ---- 1. share an account: the phone asks once, shows what it reveals
echo "== btc-account (first time: share screen)"
start_client account1 btc-account --network testnet --type p2wpkh --account 1
wait_screen "Share Bitcoin account with the Mac?"
expect_below "WHAT THE MAC WILL SEE"
expect_below "Bitcoin TESTNET"
tap_text "Share with the Mac"; sleep 2
finish_client account1 0
json_of "$OUT/account1.out" > "$WORK/wpkh.json"
grep -q '"path": "m/84'"'"'/1'"'"'/0'"'"'"' "$OUT/account1.out" || die "unexpected path: $(cat "$OUT/account1.out")"
pass "account shared: $(grep -o '"descriptor": "[^"]*' "$OUT/account1.out" | cut -c16-60)…"
tap_text "Back to Wallet" 2>/dev/null || tap_text "Continue" 2>/dev/null || true

echo "== btc-account (remembered: no screen)"
start_client account1b btc-account --network testnet --type p2wpkh --account 1
finish_client account1b 0
expect_not "Share Bitcoin account with the Mac?"
pass "remembered: answered without asking"

echo "== btc-account (declined)"
start_client account2 btc-account --network testnet --type p2tr --account 2
wait_screen "Share Bitcoin account with the Mac?"
tap_text "Don&apos;t share" 2>/dev/null || tap_text "Don't share"; sleep 2
finish_client account2 2
grep -q '"status": "rejected"' "$OUT/account2.out" || die "decline did not answer rejected"
pass "declined: rejected, nothing shared"

echo "== btc-account (Taproot, account 1, for signing)"
start_client account3 btc-account --network testnet --type p2tr --account 1
wait_screen "Share Bitcoin account with the Mac?"
tap_text "Share with the Mac"; sleep 2
finish_client account3 0
json_of "$OUT/account3.out" > "$WORK/tr.json"

# ---- 2. show an address: compare the phone's screen with the answer
echo "== btc-show"
start_client show btc-show --network testnet --type p2wpkh --account 1 --change 0 --index 0
wait_screen "Compare with your Mac"
SHOWN="$(uidump | grep -o 'text="tb1q[^"]*' | head -1 | sed 's/^text="//; s/&#10;//g; s/ //g')"
expect_below "m/84&apos;/1&apos;/0&apos;/0/0"
tap_text "Done: it matches"; sleep 2
finish_client show 0
GOT="$(grep -o '"address": "[^"]*' "$OUT/show.out" | cut -c13-)"
[[ -n "$SHOWN" && "$SHOWN" == "$GOT" ]] || die "phone showed '$SHOWN' but answered '$GOT'"
pass "address shown on the phone == address answered ($GOT)"

# ---- 3. sign: P2WPKH and P2TR, verified on the host with embit
for kind in wpkh tr; do
  echo "== btc-sign ($kind)"
  "$PY" "$TOOL" make --descriptor-json "$WORK/$kind.json" --out "$WORK/$kind.psbt" >/dev/null
  start_client "sign-$kind" btc-sign --network testnet --psbt "$WORK/$kind.psbt" --out "$WORK/$kind.signed"
  wait_screen "Send 0.00060000 tBTC"
  expect_below "CHANGE BACK TO YOUR WALLET"
  expect_below "NETWORK FEE"
  box="$(uidump | grep -o 'checkable="true"[^>]*bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' | head -1 | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/' || true)"
  [[ -n "$box" ]] || { find_text "I checked the network"; box="$(bounds_of "I checked the network")"; }
  tap_bounds "$box"; sleep 1
  tap_text "Approve &amp; sign" 2>/dev/null || tap_text "Approve & sign"; sleep 3
  system_prompt_up && enter_system_pin
  finish_client "sign-$kind" 0
  "$PY" "$TOOL" verify --unsigned "$WORK/$kind.psbt" --signed "$WORK/$kind.signed" > "$OUT/verify-$kind.json" || die "$kind: host verification failed"
  pass "$kind: signature verified on the host (embit), txid $(cut -c10-25 "$OUT/verify-$kind.json")…"
  tap_text "Back to Wallet" 2>/dev/null || true
done

echo "== btc-sign (rejected)"
start_client sign-reject btc-sign --network testnet --psbt "$WORK/wpkh.psbt"
wait_screen "Send 0.00060000 tBTC"
find_text "Reject request" >/dev/null || true
tap_text "Reject request"; sleep 2
finish_client sign-reject 2
grep -q '"status": "rejected"' "$OUT/sign-reject.out" || die "reject did not answer rejected"
pass "rejected on the phone; no signature left the device"
tap_text "Back to Wallet" 2>/dev/null || true

echo "== btc-sign (a coin of another wallet: refused)"
"$PY" "$TOOL" make --descriptor-json "$WORK/wpkh.json" --out "$WORK/foreign.psbt" --foreign >/dev/null
start_client sign-foreign btc-sign --network testnet --psbt "$WORK/foreign.psbt"
finish_client sign-foreign 2
grep -q '"status": "error"' "$OUT/sign-foreign.out" || die "foreign coin was not refused"
expect_screen "Bitcoin transaction refused"
pass "foreign coin refused with a reason on the phone"
tap_text "Continue" 2>/dev/null || true
echo "ALL BITCOIN CHECKS PASSED"
