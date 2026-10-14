#!/usr/bin/env bash
# Bitcoin round trips on a THROWAWAY dev phone (TESTNET only; nothing is broadcast, the coins
# spent are fabricated): btcGetAccount (share screen, decline, remembered, revoked from
# ☰ → Bitcoin sharing), btcShowAddress (compare screen), btcSignPsbt for P2WPKH and P2TR (review,
# sign, reject, refuse a foreign coin).
# Every approval is checked on the host with an implementation independent of the phone's Java
# code (embit, tools/btc_psbt_tool.py): the signed PSBT may only gain a signature, and that
# signature must verify for the input's key and the sighash computed on the host.
#
# Rerunnable: the phone remembers "shared" per (network, type, account) forever, so the script
# first revokes every remembered account in ☰ → Bitcoin sharing (the phone then asks again).
#
# Needs PV_HOST_PY (venv python with pyusb AND embit==0.8.0), PV_HOST_CLIENT (tools/aoa_client.py)
# and PV_BTC_TOOL (tools/btc_psbt_tool.py). Not part of CI; run by hand next to the other scripts.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
OUT="${PV_BTC_OUT:-$PV_LOG_DIR/btctest}"
WORK="$(mktemp -d)"
source "$(dirname "$0")/btclib.sh"

wake  # a sleeping screen (e.g. after a reboot) has no window to read
ensure_account1

# ---- 0. a clean slate: the phone must ask again for every account
step "reset sharing (☰ → Bitcoin sharing)"
btc_unshare
pass "no Bitcoin account remembered as shared"

# ---- 1. share an account: the phone asks once, shows what it reveals
step account1
echo "   btc-account (first time: share screen)"
start_client account1 btc-account --network testnet --type p2wpkh --account 1
wait_screen "Share Bitcoin account with the Mac?"
expect_below "WHAT THE MAC WILL SEE"
scroll_top
expect_below "Bitcoin TESTNET"
find_text "Share with the Mac" || die "no Share button: $(texts 10)"
tap_text "Share with the Mac"; sleep 2
finish_client account1 0
json_of "$OUT/account1.out" > "$WORK/wpkh.json"
grep -q '"path": "m/84'"'"'/1'"'"'/0'"'"'"' "$OUT/account1.out" || die "unexpected path: $(cat "$OUT/account1.out")"
expect_screen "Account shared"
pass "account shared: $(grep -o '"descriptor": "[^"]*' "$OUT/account1.out" | cut -c16-60)…"
leave_outcome

step account1b
echo "   btc-account (remembered: no screen)"
start_client account1b btc-account --network testnet --type p2wpkh --account 1
finish_client account1b 0
expect_not "Share Bitcoin account with the Mac?"
cmp -s <(json_of "$OUT/account1b.out" | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print(d["descriptor"])') \
       <("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["descriptor"])' "$WORK/wpkh.json") \
  || die "remembered answer differs from the first one"
pass "remembered: answered without asking (same descriptor)"

step "sharing list"
open_btc_sharing
find_text "Stop sharing · Bitcoin TESTNET · Account 1 · Native SegWit" || die "shared account not listed: $(texts 10)"
pass "☰ → Bitcoin sharing lists the shared account"
go_home

step account2
echo "   btc-account (declined)"
start_client account2 btc-account --network testnet --type p2tr --account 2
wait_screen "Share Bitcoin account with the Mac?"
find_text "Don&apos;t share" || true
try_tap "Don&apos;t share" || tap_text "Don't share"; sleep 2
finish_client account2 2
grep -q '"status": "rejected"' "$OUT/account2.out" || die "decline did not answer rejected"
pass "declined: rejected, nothing shared"

step account3
echo "   btc-account (Taproot, account 1, for signing)"
start_client account3 btc-account --network testnet --type p2tr --account 1
wait_screen "Share Bitcoin account with the Mac?"
find_text "Share with the Mac" || die "no Share button: $(texts 10)"
tap_text "Share with the Mac"; sleep 2
finish_client account3 0
json_of "$OUT/account3.out" > "$WORK/tr.json"
grep -q '"descriptor": "tr(\[[0-9a-f]\{8\}/86h/1h/0h\]tpub' "$OUT/account3.out" || die "unexpected Taproot descriptor"
pass "Taproot account shared"
leave_outcome

# ---- 2. show an address: compare the phone's screen with the answer
step show
start_client show btc-show --network testnet --type p2wpkh --account 1 --change 0 --index 0
wait_screen "Compare with your Mac"
SHOWN="$(uidump | grep -o 'text="tb1q[^"]*' | head -1 | sed 's/^text="//; s/&#10;//g; s/ //g' || true)"
expect_below "m/84'/1'/0'/0/0 (receiving address 0)"
tap_text "Done: it matches"; sleep 2
finish_client show 0
GOT="$(grep -o '"address": "[^"]*' "$OUT/show.out" | cut -c13- || true)"
[[ -n "$SHOWN" && "$SHOWN" == "$GOT" ]] || die "phone showed '$SHOWN' but answered '$GOT'"
pass "address shown on the phone == address answered ($GOT)"

# ---- 3. sign: P2WPKH and P2TR, verified on the host with embit
for kind in wpkh tr; do
  step "sign-$kind"
  "$PY" "$TOOL" make --descriptor-json "$WORK/$kind.json" --out "$WORK/$kind.psbt" >/dev/null
  start_client "sign-$kind" btc-sign --network testnet --psbt "$WORK/$kind.psbt" --out "$WORK/$kind.signed"
  wait_screen "Send 0.00060000 tBTC"
  expect_below "CHANGE BACK TO YOUR WALLET"
  expect_below "NETWORK FEE"
  approve_review
  finish_client "sign-$kind" 0
  "$PY" "$TOOL" verify --unsigned "$WORK/$kind.psbt" --signed "$WORK/$kind.signed" > "$OUT/verify-$kind.json" || die "$kind: host verification failed"
  pass "$kind: signature verified on the host (embit), txid $(grep -o '"txid": "[^"]*' "$OUT/verify-$kind.json" | cut -c10-25)…"
  leave_outcome
done

step sign-reject
start_client sign-reject btc-sign --network testnet --psbt "$WORK/wpkh.psbt"
wait_screen "Send 0.00060000 tBTC"
find_text "Reject request" || die "no Reject button: $(texts 10)"
tap_text "Reject request"; sleep 2
finish_client sign-reject 2
grep -q '"status": "rejected"' "$OUT/sign-reject.out" || die "reject did not answer rejected"
expect_screen "Request rejected"
pass "rejected on the phone; no signature left the device"
leave_outcome

step sign-foreign
echo "   btc-sign (a coin of another wallet: refused)"
"$PY" "$TOOL" make --descriptor-json "$WORK/wpkh.json" --out "$WORK/foreign.psbt" --foreign >/dev/null
start_client sign-foreign btc-sign --network testnet --psbt "$WORK/foreign.psbt"
finish_client sign-foreign 2
grep -q '"status": "error"' "$OUT/sign-foreign.out" || die "foreign coin was not refused"
expect_screen "Bitcoin transaction refused"
pass "foreign coin refused with a reason on the phone"
leave_outcome

# ---- 4. revoke one account on the phone: it asks again (and a decline keeps it unshared)
step revoke
btc_unshare "Bitcoin TESTNET · Account 1 · Taproot"
start_client revoke btc-account --network testnet --type p2tr --account 1
wait_screen "Share Bitcoin account with the Mac?"
find_text "Don&apos;t share" || true
try_tap "Don&apos;t share" || tap_text "Don't share"; sleep 2
finish_client revoke 2
pass "revoked in ☰ → Bitcoin sharing: the phone asked again (declined)"
# shellcheck disable=SC2034  # read by the EXIT trap in btclib.sh
STEP="done"
echo "ALL BITCOIN CHECKS PASSED"
