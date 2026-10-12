#!/usr/bin/env bash
# The Mac's simulation claim (hostSimulation) on a THROWAWAY dev phone.
# vault-os/docs/simulation.md. Same transaction every time: send 100 USDC to 0x7f3a…4b93 on
# Ethereum (the phone decodes it from its own token list).
#   1. honest claim (−100 USDC, −fee ETH)   → box "THE MAC'S SIMULATION · NOT VERIFIED BY THIS PHONE"
#      with "−100 USDC", no mismatch row; approve → the host verifies the signature as usual
#      (the claim is not signed: same bytes as without it)
#   2. lying claim (USDC unchanged, +5 ETH) → red "The Mac's simulation does not match what this
#      transaction does — trust the phone's review above"; the phone's own review is unchanged; reject
#   3. malformed claim (unknown key)        → the phone answers an error ("fields do not match
#      schema"); nothing is shown for approval
#   4. no claim                             → the plain review, no box; reject
# Nothing is broadcast: the phone is offline and the host only verifies the one approved signature.
#
# Needs a pinned pairing from usbsigntest.sh (PV_PAIRING_FILE), PV_HOST_PY (venv python with
# pyusb) and PV_HOST_CLIENT (tools/aoa_client.py, with --host-simulation).
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
wake
PY="${PV_HOST_PY:-/root/pv-host/.venv/bin/python}"
CLIENT="${PV_HOST_CLIENT:-/root/pv-host/tools/aoa_client.py}"
PAIRING="${PV_PAIRING_FILE:-/root/pv-host/paired-signer.json}"
OUT="${PV_SIM_OUT:-/tmp/simtest}"
[[ -x "$PY" && -s "$CLIENT" ]] || die "host client not staged ($PY / $CLIENT)"
[[ -s "$PAIRING" ]] || die "no pinned pairing at $PAIRING: run usbsigntest.sh first"
grep -q -- "--host-simulation" "$CLIENT" || die "$CLIENT predates --host-simulation: restage tools/aoa_client.py"
ensure_account1   # the pairing pins Account 1

USDC=0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48
DATA=0xa9059cbb0000000000000000000000007f3a9c04e2b16d58a41c0f9e6b2d7a8c5e1f4b930000000000000000000000000000000000000000000000000000000005f5e100
cat > "$OUT.honest.json" <<EOF
{"changes":[{"asset":"native","delta":"-66112467575160","symbol":"ETH","decimals":18},{"asset":"$USDC","delta":"-100000000","symbol":"USDC","decimals":6}],"node":"ethereum-rpc.publicnode.com","block":"0x18f603b"}
EOF
cat > "$OUT.lying.json" <<EOF
{"changes":[{"asset":"native","delta":"5000000000000000000","symbol":"ETH","decimals":18}],"node":"ethereum-rpc.publicnode.com","block":"0x18f603b"}
EOF
cat > "$OUT.bad.json" <<EOF
{"changes":[],"node":"ethereum-rpc.publicnode.com","block":"0x18f603b","verified":true}
EOF

find_checkbox() {
  local box="" i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    box="$(uidump | grep -o 'checkable="true"[^>]*bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' | head -1 | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/' || true)"
    [[ -n "$box" ]] && { echo "$box"; return 0; }
    scroll_down; sleep 0.6
  done
  return 1
}

# start_request <name> [claim file]: the USDC transfer, with or without a claim; sets $pid
start_request() {
  local name="$1" claim="${2:-}"
  usb_reset; unlock_if_locked; go_home
  "$A" kill-server; sleep 1
  "$PY" "$CLIENT" --pairing-file "$PAIRING" sign-test --chain-id 0x1 --nonce 0x0 --gas-limit 0x186a0 \
    --to "$USDC" --value 0x0 --data "$DATA" ${claim:+--host-simulation "$claim"} > "$OUT.$name" 2>&1 &
  pid=$!
  sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked
}

# review <name> <title> <must-show…>
review() {
  local name="$1" title="$2"; shift 2
  local found=0 f i seen
  for _ in $(seq 1 25); do sleep 2; kill -0 $pid 2>/dev/null || break; has_text "$title" && { found=1; break; }; done
  [[ $found -eq 1 ]] || { kill $pid 2>/dev/null || true; tail -3 "$OUT.$name"; die "$name: review '$title' never appeared: $(texts)"; }
  for f in "$@"; do
    seen=0
    for i in 1 2 3 4 5 6 7 8 9 10; do uidump | grep -qiF "$f" && { seen=1; break; }; scroll_down; sleep 0.6; done
    [[ $seen -eq 1 ]] || { kill $pid 2>/dev/null || true; die "$name: review lacks '$f': $(texts 14)"; }
    scroll_top
  done
  pass "$name: review '$title' shows: $*"
}

# lacks <name> <fragment>: scrolls the whole review; the fragment must never appear
lacks() {
  local name="$1" f="$2" i
  for i in 1 2 3 4 5 6 7 8 9 10; do uidump | grep -qiF "$f" && { kill $pid 2>/dev/null || true; die "$name: review unexpectedly shows '$f'"; }; scroll_down; sleep 0.6; done
  scroll_top
  pass "$name: no '$f'"
}

reject() {
  local name="$1" rc=0
  find_checkbox >/dev/null || true
  tap_text "Reject request"; sleep 2
  wait $pid || rc=$?
  [[ $rc -eq 2 ]] || { tail -3 "$OUT.$name"; die "$name: expected a clean rejection (exit 2), got $rc"; }
  grep -q '"status": "rejected"' "$OUT.$name" || die "$name: response not 'rejected'"
  expect_screen "Request rejected"
  tap_text "Back to Wallet" 2>/dev/null || true
  pass "$name: rejected; no signature left the device"
}

echo "== 1. honest claim: shown as the Mac's, matches; approve"
start_request honest "$OUT.honest.json"
review honest "Send 100 USDC" "NOT VERIFIED BY THIS PHONE" "The Mac says your balance changes by" "−100 USDC" "cannot check"
lacks honest "does not match what this transaction does"
box="$(find_checkbox)" || die "honest: checkbox not visible"
tap_bounds "$box"; sleep 1; tap_text "Approve &amp; sign"; sleep 3
rc=0; wait $pid || rc=$?
[[ $rc -eq 0 ]] && grep -q '"status": "approved"' "$OUT.honest" || { tail -6 "$OUT.honest"; die "honest: not approved/verified (exit $rc)"; }
expect_screen "Signature created"
tap_text "Back to Wallet" 2>/dev/null || true
pass "honest: signed; the host verified fields, hash and signer (the claim is not part of the signature)"

echo "== 2. lying claim: red mismatch row, phone's review unchanged"
start_request lying "$OUT.lying.json"
# ETH is part of what the phone decodes (the fee), so its row is a per-asset mismatch ("For ETH the
# phone decoded … the Mac claims +5 ETH"); "The Mac claims you gain" is only for an asset the
# decoding never touches (HostSimulationTest).
review lying "Send 100 USDC" "Recipient" "does not match what this transaction does" "trust the phone's review above" \
  "the Mac claims +5 ETH" "For USDC the phone decoded −100 USDC; the Mac claims no change"
reject lying

echo "== 3. malformed claim: refused before any review"
start_request bad "$OUT.bad.json"
rc=0; wait $pid || rc=$?
[[ $rc -ne 0 ]] && grep -q '"status": "error"' "$OUT.bad" && grep -qF "hostSimulation fields do not match schema" "$OUT.bad" \
  || { tail -4 "$OUT.bad"; die "bad: expected a schema error (exit $rc)"; }
pass "bad: refused with a schema error; nothing was offered for approval"

echo "== 4. no claim: plain review"
start_request plain
review plain "Send 100 USDC" "Recipient"
lacks plain "NOT VERIFIED BY THIS PHONE"
reject plain

kiosk_locked; no_crashes; unwake
pass "simtest complete"
