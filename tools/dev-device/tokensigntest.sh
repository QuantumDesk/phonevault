#!/usr/bin/env bash
# ERC-20 review round trips on a THROWAWAY dev phone: a USDC transfer (known token: "Send 50 USDC"),
# an UNLIMITED approval (rejected), an unknown-contract transfer (raw base units, rejected), an
# increaseAllowance on Base USDC (approved) and calldata with a trailing byte (refused by the phone
# before any review). Nothing is broadcast: the phone is offline and the host only verifies
# (fields incl. data, recomputed hash, recovered signer == pinned pairing).
#
# Needs a pinned pairing from usbsigntest.sh (PV_PAIRING_FILE), PV_HOST_PY (venv python with
# pyusb) and PV_HOST_CLIENT (tools/aoa_client.py). Not yet run on a phone.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
wake   # stay awake on USB: a screen-off relock would drop the USB session mid-case
OUT="${PV_TOKEN_OUT:-$PV_LOG_DIR/tokensign}"
[[ -x "$PY" && -s "$CLIENT" ]] || die "host client not staged ($PY / $CLIENT)"
[[ -s "$PAIRING" ]] || die "no pinned pairing at $PAIRING: run usbsigntest.sh first"

TO=7f3a9c04e2b16d58a41c0f9e6b2d7a8c5e1f4b93          # example recipient (not a real wallet)
SPENDER=3333333333333333333333333333333333333333      # example spender
USDC_ETH=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48   # USDC, Ethereum (Circle)
USDC_BASE=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913  # USDC, Base (Circle)
UNKNOWN=0x2222222222222222222222222222222222222222    # not in the built-in list
PAD=000000000000000000000000
MAX=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
AMT_50=0000000000000000000000000000000000000000000000000000000002faf080   # 50 000 000 = 50 USDC
AMT_2_5=00000000000000000000000000000000000000000000000000000000002625a0  # 2 500 000 = 2.5 USDC

find_checkbox() {
  local box=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    box="$(uidump | grep -o 'checkable="true"[^>]*bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' | head -1 | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/' || true)"
    [[ -n "$box" ]] && { echo "$box"; return 0; }
    scroll_down; sleep 0.6
  done
  return 1
}

# run_case <name> <screen title> <approve|reject> <sign button (xml-escaped)> <must-show text> -- sign-test args…
run_case() {
  local name="$1" title="$2" decision="$3" button="$4" must="$5"; shift 6
  echo "== $name"
  usb_reset; unlock_if_locked; go_home
  "$A" kill-server; sleep 1
  "$PY" "$CLIENT" --pairing-file "$PAIRING" sign-test --nonce 0x0 --priority-fee 0x3b9aca00 \
    --max-fee 0x4a817c800 --gas-limit 0x186a0 --value 0x0 "$@" > "$OUT.$name" 2>&1 &
  local pid=$! found=0 rc=0
  sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked
  for _ in $(seq 1 25); do sleep 2; kill -0 $pid 2>/dev/null || break; has_text "$title" && { found=1; break; }; done
  [[ $found -eq 1 ]] || { kill $pid 2>/dev/null || true; tail -3 "$OUT.$name"; die "$name: review '$title' never appeared: $(texts)"; }
  qa_shots "token-$name"
  local seen=0
  for _ in 1 2 3 4 5 6; do uidump | grep -qF "$must" && { seen=1; break; }; scroll_down; sleep 0.6; done
  [[ $seen -eq 1 ]] || { kill $pid 2>/dev/null || true; die "$name: review lacks '$must': $(texts 14)"; }
  pass "$name: review shows '$title' and '$must'"
  if [[ "$decision" == approve ]]; then
    # to the end of the review, then "I verified…" (+ "I understand: …" when the review has a DANGER)
    tick_review || { kill $pid 2>/dev/null || true; die "$name: review checkboxes not ticked: $(texts 10)"; }
    tap_text "$button"; sleep 3
    rc=0; wait $pid || rc=$?
    tail -6 "$OUT.$name" | sed -E 's/("signedTransaction": ")0x[0-9a-f]{20}[0-9a-f]*/\10x…/'
    [[ $rc -eq 0 ]] || die "$name: host client exited $rc"
    grep -q '"status": "approved"' "$OUT.$name" || die "$name: response not approved"
    expect_screen "Signature created"
    pass "$name: host verified to/value/data, hash and signer == pinned pairing"
  else
    find_checkbox >/dev/null || true
    tap_text "Reject request"; sleep 2
    rc=0; wait $pid || rc=$?
    [[ $rc -eq 2 ]] || { tail -3 "$OUT.$name"; die "$name: expected a clean rejection (exit 2), got $rc"; }
    grep -q '"status": "rejected"' "$OUT.$name" || die "$name: response not 'rejected'"
    expect_screen "Request rejected"
    pass "$name: rejected on the phone; no signature left the device"
  fi
  tap_text "Back to Wallet" 2>/dev/null || true
}

run_case usdc-transfer "Send 50 USDC" approve "Approve &amp; sign" "Send 50 USDC to 0x7F3A 9C04" -- \
  --chain-id 0x1 --to "$USDC_ETH" --data "0xa9059cbb${PAD}${TO}${AMT_50}"
run_case unlimited-approve "UNLIMITED permission" reject "" "UNLIMITED allowance" -- \
  --chain-id 0x1 --to "$USDC_ETH" --data "0x095ea7b3${PAD}${SPENDER}${MAX}"
run_case unknown-token "Unknown token transfer" reject "" "Unknown token contract $(evm_grouped "$UNKNOWN")" -- \
  --chain-id 0x1 --to "$UNKNOWN" --data "0xa9059cbb${PAD}${TO}${AMT_50}"
run_case base-increase "Review permission" approve "Approve permission &amp; sign" "allowance by 2.5 USDC" -- \
  --chain-id 0x2105 --to "$USDC_BASE" --data "0x39509351${PAD}${SPENDER}${AMT_2_5}"

echo "== trailing-byte (refused before review)"
usb_reset; unlock_if_locked; go_home
"$A" kill-server; sleep 1
rc=0
( "$PY" "$CLIENT" --pairing-file "$PAIRING" sign-test --chain-id 0x1 --gas-limit 0x186a0 --to "$USDC_ETH" \
    --data "0xa9059cbb${PAD}${TO}${AMT_50}00" > "$OUT.trailing" 2>&1 && echo 0 > "$OUT.trailing.rc" || echo $? > "$OUT.trailing.rc" ) &
sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked; wait
rc="$(cat "$OUT.trailing.rc")"
[[ "$rc" == 2 ]] && grep -q '"status": "error"' "$OUT.trailing" && grep -q 'trailing bytes' "$OUT.trailing" \
  || { tail -4 "$OUT.trailing"; die "trailing-byte calldata was not refused with an error (exit $rc)"; }
has_text "Send 50 USDC" && die "a review appeared for malformed calldata"
pass "trailing-byte calldata refused by the phone with no review"

kiosk_locked; no_crashes; unwake
pass "tokensigntest complete"
