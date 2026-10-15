#!/usr/bin/env bash
# "Safety you can see" round trips on a THROWAWAY dev phone:
#   1. first send to an address  → "First time sending to this address"; approve; on the receipt
#      "Save recipient … as contact", typed on the phone's own keyboard as "Alice"
#   2. second send to it         → "Saved contact: Alice (named on this phone)" + "Sent here once before"; reject
#   3. a poisoned look-alike     → DANGER "Looks like … but it is a DIFFERENT address" + chunk grid; reject
#   4. setApprovalForAll(op,true) on an unknown collection → "Permission for EVERY NFT"; reject
#   5. a real Universal Router swap (mainnet tx 0x65b058dd…, from swap-vectors.json) →
#      "You get at least 227.107032 USDC · Recipient: this wallet ✓"; reject
#   6. an unknown contract call  → refused by the phone with no review ("Contract call refused")
#   7. personal_sign of an EIP-7702 authorization tuple → refused ("Delegation refused")
#   8. ☰ → Address book → Alice → Delete → the book is empty again
# Nothing is broadcast: the phone is offline and the host only verifies the one approved
# signature (fields, recomputed hash, recovered signer == pinned pairing).
#
# Needs a pinned pairing from usbsigntest.sh (PV_PAIRING_FILE), PV_HOST_PY (venv python with
# pyusb) and PV_HOST_CLIENT (tools/aoa_client.py).
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
wake   # stay awake on USB: a screen-off relock would drop the USB session mid-case
VECTORS="${PV_SWAP_VECTORS:-$(cd "$(dirname "$0")/../.." && pwd)/app/src/test/resources/swap-vectors.json}"
OUT="${PV_SAFETY_OUT:-$PV_LOG_DIR/safetytest}"
[[ -x "$PY" && -s "$CLIENT" ]] || die "host client not staged ($PY / $CLIENT)"
[[ -s "$PAIRING" ]] || die "no pinned pairing at $PAIRING: run usbsigntest.sh first"
[[ -s "$VECTORS" ]] || die "swap vectors not found: $VECTORS"

# Example recipient (not a real wallet), fresh each run: the phone keeps a per-wallet send history
# with no way to clear it, so a fixed address would only be "First time" once per wallet.
ALICE="0xabcd$(od -An -N16 -tx1 /dev/urandom | tr -d " \n")1234"
POISON=0xabcd000000000000000000000000000000001234   # same first 4 / last 4 characters
UNKNOWN_NFT=0x5555555555555555555555555555555555555555
OPERATOR=3333333333333333333333333333333333333333
PAD=000000000000000000000000
swap_field() { "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1]))["vectors"]; print(next(v for v in d if v["tx"].startswith(sys.argv[2]))[sys.argv[3]], end="")' "$VECTORS" "$1" "$2"; }
SWAP_TO="$(swap_field 0x65b058dd to)"
SWAP_DATA="$(swap_field 0x65b058dd data)"
# 0x05 ‖ rlp([1, 0x63c0…e32b, 0]): an EIP-7702 authorization tuple
AUTH_HEX=0x05d7019463c0c19a282a1b52b07dd5a65b58948a07dae32b80
ensure_account1   # the pairing pins Account 1: a request "from" another active account is refused

find_checkbox() {
  local box=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    box="$(uidump | grep -o 'checkable="true"[^>]*bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' | head -1 | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/' || true)"
    [[ -n "$box" ]] && { echo "$box"; return 0; }
    scroll_down; sleep 0.6
  done
  return 1
}

# start_request <name> <client subcommand + args…>: sends in the background, sets $pid
start_request() {
  local name="$1"; shift
  usb_reset; unlock_if_locked; go_home
  "$A" kill-server; sleep 1
  "$PY" "$CLIENT" --pairing-file "$PAIRING" "$@" > "$OUT.$name" 2>&1 &
  pid=$!
  sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked
}

# review <name> <title> <must-show…>: waits for the review, then scrolls for every fragment
review() {
  local name="$1" title="$2"; shift 2
  local found=0 f seen
  for _ in $(seq 1 25); do sleep 2; kill -0 $pid 2>/dev/null || break; has_text "$title" && { found=1; break; }; done
  [[ $found -eq 1 ]] || { kill $pid 2>/dev/null || true; tail -3 "$OUT.$name"; die "$name: review '$title' never appeared: $(texts)"; }
  qa_shots "safety-$name"
  for f in "$@"; do
    seen=0
    for _ in 1 2 3 4 5 6 7 8; do uidump | grep -qF "$f" && { seen=1; break; }; scroll_down; sleep 0.6; done
    [[ $seen -eq 1 ]] || { kill $pid 2>/dev/null || true; die "$name: review lacks '$f': $(texts 14)"; }
    scroll_top
  done
  pass "$name: review '$title' shows: $*"
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

# refused <name> <phone title> <error fragment>: the phone answers an error and shows why
refused() {
  local name="$1" title="$2" frag="$3" rc=0
  wait $pid || rc=$?
  [[ $rc -ne 0 ]] && grep -q '"status": "error"' "$OUT.$name" && grep -qF "$frag" "$OUT.$name" \
    || { tail -4 "$OUT.$name"; die "$name: expected an error containing '$frag' (exit $rc)"; }
  sleep 2; expect_screen "$title"
  tap_text "Continue" 2>/dev/null || true
  pass "$name: refused with '$frag'; the phone showed '$title'"
}

send_eth() { start_request "$1" sign-test --chain-id 0x1 --nonce 0x0 --priority-fee 0x3b9aca00 --max-fee 0x4a817c800 \
  --gas-limit 0x5208 --value 0x38d7ea4c68000 --to "$2" --data 0x; }

echo "== 1. first send, save as contact"
send_eth first "$ALICE"
review first "Review transfer" "First time sending to this address"
tick_review || die "first: review checkboxes not ticked: $(texts 10)"
tap_text "Approve &amp; sign"; sleep 3
rc=0; wait $pid || rc=$?
[[ $rc -eq 0 ]] && grep -q '"status": "approved"' "$OUT.first" || { tail -6 "$OUT.first"; die "first: not approved/verified (exit $rc)"; }
expect_screen "Signature created"
tap_text "Save recipient 0xabcd…1234 as contact"; sleep 1.2
expect_screen "Type a name"
for k in A l i c e; do tap_text "$k"; sleep 0.4; done
expect_screen "Alice▌"
tap_text "Save name"; sleep 1.5
pass "first: signed, host-verified, saved as contact 'Alice'"

echo "== 2. repeat send shows the contact and the history"
send_eth second "$ALICE"
review second "Review transfer" "Alice (named on this phone)" "Sent here once before"
reject second

echo "== 3. address-poisoning look-alike"
send_eth poison "$POISON"
review poison "Review transfer" "but it is a DIFFERENT address" "✗ DIFFERENT"
reject poison

echo "== 4. setApprovalForAll on an unknown collection"
start_request nft sign-test --chain-id 0x1 --gas-limit 0x186a0 --to "$UNKNOWN_NFT" --data "0xa22cb465${PAD}${OPERATOR}0000000000000000000000000000000000000000000000000000000000000001"
review nft "Permission for EVERY NFT" "move EVERY NFT in this collection, now and in future"
reject nft

echo "== 5. real Universal Router swap"
start_request swap sign-test --chain-id 0x1 --gas-limit 0x493e0 --to "$SWAP_TO" --data "$SWAP_DATA"
review swap "Swap" "You get at least 227.107032 USDC" "Recipient: this wallet ✓"
reject swap

echo "== 6. unknown contract call"
start_request unknown sign-test --chain-id 0x1 --gas-limit 0x186a0 --to "$UNKNOWN_NFT" --data 0x1249c58b
refused unknown "Contract call refused" "can't be explained by the phone"

echo "== 7. EIP-7702 authorization as a message"
start_request delegation sign-message --hex "$AUTH_HEX" --chain-id 0x1
refused delegation "Delegation refused" "Account delegation (EIP-7702) is not supported"

echo "== 8. address book: delete the contact"
go_home; open_menu || die "menu did not open"
tap_text "Address book"; sleep 1.2
expect_screen "Contacts"
tap_text "Alice · 0xabcd…1234"; sleep 1.2
tap_text "Delete contact"; sleep 1
tap_text "Delete"; sleep 1.2
expect_screen "No contacts yet"
pass "address book: contact deleted without a PIN"

kiosk_locked; no_crashes; unwake
pass "safetytest complete"
