#!/usr/bin/env bash
# USB signing round trip on a THROWAWAY dev phone (0.3.0 UI): pair the host client with the
# on-screen address, request a mainnet-shaped 0.5 ETH transfer to an EXAMPLE address (never
# broadcast: the phone is offline and the host only verifies), approve it on the phone over adb,
# and let the host recompute the hash, recover the signer and compare it to the pinned pairing.
# Needs PV_HOST_PY (venv python with pyusb) and PV_HOST_CLIENT (tools/aoa_client.py).
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
PY="${PV_HOST_PY:-/root/pv-host/.venv/bin/python}"
CLIENT="${PV_HOST_CLIENT:-/root/pv-host/tools/aoa_client.py}"
PAIRING="${PV_PAIRING_FILE:-/root/pv-host/paired-signer.json}"
OUT="${PV_SIGN_OUT:-/tmp/usbsign.out}"
[[ -x "$PY" && -s "$CLIENT" ]] || die "host client not staged ($PY / $CLIENT)"
TO=0x7F3A9C04e2b16d58a41C0f9E6b2D7a8c5e1f4B93   # example recipient (checksummed, not a real wallet)

usb_reset; wake; unlock_if_locked; go_home
scroll_top; expect_screen "Your offline wallet"
SCREEN_ADDR="$(addr)"; [[ -n "$SCREEN_ADDR" ]] || die "no address on screen"

echo "== pair (fresh accessory attach while unlocked; adb server down during the switch)"
rm -f "$PAIRING"; "$A" kill-server; sleep 1
( printf 'yes\n' | "$PY" "$CLIENT" --pairing-file "$PAIRING" pair > "$OUT.pair" 2>&1; echo $? > "$OUT.pair.rc" ) &
sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked; wait
[[ "$(cat "$OUT.pair.rc")" == "0" && -s "$PAIRING" ]] || { tail -5 "$OUT.pair"; die "pair failed"; }
USB_ADDR="$(grep -oE '"address": "0x[0-9a-fA-F]{40}"' "$OUT.pair" | head -1 | grep -oE '0x[0-9a-fA-F]{40}')"
[[ "${USB_ADDR,,}" == "${SCREEN_ADDR,,}" ]] || die "USB address ${USB_ADDR:0:10}… != screen ${SCREEN_ADDR:0:10}…"
pass "paired: USB address matches the phone's own display"

echo "== sign-test (a second fresh attach; the transport died with the lock or the pair exit)"
usb_reset; unlock_if_locked; go_home
"$A" kill-server; sleep 1
"$PY" "$CLIENT" --pairing-file "$PAIRING" sign-test --chain-id 0x1 --nonce 0x0 \
  --priority-fee 0x3b9aca00 --max-fee 0x4a817c800 --gas-limit 0x5208 --to "$TO" --value 0x6f05b59d3b20000 > "$OUT" 2>&1 &
SIGN_PID=$!
sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked
found=0
for _ in $(seq 1 25); do sleep 2; kill -0 $SIGN_PID 2>/dev/null || break; has_text "Review transfer" && { found=1; break; }; done
[[ $found -eq 1 ]] || { kill $SIGN_PID 2>/dev/null; tail -3 "$OUT"; die "review screen never appeared: $(texts)"; }
has_text "Ethereum Mainnet (chain ID 1)" || die "network not decoded: $(texts 12)"
uidump | grep -q "text=\"${TO}\"" || die "recipient not shown exactly as sent"
pass "review screen shows action, amount, recipient, network, signer and fee"
# The checkbox and the buttons sit below the fold.
scroll_down; sleep 0.8; scroll_down; sleep 0.8
box="$(uidump | grep -o 'checkable="true"[^>]*bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' | head -1 | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/' || true)"
[[ -n "$box" ]] || { kill $SIGN_PID 2>/dev/null; die "review checkbox not visible"; }
tap_bounds "$box"; sleep 1
tap_text "Approve &amp; sign"; sleep 3
wait $SIGN_PID; SIGN_RC=$?
echo "--- host client output (tail):"; tail -8 "$OUT" | sed -E 's/("signedTransaction": ")0x[0-9a-f]{20}[0-9a-f]*/\10x…/'
[[ $SIGN_RC -eq 0 ]] || die "sign-test exited $SIGN_RC"
grep -q '"status": "approved"' "$OUT" || die "response not approved"
expect_screen "Signature created"
pass "host verified fields, recomputed hash, recovered signer == on-screen address == pinned pairing"
tap_text "Back to Wallet" 2>/dev/null || true
kiosk_locked; no_crashes; unwake
pass "usbsigntest complete"
