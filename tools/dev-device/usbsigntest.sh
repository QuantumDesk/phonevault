#!/usr/bin/env bash
# USB signing round trip on a THROWAWAY dev phone: pair the host client with the on-screen
# address, request a disposable Sepolia signature, approve it on the phone (driven over adb,
# which survives AOA because the gadget becomes accessory+adb), and let the host verify hash,
# signer recovery and the pinned identity. Needs PV_HOST_PY (venv python with pyusb) and the
# tools/ checkout next to it.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
PY="${PV_HOST_PY:-/root/pv-host/.venv/bin/python}"
CLIENT="${PV_HOST_CLIENT:-/root/pv-host/tools/aoa_client.py}"
PAIRING="${PV_PAIRING_FILE:-/root/pv-host/paired-signer.json}"
[[ -x "$PY" && -s "$CLIENT" ]] || die "host client not staged ($PY / $CLIENT)"
# Leave any stale accessory session from a prior run: reset the gadget to plain adb so the
# next client run triggers a FRESH ACCESSORY_ATTACHED and the app opens a new transport.
"$A" shell svc usb setFunctions >/dev/null 2>&1 || true
sleep 6; wait_adb 12
wake
has_text "LOCKED" && unlock
expect_screen "PHONE VAULT"
SCREEN_ADDR="$(addr)"; [[ -n "$SCREEN_ADDR" ]] || die "no address on screen"
echo "on-screen address prefix: ${SCREEN_ADDR:0:10}…"

echo "== pair (the client fetches the address over USB; we confirm it against the phone's screen)"
rm -f "$PAIRING"
# The host adb server holds the device's USB interfaces (EBUSY for libusb). Release them for
# the AOA switch; once the phone is in accessory+adb mode both can coexist on separate interfaces.
"$A" kill-server; sleep 2
PAIR_OUT="$(printf 'yes\n' | "$PY" "$CLIENT" --pairing-file "$PAIRING" pair 2>&1)" || { echo "$PAIR_OUT" | tail -5; "$A" start-server >/dev/null 2>&1; die "pair failed"; }
"$A" start-server >/dev/null 2>&1
USB_ADDR="$(echo "$PAIR_OUT" | grep -oE '"address": "0x[0-9a-fA-F]{40}"' | head -1 | grep -oE '0x[0-9a-fA-F]{40}')"
[[ -n "$USB_ADDR" ]] || { echo "$PAIR_OUT" | tail -5; die "no address in pair output"; }
[[ "${USB_ADDR,,}" == "${SCREEN_ADDR,,}"* || "${USB_ADDR,,}" == "${SCREEN_ADDR,,}" ]] || die "USB address ${USB_ADDR:0:10}… does not match the screen ${SCREEN_ADDR:0:10}…"
[[ -s "$PAIRING" ]] || die "pairing file not written"
pass "paired: USB address matches the phone's own display"

echo "== sign-test (waits for on-phone approval)"
"$A" kill-server; sleep 2
"$PY" "$CLIENT" --pairing-file "$PAIRING" sign-test > /tmp/usbsign.out 2>&1 &
SIGN_PID=$!
sleep 5; "$A" start-server >/dev/null 2>&1; wait_adb 12
# Approve on the phone: find the review checkbox and the Sign button by live UI bounds.
found=0
for _ in $(seq 1 40); do
  sleep 2
  if uidump | grep -q 'text="Approve transaction?"'; then found=1; break; fi
done
[[ $found -eq 1 ]] || { kill $SIGN_PID 2>/dev/null; die "approval screen never appeared: $(texts)"; }
pass "approval screen shown"
box="$(uidump | grep -o 'checkable="true"[^>]*bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' | head -1 | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/')"
[[ -n "$box" ]] || { kill $SIGN_PID 2>/dev/null; die "review checkbox not found"; }
read -r x1 y1 x2 y2 <<<"$box"; "$A" shell input tap $(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 )); sleep 1
tap_text "Sign"; sleep 2
wait $SIGN_PID; SIGN_RC=$?
echo "--- host client output (tail):"; tail -12 /tmp/usbsign.out | sed -E 's/("signedTransaction": ")0x[0-9a-f]{20}[0-9a-f]*/\10x…/'
[[ $SIGN_RC -eq 0 ]] || die "sign-test exited $SIGN_RC"
grep -q '"status": "approved"' /tmp/usbsign.out || die "response not approved"
pass "host verified fields, recomputed hash, recovered signer == on-screen address == pinned pairing"
sleep 2; wait_adb 12
echo "phone status: $(texts 4)"
kiosk_locked; no_crashes; unwake
pass "usbsigntest complete"
