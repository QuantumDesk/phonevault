#!/usr/bin/env bash
# Reconnect without a replug on a THROWAWAY dev phone: every request below is a FRESH host client
# process, and nothing between two requests resets USB from the phone side (no `usb_reset`, no
# `svc usb`): adb only taps, keys the PIN and is stopped while the client talks (as everywhere).
#   1. first request: a fresh accessory attach (the one usb_reset at the start sets this up)
#   2. client restart: a new process on the live session (no handshake, no port reset)
#   3. lock → unlock → request: the app reopened the still-attached accessory after the lock
#   4. lock → request → unlock: held behind the gate (nothing answered while locked), then answered
#   5. client killed mid-request: the phone's answer to it is drained, the next client gets its own
#   6. a session the phone ended itself (a malformed line): the phone opens the still-attached
#      accessory again by itself (beta5); an older app needs the host's re-attach (START + USB port
#      reset). Either way: answered, no replug
#   7. the host gives up while its request is held behind the lock (the Pixel 6a beta4 wedge:
#      later clients were not answered until a replug): the vault stays locked, the client times
#      out; unlock, then a NEW client is answered, without a replug
# Before this fix (vault-os docs: stale accessory session) 3, 4 and 6 timed out ("[Errno 110]")
# unless the gadget was reset over adb. Needs the pairing from usbsigntest.sh for step 5.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
OUT="${PV_RECONNECT_OUT:-$PV_LOG_DIR/reconnect.out}"
[[ -x "$PY" && -s "$CLIENT" ]] || die "host client not staged ($PY / $CLIENT)"
[[ -s "$PAIRING" ]] || die "no pairing in $PAIRING: run usbsigntest.sh first"
TO=0x7F3A9C04e2b16d58a41C0f9E6b2D7a8c5e1f4B93   # example recipient (never broadcast)
RECOVERED="attaching it afresh"                   # what the client says when it had to re-attach

usb_reset; wake; unlock_if_locked; ensure_account1
scroll_top; expect_screen "Your offline wallet"
SCREEN_ADDR="$(addr)"; [[ -n "$SCREEN_ADDR" ]] || die "no address on screen"

# ask <name>: getAddress from a new client process, adb server down while it runs; checks the
# answer is the on-screen address and prints how long the connect took.
ask() {
  local name="$1" t0 rc=0 got
  "$A" kill-server; sleep 1
  t0=$(date +%s)
  "$PY" "$CLIENT" --pairing-file "$PAIRING" address > "$OUT.$name" 2>&1 || rc=$?
  ELAPSED=$(( $(date +%s) - t0 ))
  "$A" start-server >/dev/null 2>&1; wait_adb 12; nudge
  [[ $rc -eq 0 ]] || { tail -4 "$OUT.$name"; die "$name: client exited $rc after ${ELAPSED}s"; }
  got="$(grep -oE '"address": "0x[0-9a-fA-F]{40}"' "$OUT.$name" | head -1 | grep -oE '0x[0-9a-fA-F]{40}')"
  [[ "${got,,}" == "${SCREEN_ADDR,,}" ]] || die "$name: USB address ${got:0:10}… != screen ${SCREEN_ADDR:0:10}…"
}
# Screen off locks the vault (onStop). lib.sh's relock wakes it after 2 s, which right after a USB
# exchange was sometimes too soon (still Home); give it 4 s and one retry.
lock_vault() {
  local i
  for i in 1 2; do
    "$A" shell input keyevent KEYCODE_SLEEP; sleep 4; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 3
    for _ in 1 2 3 4 5; do locked_now && return 0; sleep 1.5; done
    echo "  (screen-off did not lock on try $i; again)"
  done
  die "expected a locked vault after screen-off, saw: $(texts)"
}
# The phone's own session must have been there: no host-side re-attach.
no_recovery() { ! grep -q "$RECOVERED" "$OUT.$1" || die "$1: the host had to re-attach the accessory (the phone did not reopen its session)"; }

echo "== 1. first request (fresh attach)"
"$A" kill-server; sleep 1
( rc=0; "$PY" "$CLIENT" --pairing-file "$PAIRING" address > "$OUT.first" 2>&1 || rc=$?; echo $rc > "$OUT.first.rc" ) &
sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked; wait
[[ "$(cat "$OUT.first.rc")" == "0" ]] || { tail -4 "$OUT.first"; die "first request failed"; }
pass "first request answered (fresh attach)"

echo "== 2. client restart on the live session"
ask restart; no_recovery restart
pass "a new client process reuses the live session (${ELAPSED}s, no handshake, no reset)"

echo "== 3. lock, unlock, then a request"
lock_vault; unlock; go_home
ask afterlock; no_recovery afterlock
[[ $ELAPSED -le 8 ]] || die "afterlock: connect took ${ELAPSED}s"
pass "after a lock the phone reopened the attached accessory: answered in ${ELAPSED}s, no replug, no adb USB reset"

echo "== 4. lock, request while locked, unlock"
lock_vault
"$A" kill-server; sleep 1
"$PY" "$CLIENT" --pairing-file "$PAIRING" address > "$OUT.locked" 2>&1 &
pid=$!
sleep 8; "$A" start-server >/dev/null 2>&1; wait_adb 12
kill -0 $pid 2>/dev/null || { tail -4 "$OUT.locked"; die "the host got an answer (or gave up) while the vault was LOCKED"; }
pass "locked: the request is held, nothing answered"
unlock
rc=0; wait $pid || rc=$?
[[ $rc -eq 0 ]] || { tail -4 "$OUT.locked"; die "after unlock the held request did not complete ($rc)"; }
grep -qiF "\"address\": \"$SCREEN_ADDR\"" "$OUT.locked" || die "held request answered with another address"
no_recovery locked
pass "after unlock the held request was answered on the same session"
go_home

echo "== 5. client killed mid-request; its answer must not reach the next client"
"$A" kill-server; sleep 1
"$PY" "$CLIENT" --pairing-file "$PAIRING" sign-test --chain-id 0x1 --nonce 0x0 --priority-fee 0x3b9aca00 \
  --max-fee 0x4a817c800 --gas-limit 0x5208 --to "$TO" --value 0x1 > "$OUT.orphan" 2>&1 &
pid=$!
sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked
found=0
for _ in $(seq 1 25); do sleep 2; kill -0 $pid 2>/dev/null || break; has_text "Review transfer" && { found=1; break; }; done
[[ $found -eq 1 ]] || { kill $pid 2>/dev/null || true; tail -3 "$OUT.orphan"; die "review screen never appeared: $(texts)"; }
kill -9 $pid 2>/dev/null || true; wait $pid 2>/dev/null || true
for _ in 1 2 3 4 5 6; do has_text "Reject request" && break; scroll_down; sleep 0.6; done
tap_text "Reject request"; sleep 3   # the phone answers "rejected" to a client that is gone
tap_text "Back to Wallet" 2>/dev/null || true; go_home
ask orphan; no_recovery orphan
pass "the next client drained the orphaned answer and got its own (${ELAPSED}s)"

echo "== 6. a session the phone ended itself"
"$A" kill-server; sleep 1
# A malformed line: AccessoryTransport ends the session on purpose (it is not reopened, the
# accessory stays attached), so the phone is in accessory mode with nothing reading it.
"$PY" - "$(dirname "$CLIENT")" > "$OUT.malformed" 2>&1 <<'PY' || { "$A" start-server >/dev/null 2>&1; cat "$OUT.malformed"; die "could not send the malformed line"; }
import sys
sys.path.insert(0, sys.argv[1])
import aoa_client
endpoint_in, endpoint_out = aoa_client.connect()
endpoint_out.write(b"{not json\n", timeout=5000)
PY
sleep 3; "$A" start-server >/dev/null 2>&1; wait_adb 12; nudge; unlock_if_locked; go_home
ask stale
if grep -q "$RECOVERED" "$OUT.stale"; then
  pass "a dead session on a still-attached accessory: the host re-attached it (START + port reset) in ${ELAPSED}s, no replug"
else
  pass "a dead session on a still-attached accessory: the phone reopened it by itself, answered in ${ELAPSED}s, no replug"
fi

echo "== 7. host times out while its request is held behind the lock; then a new client"
lock_vault
"$A" kill-server; sleep 1
# A short --timeout plays a host that gives up (the companion's own wait is 300 s).
rc=0; t0=$(date +%s)
"$PY" "$CLIENT" --pairing-file "$PAIRING" --timeout 20 address > "$OUT.gaveup" 2>&1 || rc=$?
gaveup_after=$(( $(date +%s) - t0 ))
"$A" start-server >/dev/null 2>&1; wait_adb 12
[[ $rc -ne 0 ]] || { tail -4 "$OUT.gaveup"; die "gaveup: the host got an answer while the vault was LOCKED"; }
grep -q "Timed out waiting" "$OUT.gaveup" || { tail -4 "$OUT.gaveup"; die "gaveup: expected the client to time out (exit $rc)"; }
pass "locked: the request was held, the host gave up after ${gaveup_after}s"
unlock; sleep 3; go_home
ask aftergaveup
pass "after the host gave up behind the lock, a new client was answered in ${ELAPSED}s, no replug"
if grep -q "$RECOVERED" "$OUT.aftergaveup"; then echo "  (the host re-attached the accessory first)"; fi

kiosk_locked; no_crashes; unwake
pass "reconnecttest complete"
