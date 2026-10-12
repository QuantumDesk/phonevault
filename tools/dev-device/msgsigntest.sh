#!/usr/bin/env bash
# Message-signing round trips on a THROWAWAY dev phone: personal_sign (text, sign-in for someone
# else, unreadable bytes) and eth_signTypedData_v4 (EIP-712 Mail example, Permit2 unlimited
# allowance). Each request is reviewed on the phone over adb; approvals are verified by the host
# (digest compared with one derived on the host, signer recovered and compared with the pinned
# pairing), rejections must come back as schema-exact "rejected" responses.
#
# Needs a pinned pairing from usbsigntest.sh (PV_PAIRING_FILE), PV_HOST_PY (venv python with
# pyusb) and PV_HOST_CLIENT (tools/aoa_client.py). Vectors come from the app's shared fixture.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
PY="${PV_HOST_PY:-/root/pv-host/.venv/bin/python}"
CLIENT="${PV_HOST_CLIENT:-/root/pv-host/tools/aoa_client.py}"
PAIRING="${PV_PAIRING_FILE:-/root/pv-host/paired-signer.json}"
VECTORS="${PV_VECTORS:-$(cd "$(dirname "$0")/../.." && pwd)/app/src/test/resources/message-signing-vectors.json}"
OUT="${PV_MSG_OUT:-/tmp/msgsign}"
[[ -x "$PY" && -s "$CLIENT" ]] || die "host client not staged ($PY / $CLIENT)"
[[ -s "$PAIRING" ]] || die "no pinned pairing at $PAIRING: run usbsigntest.sh first"
[[ -s "$VECTORS" ]] || die "vector fixture not found: $VECTORS"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# vector <name> <field>: one field of the shared fixture
vector() { "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(next(v for v in d["vectors"] if v["name"]==sys.argv[2])[sys.argv[3]], end="")' "$VECTORS" "$1" "$2"; }
vector eip712-mail typedData > "$WORK/mail.json"
vector permit2-single typedData > "$WORK/permit2.json"
MAIL_DIGEST="$(vector eip712-mail digest)"
PERMIT2_DIGEST="$(vector permit2-single digest)"
SIWE_OTHER_HEX="$(vector personal-siwe message)"   # signs in as the EIP-712 example account, not this wallet
BINARY_HEX="$(vector personal-binary-32 message)"

# scroll until the review checkbox is visible (message reviews can be long); prints its bounds
find_checkbox() {
  local box="" i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    box="$(uidump | grep -o 'checkable="true"[^>]*bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' | head -1 | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/' || true)"
    [[ -n "$box" ]] && { echo "$box"; return 0; }
    scroll_down; sleep 0.6
  done
  return 1
}

# run_case <name> <screen title> <approve|reject> <sign button text (xml-escaped)> <must-show text> -- client args…
run_case() {
  local name="$1" title="$2" decision="$3" button="$4" must="$5"; shift 6
  echo "== $name"
  usb_reset; unlock_if_locked; go_home
  "$A" kill-server; sleep 1
  "$PY" "$CLIENT" --pairing-file "$PAIRING" sign-message "$@" > "$OUT.$name" 2>&1 &
  local pid=$! found=0 rc=0
  sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked
  for _ in $(seq 1 25); do sleep 2; kill -0 $pid 2>/dev/null || break; has_text "$title" && { found=1; break; }; done
  [[ $found -eq 1 ]] || { kill $pid 2>/dev/null || true; tail -3 "$OUT.$name"; die "$name: review '$title' never appeared: $(texts)"; }
  local seen=0 i
  for i in 1 2 3 4 5 6; do uidump | grep -qF "$must" && { seen=1; break; }; scroll_down; sleep 0.6; done
  [[ $seen -eq 1 ]] || { kill $pid 2>/dev/null || true; die "$name: review lacks '$must': $(texts 14)"; }
  pass "$name: review shows '$title' and '$must'"
  if [[ "$decision" == approve ]]; then
    local box; box="$(find_checkbox)" || { kill $pid 2>/dev/null || true; die "$name: review checkbox not visible"; }
    tap_bounds "$box"; sleep 1
    tap_text "$button"; sleep 3
    rc=0; wait $pid || rc=$?
    tail -6 "$OUT.$name" | sed -E 's/("signature": ")0x[0-9a-f]{16}[0-9a-f]*/\10x…/'
    [[ $rc -eq 0 ]] || die "$name: host client exited $rc"
    grep -q '"status": "approved"' "$OUT.$name" || die "$name: response not approved"
    expect_screen "Signature created"
    pass "$name: host verified the digest and recovered signer == pinned pairing"
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

run_case text "Review message" approve "Approve &amp; sign" "Phone Vault message test" -- \
  --text "Phone Vault message test $(date -u +%Y-%m-%dT%H:%M:%SZ)" --chain-id 0x1
run_case siwe-other "Review sign-in" reject "" "NOT this wallet" -- --hex "$SIWE_OTHER_HEX" --chain-id 0x1
run_case unreadable "Review unreadable data" reject "" "Unreadable data" -- --hex "$BINARY_HEX" --chain-id 0x1
run_case mail "Review typed data" approve "Approve &amp; sign" "Ether Mail" -- \
  --typed-file "$WORK/mail.json" --expect-digest "$MAIL_DIGEST" --chain-id 0x1
run_case permit2 "Review token allowance" approve "Approve permission &amp; sign" "UNLIMITED" -- \
  --typed-file "$WORK/permit2.json" --expect-digest "$PERMIT2_DIGEST" --chain-id 0x1
# Chain mismatch: the same Permit2 message while the host says Base.
run_case permit2-wrong-chain "Review token allowance" reject "" "but your host is on Base" -- \
  --typed-file "$WORK/permit2.json" --expect-digest "$PERMIT2_DIGEST" --chain-id 0x2105

kiosk_locked; no_crashes; unwake
pass "msgsigntest complete"
