#!/usr/bin/env bash
# Device attestation on a THROWAWAY dev phone (vault-os/docs/device-attestation.md). Not yet run.
#
#   1. unlocked: "attest" with a fresh 32-byte challenge answers with a StrongBox chain; the
#      companion's verifier (same Rust code as the app) checks it: DEVELOPMENT with Developer
#      mode (bootloader unlocked, dev-signed app), FAIL without it (development key)
#   2. the same challenge again is refused ("already answered")
#   3. locked: the request is held on the lock screen ("prove it is genuine"), nothing is
#      answered until the PIN, then the answer arrives and verifies
#   4. the wallet key was not used: no review screen ever appeared, no crash, kiosk still LOCKED
#
# Needs the pairing from usbsigntest.sh (PV_PAIRING_FILE), PV_HOST_PY / PV_HOST_CLIENT like the
# other USB scripts, and PV_ATTEST_VERIFIER: the companion's verifier binary, built with
#   cargo build --release --manifest-path companion/src-tauri/Cargo.toml --example attest_verify
# (target/release/examples/attest_verify). It fetches Google's revocation list if it can.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
PY="${PV_HOST_PY:-/root/pv-host/.venv/bin/python}"
CLIENT="${PV_HOST_CLIENT:-/root/pv-host/tools/aoa_client.py}"
PAIRING="${PV_PAIRING_FILE:-/root/pv-host/paired-signer.json}"
VERIFY="${PV_ATTEST_VERIFIER:-}"
[[ -x "$PY" && -s "$CLIENT" ]] || die "host client not staged ($PY / $CLIENT)"
[[ -s "$PAIRING" ]] || die "no pinned pairing at $PAIRING: run usbsigntest.sh first"
[[ -x "$VERIFY" ]] || die "set PV_ATTEST_VERIFIER to the built attest_verify example (see the header)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# attest <dir> [client args…]: one exchange over AOA (adb is stopped while the accessory is up)
attest() {
  local dir="$1"; shift
  "$A" kill-server; sleep 1
  local rc=0
  "$PY" "$CLIENT" --pairing-file "$PAIRING" attest --save "$dir" "$@" > "$dir.log" 2>&1 || rc=$?
  sleep 4; "$A" start-server >/dev/null 2>&1; wait_adb 12
  return $rc
}

# verdict <dir> <expected exit> [--dev-mode]
verdict() {
  local dir="$1" want="$2"; shift 2
  local rc=0
  "$VERIFY" "$dir/request.json" "$dir/response.json" "$@" > "$dir.report" 2>&1 || rc=$?
  "$PY" -c 'import json,sys; r=json.load(open(sys.argv[1])); d=r.get("details") or {}
print("  verdict:", r["verdict"], "-", r["headline"])
for k in ("problems","cautions","notes"):
    for x in r.get(k, []): print("  %s: %s" % (k[:-1], x))
for k in ("attestation_security_level","device_locked","verified_boot_state","os_patch_level","app_package","app_signer_kind","root","revocation"):
    print("  %s: %s" % (k, d.get(k)))' "$dir.report" 2>/dev/null || cat "$dir.report"
  [[ $rc -eq $want ]] || die "verifier exited $rc, expected $want ($dir.report)"
}

echo "== 1. unlocked attestation"
usb_reset; wake; unlock_if_locked; go_home
mkdir -p "$WORK/one"
attest "$WORK/one" || { cat "$WORK/one.log"; die "attest failed"; }
grep -q '"securityLevel": "StrongBox"' "$WORK/one/response.json" || die "not attested by StrongBox: $(grep securityLevel "$WORK/one/response.json")"
pass "phone answered with a StrongBox attestation for the pinned address"
verdict "$WORK/one" 10 --dev-mode
pass "verifier: DEVELOPMENT with Developer mode (chain to Google root, challenge, binding, app, unlocked bootloader)"
verdict "$WORK/one" 20
pass "verifier: FAIL without Developer mode (development-signed app)"
expect_not "Review"
pass "no review screen: the wallet key was not used"

echo "== 2. replayed challenge"
CHALLENGE="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["challenge"])' "$WORK/one/request.json")"
mkdir -p "$WORK/two"
rc=0; attest "$WORK/two" --challenge "$CHALLENGE" || rc=$?
[[ $rc -eq 2 ]] || { cat "$WORK/two.log"; die "a repeated challenge must be refused (exit 2), got $rc"; }
grep -q "already answered" "$WORK/two/response.json" || die "refusal does not say why: $(cat "$WORK/two/response.json")"
pass "the same challenge is answered only once"

echo "== 3. locked phone holds the request"
relock
mkdir -p "$WORK/three"
"$A" kill-server; sleep 1
"$PY" "$CLIENT" --pairing-file "$PAIRING" attest --save "$WORK/three" > "$WORK/three.log" 2>&1 &
pid=$!
sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12
seen=0; for _ in $(seq 1 10); do has_text "INCOMING REQUEST" && { seen=1; break; }; sleep 2; done
[[ $seen -eq 1 ]] || { kill $pid 2>/dev/null; die "locked phone did not show the held request: $(texts)"; }
uidump | grep -q "prove it is genuine" || { kill $pid 2>/dev/null; die "held request is not described as a device check: $(texts 10)"; }
kill -0 $pid 2>/dev/null || die "the host got an answer from a LOCKED phone"
pass "locked: request held and described, nothing answered"
unlock
rc=0; wait $pid || rc=$?
[[ $rc -eq 0 ]] || { cat "$WORK/three.log"; die "after unlock the attestation did not complete ($rc)"; }
verdict "$WORK/three" 10 --dev-mode
pass "after unlock: answered and verified"

kiosk_locked; no_crashes; unwake
pass "attesttest complete"
