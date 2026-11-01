#!/usr/bin/env bash
# Device attestation on a THROWAWAY dev phone (vault-os/docs/device-attestation.md). Not yet run.
#
#   1. unlocked: "attest" with a fresh 32-byte challenge answers with a StrongBox chain; the
#      companion's verifier (same Rust code as the app) checks it: DEVELOPMENT with Developer
#      mode (bootloader unlocked, dev-signed app), FAIL without it (development key)
#   2. the same challenge again is refused ("already answered")
#   3. locked: the request is held on the lock screen ("prove it is genuine"), the system PIN
#      prompt over it says so where it is readable ("Incoming request", "From your Mac",
#      "Hardware check."), nothing is answered until the PIN, then the answer arrives and verifies
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
# A review page's title is a short "Review transfer" / "Review message" / … ; Home's own line
# "Review every request here. Your keys stay on this phone." is not one (a prefix match on "Review"
# failed on it).
if uidump | grep -qE 'text="Review [A-Za-z -]{1,40}"'; then die "a review screen appeared: $(texts 8)"; fi
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
# Credential mode: the locked page opens the system PIN prompt at once, and it covers the page.
# The prompt itself must say a request waits (title "Incoming request", "From your Mac", the kind
# only): a prompt already open when the request arrives is re-shown with that text. Where the
# prompt is drawn readable (Pixel 6a) uiautomator sees only the prompt: read it, then dismiss it
# once (Back = cancel; the locked page and its Unlock button stay) to read what the page shows.
# Where it is a secure window (crosshatch) its text cannot be read; the page under it can.
seen=0; dismissed=0; readable=0; said=0
for _ in $(seq 1 12); do
  dump="$(uidump)"
  if grep -q 'text="Incoming request"' <<<"$dump"; then
    readable=1
    grep -q 'text="From your Mac"' <<<"$dump" || { kill $pid 2>/dev/null; die "the PIN prompt does not say who sent the request: $(texts 8)"; }
    grep -q 'text="Hardware check\. Unlock to review it\. Nothing is signed until you approve it\."' <<<"$dump" \
      || { kill $pid 2>/dev/null; die "the PIN prompt does not name the request's kind: $(texts 8)"; }
    said=1
  elif grep -q 'text="Enter your PIN to unlock' <<<"$dump"; then
    readable=1   # the plain prompt: it is cancelled and re-shown with the request in a moment
  fi
  grep -q 'text="INCOMING REQUEST' <<<"$dump" && { seen=1; break; }
  if [[ $dismissed -eq 0 ]] && system_prompt_up && { [[ $said -eq 1 || $readable -eq 0 ]]; }; then
    "$A" shell input keyevent KEYCODE_BACK </dev/null; dismissed=1; sleep 1.5; continue
  fi
  sleep 2
done
[[ $readable -eq 0 || $said -eq 1 ]] || { kill $pid 2>/dev/null; die "the PIN prompt never said a request is waiting: $(texts 8)"; }
[[ $readable -eq 1 ]] && pass "locked: the PIN prompt says a request is waiting (from your Mac, a hardware check)" \
  || echo "note: the PIN prompt is a secure window here; its text was not read"
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
