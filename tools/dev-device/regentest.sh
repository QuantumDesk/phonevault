#!/usr/bin/env bash
# Two-phase wallet replacement on a THROWAWAY dev phone: cancel keeps the wallet, activate swaps
# address (+ QR) and the new wallet survives a relock. Starts from any state; needs PV_TEST_PIN.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
wake
relock
unlock
BEFORE="$(addr)"; [[ -n "$BEFORE" ]] || die "no address on home"

tap_text "Regenerate wallet"; sleep 1.5; expect_screen "Regenerate wallet?"
tap_text "Continue"; sleep 5; expect_screen "NEW RECOVERY PHRASE"
tap_text "Cancel · keep current wallet"; sleep 3; expect_screen "PHONE VAULT"
[[ "$(addr)" == "$BEFORE" ]] || die "cancel changed the address: $BEFORE → $(addr)"
pass "cancel keeps the current wallet"

tap_text "Regenerate wallet"; sleep 1.5; tap_text "Continue"; sleep 5; expect_screen "NEW RECOVERY PHRASE"
tap_text "Activate new wallet"; sleep 5; expect_screen "PHONE VAULT"
AFTER="$(addr)"; [[ -n "$AFTER" && "$AFTER" != "$BEFORE" ]] || die "activate did not change the address ($BEFORE → $AFTER)"
has_text "NEW WALLET ACTIVE" || die "status did not confirm activation: $(texts)"
pass "activate swaps the identity"

relock; unlock
[[ "$(addr)" == "$AFTER" ]] || die "new wallet did not persist across relock: $AFTER → $(addr)"
pass "new wallet persisted"
if adb_is_root; then
  JOURNAL="$("$A" shell "grep -c wallet_write_pending /data/data/$PKG/shared_prefs/vault.xml" | tr -d '\r' || true)"
  [[ "${JOURNAL:-0}" == "0" ]] || die "write journal still pending after a successful replacement"
  "$A" shell "test -s /data/data/$PKG/files/wallet.pvw3" || die "wallet record file missing"
  pass "record settled on disk"
else
  echo "SKIP: on-disk record/journal check needs a root adb shell (Lineage 'Rooted debugging' toggle)"
fi
kiosk_locked; no_crashes; unwake
pass "regentest complete"
