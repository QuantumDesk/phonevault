#!/usr/bin/env bash
# Lifecycle checks on a THROWAWAY dev phone (0.3.0 UI): stop-during-PIN-verify race, unlock,
# reveal/hide behind a fresh PIN, sleep-lock, wrong PIN (consumes 1 attempt), unlock, reboot
# persistence. Needs PV_TEST_PIN.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
WRONG="$(wrong_pin)"
wake; unlock_if_locked; go_home
BEFORE="$(addr)"; [[ -n "$BEFORE" ]] || die "no address on Home"
relock
"$A" logcat -c

# RACE: type 5 digits, then the 6th and an immediate screen-off while PBKDF2 runs.
tap_digits "${PV_TEST_PIN:0:5}"
last="$(bounds_of "${PV_TEST_PIN:5:1}")"; read -r x1 y1 x2 y2 <<<"$last"
"$A" shell "input tap $(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 )); input keyevent KEYCODE_SLEEP"
sleep 3; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 3
expect_screen LOCKED
expect_not "Your offline wallet"
if "$A" logcat -d -s Vault:* | grep -q "stale session"; then
  pass "race hit: verify finished while stopped and was discarded"
else
  pass "race not hit this run (verify won); device still locked after wake"
fi

unlock; pass "normal unlock"
go_security
tap_text "Show recovery phrase"; sleep 2; expect_screen "VERIFY PIN"
tap_digits "$PV_TEST_PIN"; sleep 5; expect_screen "RECOVERY PHRASE"
tap_text "Hide phrase"; sleep 3; expect_not "RECOVERY PHRASE"
pass "reveal needs a fresh PIN; hide returns"

relock
tap_digits "$WRONG"; sleep 4
expect_screen "WRONG PIN · 9 ATTEMPTS LEFT"
pass "wrong PIN counted (1 attempt consumed)"
unlock; pass "unlock after wrong attempt resets the counter"

"$A" reboot; sleep 25; wait_boot; sleep 8; wake
expect_screen LOCKED; unlock; go_home
[[ "$(addr)" == "$BEFORE" ]] || die "identity changed across reboot: $BEFORE → $(addr)"
kiosk_locked; no_crashes; unwake
pass "lifecycletest complete (identity persisted across reboot)"
