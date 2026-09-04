#!/usr/bin/env bash
# Lifecycle checks on a THROWAWAY dev phone: stop-during-PIN-verify race, unlock, reveal/hide,
# sleep-lock, wrong PIN (consumes 1 attempt), unlock. Needs PV_TEST_PIN.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
WRONG="$(wrong_pin)"
wake
relock
"$A" logcat -c

# RACE: type 5 digits, then the 6th and an immediate screen-off while PBKDF2 runs.
tap_digits "${PV_TEST_PIN:0:5}"
"$A" shell "input tap ${K[${PV_TEST_PIN:5:1}]}; input keyevent KEYCODE_SLEEP"
sleep 3; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 2; "$A" shell input tap 700 1200; sleep 1.5
expect_screen LOCKED
expect_not "PHONE VAULT"
if "$A" logcat -d -s Vault:* | grep -q "stale session"; then
  pass "race hit: verify finished while stopped and was discarded"
else
  pass "race not hit this run (verify won); device still locked after wake"
fi

unlock
pass "normal unlock"
tap_text "Recovery phrase"; sleep 1.5; expect_screen "Show recovery phrase?"
tap_text "Show"; sleep 4; expect_screen "RECOVERY PHRASE"
tap_text "Hide phrase"; sleep 2; expect_screen "PHONE VAULT"
pass "reveal and hide"

relock
tap_digits "$WRONG"; sleep 4
expect_screen "WRONG PIN · 9 ATTEMPTS LEFT"
pass "wrong PIN counted (1 attempt consumed)"
unlock
pass "unlock after wrong attempt"
kiosk_locked; no_crashes; unwake
pass "lifecycletest complete"
