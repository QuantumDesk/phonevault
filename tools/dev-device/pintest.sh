#!/usr/bin/env bash
# First-run PIN flow on a THROWAWAY dev phone that is sitting at SET PIN:
# partial entry → confirm → mismatch → set → home → sleep-lock → wrong PIN → unlock.
# Sets PV_TEST_PIN as the device PIN (prompted if unset; never logged).
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
wake
expect_screen "SET PIN"
require_pin
WRONG="$(wrong_pin)"

tap_digits "${PV_TEST_PIN:0:3}"; sleep 1
has_text "■ ■ ■ □ □ □" || die "partial entry not reflected: $(texts)"
tap_digits "${PV_TEST_PIN:3}"; sleep 2
expect_screen "CONFIRM PIN"
tap_digits "$WRONG"; sleep 3
expect_screen "PINS DID NOT MATCH"
expect_screen "SET PIN"
pass "mismatch is refused and restarts SET PIN"

tap_digits "$PV_TEST_PIN"; sleep 1.5; tap_digits "$PV_TEST_PIN"; sleep 6
expect_screen "PHONE VAULT"
[[ -n "$(addr)" ]] || die "no signing address after first unlock"
pass "PIN set, wallet created, home shown"

relock
tap_digits "$WRONG"; sleep 4
expect_screen "WRONG PIN · 9 ATTEMPTS LEFT"
pass "wrong PIN counted (1 attempt consumed)"
unlock
pass "unlock with the new PIN"
[[ "$("$A" shell settings get system screen_off_timeout | tr -d '\r')" == "60000" ]] || die "screen_off_timeout policy not applied"
kiosk_locked; no_crashes; unwake
pass "pintest complete"
