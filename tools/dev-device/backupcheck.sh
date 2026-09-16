#!/usr/bin/env bash
# Backup spot check on a THROWAWAY dev phone from Home: fresh PIN → 3 random positions answered
# from PV_WORDS_FILE → confirm account. Proves the check binds to the on-screen account.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
require_words
wake; unlock_if_locked; go_home
if has_text "I have my backup"; then tap_text "I have my backup · check words"
else go_security; tap_text "Check my backup"; fi
sleep 2; expect_screen "VERIFY PIN"
tap_digits "$PV_TEST_PIN"; sleep 5
spot_check
CHECKED="$(addr)"
tap_text "Confirm account &amp; finish"; sleep 5
expect_screen "Your offline wallet"
[[ "${CHECKED,,}" == "$(addr | tr 'A-F' 'a-f')" ]] || die "checked account $CHECKED differs from Home $(addr)"
pass "spot check passed for $(addr | cut -c1-10)…; receiving enabled"
kiosk_locked; no_crashes; unwake
