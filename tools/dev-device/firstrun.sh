#!/usr/bin/env bash
# First run on a THROWAWAY dev phone sitting at SET PIN: set PV_TEST_PIN, Create new wallet,
# fresh-PIN confirm, page through the 24 words (captured to PV_WORDS_FILE, mode 0600, for the
# later backup/restore scripts), 3-word spot check, confirm account, Home.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
[[ -n "${PV_WORDS_FILE:-}" ]] || die "set PV_WORDS_FILE: where to store the THROWAWAY phrase (0600)"
wake
expect_screen "SET PIN"
clear_entry
tap_digits "$PV_TEST_PIN"; sleep 2
tap_digits "$PV_TEST_PIN"; sleep 6
expect_screen "Set up your wallet"
pass "PIN set → Create-or-Restore (no wallet minted silently)"

tap_text "Create new wallet"; sleep 6
expect_screen "Write down your recovery phrase"
tap_text "Continue"; sleep 2
expect_screen "VERIFY PIN"
tap_digits "$PV_TEST_PIN"; sleep 5
expect_screen "RECOVERY PHRASE"
pass "wallet created; phrase shown only after a fresh PIN"

# Six pages of four words. The words are written to the caller's private file, never printed.
umask 077; : > "$PV_WORDS_FILE"
for page in 1 2 3 4 5 6; do
  uidump | grep -o 'text="[a-z]\{3,8\}"' | sed 's/text="//; s/"//' | grep -vE '^(word|words)$' | head -4 >> "$PV_WORDS_FILE"
  if [[ $page -lt 6 ]]; then tap_text "Next four words"; sleep 1.2; fi
done
require_words
tap_text "I've written them down · spot-check"; sleep 2
spot_check
tap_text "Confirm account &amp; finish"; sleep 5
expect_screen "Your offline wallet"
[[ -n "$(addr)" ]] || die "no address on Home"
pass "backup spot-checked, account confirmed, Home shows the address"
kiosk_locked; no_crashes; unwake
pass "firstrun complete"
