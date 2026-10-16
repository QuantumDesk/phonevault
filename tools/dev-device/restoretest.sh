#!/usr/bin/env bash
# Restore drill on a THROWAWAY dev phone. Two modes:
#   restoretest.sh firstrun  EXPECTED_ADDR   phone at "Set up your wallet" (after SET PIN)
#   restoretest.sh replace   EXPECTED_ADDR   phone has a wallet; Security → Restore a different wallet
# Picks the phrase's length (12, 15, 18, 21 or 24 words, from PV_WORDS_FILE), types the words on the
# on-device keyboard, requires the derived address to equal EXPECTED_ADDR BEFORE anything is saved,
# confirms, and checks Home.
source "$(dirname "$0")/lib.sh"
MODE="${1:?firstrun|replace}"; EXPECT="${2:?expected 0x address}"
require_throwaway
require_dev_appliance
require_pin
require_words
N="${#WORDS[@]}"
wake; unlock_if_locked
case "$MODE" in
  firstrun)
    expect_screen "Set up your wallet"
    tap_text "Restore from recovery phrase"; sleep 2
    expect_screen "How many words?"
    tap_text "${N} words"; sleep 1.5
    expect_screen "RESTORE · WORD 1 OF ${N}" ;;
  replace)
    # a previous interrupted run may have left the entry screen up: cancel keeps the current wallet
    if has_text "REPLACE BY RESTORE"; then tap_text "Cancel · keep current wallet"; sleep 2; fi
    go_home; BEFORE="$(addr)"
    go_security
    tap_text "Restore a different wallet"; sleep 1.5
    expect_screen "Restore a different wallet?"
    tap_text "Continue · verify PIN"; sleep 1.5
    expect_screen "VERIFY PIN"; tap_digits "$PV_TEST_PIN"; sleep 4
    expect_screen "How many words?"
    tap_text "${N} words"; sleep 1.5
    expect_screen "REPLACE BY RESTORE · WORD 1 OF ${N}" ;;
  *) die "mode must be firstrun or replace" ;;
esac
type_words
sleep 5
if [[ "$MODE" == firstrun ]]; then expect_screen "Is this your wallet?"; else expect_screen "Replace with this wallet?"; fi
NEW="$(addr)"
[[ "${NEW,,}" == "${EXPECT,,}" ]] || die "derived address ${NEW} != expected ${EXPECT} (nothing was saved)"
pass "${N} words accepted; derived address shown before saving matches"
if [[ "$MODE" == firstrun ]]; then tap_text "Yes, restore this wallet"; else tap_text "Yes, replace with this wallet"; fi
sleep 8
expect_screen "Your offline wallet"
[[ "$(addr | tr 'A-F' 'a-f')" == "${EXPECT,,}" ]] || die "Home shows $(addr), expected $EXPECT"
[[ "$MODE" == firstrun || "${BEFORE,,}" != "${EXPECT,,}" ]] && pass "restored wallet active on Home (backup verified by entry)"
kiosk_locked; no_crashes; unwake
pass "restoretest ($MODE) complete"
