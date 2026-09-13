#!/usr/bin/env bash
# Shared guards and helpers for the development-device scripts (0.3.0 UI). Source, don't run.
#
#   PV_THROWAWAY_DEVICE=1   required: the phone's wallet holds nothing and may be wiped
#   PV_TEST_PIN=nnnnnn      the current (or, for firstrun.sh, the to-be-set) 6-digit PIN;
#                           prompted for silently if unset; never printed or logged
#   PV_WORDS_FILE=path      a 0600 file holding a THROWAWAY 24-word phrase, one word per line or
#                           space-separated; read by backupcheck/restore scripts, never echoed
#   ADB=/path/to/adb        optional override
#
# Every tap is found by the widget's text and live bounds (uiautomator). No coordinates are
# guessed. uiautomator only lists VISIBLE nodes, so scroll before tapping anything below the fold.
set -euo pipefail

A="${ADB:-adb}"
PKG=dev.phonevault.signer

die()  { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

require_throwaway() {
  [[ "${PV_THROWAWAY_DEVICE:-}" == "1" ]] || die "refusing: set PV_THROWAWAY_DEVICE=1 only for a dev phone whose wallet holds nothing (every wrong PIN counts toward the 10-attempt erase)"
}

require_dev_appliance() {
  local version
  version="$("$A" shell dumpsys package "$PKG" 2>/dev/null | grep -m1 'versionName=' | tr -d '\r' || true)"
  [[ "$version" == *dev-appliance* ]] || die "installed build is not the dev appliance (${version:-not installed}); these scripts only target it"
  [[ "$version" == *0.3.*dev-appliance* ]] || die "harness targets the 0.3.x UI (installed: $version)"
  # NEVER call `adb root` here. On LineageOS it is gated by the "Rooted debugging" developer
  # toggle (adbroot service), which a fresh /data resets; the refused call is harmless, but
  # chasing it by toggling adb_enabled remotely disabled adb on a kiosk with no UI (2026-09-05).
}

adb_is_root() { "$A" shell id 2>/dev/null | grep -q "uid=0"; }

require_pin() {
  if [[ -z "${PV_TEST_PIN:-}" ]]; then
    read -r -s -p "Test PIN (6 digits; never logged): " PV_TEST_PIN; echo
  fi
  [[ "$PV_TEST_PIN" =~ ^[0-9]{6}$ ]] || die "PIN must be exactly 6 digits"
}

# A PIN that differs from the test PIN in its first digit (for deliberate wrong entries).
wrong_pin() { printf '%d%s' "$(( (10#${PV_TEST_PIN:0:1} + 1) % 10 ))" "${PV_TEST_PIN:1}"; }

# The throwaway phrase: 24 lowercase words; the file must be private to the caller.
require_words() {
  [[ -n "${PV_WORDS_FILE:-}" && -s "$PV_WORDS_FILE" ]] || die "set PV_WORDS_FILE to a 0600 file holding the THROWAWAY 24-word phrase"
  [[ "$(stat -c %a "$PV_WORDS_FILE")" =~ ^[0-7]00$ ]] || die "$PV_WORDS_FILE must be mode 0600 (it is a recovery phrase)"
  mapfile -t WORDS < <(tr -s ' ' '\n' < "$PV_WORDS_FILE" | grep -v '^$')
  [[ ${#WORDS[@]} -eq 24 ]] || die "words file must hold exactly 24 words (has ${#WORDS[@]})"
}

# adb drops for a few seconds when the device owner (re)applies USB restrictions or the gadget
# is reset for an accessory switch; wait for it instead of dying on the first failed command.
wait_adb() { local i; for i in $(seq 1 "${1:-24}"); do "$A" get-state >/dev/null 2>&1 && return 0; sleep 5; done; die "adb did not come back"; }
wait_boot() { local i; for i in $(seq 1 "${1:-40}"); do "$A" get-state >/dev/null 2>&1 && [[ "$("$A" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]] && return 0; sleep 5; done; die "device did not finish booting"; }

# /data/local/tmp: /sdcard is not always readable from the shell on a fresh device.
uidump() { "$A" shell uiautomator dump /data/local/tmp/ui.xml >/dev/null 2>&1; "$A" exec-out cat /data/local/tmp/ui.xml; }
texts()  { uidump | grep -o 'text="[^"]\{1,70\}"' | sed 's/^text=//; s/"//g' | grep -vE '^[0-9⌫a-z]$' | head -"${1:-6}" | tr '\n' '|' || true; }
has_text() { uidump | grep -q "text=\"$1"; }
expect_screen() { has_text "$1" || die "expected '$1' on screen, saw: $(texts)"; }
expect_not()    { has_text "$1" && die "did not expect '$1' on screen: $(texts)"; return 0; }

# Bounds "x1 y1 x2 y2" of the first visible widget whose text matches exactly (XML-escaped: use
# &amp; for '&'). Empty when not visible.
bounds_of() {
  uidump | grep -o -i "text=\"$1\"[^>]*bounds=\"\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]\"" | head -1 \
    | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/' || true
}
tap_bounds() { local x1 y1 x2 y2; read -r x1 y1 x2 y2 <<<"$1"; "$A" shell input tap $(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 )) </dev/null; }
# Tap a widget by exact text; scrolls down once and retries if it is below the fold.
tap_text() {
  local b; b="$(bounds_of "$1")"
  if [[ -z "$b" ]]; then scroll_down; sleep 0.8; b="$(bounds_of "$1")"; fi
  [[ -n "$b" ]] || die "button '$1' not found on screen: $(texts)"
  tap_bounds "$b"
}
scroll_down() { "$A" shell input swipe 720 2300 720 700 350 </dev/null; }
scroll_top()  { "$A" shell input swipe 720 700 720 2300 350 </dev/null; sleep 0.5; "$A" shell input swipe 720 700 720 2300 350 </dev/null; }

# Digits are buttons whose text is the digit itself (PinScreen); `⌫` is backspace.
tap_digits() { local i; for (( i = 0; i < ${#1}; i++ )); do tap_text "${1:$i:1}"; sleep 0.2; done; }
clear_entry() { local i b; b="$(bounds_of "⌫")"; [[ -n "$b" ]] || return 0; for i in 1 2 3 4 5 6; do tap_bounds "$b"; sleep 0.15; done; }

# The first 0x address on screen; the home card wraps it with a line break the dump encodes as &#10;.
addr() { uidump | grep -o 'text="0x[0-9a-fA-F&#;]*' | head -1 | sed 's/^text="//; s/&#10;//g' || true; }

wake()   { "$A" shell svc power stayon usb; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 2; }
unwake() { "$A" shell svc power stayon false; }
# Screen off → onStop locks the vault.
relock() { "$A" shell input keyevent KEYCODE_SLEEP; sleep 2; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 3; expect_screen LOCKED; }
unlock() { expect_screen LOCKED; tap_digits "$PV_TEST_PIN"; sleep 6; expect_screen "PHONE VAULT"; expect_not LOCKED; }
unlock_if_locked() { if has_text LOCKED; then clear_entry; tap_digits "$PV_TEST_PIN"; sleep 6; expect_not LOCKED; fi; }
# Back to the Wallet tab from Security/preferences; leaves other screens alone (callers assert).
go_home() {
  local b
  if has_text "Your offline wallet" || has_text "Protect your recovery"; then return 0; fi
  b="$(bounds_of "Back to Security")"; [[ -n "$b" ]] && { tap_bounds "$b"; sleep 1.2; }
  b="$(bounds_of "Wallet")"; [[ -n "$b" ]] && { tap_bounds "$b"; sleep 1.5; }
  return 0
}

# Answer the 3-word spot check ("Find word N") from WORDS, then confirm the account.
spot_check() {
  local i n
  for i in 1 2 3; do
    n="$(uidump | grep -o 'Find word [0-9]*' | head -1 | awk '{print $3}' || true)"
    [[ -n "$n" ]] || die "no spot-check challenge on screen at round $i: $(texts)"
    tap_text "${WORDS[$((n - 1))]}"; sleep 1.2
  done
  expect_screen "3 OF 3 WORDS CHECKED"
}

# Type all 24 WORDS on the on-device restore keyboard (letters by live key bounds, word by text).
type_words() {
  declare -A K; local l x1 y1 x2 y2 w i
  while read -r l x1 y1 x2 y2; do K[$l]="$(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 ))"; done \
    < <(uidump | grep -o 'text="[a-z⌫]"[^>]*bounds="[^"]*"' | sed -E 's/text="(.)".*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]"/\1 \2 \3 \4 \5/')
  [[ ${#K[@]} -ge 26 ]] || die "restore keyboard not fully visible (${#K[@]} keys)"
  for w in "${WORDS[@]}"; do
    # shellcheck disable=SC2086
    for (( i = 0; i < ${#w}; i++ )); do "$A" shell input tap ${K[${w:$i:1}]} </dev/null; sleep 0.25; done
    sleep 0.6; tap_text "$w"; sleep 0.5
  done
}

# Only OUR process counts: the dev image still ships vendor apps that crash for lack of GSF.
no_crashes() { [[ "$("$A" logcat -d -s AndroidRuntime:E | grep -A1 FATAL | grep -c "Process: $PKG" || true)" == "0" ]] || die "app crashed (see logcat AndroidRuntime:E)"; }
kiosk_locked() { "$A" shell dumpsys activity activities | grep -q 'mLockTaskModeState=LOCKED' || die "kiosk is not LOCKED"; }

# USB: the app opens an accessory transport only on a FRESH ACCESSORY_ATTACHED. Reset the gadget
# to plain adb so the host's AOA switch produces one; the host adb server must be down during the
# switch (it holds the device), and comes back once the phone is in accessory+adb mode.
usb_reset() { "$A" shell svc usb setFunctions >/dev/null 2>&1 || true; sleep 6; wait_adb 12; }
