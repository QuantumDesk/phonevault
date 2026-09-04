#!/usr/bin/env bash
# Shared guards and assertions for the development-device scripts. Source, don't run.
#
#   PV_THROWAWAY_DEVICE=1   required: the phone's wallet holds nothing and may be wiped
#   PV_TEST_PIN=nnnnnn      the current (or, for pintest.sh, the to-be-set) 6-digit PIN;
#                           prompted for silently if unset; never printed or logged
#   ADB=/path/to/adb        optional override
set -euo pipefail

A="${ADB:-/root/android-sdk/platform-tools/adb}"
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
  "$A" root >/dev/null 2>&1 || true
}

require_pin() {
  if [[ -z "${PV_TEST_PIN:-}" ]]; then
    read -r -s -p "Test PIN (6 digits; never logged): " PV_TEST_PIN; echo
  fi
  [[ "$PV_TEST_PIN" =~ ^[0-9]{6}$ ]] || die "PIN must be exactly 6 digits"
}

# A PIN that differs from the test PIN in its first digit (for deliberate wrong entries).
wrong_pin() { printf '%d%s' "$(( (10#${PV_TEST_PIN:0:1} + 1) % 10 ))" "${PV_TEST_PIN:1}"; }

# Keypad centres for the 1440x2960 panel (PinScreen layout). Update if the layout moves.
declare -A K=([1]="300 1971" [2]="719 1971" [3]="1138 1971" [4]="300 2223" [5]="719 2223" [6]="1138 2223" [7]="300 2475" [8]="719 2475" [9]="1138 2475" [b]="300 2726" [0]="719 2726")

# shellcheck disable=SC2086  # K values are "x y" pairs and must word-split into two arguments
tap_digits() { local d i; for (( i = 0; i < ${#1}; i++ )); do d="${1:$i:1}"; "$A" shell input tap ${K[$d]}; sleep 0.35; done; }
# shellcheck disable=SC2086
tap_key()    { "$A" shell input tap ${K[$1]}; }

uidump() { "$A" shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; "$A" exec-out cat /sdcard/ui.xml; }
texts()  { uidump | grep -o 'text="[^"]\{1,60\}"' | sed 's/^text=//; s/"//g' | grep -vE '^[0-9⌫]$' | head -"${1:-6}" | tr '\n' '|'; }
has_text() { uidump | grep -q "text=\"$1"; }
expect_screen() { has_text "$1" || die "expected '$1' on screen, saw: $(texts)"; }
expect_not()    { has_text "$1" && die "did not expect '$1' on screen: $(texts)"; return 0; }

# Tap a widget by (case-insensitive) exact text.
tap_text() {
  local bounds
  bounds="$(uidump | grep -o -i "text=\"$1\"[^>]*bounds=\"\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]\"" | head -1 \
    | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/')"
  [[ -n "$bounds" ]] || die "button '$1' not found on screen: $(texts)"
  local x1 y1 x2 y2; read -r x1 y1 x2 y2 <<<"$bounds"
  "$A" shell input tap $(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 ))
}

addr() { uidump | grep -o 'text="0x[0-9a-fA-F]*' | head -1 | cut -c7-; }

wake()   { "$A" shell svc power stayon usb; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 2; }
unwake() { "$A" shell svc power stayon false; }
# Screen off → onStop locks; wake and dismiss the (nonexistent) keyguard tap.
relock() { "$A" shell input keyevent KEYCODE_SLEEP; sleep 2; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 3; "$A" shell input tap 700 1200; sleep 1.5; expect_screen LOCKED; }
unlock() { expect_screen LOCKED; tap_digits "$PV_TEST_PIN"; sleep 6; expect_screen "PHONE VAULT"; }

no_crashes() { [[ "$("$A" logcat -d -s AndroidRuntime:E | grep -c FATAL || true)" == "0" ]] || die "app crashed (see logcat AndroidRuntime:E)"; }
kiosk_locked() { "$A" shell dumpsys activity activities | grep -q 'mLockTaskModeState=LOCKED' || die "kiosk is not LOCKED"; }
