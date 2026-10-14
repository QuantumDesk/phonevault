#!/usr/bin/env bash
# Display polish round trip on a THROWAWAY dev phone:
#   1. battery indicator in every page header (content-desc "Battery NN percent")
#   2. Display & auto-lock: screen timeout 30 s → system screen_off_timeout == 30000, then back
#      to 1 minute (60000); haptics off/on; the "To turn off: hold the power button" line
#   3. standard AND large text: screenshot the key screens and fail if any text node's bounds
#      leave the screen (horizontal overflow) — Home, ☰ menu, Security, Display & auto-lock,
#      Device information, Address book, Coming next, Backup reminder, locked gate
#   Ends in standard text with the 1-minute timeout (the defaults).
#
# Screenshots: dev/appliance builds lift FLAG_SECURE (DevTools.SCREENSHOTS), so screencap works.
# Request reviews need a host: run safetytest.sh / msgsigntest.sh after step 3 leaves large text
# on (PV_POLISH_KEEP_LARGE=1) to capture the approval screens at large text too.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
OUT="${PV_POLISH_OUT:-$PV_LOG_DIR/polishtest}"
mkdir -p "$OUT"
wake
trap unwake EXIT

W="$("$A" shell wm size | grep -oE '[0-9]+x[0-9]+' | tail -1 | cut -dx -f1)"
[[ -n "$W" ]] || die "could not read the screen width"

shot() { "$A" exec-out screencap -p > "$OUT/$1.png"; echo "  shot $OUT/$1.png"; }

# Every text node must lie inside the screen horizontally (a clipped or overflowing label shows
# up as x2 > width). Vertical overflow is fine: pages scroll.
check_bounds() {
  local bad
  bad="$(uidump | grep -o 'text="[^"]\{1,60\}"[^>]*bounds="\[[0-9-]*,[0-9-]*\]\[[0-9-]*,[0-9-]*\]"' \
    | sed -E 's/text="([^"]*)".*bounds="\[(-?[0-9]+),(-?[0-9]+)\]\[(-?[0-9]+),(-?[0-9]+)\]"/\2 \4 \1/' \
    | awk -v w="$W" '$1 < 0 || $2 > w { $1=""; $2=""; print }' | head -3 || true)"
  [[ -z "$bad" ]] || die "$1: text leaves the screen: $bad"
}

expect_battery() {
  uidump | grep -qE 'content-desc="Battery ([0-9]+ percent|level unavailable)' || die "$1: no battery indicator in the header"
}

capture() { # capture <mode> <name>
  sleep 1.2; expect_battery "$2"; check_bounds "$1-$2"; shot "$1-$2"
  scroll_down; sleep 0.8; check_bounds "$1-$2 (scrolled)"; shot "$1-$2-scrolled"; scroll_top
}

display_section() { go_section "Display &amp; auto-lock" || die "menu not available"; expect_screen "Display &amp; auto-lock"; }

set_text() { # set_text standard|large
  display_section
  if [[ "$1" == large ]]; then has_text "Use larger text" && { tap_text "Use larger text"; sleep 1.5; }; expect_screen "Large · easier reading"
  else has_text "Use standard text" && { tap_text "Use standard text"; sleep 1.5; }; expect_screen "Standard · comfortable reading"; fi
}

timeout_ms() { "$A" shell settings get system screen_off_timeout | tr -d '\r'; }

unlock_if_locked
go_home
expect_battery "home"
pass "battery indicator on Home"

# ---- 2. Display & auto-lock settings
display_section
tap_text "Screen off after 30 seconds"; sleep 1.5
[[ "$(timeout_ms)" == "30000" ]] || die "screen_off_timeout is $(timeout_ms), expected 30000"
expect_screen "Locks after 30 seconds"
pass "screen timeout 30 s applied as device owner (idle lock capped to 30 s)"
tap_text "Screen off after 1 minute"; sleep 1.5
[[ "$(timeout_ms)" == "60000" ]] || die "screen_off_timeout is $(timeout_ms), expected 60000"
pass "screen timeout back to 1 minute"
# Haptics sits below the fold, and each tap rebuilds the page from the top: scroll to it each time.
find_text "Turn haptics " || die "no haptics toggle on Display &amp; auto-lock"
if has_text "Turn haptics on"; then  # an interrupted run left haptics off: back to the default first
  tap_text "Turn haptics on"; sleep 1.2; find_text "Turn haptics off" || die "haptics did not turn on"
fi
tap_text "Turn haptics off"; sleep 1.2; expect_below "Off · no vibration feedback"
find_text "Turn haptics on" || die "no 'Turn haptics on' after turning haptics off"
tap_text "Turn haptics on"; sleep 1.2; expect_below "On · a tap for PIN keys"
pass "haptics toggle persists in the UI"
expect_below "To turn off: hold the power button"
pass "power-off hint shown"
scroll_top

# ---- 3. screens at standard and large text
for mode in standard large; do
  set_text "$mode"
  capture "$mode" display
  go_home;                                   capture "$mode" home
  open_menu || die "menu did not open";      capture "$mode" menu
  go_section "Security";                     capture "$mode" security
  b="$(bounds_of 'Backup reminder · [^"]*')"
  if [[ -n "$b" ]]; then tap_bounds "$b"; sleep 1.2; has_text "Check your backup" && capture "$mode" reminder; fi
  go_section "Device information";           capture "$mode" device
  go_section "Address book";                 capture "$mode" addressbook
  go_section "Coming next";                  capture "$mode" features
  # Locked gate (credential mode: our "Phone Vault is locked" page; app-PIN mode: the PinScreen)
  "$A" shell input keyevent KEYCODE_SLEEP; sleep 2; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 3
  if system_prompt_up; then "$A" shell input keyevent KEYCODE_BACK; sleep 1.5; fi
  if has_text "Phone Vault is locked" || has_text LOCKED; then
    sleep 1.2; check_bounds "$mode-locked"; shot "$mode-locked"
    uidump | grep -qE 'content-desc="Battery' || echo "  note: no battery indicator on the locked gate"
  fi
  unlock_if_locked; go_home
  pass "$mode text: screens captured, nothing leaves the screen"
done

if [[ "${PV_POLISH_KEEP_LARGE:-0}" != "1" ]]; then set_text standard; go_home; fi
no_crashes
kiosk_locked
pass "polish checks done · screenshots in $OUT (compare standard-* with large-*)"
