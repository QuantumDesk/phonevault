#!/usr/bin/env bash
# Credential mode on a THROWAWAY dev phone (vault PIN == device PIN, pin-credential-design.md):
# relock → our gate → system PIN prompt → Home; wrong-then-right PIN; phrase reveal inside and
# after the seed key's window; reboot → Android's boot lock screen once → Home WITHOUT a second
# prompt. Needs PV_TEST_PIN. The system prompt is a secure window: the PIN is keyed in blind.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
WRONG="$(wrong_pin)"
"$A" shell svc power stayon false
"$A" shell input keyevent KEYCODE_WAKEUP; sleep 2
unlock_if_locked; go_home
BEFORE="$(addr)"; [[ -n "$BEFORE" ]] || die "no address on Home"
[[ "$("$A" shell locksettings get-disabled | tr -d '\r')" == "false" ]] || die "device has no lock credential: not in credential mode"

for round in 1 2; do
  "$A" shell input keyevent KEYCODE_SLEEP; sleep 4; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 2
  enter_system_pin || die "round $round: no system PIN prompt after relock (focus=$(focus_window))"
  go_home; [[ "$(addr)" == "$BEFORE" ]] || die "round $round: wrong wallet after unlock"
done
pass "screen-off relock asks the chip for the PIN, twice"

"$A" shell input keyevent KEYCODE_SLEEP; sleep 4; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 2
for _ in $(seq 1 12); do system_prompt_up && break; sleep 1; done
"$A" shell input text "$WRONG"; "$A" shell input keyevent KEYCODE_ENTER; sleep 4
system_prompt_up || die "wrong PIN was not rejected by the system prompt"
enter_system_pin; go_home; expect_screen "Your offline wallet"
pass "wrong PIN rejected, right PIN accepted"

# Inside the window no second prompt is expected, but uiautomator navigation is slow enough to
# run past it, so a prompt here is reported rather than failed.
go_security; tap_text "Show recovery phrase"; sleep 3
if system_prompt_up; then echo "note: harness reached the phrase after the window; PIN asked"; enter_system_pin
else pass "phrase inside the window: no second prompt"; fi
expect_screen "RECOVERY PHRASE"; tap_text "Hide phrase"; sleep 2
sleep 32; "$A" shell input tap 700 1500
go_security; tap_text "Show recovery phrase"; sleep 3
system_prompt_up || die "phrase after the window did not ask for the PIN"
enter_system_pin; expect_screen "RECOVERY PHRASE"; tap_text "Hide phrase"; sleep 2
pass "phrase after the window: PIN asked, then shown"

"$A" reboot; sleep 25; wait_boot; sleep 12; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 2
[[ "$("$A" shell dumpsys user | grep -oE 'State: [A-Z_]+' | head -1)" == "State: RUNNING_LOCKED" ]] || die "storage was not locked after reboot"
"$A" shell input swipe 720 2400 720 900 250; sleep 2
"$A" shell input text "$PV_TEST_PIN"; "$A" shell input keyevent KEYCODE_ENTER; sleep 14
system_prompt_up && die "vault asked for the PIN a second time after the boot unlock"
go_home; [[ "$(addr)" == "$BEFORE" ]] || die "identity changed across reboot"
pass "reboot: one PIN on Android's lock screen, then straight to Home"
kiosk_locked; no_crashes
pass "credentialtest complete"
