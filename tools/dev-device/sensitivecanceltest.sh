#!/usr/bin/env bash
# Credential mode: a dismissed system PIN prompt on a sensitive action must not wedge the next one
# (Pixel 6a: Back on the prompt of Security → Show recovery phrase left the flow's token taken, and
# every later sensitive action, "Continue · verify PIN" or ☰ → Wallet included, opened nothing until
# the next lock). Runs past the seed key's window so each tap really asks, cancels the prompt twice
# (Back), requires a fresh prompt each time, then enters the PIN and requires the phrase screen.
# The phrase screen's words are never read or printed (texts() masks secret screens).
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
"$A" shell svc power stayon usb
"$A" shell input keyevent KEYCODE_WAKEUP; sleep 2
# An open accessory session refuses the phrase screens ("Disconnect USB first", by design).
usb_reset
unlock_if_locked; go_home
[[ "$("$A" shell locksettings get-disabled | tr -d '\r')" == "false" ]] || die "device has no lock credential: not in credential mode"

# Past the seed key's window (SeedKeyWindow): the next sensitive action has to ask for the PIN.
sleep 34; nudge
go_security; expect_screen "Show recovery phrase"

for round in 1 2; do
  tap_text "Show recovery phrase"
  up=0; for _ in $(seq 1 10); do system_prompt_up && { up=1; break; }; sleep 1; done
  [[ $up -eq 1 ]] || die "round $round: Show recovery phrase opened no system PIN prompt (focus=$(focus_window), saw: $(texts))"
  "$A" shell input keyevent KEYCODE_BACK; sleep 2
  system_prompt_up && die "round $round: Back did not dismiss the system PIN prompt"
  expect_not "RECOVERY PHRASE"
  locked_now && die "round $round: dismissing the prompt locked the vault"
  go_security; expect_screen "Show recovery phrase"
  pass "round $round: the prompt appeared and Back dismissed it (still on Security, nothing shown)"
done

tap_text "Show recovery phrase"
enter_system_pin || die "after two dismissed prompts the next sensitive action opened no prompt"
sleep 3
expect_screen "RECOVERY PHRASE"
pass "after two dismissed prompts the next sensitive action asked again and opened the phrase"
tap_text "Hide phrase"; sleep 2
go_home
kiosk_locked; no_crashes; unwake
pass "sensitivecanceltest complete"
