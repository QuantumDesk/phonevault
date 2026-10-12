#!/usr/bin/env bash
# SeedQR + backup reminder on a THROWAWAY dev phone (not yet run on a phone).
#  1. Security → Show as SeedQR asks for the PIN, then shows the CompactSeedQR (25 × 25) with Hide,
#     the seed timer, and a switch to Standard SeedQR (29 × 29); "Show as words" goes to page 1 of
#     the phrase and "Show as SeedQR" comes back; Hide returns Home with nothing sensitive left.
#  2. While the SeedQR is up, a USB accessory attach is parked (no session) — checked only when
#     PV_USB_CHECK=1 and a host is on the cable (the host side is left to usbsigntest.sh).
#  3. Security → Backup reminder: the four choices (Off / month / 3 months / 6 months) save and
#     show as the selected button; the default (Every 3 months) is restored at the end.
# The "due" timing (90 days, 14-day snooze, clock going backwards, reset on a successful check) is
# covered by BackupReminderTest; the phone's clock cannot be moved from adb on the appliance.
# The SeedQR modules are drawn on a canvas: no seed data appears in the UI dump.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
wake; unlock_if_locked; go_home
has_text "Your offline wallet" || die "the backup must be checked first (run backupcheck.sh)"

# --- 1. SeedQR
go_security
tap_text "Show as SeedQR"; sleep 2
if has_text "VERIFY PIN"; then tap_digits "$PV_TEST_PIN"; sleep 5
elif system_prompt_up; then enter_system_pin; sleep 5; fi
expect_screen "RECOVERY PHRASE · SEEDQR"
expect_screen "CompactSeedQR · 25 × 25"
has_text "Hides in" || die "seed timer missing on the SeedQR screen"
expect_not "☰"  # no menu over a sensitive screen
tap_text "Use Standard SeedQR (29 × 29)"; sleep 1.5
expect_screen "Standard SeedQR · 29 × 29"
tap_text "Use CompactSeedQR (25 × 25)"; sleep 1.5
expect_screen "CompactSeedQR · 25 × 25"

if [[ "${PV_USB_CHECK:-}" == "1" ]]; then
  echo "Plug the host cable in now (15 s)…"; sleep 15
  expect_screen "RECOVERY PHRASE · SEEDQR"   # still showing: the attach was parked, not served
  expect_not "USB connected"
fi

scroll_down; tap_text "Show as words"; sleep 1.5
expect_screen "Write words 1"
scroll_down; tap_text "Show as SeedQR"; sleep 1.5
expect_screen "CompactSeedQR · 25 × 25"
scroll_top; tap_text "Hide"; sleep 2
expect_screen "Your offline wallet"
expect_not "SEEDQR"

# --- 3. reminder settings
go_security
scroll_down
tap_text "Backup reminder"; sleep 1.5
expect_screen "SECURITY / BACKUP REMINDER"
expect_screen "Last checked"
for choice in "Off" "Every month" "Every 6 months" "Every 3 months"; do
  tap_text "$choice"; sleep 1.2
  expect_screen "SECURITY / BACKUP REMINDER"
done
tap_text "Back to Security"; sleep 1.2
expect_screen "Backup reminder · Every 3 months"
go_home
pass "SeedQR shown/hidden inside the PIN flow; reminder interval saves"
kiosk_locked; no_crashes; unwake
