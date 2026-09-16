#!/usr/bin/env bash
# THROWAWAY dev phone only: Security → Show recovery phrase → fresh PIN → screencap the six
# phrase pages for UI review (dev build allows screenshots), then hide. Output dir: $OUT.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
OUTDIR="${OUT:-/root/backup-pages}"; umask 077; mkdir -p "$OUTDIR"
wake; unlock_if_locked; go_home
go_security
tap_text "Show recovery phrase"; sleep 2; expect_screen "VERIFY PIN"
tap_digits "$PV_TEST_PIN"; sleep 5; expect_screen "RECOVERY PHRASE"
for page in 1 2 3 4 5 6; do
  "$A" exec-out screencap -p > "$OUTDIR/page-$page.png"
  [[ $page -lt 6 ]] && { tap_text "Next four words"; sleep 1.2; }
done
tap_text "Hide phrase"; sleep 3; expect_not "RECOVERY PHRASE"
unwake
pass "six phrase pages captured under $OUTDIR (dev wallet only; delete after review)"
