#!/usr/bin/env bash
# THROWAWAY dev phone only: from the unlocked home, tap "Recovery phrase" → "Show", pull the
# app-rendered dump of the seed screen (for UI review of a wallet that holds nothing), then hide.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
wake
expect_screen "PHONE VAULT"
tap_text "Recovery phrase"; sleep 1.5; expect_screen "Show recovery phrase?"
tap_text "Show"; sleep 4; expect_screen "RECOVERY PHRASE"
"$A" exec-out cat "/data/data/$PKG/files/vault_dump.png" > "${OUT:-/root/backup.png}"
echo "BACKUP_DUMP_BYTES=$(stat -c%s "${OUT:-/root/backup.png}")"
tap_text "Hide phrase"; sleep 2; expect_screen "PHONE VAULT"
unwake
pass "recovery-phrase screen captured to ${OUT:-/root/backup.png} (dev wallet only)"
