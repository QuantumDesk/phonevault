#!/usr/bin/env bash
# Erase userdata + metadata from the bootloader and watch the first boot come back on adb.
# ONLY with the owner's explicit approval, ONLY on a throwaway wallet. The phone must already be
# in the bootloader (Power + Volume Down) or reachable over adb (it is rebooted there).
# Requires PV_THROWAWAY_DEVICE=1 and exactly one attached device ($PV_SERIAL); every adb/fastboot
# call is pinned to that serial. PV_SERIAL (or ANDROID_SERIAL) is required; ADB / FASTBOOT
# default to adb / fastboot on PATH.
set -uo pipefail
A="${ADB:-adb}"; FB="${FASTBOOT:-fastboot}"
SERIAL="${PV_SERIAL:-${ANDROID_SERIAL:-}}"
[[ -n "$SERIAL" ]] || { echo "set PV_SERIAL (or ANDROID_SERIAL) to the development phone's serial (adb devices / fastboot devices)" >&2; exit 2; }
# log, only_device_guard (exactly one phone attached), adb_state, wait_for_fastboot,
# erase_userdata_metadata (throwaway only), wait_for_boot.
# shellcheck source=vault-os/dev-ladder/device-guard.sh
source "$(dirname "$0")/device-guard.sh"
only_device_guard
[[ "${PV_THROWAWAY_DEVICE:-}" == "1" ]] || { log "refusing: set PV_THROWAWAY_DEVICE=1 only for the dev phone $SERIAL whose wallet holds nothing (this erases userdata + metadata)"; exit 1; }
if [[ "$(adb_state)" == "device" ]]; then log "phone on adb → rebooting to bootloader"; timeout 15 "$A" -s "$SERIAL" reboot bootloader || true; fi
log "waiting for the bootloader (hold Power + Volume Down if the phone is not already there)"
wait_for_fastboot 600 || { log "phone never reached fastboot"; exit 1; }
log "slot: $("$FB" -s "$SERIAL" getvar current-slot 2>&1 | grep -m1 current-slot | tr -d '\r')"
erase_userdata_metadata
"$FB" -s "$SERIAL" reboot
log "boot-watch (10 min)"
wait_for_boot 600 || { log "did not come back on adb within 10 min"; exit 1; }
sleep 15
log "*** BOOTED $("$A" -s "$SERIAL" shell getprop ro.build.date | tr -d '\r') — adb restored ***"
echo "adb_enabled=$("$A" -s "$SERIAL" shell settings get global adb_enabled | tr -d '\r')"
"$A" -s "$SERIAL" shell dumpsys device_policy | grep -m1 "admin="
"$A" -s "$SERIAL" shell dumpsys activity activities | grep -m1 mLockTaskModeState
"$A" -s "$SERIAL" shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; "$A" -s "$SERIAL" exec-out cat /sdcard/ui.xml | grep -o 'text="[^"]\{1,30\}"' | head -3 | tr '\n' ' '; echo
