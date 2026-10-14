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
log(){ echo "[$(date +%H:%M:%S)] $*"; }
# Exactly one phone may be attached: every adb/fastboot call below is pinned to "$SERIAL", and a
# second phone on the bus is refused outright, so a flash or erase can never land on the wrong
# device (e.g. the owner's real wallet plugged in for charging).
only_device_guard() {
  local seen others
  seen="$({ "$A" devices 2>/dev/null | awk 'NR>1 && NF>=2 {print $1}'; "$FB" devices 2>/dev/null | awk 'NF>=2 {print $1}'; } | sort -u)"
  others="$(grep -vxF -- "$SERIAL" <<<"$seen" | grep -v '^$' || true)"
  if [[ -n "$others" ]]; then
    log "refusing: other device(s) attached ($(tr '\n' ' ' <<<"$others")); unplug them — this script only touches $SERIAL"
    exit 1
  fi
}
only_device_guard
[[ "${PV_THROWAWAY_DEVICE:-}" == "1" ]] || { log "refusing: set PV_THROWAWAY_DEVICE=1 only for the dev phone $SERIAL whose wallet holds nothing (this erases userdata + metadata)"; exit 1; }
if "$A" devices | grep -q "^$SERIAL.*device$"; then log "phone on adb → rebooting to bootloader"; timeout 15 "$A" -s "$SERIAL" reboot bootloader || true; fi
log "waiting for the bootloader (hold Power + Volume Down if the phone is not already there)"
end=$((SECONDS+600)); while [[ $SECONDS -lt $end ]] && ! "$FB" devices | grep -q "$SERIAL"; do sleep 3; done
"$FB" devices | grep -q "$SERIAL" || { log "phone never reached fastboot"; exit 1; }
log "slot: $("$FB" -s "$SERIAL" getvar current-slot 2>&1 | grep -m1 current-slot | tr -d '\r')"
only_device_guard; "$FB" -s "$SERIAL" erase userdata && "$FB" -s "$SERIAL" erase metadata || { log "erase failed"; exit 1; }
"$FB" -s "$SERIAL" reboot
log "boot-watch (10 min)"
end=$((SECONDS+600))
while [[ $SECONDS -lt $end ]]; do
  if "$A" devices | grep -q "^$SERIAL.*device$"; then
    bc=$(timeout 6 "$A" -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r'); [[ "$bc" == "1" ]] && break
  fi
  sleep 5
done
[[ "${bc:-}" == "1" ]] || { log "did not come back on adb within 10 min"; exit 1; }
sleep 15
log "*** BOOTED $("$A" -s "$SERIAL" shell getprop ro.build.date | tr -d '\r') — adb restored ***"
echo "adb_enabled=$("$A" -s "$SERIAL" shell settings get global adb_enabled | tr -d '\r')"
"$A" -s "$SERIAL" shell dumpsys device_policy | grep -m1 "admin="
"$A" -s "$SERIAL" shell dumpsys activity activities | grep -m1 mLockTaskModeState
"$A" -s "$SERIAL" shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; "$A" -s "$SERIAL" exec-out cat /sdcard/ui.xml | grep -o 'text="[^"]\{1,30\}"' | head -3 | tr '\n' ' '; echo
