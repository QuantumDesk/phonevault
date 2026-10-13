#!/usr/bin/env bash
# Flash one ladder rung to the development phone over adb sideload and verify the boot.
#   flash-rung.sh RUNG [--wipe]
# --wipe erases userdata+metadata from the bootloader after the sideload so the NEXT boot is a
# genuine first boot (automatic owner provisioning only happens then). It destroys the on-device
# wallet and PIN: only with the owner's explicit approval, only on a throwaway wallet.
# --wipe requires PV_THROWAWAY_DEVICE=1. Exactly one device ($PV_SERIAL) may be attached; every
# adb/fastboot call is pinned to it.
# The recovery still shows "Signature verification failed — install anyway?" at ~47%: someone
# must tap Yes on the phone (until the OTA key is trusted, release-trust chunk).
set -uo pipefail
RUNG="${1:?rung}"; WIPE=0; [[ "${2:-}" == "--wipe" ]] && WIPE=1
OTA="${PV_OTA:-/home/aipg/rung-${RUNG}-ota.zip}"
A="${ADB:-/root/android-sdk/platform-tools/adb}"; FB="${FASTBOOT:-/root/android-sdk/platform-tools/fastboot}"
SERIAL="${PV_SERIAL:-8A7Y0FJ6Z}"
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
if [[ $WIPE -eq 1 && "${PV_THROWAWAY_DEVICE:-}" != "1" ]]; then
  log "refusing --wipe: set PV_THROWAWAY_DEVICE=1 only for the dev phone $SERIAL whose wallet holds nothing"
  exit 1
fi
state(){ "$A" devices 2>/dev/null | grep "$SERIAL" | awk '{print $2}'; }
[[ -s "$OTA" ]] || { log "OTA missing: $OTA"; exit 1; }
log "rung $RUNG OTA $(stat -c%s "$OTA") bytes sha256 $(sha256sum "$OTA" | cut -c1-16)…  wipe=$WIPE"
[[ "$(state)" == "device" ]] || { log "phone not on adb (state=[$(state)])"; exit 1; }
log "fingerprint before: $("$A" -s "$SERIAL" shell getprop ro.build.date | tr -d '\r')"
"$A" -s "$SERIAL" reboot sideload
rc=1
for attempt in 1 2 3; do
  end=$((SECONDS+180)); while [[ $SECONDS -lt $end && "$(state)" != "sideload" ]]; do sleep 3; done
  [[ "$(state)" == "sideload" ]] || { log "attempt $attempt: no sideload mode (st=[$(state)])"; continue; }
  log "attempt $attempt: sideloading (tap 'Install anyway' on the phone when it pauses near 47%)"
  # Long timeout: the transfer finishes in minutes but the recovery waits at ~47% for the
  # physical "Install anyway" tap (unsigned OTA). A short timeout just wastes the session; give
  # a late tap up to 2 h so one attempt still completes cleanly and the boot-watch runs.
  timeout 7200 "$A" -s "$SERIAL" sideload "$OTA" > "/root/rung-${RUNG}-sideload.log" 2>&1; rc=$?
  log "attempt $attempt rc=$rc ($(tail -c 80 "/root/rung-${RUNG}-sideload.log" | tr -d '\r\n'))"
  [[ $rc -eq 0 ]] && break; sleep 8
done
[[ $rc -eq 0 ]] || { log "sideload failed"; exit 1; }
sleep 3
if [[ $WIPE -eq 1 ]]; then
  log "WIPE: rebooting to bootloader to erase userdata + metadata (first-boot provisioning test)"
  timeout 15 "$A" -s "$SERIAL" reboot bootloader || true
  end=$((SECONDS+120)); while [[ $SECONDS -lt $end ]] && ! "$FB" devices | grep -q "$SERIAL"; do sleep 3; done
  "$FB" devices | grep -q "$SERIAL" || { log "phone did not reach fastboot"; exit 1; }
  only_device_guard; "$FB" -s "$SERIAL" erase userdata && "$FB" -s "$SERIAL" erase metadata || { log "erase failed"; exit 1; }
  "$FB" -s "$SERIAL" reboot
else
  timeout 15 "$A" -s "$SERIAL" reboot || log "reboot refused; tap Reboot on the phone"
fi
log "boot-watch (15 min)"
end=$((SECONDS+900)); booted=0
while [[ $SECONDS -lt $end ]]; do
  if [[ "$(state)" == "device" ]]; then
    bc=$(timeout 6 "$A" -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
    [[ "$bc" == "1" ]] && { booted=1; break; }
  fi
  sleep 5
done
[[ $booted -eq 1 ]] || { log "did not boot within 15 min (adb state=[$(state)], usb=[$(lsusb 2>/dev/null | grep -iE "google|18d1" | sed "s/.*ID //" | tr "\n" " ")]) — an empty usb field means the phone is OFF THE CABLE, not necessarily hung"; exit 1; }
sleep 22  # never `adb root` here (see tools/dev-device/lib.sh): every check below works as shell
log "*** BOOTED rung $RUNG: $("$A" -s "$SERIAL" shell getprop ro.build.date | tr -d '\r') ***"
echo "--- owner / provisioning ---"
"$A" -s "$SERIAL" shell dumpsys device_policy | grep -A3 -iE "Device Owner|deviceOwner" | head -6
echo "device_provisioned=$("$A" -s "$SERIAL" shell settings get global device_provisioned | tr -d '\r') user_setup_complete=$("$A" -s "$SERIAL" shell settings get secure user_setup_complete | tr -d '\r')"
echo "--- home resolution ---"
"$A" -s "$SERIAL" shell cmd package resolve-activity -a android.intent.action.MAIN -c android.intent.category.HOME 2>/dev/null | grep -E "packageName|name=" | head -3
echo "--- kiosk / keyguard ---"
"$A" -s "$SERIAL" shell dumpsys activity activities | grep -m1 mLockTaskModeState
"$A" -s "$SERIAL" shell dumpsys trust 2>/dev/null | grep -m1 -i "keyguard" ; "$A" -s "$SERIAL" shell locksettings get-disabled 2>/dev/null
echo "--- screen ---"
"$A" -s "$SERIAL" shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; "$A" -s "$SERIAL" exec-out cat /sdcard/ui.xml | grep -o 'text="[^"]\{1,40\}"' | head -5 | tr '\n' ' '; echo
echo "--- provisioning log lines ---"
"$A" -s "$SERIAL" logcat -d | grep -iE "fixed-function|FixedFunction|wtf.*DevicePolicy|set-device-owner|DeviceOwner" | head -8
echo "--- popup tripwire ---"; "$A" -s "$SERIAL" logcat -d | grep -ciE "internal problem|isBuildConsistent|system_error"
