# shellcheck shell=bash
# Sourced (never run) by flash-rung.sh and wipe-data.sh: the one-device guard, the throwaway-only
# erase and the boot watch. The caller sets A (adb), FB (fastboot) and SERIAL before sourcing;
# every adb/fastboot call here is pinned to "$SERIAL".
: "${A:?set A (adb) before sourcing device-guard.sh}"
: "${FB:?set FB (fastboot) before sourcing device-guard.sh}"
: "${SERIAL:?set SERIAL before sourcing device-guard.sh}"

log(){ echo "[$(date +%H:%M:%S)] $*"; }

# Exactly one phone may be attached: every adb/fastboot call is pinned to "$SERIAL", and a
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

# adb state of $SERIAL (device, sideload, recovery, unauthorized, ...); empty when it is not on adb.
adb_state() { "$A" devices 2>/dev/null | awk -v s="$SERIAL" 'NR>1 && $1==s {print $2}'; }

fastboot_present() { "$FB" devices 2>/dev/null | awk -v s="$SERIAL" '$1==s {f=1} END {exit !f}'; }

# wait_for_fastboot SECONDS: 0 once $SERIAL is in fastboot, 1 when it never got there.
wait_for_fastboot() {
  local end=$((SECONDS + $1))
  while [[ $SECONDS -lt $end ]] && ! fastboot_present; do sleep 3; done
  fastboot_present
}

# Erase userdata + metadata from the bootloader: destroys the on-device wallet and PIN. Only on
# a throwaway wallet (PV_THROWAWAY_DEVICE=1, checked here as well as by the caller) and only
# with exactly $SERIAL attached.
erase_userdata_metadata() {
  [[ "${PV_THROWAWAY_DEVICE:-}" == "1" ]] || { log "refusing to erase $SERIAL: PV_THROWAWAY_DEVICE is not 1"; exit 1; }
  only_device_guard
  if ! { "$FB" -s "$SERIAL" erase userdata && "$FB" -s "$SERIAL" erase metadata; }; then
    log "erase failed"
    exit 1
  fi
}

# wait_for_boot SECONDS: 0 once $SERIAL reports sys.boot_completed=1 over adb, 1 on timeout.
wait_for_boot() {
  local end=$((SECONDS + $1)) completed
  while [[ $SECONDS -lt $end ]]; do
    if [[ "$(adb_state)" == "device" ]]; then
      completed="$(timeout 6 "$A" -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
      [[ "$completed" == "1" ]] && return 0
    fi
    sleep 5
  done
  return 1
}
