#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 DEVICE_SERIAL NEW_EVIDENCE_DIRECTORY EXPECTED_APP_SHA256 EXPECTED_VBMETA_DIGEST" >&2
  exit 2
fi

ADB_BIN="${ADB_BIN:-adb}"
SERIAL="$1"
EVIDENCE="$2"
EXPECTED_APP_SHA="$(printf '%s' "$3" | tr '[:upper:]' '[:lower:]')"
EXPECTED_VBMETA_DIGEST="$(printf '%s' "$4" | tr '[:upper:]' '[:lower:]')"
PACKAGE='dev.phonevault.signer'
ADMIN="${PACKAGE}/.VaultDeviceAdminReceiver"
HOME_ACTIVITY="${PACKAGE}/.MainActivity"

command -v "${ADB_BIN}" >/dev/null || {
  echo "adb is required" >&2
  exit 1
}
[[ "${EXPECTED_APP_SHA}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "expected app hash must be a 64-digit SHA-256 digest" >&2
  exit 1
}
[[ "${EXPECTED_VBMETA_DIGEST}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "expected vbmeta digest must be a 64-digit SHA-256 digest" >&2
  exit 1
}
[[ ! -e "${EVIDENCE}" ]] || {
  echo "refusing to overwrite evidence path: ${EVIDENCE}" >&2
  exit 1
}
mkdir -m 0700 "${EVIDENCE}"

failures=()
record_failure() {
  failures+=("$1")
  printf 'FAIL: %s\n' "$1" >&2
}

capture() {
  local name="$1"
  shift
  if ! "$@" > "${EVIDENCE}/${name}.txt" 2>&1; then
    record_failure "could not capture ${name}"
  fi
  # adb shell normally emits CRLF even when redirected on Unix hosts.
  tr -d '\r' < "${EVIDENCE}/${name}.txt" > "${EVIDENCE}/${name}.clean"
  mv "${EVIDENCE}/${name}.clean" "${EVIDENCE}/${name}.txt"
}

adb_device=("${ADB_BIN}" -s "${SERIAL}")
state="$("${adb_device[@]}" get-state 2>/dev/null || true)"
[[ "${state}" == device ]] || {
  echo "device is not available through adb: ${SERIAL}" >&2
  exit 1
}

{
  printf 'captured_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'serial=%s\n' "${SERIAL}"
  printf 'expected_phonevault_app_sha256=%s\n' "${EXPECTED_APP_SHA}"
  printf 'expected_vbmeta_digest_sha256=%s\n' "${EXPECTED_VBMETA_DIGEST}"
  printf 'host_uname='
  uname -a
  "${ADB_BIN}" version | head -1
} > "${EVIDENCE}/metadata.txt"

capture properties "${adb_device[@]}" shell getprop
capture processes "${adb_device[@]}" shell ps -A
capture binder-services "${adb_device[@]}" shell service list
capture package "${adb_device[@]}" shell dumpsys package "${PACKAGE}"
capture activity "${adb_device[@]}" shell dumpsys activity activities
capture owners "${adb_device[@]}" shell dpm list-owners
capture home "${adb_device[@]}" shell cmd package resolve-activity --brief \
  -a android.intent.action.MAIN -c android.intent.category.HOME
capture user-setup-complete "${adb_device[@]}" shell settings get secure \
  user_setup_complete
capture device-provisioned "${adb_device[@]}" shell settings get global \
  device_provisioned
capture features "${adb_device[@]}" shell pm list features
capture usb "${adb_device[@]}" shell dumpsys usb
# Expansion is intentionally performed by the Android shell, not the host.
# shellcheck disable=SC2016
capture network-interfaces "${adb_device[@]}" shell \
  'for interface in /sys/class/net/*; do basename "${interface}"; done'
# Record Qualcomm subsystem/remoteproc state without requiring root. Missing
# trees are valid; an exposed modem/MPSS node is not.
# shellcheck disable=SC2016
capture remote-subsystems "${adb_device[@]}" shell \
  'for base in /sys/bus/msm_subsys/devices/* /sys/class/remoteproc/*; do
     [ -e "${base}" ] || continue
     name=$(cat "${base}/name" 2>/dev/null)
     state=$(cat "${base}/state" 2>/dev/null)
     printf "%s:%s:%s\n" "$(basename "${base}")" "${name}" "${state}"
   done'
capture selinux "${adb_device[@]}" shell getenforce

runtime_apk="${EVIDENCE}/PhoneVault.apk"
if ! "${adb_device[@]}" exec-out cat \
    /system/app/PhoneVault/PhoneVault.apk > "${runtime_apk}"; then
  record_failure 'could not capture installed Phone Vault APK'
elif [[ ! -s "${runtime_apk}" ]]; then
  record_failure 'installed Phone Vault APK capture is empty'
else
  if command -v sha256sum >/dev/null; then
    runtime_app_sha="$(sha256sum "${runtime_apk}" | awk '{print $1}')"
  else
    runtime_app_sha="$(shasum -a 256 "${runtime_apk}" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "${runtime_app_sha}" PhoneVault.apk \
    > "${EVIDENCE}/PhoneVault.apk.sha256"
  [[ "${runtime_app_sha}" == "${EXPECTED_APP_SHA}" ]] || \
    record_failure "installed Phone Vault APK hash mismatch: ${runtime_app_sha}"
fi

property() {
  "${adb_device[@]}" shell getprop "$1" 2>/dev/null | tr -d '\r'
}
require_property() {
  local name="$1"
  local expected="$2"
  local actual
  actual="$(property "${name}")"
  [[ "${actual}" == "${expected}" ]] || \
    record_failure "${name} expected ${expected}, found ${actual:-<empty>}"
}

require_property ro.product.device crosshatch
require_property ro.product.brand PhoneVault
require_property ro.phonevault.offline true
require_property ro.vendor.phonevault.offline true
require_property ro.radio.noril true
require_property ro.secure 1
require_property ro.adb.secure 1
require_property ro.debuggable 1
require_property ro.build.type userdebug
require_property ro.boot.veritymode enforcing
require_property ro.boot.vbmeta.digest "${EXPECTED_VBMETA_DIGEST}"

verified_boot_state="$(property ro.boot.verifiedbootstate)"
flash_locked="$(property ro.boot.flash.locked)"
vbmeta_state="$(property ro.boot.vbmeta.device_state)"
case "${verified_boot_state}:${flash_locked}:${vbmeta_state}" in
  orange:0:unlocked|yellow:1:locked) ;;
  *) record_failure "inconsistent Verified Boot state: ${verified_boot_state}:${flash_locked}:${vbmeta_state}" ;;
esac

[[ "$(< "${EVIDENCE}/selinux.txt")" == Enforcing ]] || \
  record_failure 'SELinux is not enforcing'
[[ "$(< "${EVIDENCE}/owners.txt")" == $'1 owner:\nUser  0: admin='"${ADMIN}"',DeviceOwner,Affiliated' ]] || \
  record_failure 'Phone Vault is not the sole user-0 device owner'
grep -Fqx "${HOME_ACTIVITY}" "${EVIDENCE}/home.txt" || \
  record_failure 'Phone Vault is not the resolved HOME activity'
grep -Fqx '1' "${EVIDENCE}/user-setup-complete.txt" || \
  record_failure 'system user setup is not complete'
grep -Fqx '1' "${EVIDENCE}/device-provisioned.txt" || \
  record_failure 'device is not marked provisioned'
grep -Eq '^[[:space:]]*mLockTaskModeState=LOCKED$' \
  "${EVIDENCE}/activity.txt" || \
  record_failure 'appliance is not in managed lock-task mode'
grep -Eq '^[[:space:]]*u0:\[dev\.phonevault\.signer\]$' \
  "${EVIDENCE}/activity.txt" || \
  record_failure 'Phone Vault is not the sole user-0 lock-task package'
grep -Fq "${HOME_ACTIVITY}" "${EVIDENCE}/activity.txt" || \
  record_failure 'Phone Vault HOME activity is not present in the active task state'
grep -Fq 'codePath=/system/app/PhoneVault' "${EVIDENCE}/package.txt" || \
  record_failure 'Phone Vault is not installed as an ordinary system app'
if grep -Fq 'android.permission.INTERNET' "${EVIDENCE}/package.txt"; then
  record_failure 'Phone Vault package requests INTERNET permission'
fi

forbidden_features="$(grep -E \
  '^feature:android\.hardware\.(bluetooth|camera|context_hub|location|microphone|nfc|se|sensor|telephony|usb\.host|wifi)(\.|$)|^feature:android\.software\.(ipsec_tunnels|sip|telecom)(\.|$)' \
  "${EVIDENCE}/features.txt" || true)"
if [[ -n "${forbidden_features}" ]]; then
  record_failure "forbidden hardware/software features are declared"
  printf '%s\n' "${forbidden_features}" > "${EVIDENCE}/forbidden-features.txt"
fi
grep -Fqx 'feature:android.hardware.usb.accessory' \
  "${EVIDENCE}/features.txt" || \
  record_failure 'Android Open Accessory feature is not declared at runtime'

forbidden_processes="$(grep -Ei \
  '(^|[^[:alnum:]_])(android\.hardware\.(bluetooth|camera|gnss|nfc|radio|sensors|wifi)[^[:space:]]*|cameraserver|clatd|cnd|cnss-daemon|dmesgd|heapprofd|hostapd|imsdatadaemon|incidentd|ipacm|mdnsd|mediatranscoding|netd|netmgrd|perfetto|qcrild|rild|sensors|sscrpcd|traced(_probes)?|wificond|wpa_supplicant)([^[:alnum:]_]|$)' \
  "${EVIDENCE}/processes.txt" || true)"
if [[ -n "${forbidden_processes}" ]]; then
  record_failure 'forbidden network/radio/camera/sensor processes are running'
  printf '%s\n' "${forbidden_processes}" > "${EVIDENCE}/forbidden-processes.txt"
fi

forbidden_services="$(grep -Ei \
  '(^|[^[:alnum:]_])(adservices|appcompat_overrides|appsearch|bluetooth|camera|connectivity|device_lock|ethernet|game|gnss|healthconnect|incidentcompanion|isolated_compilation|location|media_communication|netd|netpolicy|netstats|network_management|network_score|nfc|on_device_personalization|radio|ranging|reboot_readiness|safety_center|sdk_sandbox|sensorservice|telecom|telephony|tethering|uwb|vcn|vpn|wifi)([^[:alnum:]_]|$)' \
  "${EVIDENCE}/binder-services.txt" || true)"
if [[ -n "${forbidden_services}" ]]; then
  record_failure 'forbidden framework/HAL services are registered'
  printf '%s\n' "${forbidden_services}" > "${EVIDENCE}/forbidden-services.txt"
fi

forbidden_interfaces="$(grep -Ei \
  '^(ap|ccmni|eth|p2p|rmnet|rndis|swlan|usb|wlan)[0-9._-]*$' \
  "${EVIDENCE}/network-interfaces.txt" || true)"
if [[ -n "${forbidden_interfaces}" ]]; then
  record_failure 'forbidden external network interfaces exist'
  printf '%s\n' "${forbidden_interfaces}" > "${EVIDENCE}/forbidden-interfaces.txt"
fi

forbidden_remote_subsystems="$(grep -Ei \
  '(^|:)(modem|mpss)(:|$)' "${EVIDENCE}/remote-subsystems.txt" || true)"
if [[ -n "${forbidden_remote_subsystems}" ]]; then
  record_failure 'modem/MPSS remote subsystem is exposed by the running kernel'
  printf '%s\n' "${forbidden_remote_subsystems}" \
    > "${EVIDENCE}/forbidden-remote-subsystems.txt"
fi

usb_config="$(property sys.usb.config)"
usb_state="$(property sys.usb.state)"
case "${usb_config}" in
  accessory,adb|adb,accessory) ;;
  *) record_failure "development USB config is not exactly accessory plus ADB: ${usb_config:-<empty>}" ;;
esac
case "${usb_state}" in
  accessory,adb|adb,accessory) ;;
  *) record_failure "development USB state is not exactly accessory plus ADB: ${usb_state:-<empty>}" ;;
esac
[[ "${usb_state}" == "${usb_config}" ]] || \
  record_failure "USB configured and active functions differ: ${usb_config:-<empty>} vs ${usb_state:-<empty>}"

forbidden_properties="$(grep -Ei \
  '^\[(debug\.(media\.transcoding|stagefright)|masterclear\.allow_retain_esim|persist\.(camera|radio|rcs)(\.|\])|persist\.traced\.enable\]|persist\.vendor\.(cne|data\.iwlan|debug\.sensors|radio|sys\.modem)(\.|\])|persist\.vendor\.sys\.ssr\.restart_level\]: \[[^]]*(modem|slpi)|ro\.audio\.monitorRotation\]|ro\.radio\.log_|ro\.telephony\.|ro\.vendor\.(bt|bluetooth|camera|display\.sensortype)|vendor\.(ese|qcom\.bluetooth|rild)\.)' \
  "${EVIDENCE}/properties.txt" || true)"
if [[ -n "${forbidden_properties}" ]]; then
  record_failure 'forbidden consumer/radio properties exist at runtime'
  printf '%s\n' "${forbidden_properties}" > "${EVIDENCE}/forbidden-properties.txt"
fi

if ((${#failures[@]} == 0)); then
  printf 'PASS: Phone Vault development-device static runtime audit\n' \
    > "${EVIDENCE}/RESULT.txt"
else
  {
    printf 'FAIL: Phone Vault development-device static runtime audit\n'
    printf '%s\n' "${failures[@]}"
  } > "${EVIDENCE}/RESULT.txt"
fi

(
  cd "${EVIDENCE}"
  checksum_file="$(mktemp -t phone-vault-audit-checksums.XXXXXX)"
  if command -v sha256sum >/dev/null; then
    find . -type f ! -name SHA256SUMS -print0 | sort -z | \
      xargs -0 sha256sum > "${checksum_file}"
  else
    find . -type f ! -name SHA256SUMS -print0 | sort -z | \
      xargs -0 shasum -a 256 > "${checksum_file}"
  fi
  mv "${checksum_file}" SHA256SUMS
)

if command -v sha256sum >/dev/null; then
  evidence_checksum_manifest_sha="$(sha256sum \
    "${EVIDENCE}/SHA256SUMS" | awk '{print $1}')"
else
  evidence_checksum_manifest_sha="$(shasum -a 256 \
    "${EVIDENCE}/SHA256SUMS" | awk '{print $1}')"
fi
[[ "${evidence_checksum_manifest_sha}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "could not derive evidence checksum-manifest digest" >&2
  exit 1
}

cat "${EVIDENCE}/RESULT.txt"
printf 'evidence_checksum_manifest_sha256=%s\n' \
  "${evidence_checksum_manifest_sha}"
((${#failures[@]} == 0))
