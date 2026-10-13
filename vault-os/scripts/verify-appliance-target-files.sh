#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 4 ]]; then
  echo "usage: $0 TARGET_FILES_ZIP [EXPECTED_AVB_KEY_PATH [EXPECTED_APP_CERT_SHA256 [EXPECTED_APP_SHA256]]]" >&2
  exit 2
fi

TARGET_FILES="$1"
EXPECTED_AVB_KEY_PATH="${2:-vendor/phonevault/keys/avb.pem}"
EXPECTED_APP_CERT="${3:-}"
EXPECTED_APP_SHA="${4:-}"
[[ -s "${TARGET_FILES}" ]] || {
  echo "missing target-files archive: ${TARGET_FILES}" >&2
  exit 1
}
command -v unzip >/dev/null || {
  echo "unzip is required" >&2
  exit 1
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POLICY="${ROOT}/policy/forbidden-target-files.regex"
CONNECTIVITY_APEX_POLICY="${ROOT}/policy/forbidden-connectivity-apex.regex"
WIRELESS_APEX_POLICY="${ROOT}/policy/forbidden-wireless-apex.regex"
MEDIA_APEX_POLICY="${ROOT}/policy/forbidden-media-apex.regex"
KERNEL_POLICY="${ROOT}/policy/forbidden-kernel-config.regex"
[[ -s "${POLICY}" ]] || {
  echo "missing appliance policy: ${POLICY}" >&2
  exit 1
}
[[ -s "${KERNEL_POLICY}" ]] || {
  echo "missing kernel appliance policy: ${KERNEL_POLICY}" >&2
  exit 1
}
[[ -s "${CONNECTIVITY_APEX_POLICY}" ]] || {
  echo "missing connectivity APEX policy: ${CONNECTIVITY_APEX_POLICY}" >&2
  exit 1
}
[[ -s "${WIRELESS_APEX_POLICY}" ]] || {
  echo "missing wireless compatibility APEX policy: ${WIRELESS_APEX_POLICY}" >&2
  exit 1
}
[[ -s "${MEDIA_APEX_POLICY}" ]] || {
  echo "missing media compatibility APEX policy: ${MEDIA_APEX_POLICY}" >&2
  exit 1
}

listing="$(mktemp -t phone-vault-target-files.XXXXXX)"
violations="$(mktemp -t phone-vault-violations.XXXXXX)"
signer_apk="$(mktemp -t phone-vault-signer.XXXXXX)"
apex_audit_dir="$(mktemp -d -t phone-vault-apex-audit.XXXXXX)"
trap 'rm -f "${listing}" "${violations}" "${signer_apk}"; rm -rf -- "${apex_audit_dir}"' EXIT
unzip -Z1 "${TARGET_FILES}" > "${listing}"

audit_apex_payload() {
  local apex_name="$1"
  local payload_policy="$2"
  local violation_label="$3"
  local apex_paths apex_count apex_path module_dir packaged_apex
  local original_entry original_entry_count payload_listing
  local payload_violations expression matches

  apex_paths="$(
    grep -E "(^|/)${apex_name//./\\.}\\.(apex|capex)$" "${listing}" || true
  )"
  [[ -n "${apex_paths}" ]] || return 0
  apex_count="$(wc -l <<<"${apex_paths}" | tr -d ' ')"
  [[ "${apex_count}" == 1 ]] || {
    echo "expected exactly one ${apex_name} APEX when present, found ${apex_count}" >&2
    return 1
  }
  command -v debugfs >/dev/null || {
    echo "debugfs is required to audit ${apex_name} APEX payload" >&2
    return 1
  }

  apex_path="${apex_paths}"
  module_dir="${apex_audit_dir}/${apex_name}"
  mkdir -p "${module_dir}/root"
  packaged_apex="${module_dir}/packaged.apex"
  unzip -p "${TARGET_FILES}" "${apex_path}" > "${packaged_apex}" || {
    echo "could not extract ${apex_name} from target-files" >&2
    return 1
  }
  if [[ "${apex_path}" == *.capex ]]; then
    original_entry="$(
      unzip -Z1 "${packaged_apex}" | grep -E '(^|/)original_apex$' || true
    )"
    original_entry_count="$(
      grep -Ec '(^|/)original_apex$' <<<"${original_entry}" || true
    )"
    [[ "${original_entry_count}" == 1 ]] || {
      echo "compressed ${apex_name} APEX must contain exactly one original_apex" >&2
      return 1
    }
    unzip -p "${packaged_apex}" "${original_entry}" \
      > "${module_dir}/original.apex" || {
        echo "could not decompress ${apex_name} APEX" >&2
        return 1
      }
    packaged_apex="${module_dir}/original.apex"
  fi
  unzip -p "${packaged_apex}" apex_payload.img \
    > "${module_dir}/apex_payload.img" || {
      echo "could not extract ${apex_name} filesystem payload" >&2
      return 1
    }
  debugfs -R "rdump / ${module_dir}/root" \
    "${module_dir}/apex_payload.img" >/dev/null 2>&1 || {
      echo "could not inspect ${apex_name} filesystem payload" >&2
      return 1
    }
  payload_listing="$(
    cd "${module_dir}/root"
    find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort
  )"
  payload_violations=''
  local permitted_expression permitted_matches
  while IFS= read -r expression; do
    [[ -n "${expression}" && "${expression}" != \#* && "${expression}" != !* ]] || continue
    matches="$(grep -Ei "${expression}" <<<"${payload_listing}" || true)"
    if [[ -n "${matches}" ]]; then
      payload_violations+="${matches}"$'\n'
    fi
  done < "${payload_policy}"
  # Lines beginning with "!" are exact permitted patterns; a matching path is
  # exempt from the forbidden patterns above.
  while IFS= read -r permitted_expression; do
    [[ "${permitted_expression}" == !* ]] || continue
    permitted_expression="${permitted_expression#!}"
    [[ -n "${payload_violations}" ]] || break
    permitted_matches="$(grep -E "${permitted_expression}" <<<"${payload_violations}" || true)"
    if [[ -n "${permitted_matches}" ]]; then
      payload_violations="$(grep -Fvx -f <(printf '%s\n' "${permitted_matches}") \
        <<<"${payload_violations}" || true)"
      [[ -z "${payload_violations}" ]] || payload_violations+=$'\n'
    fi
  done < "${payload_policy}"
  if [[ -n "${payload_violations}" ]]; then
    echo "${violation_label} inside ${apex_name} APEX:" >&2
    printf '%s' "${payload_violations}" | sort -u >&2
    return 1
  fi
}

while IFS= read -r expression; do
  [[ -n "${expression}" && "${expression}" != \#* ]] || continue
  grep -Ei "${expression}" "${listing}" >> "${violations}" || true
done < "${POLICY}"

kernel_configs='META/kernel_configs.txt'
grep -Fqx "${kernel_configs}" "${listing}" || {
  echo "missing target-files kernel configuration: ${kernel_configs}" >&2
  exit 1
}
kernel_policy="$(unzip -p "${TARGET_FILES}" "${kernel_configs}")"
kernel_violations=''
while IFS= read -r expression; do
  [[ -n "${expression}" && "${expression}" != \#* ]] || continue
  matches="$(grep -E "${expression}" <<<"${kernel_policy}" || true)"
  if [[ -n "${matches}" ]]; then
    kernel_violations+="${matches}"$'\n'
  fi
done < "${KERNEL_POLICY}"
if [[ -n "${kernel_violations}" ]]; then
  echo "forbidden appliance kernel drivers remain enabled:" >&2
  printf '%s' "${kernel_violations}" | sort -u >&2
  exit 1
fi
for required_kernel_setting in \
    'CONFIG_PHONEVAULT_APPLIANCE=y' \
    'CONFIG_KEYS=y' \
    'CONFIG_DM_VERITY=y' \
    'CONFIG_QCOM_SCM=y' \
    'CONFIG_QSEECOM=y' \
    'CONFIG_CITADEL=y' \
    'CONFIG_MSM_GLINK_SPI_XPRT=y' \
    'CONFIG_USB_GADGET=y' \
    'CONFIG_USB_DWC3=y' \
    'CONFIG_USB_DWC3_DUAL_ROLE=y' \
    'CONFIG_USB_DWC3_MSM=y' \
    'CONFIG_USB_CONFIGFS=y' \
    'CONFIG_USB_CONFIGFS_F_ACC=y'; do
  grep -Fqx "${required_kernel_setting}" <<<"${kernel_policy}" || {
    echo "missing required appliance kernel setting: ${required_kernel_setting}" >&2
    exit 1
  }
done

sort -u -o "${violations}" "${violations}"
# Exact-path exemptions for HAL client interface libraries that core platform
# code links (see policy/permitted-interface-libraries.txt). Entries are
# constrained to shared libraries under SYSTEM/VENDOR lib directories and are
# matched literally, so no pattern can widen the exemption.
PERMITTED_INTERFACE_LIBRARIES="${ROOT}/policy/permitted-interface-libraries.txt"
if [[ -s "${PERMITTED_INTERFACE_LIBRARIES}" ]]; then
  permitted_entries="$(mktemp -t phone-vault-permitted.XXXXXX)"
  trap 'rm -f "${listing}" "${violations}" "${signer_apk}" "${permitted_entries}"; rm -rf -- "${apex_audit_dir}"' EXIT
  grep -Ev '^([[:space:]]*#|[[:space:]]*$)' "${PERMITTED_INTERFACE_LIBRARIES}" \
    > "${permitted_entries}" || true
  while IFS= read -r permitted_entry; do
    [[ "${permitted_entry}" =~ ^(SYSTEM|VENDOR)/lib(64)?/[A-Za-z0-9._@+-]+\.so$ ]] || {
      echo "invalid permitted interface library entry: ${permitted_entry}" >&2
      exit 1
    }
  done < <(cat "${permitted_entries}")
  if [[ -s "${permitted_entries}" ]]; then
    grep -Fvx -f "${permitted_entries}" "${violations}" > "${violations}.filtered" || true
    mv "${violations}.filtered" "${violations}"
  fi
fi
if [[ -s "${violations}" ]]; then
  echo "forbidden appliance artifacts found:" >&2
  sed -n '1,200p' "${violations}" >&2
  exit 1
fi

# These APEXes remain only because Android/SystemUI links their framework jars.
# Inspect the actual payload rather than trusting the outer target-files path.
audit_apex_payload com.android.tethering "${CONNECTIVITY_APEX_POLICY}" \
  "forbidden network runtime remains"
for wireless_apex_name in com.android.btservices com.android.wifi; do
  audit_apex_payload "${wireless_apex_name}" "${WIRELESS_APEX_POLICY}" \
    "forbidden radio runtime remains"
done
for media_apex_name in com.android.media com.android.mediaprovider; do
  audit_apex_payload "${media_apex_name}" "${MEDIA_APEX_POLICY}" \
    "forbidden consumer runtime remains"
done

phone_vault_apks="$(grep -Ec '/PhoneVault\.apk$' "${listing}" || true)"
[[ "${phone_vault_apks}" == 1 ]] || {
  echo "expected exactly one PhoneVault.apk, found ${phone_vault_apks}" >&2
  exit 1
}
phone_vault_path="$(grep -E '/PhoneVault\.apk$' "${listing}")"
if [[ "${phone_vault_path}" == */priv-app/* ]]; then
  echo "PhoneVault must not receive implicit priv-app authority: ${phone_vault_path}" >&2
  exit 1
fi
[[ "${phone_vault_path}" == SYSTEM/app/PhoneVault/PhoneVault.apk ]] || {
  echo "unexpected PhoneVault system-app path: ${phone_vault_path}" >&2
  exit 1
}
if [[ -n "${EXPECTED_APP_CERT}" || -n "${EXPECTED_APP_SHA}" ]]; then
  unzip -p "${TARGET_FILES}" "${phone_vault_path}" > "${signer_apk}"
fi
if [[ -n "${EXPECTED_APP_CERT}" ]]; then
  "${ROOT}/scripts/verify-signer-apk.sh" "${signer_apk}" "${EXPECTED_APP_CERT}"
fi
if [[ -n "${EXPECTED_APP_SHA}" ]]; then
  expected_app_sha_lower="$(printf '%s' "${EXPECTED_APP_SHA}" | tr '[:upper:]' '[:lower:]')"
  [[ "${expected_app_sha_lower}" =~ ^[0-9a-f]{64}$ ]] || {
    echo "expected Phone Vault APK hash is not a SHA-256 digest" >&2
    exit 1
  }
  actual_app_sha="$(sha256sum "${signer_apk}" | awk '{print $1}')"
  [[ "${actual_app_sha}" == "${expected_app_sha_lower}" ]] || {
    echo "Phone Vault APK hash mismatch: expected ${expected_app_sha_lower}, got ${actual_app_sha}" >&2
    exit 1
  }
fi

misc_info='META/misc_info.txt'
grep -Fqx "${misc_info}" "${listing}" || {
  echo "missing target-files metadata: ${misc_info}" >&2
  exit 1
}
misc_policy="$(unzip -p "${TARGET_FILES}" "${misc_info}")"

android_info='OTA/android-info.txt'
grep -Fqx "${android_info}" "${listing}" || {
  echo "missing target-files device identity gate: ${android_info}" >&2
  exit 1
}
android_info_policy="$(unzip -p "${TARGET_FILES}" "${android_info}" | tr -d '\r')"
[[ "${android_info_policy}" == 'require board=crosshatch' ]] || {
  echo "android-info.txt must allow exactly crosshatch: ${android_info_policy}" >&2
  exit 1
}

for required_avb_setting in \
    'avb_enable=true' \
    'avb_vbmeta_algorithm=SHA256_RSA4096' \
    "avb_vbmeta_key_path=${EXPECTED_AVB_KEY_PATH}"; do
  grep -Fqx "${required_avb_setting}" <<<"${misc_policy}" || {
    echo "missing required AVB policy: ${required_avb_setting}" >&2
    exit 1
  }
done
vbmeta_args="$(sed -n 's/^avb_vbmeta_args=//p' <<<"${misc_policy}")"
[[ -n "${vbmeta_args}" ]] || {
  echo "missing top-level AVB arguments" >&2
  exit 1
}
if grep -Eq '(^|[[:space:]])--flags([=[:space:]]|$)' \
    <<<"${vbmeta_args}"; then
  echo "top-level vbmeta disables verification or hashtree enforcement: ${vbmeta_args}" >&2
  exit 1
fi
rollback_index="$(sed -E -n \
  's/.*--rollback_index[=[:space:]]+([0-9]+).*/\1/p' \
  <<<"${vbmeta_args}")"
[[ "${rollback_index}" =~ ^[0-9]+$ && "${rollback_index}" != 0 ]] || {
  echo "top-level vbmeta lacks a positive rollback index: ${vbmeta_args}" >&2
  exit 1
}

system_properties=''
for build_prop in SYSTEM/build.prop SYSTEM/system/build.prop; do
  if grep -Fqx "${build_prop}" "${listing}"; then
    system_properties+="$(unzip -p "${TARGET_FILES}" "${build_prop}")"$'\n'
  fi
done
[[ -n "${system_properties}" ]] || {
  echo "missing system build properties" >&2
  exit 1
}
for required_property in \
    'ro.phonevault.offline=true' \
    'ro.radio.noril=true' \
    'config.disable_cameraservice=true' \
    'config.disable_networktime=true'; do
  grep -Fqx "${required_property}" <<<"${system_properties}" || {
    echo "missing required appliance property: ${required_property}" >&2
    exit 1
  }
done
grep -Eq '^ro\.phonevault\.version=.+$' <<<"${system_properties}" || {
  echo "missing Phone Vault build version" >&2
  exit 1
}
# Android composes ro.product.brand at runtime from the partition-specific
# brand properties (product first in the default source order); the system
# partition keeps a generic brand. Require the appliance brand where it is
# actually recorded and in the build fingerprint.
grep -Eq '^ro\.build\.fingerprint=PhoneVault/vault_crosshatch/crosshatch:' \
    <<<"${system_properties}" || {
  echo "system build fingerprint is not a PhoneVault vault_crosshatch build" >&2
  exit 1
}
product_properties=''
for build_prop in PRODUCT/etc/build.prop PRODUCT/build.prop; do
  if grep -Fqx "${build_prop}" "${listing}"; then
    product_properties+="$(unzip -p "${TARGET_FILES}" "${build_prop}")"$'\n'
  fi
done
grep -Fqx 'ro.product.product.brand=PhoneVault' <<<"${product_properties}" || {
  echo "missing product partition appliance brand" >&2
  exit 1
}

vendor_properties=''
for build_prop in VENDOR/build.prop VENDOR/etc/build.prop; do
  if grep -Fqx "${build_prop}" "${listing}"; then
    vendor_properties+="$(unzip -p "${TARGET_FILES}" "${build_prop}")"$'\n'
  fi
done
[[ -n "${vendor_properties}" ]] || {
  echo "missing vendor build properties" >&2
  exit 1
}
grep -Fqx 'ro.vendor.phonevault.offline=true' <<<"${vendor_properties}" || {
  echo "missing immutable vendor HAL appliance property" >&2
  exit 1
}
grep -Fqx 'ro.product.vendor.brand=PhoneVault' <<<"${vendor_properties}" || {
  echo "missing vendor partition appliance brand" >&2
  exit 1
}
installed_properties="$({
  while IFS= read -r build_prop; do
    unzip -p "${TARGET_FILES}" "${build_prop}"
  done < <(grep -E '(^|/)build\.prop$' "${listing}")
})"
forbidden_properties="$(printf '%s\n' "${installed_properties}" |
  grep -Ei '^(bluetooth\.|debug\.(media\.transcoding|stagefright)|masterclear\.allow_retain_esim|media\.(aac_51_output_enabled|stagefright)|mm\.enable\.|mmp\.enable\.|persist\.(bluetooth|camera|data|mm|radio|rcs|rild|rmnet|timed)(\.|=)|persist\.traced\.enable=|persist\.vendor\.(cne|data\.(iwlan|mode)|debug\.sensors|radio|sys\.modem)(\.|=)|persist\.vendor\.sys\.ssr\.restart_level=.*(modem|slpi)|ro\.audio\.monitorRotation=|ro\.bluetooth\.|ro\.qti\.(sdk\.)?sensors\.|ro\.radio\.log_|ro\.telephony\.|ro\.vendor\.(bt|bluetooth|camera|display\.sensortype)|telephony\.|vendor\.(ese|qcom\.bluetooth|rild)\.|vidc\.)' || true)"
if [[ -n "${forbidden_properties}" ]]; then
  echo "forbidden consumer/radio properties remain:" >&2
  printf '%s\n' "${forbidden_properties}" >&2
  exit 1
fi

core_hardware='VENDOR/etc/permissions/handheld_core_hardware.xml'
grep -Fqx "${core_hardware}" "${listing}" || {
  echo "missing minimal Phone Vault core hardware declaration: ${core_hardware}" >&2
  exit 1
}
core_hardware_policy="$(unzip -p "${TARGET_FILES}" "${core_hardware}")"
declared_core_features="$(sed -n 's/.*<feature[[:space:]][^>]*name="\([^"]*\)".*/\1/p' \
  <<<"${core_hardware_policy}" | sort -u)"
allowed_core_features="$(printf '%s\n' \
  'android.hardware.screen.landscape' \
  'android.hardware.screen.portrait' \
  'android.hardware.security.model.compatible' \
  'android.hardware.touchscreen' \
  'android.software.device_admin' \
  'android.software.home_screen' \
  'android.software.secure_lock_screen' | sort -u)"
[[ "${declared_core_features}" == "${allowed_core_features}" ]] || {
  echo "core hardware declarations do not match the Phone Vault allowlist" >&2
  diff -u <(printf '%s\n' "${allowed_core_features}") \
    <(printf '%s\n' "${declared_core_features}") >&2 || true
  exit 1
}

for forbidden_feature_file in \
    VENDOR/etc/permissions/android.hardware.usb.host.xml \
    VENDOR/etc/permissions/android.hardware.context_hub.xml \
    VENDOR/etc/permissions/android.hardware.sensor.accelerometer.xml \
    VENDOR/etc/permissions/android.hardware.sensor.assist.xml \
    VENDOR/etc/permissions/android.hardware.sensor.barometer.xml \
    VENDOR/etc/permissions/android.hardware.sensor.compass.xml \
    VENDOR/etc/permissions/android.hardware.sensor.gyroscope.xml \
    VENDOR/etc/permissions/android.hardware.sensor.hifi_sensors.xml \
    VENDOR/etc/permissions/android.hardware.sensor.light.xml \
    VENDOR/etc/permissions/android.hardware.sensor.proximity.xml \
    VENDOR/etc/permissions/android.hardware.sensor.stepcounter.xml \
    VENDOR/etc/permissions/android.hardware.sensor.stepdetector.xml; do
  if grep -Fqx "${forbidden_feature_file}" "${listing}"; then
    echo "forbidden appliance hardware feature file: ${forbidden_feature_file}" >&2
    exit 1
  fi
done

# Feature XMLs are data, so a misleading filename could otherwise evade the
# path policy. Inspect every installed permissions XML and reject capabilities
# outside the appliance boundary regardless of where they were declared.
installed_declared_features="$({
  while IFS= read -r feature_xml; do
    unzip -p "${TARGET_FILES}" "${feature_xml}" |
      sed -n 's/.*<feature[[:space:]][^>]*name="\([^"]*\)".*/\1/p'
  done < <(grep -E '/etc/permissions/[^/]+\.xml$' "${listing}")
} | sort -u)"
grep -Fqx 'android.hardware.usb.accessory' \
  <<<"${installed_declared_features}" || {
  echo "Android Open Accessory feature is not declared" >&2
  exit 1
}
forbidden_declared_features="$(grep -E \
  '^android\.hardware\.(bluetooth|camera|context_hub|location|microphone|nfc|se|sensor|telephony|usb\.host|wifi)(\.|$)|^android\.software\.(ipsec_tunnels|sip|telecom)(\.|$)' \
  <<<"${installed_declared_features}" || true)"
if [[ -n "${forbidden_declared_features}" ]]; then
  echo "forbidden capabilities declared by installed feature XML:" >&2
  printf '%s\n' "${forbidden_declared_features}" >&2
  exit 1
fi

# VINTF declarations are part of the runtime contract. A removed binary is not
# enough if the device manifest or compatibility matrices still advertise a
# network, sensor, camera, or consumer-media HAL under an innocuous XML path.
# system_server's own android.frameworks.sensorservice declaration is retained
# with the framework sensor service (zero sensors, no vendor sensors HAL); the
# vendor android.hardware.sensors HAL remains forbidden.
# Android's numbered framework compatibility matrices
# (SYSTEM/etc/vintf/compatibility_matrix.<level>.xml) enumerate every HAL the
# framework at that level may optionally consume; they declare nothing about
# this device and libvintf requires them at boot. Every manifest, manifest
# fragment, the device compatibility matrix, and the device-owned framework
# matrix (compatibility_matrix.device.xml) are still scanned.
vintf_xmls="$(grep -E '^(SYSTEM|SYSTEM_EXT|PRODUCT|VENDOR|ODM)(/[^/]+)*/etc/vintf/.*\.xml$' \
  "${listing}" | grep -Ev '^SYSTEM/etc/vintf/compatibility_matrix\.[0-9]+\.xml$' || true)"
[[ -n "${vintf_xmls}" ]] || {
  echo "missing installed VINTF declarations" >&2
  exit 1
}
forbidden_vintf_names="$({
  while IFS= read -r vintf_xml; do
    unzip -p "${TARGET_FILES}" "${vintf_xml}" |
      sed -n 's/.*<name>[[:space:]]*\([^<[:space:]]*\)[[:space:]]*<\/name>.*/\1/p'
  done <<<"${vintf_xmls}"
} | grep -E '^(android\.system\.wifi\.|android\.hardware\.(bluetooth|camera|gnss|neuralnetworks|nfc|radio|sensors|soundtrigger|tetheroffload|wifi)(\.|$)|com\.qualcomm\.qti\.(imscmservice|uceservice)$|lineage\.hardware\.radio(\.|$)|vendor\.google\.(paintbox|radioext|wifi_ext|wireless_charger)(\.|$)|vendor\.lineage\.(powershare|radio)(\.|$)|vendor\.nxp\.(nxpese|nxpnfc)$|vendor\.qti\.(data\.factory|hardware\.radio)(\.|$)|vendor\.qti\.ims)' \
  | sort -u || true)"
if [[ -n "${forbidden_vintf_names}" ]]; then
  echo "forbidden HALs remain in installed VINTF declarations:" >&2
  printf '%s\n' "${forbidden_vintf_names}" >&2
  exit 1
fi

installed_init_rcs="$(grep -E '(^|/)etc/init/.*\.rc$|^(ROOT|BOOT/RAMDISK|VENDOR_BOOT/RAMDISK|RECOVERY/RAMDISK)/init[^/]*\.rc$' \
  "${listing}" || true)"
[[ -n "${installed_init_rcs}" ]] || {
  echo "missing installed init policy" >&2
  exit 1
}
forbidden_init_policy="$({
  while IFS= read -r init_rc; do
    unzip -p "${TARGET_FILES}" "${init_rc}" |
      awk -v file="${init_rc}" '
        /^[[:space:]]*#/ { next }
        /^on[[:space:]]/ { trigger = $0 }
        /^[^[:space:]]/ && !/^on[[:space:]]/ { trigger = "" }
        { print file ":" trigger ":" $0 }
      '
  done <<<"${installed_init_rcs}"
} | grep -Ei 'import .*\.(diag|logging|mpssrfs)\.rc|[[:space:]](start|restart)[[:space:]]+([^[:space:]]*(bluetooth|camera|gnss|gps|location|modem|netd|nfc|radio|ril|sensor|wifi)|bugreport|devstart_sh|ss_ramdump)|[[:space:]]service[[:space:]]+[^[:space:]]*(bluetooth|camera|gnss|gps|location|modem|nfc|radio|ril|sensor|wifi)|/data/vendor/(camera|location|modem|netmgr|nfc|nnhal|radio|rebootescrow|secure_element|sensors|wifi|wifidump)|/dev/socket/(location|netmgr|qmux_(bluetooth|gps|radio))|/dev/stune/camera-daemon|/sys/(class/(power_supply/wireless|rfkill)|kernel/boot_(cdsp|slpi)|module/wlan)|setprop[[:space:]]+[^[:space:]]*(radio|wifi)|wait_for_prop[[:space:]]+vendor\.qcom\.(devup|time\.set)' \
  | grep -Ev '^SYSTEM(/system)?/etc/init/hw/init\.rc:on bpf-progs-loaded && property:ro\.phonevault\.offline=false:[[:space:]]+start netd$' \
  | sort -u || true)"
if [[ -n "${forbidden_init_policy}" ]]; then
  echo "forbidden runtime policy remains in installed init files:" >&2
  printf '%s\n' "${forbidden_init_policy}" >&2
  exit 1
fi

usb_rc='VENDOR/etc/init/hw/init.sdm845.usb.rc'
grep -Fqx "${usb_rc}" "${listing}" || {
  echo "missing minimal USB init policy: ${usb_rc}" >&2
  exit 1
}
usb_policy="$(unzip -p "${TARGET_FILES}" "${usb_rc}")"
grep -Fq 'functions/accessory.gs2' <<<"${usb_policy}" || {
  echo "USB accessory function is missing" >&2
  exit 1
}
grep -Fq 'setprop sys.usb.configfs 2' <<<"${usb_policy}" || {
  echo "USB policy does not select the isolated Phone Vault configfs mode" >&2
  exit 1
}
grep -Fq 'write /sys/class/typec/port0/port_type sink' <<<"${usb_policy}" || {
  echo "USB policy does not pin the Type-C port to peripheral/sink mode" >&2
  exit 1
}
if grep -Eq 'audio_source|cser\.|diag\.|ffs\.(mtp|ptp)|gsi\.(rmnet|rndis)|midi\.|nmea|qdss|rndis' \
    <<<"${usb_policy}"; then
  echo "forbidden USB gadget function found in ${usb_rc}" >&2
  exit 1
fi
adb_setup_triggers="$(awk '
  /^on / { trigger = $0 }
  /^[[:space:]]+(mkdir|mount)[[:space:]].*(functions\/ffs\.adb|\/dev\/usb-ffs\/adb|functionfs[[:space:]]+adb)/ {
    print trigger
  }
' <<<"${usb_policy}" | sort -u)"
if [[ -n "${adb_setup_triggers}" && \
      "${adb_setup_triggers}" != 'on early-boot && property:ro.debuggable=1' ]]; then
  echo "ADB endpoint setup is not confined to immutable userdebug policy" >&2
  printf '%s\n' "${adb_setup_triggers}" >&2
  exit 1
fi

# DWC3 stays dual-role in the kernel (dev ladder rung 2d-d), so the dwc3-msm
# "id" node must stay root-only: writing 0 to it forces the controller into
# host mode underneath the Type-C port policy (rung 3 / device patch 0029).
dwc3_id_access="$({
  while IFS= read -r init_rc; do
    unzip -p "${TARGET_FILES}" "${init_rc}" |
      grep -E '^[[:space:]]*(chown|chmod)[[:space:]].*/a600000\.ssusb/id([[:space:]]|$)' |
      sed "s|^|${init_rc}:|"
  done <<<"${installed_init_rcs}"
} || true)"
if [[ -n "${dwc3_id_access}" ]]; then
  echo "init grants non-root access to the DWC3 host-mode id node:" >&2
  printf '%s\n' "${dwc3_id_access}" >&2
  exit 1
fi

usb_hal='VENDOR/bin/hw/android.hardware.usb.gadget-service.crosshatch'
grep -Fqx "${usb_hal}" "${listing}" || {
  echo "missing crosshatch USB gadget HAL" >&2
  exit 1
}
usb_hal_strings="$(unzip -p "${TARGET_FILES}" "${usb_hal}" | strings)"
grep -Fq 'Phone Vault rejected USB gadget functions' <<<"${usb_hal_strings}" || {
    echo "USB gadget HAL does not contain the Phone Vault function allowlist" >&2
    exit 1
  }
grep -Fq 'ro.vendor.phonevault.offline' <<<"${usb_hal_strings}" || {
  echo "USB gadget HAL is not keyed by the vendor appliance property" >&2
  exit 1
}

usb_role_hal='VENDOR/bin/hw/android.hardware.usb-service.crosshatch'
grep -Fqx "${usb_role_hal}" "${listing}" || {
  echo "missing crosshatch USB role HAL" >&2
  exit 1
}
usb_role_hal_strings="$(unzip -p "${TARGET_FILES}" "${usb_role_hal}" | strings)"
grep -Fq 'Phone Vault rejected USB host role' <<<"${usb_role_hal_strings}" || {
    echo "USB role HAL does not contain the Phone Vault device-role restriction" >&2
    exit 1
  }
grep -Fq 'ro.vendor.phonevault.offline' <<<"${usb_role_hal_strings}" || {
  echo "USB role HAL is not keyed by the vendor appliance property" >&2
  exit 1
}

echo "Appliance target-files policy passed."
