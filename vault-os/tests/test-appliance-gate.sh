#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 "${ROOT}/tests/test_forbidden_policy_coverage.py"
work_dir="$(mktemp -d -t phone-vault-gate-test.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT
fixture="${work_dir}/fixture"
mkdir -p \
  "${fixture}/META" \
  "${fixture}/OTA" \
  "${fixture}/SYSTEM/app/PhoneVault" \
  "${fixture}/SYSTEM/bin" \
  "${fixture}/SYSTEM/lib64" \
  "${fixture}/SYSTEM/etc/init/hw" \
  "${fixture}/SYSTEM_EXT/etc/init" \
  "${fixture}/SYSTEM_EXT/etc/vintf" \
  "${fixture}/PRODUCT/etc" \
  "${fixture}/VENDOR" \
  "${fixture}/VENDOR/bin/hw" \
  "${fixture}/VENDOR/etc/init/hw" \
  "${fixture}/VENDOR/etc/permissions" \
  "${fixture}/VENDOR/etc/vintf" \
  "${fixture}/VENDOR/lib64"

printf '%s\n' \
  'avb_enable=true' \
  'avb_vbmeta_algorithm=SHA256_RSA4096' \
  'avb_vbmeta_key_path=vendor/phonevault/keys/avb.pem' \
  'avb_vbmeta_args=--padding_size 4096 --rollback_index 1785542400' \
  > "${fixture}/META/misc_info.txt"
printf '%s\n' 'require board=crosshatch' \
  > "${fixture}/OTA/android-info.txt"
printf '%s\n' \
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
  'CONFIG_USB_CONFIGFS_F_ACC=y' \
  '# CONFIG_WLAN is not set' \
  '# CONFIG_BT is not set' \
  > "${fixture}/META/kernel_configs.txt"
printf '%s\n' \
  'ro.build.fingerprint=PhoneVault/vault_crosshatch/crosshatch:15/TEST/1:userdebug/test-keys' \
  'ro.phonevault.offline=true' \
  'ro.phonevault.version=test' \
  'ro.radio.noril=true' \
  'config.disable_cameraservice=true' \
  'config.disable_networktime=true' \
  > "${fixture}/SYSTEM/build.prop"
printf '%s\n' \
  'ro.product.vendor.brand=PhoneVault' \
  'ro.vendor.phonevault.offline=true' \
  > "${fixture}/VENDOR/build.prop"
printf '%s\n' 'ro.product.product.brand=PhoneVault' \
  > "${fixture}/PRODUCT/etc/build.prop"
printf 'fixture\n' > "${fixture}/SYSTEM/app/PhoneVault/PhoneVault.apk"
# Exact-path permitted HAL client stub linked by system_server JNI.
printf 'fixture\n' > "${fixture}/SYSTEM/lib64/android.hardware.gnss@1.0.so"
printf '%s\n' \
  'on boot' \
  '    mkdir /config/usb_gadget/g1/functions/accessory.gs2' \
  '    setprop sys.usb.configfs 2' \
  '    write /sys/class/typec/port0/port_type sink' \
  'on early-boot && property:ro.debuggable=1' \
  '    mkdir /config/usb_gadget/g1/functions/ffs.adb' \
  '    mkdir /dev/usb-ffs/adb 0770 shell shell' \
  '    mount functionfs adb /dev/usb-ffs/adb rmode=0770' \
  > "${fixture}/VENDOR/etc/init/hw/init.sdm845.usb.rc"
printf 'Phone Vault rejected USB gadget functions\nro.vendor.phonevault.offline\n' \
  > "${fixture}/VENDOR/bin/hw/android.hardware.usb.gadget-service.crosshatch"
printf 'Phone Vault rejected USB host role\nro.vendor.phonevault.offline\n' \
  > "${fixture}/VENDOR/bin/hw/android.hardware.usb-service.crosshatch"
cp "${ROOT}/vendor/phonevault/prebuilt/phonevault_core_hardware.xml" \
  "${fixture}/VENDOR/etc/permissions/handheld_core_hardware.xml"
printf '%s\n' \
  '<?xml version="1.0" encoding="utf-8"?>' \
  '<permissions><feature name="android.hardware.usb.accessory" /></permissions>' \
  > "${fixture}/VENDOR/etc/permissions/android.hardware.usb.accessory.xml"
printf '%s\n' \
  '<manifest version="1.0" type="device" target-level="5">' \
  '  <hal format="hidl"><name>android.hardware.keymaster</name></hal>' \
  '</manifest>' \
  > "${fixture}/VENDOR/etc/vintf/manifest.xml"
# Android's numbered framework compatibility matrix lists optional HALs the
# framework may consume; it declares nothing about the device and must not
# trip the VINTF declaration scan.
mkdir -p "${fixture}/SYSTEM/etc/vintf"
printf '%s\n' \
  '<compatibility-matrix version="1.0" type="framework" level="5">' \
  '  <hal format="hidl" optional="true"><name>android.hardware.radio</name></hal>' \
  '</compatibility-matrix>' \
  > "${fixture}/SYSTEM/etc/vintf/compatibility_matrix.5.xml"
printf '%s\n' \
  'on bpf-progs-loaded && property:ro.phonevault.offline=false' \
  '    start netd' \
  > "${fixture}/SYSTEM/etc/init/hw/init.rc"

positive="${work_dir}/positive.zip"
(cd "${fixture}" && zip -qr "${positive}" .)
"${ROOT}/scripts/verify-appliance-target-files.sh" "${positive}"
fixture_app_sha="$(sha256sum \
  "${fixture}/SYSTEM/app/PhoneVault/PhoneVault.apk" | awk '{print $1}')"
"${ROOT}/scripts/verify-appliance-target-files.sh" "${positive}" \
  vendor/phonevault/keys/avb.pem '' "${fixture_app_sha}"
if "${ROOT}/scripts/verify-appliance-target-files.sh" "${positive}" \
    vendor/phonevault/keys/avb.pem '' \
    0000000000000000000000000000000000000000000000000000000000000000 \
    > "${work_dir}/negative-app-hash.stdout" \
    2> "${work_dir}/negative-app-hash.stderr"; then
  echo "incorrect Phone Vault APK hash unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'Phone Vault APK hash mismatch' \
  "${work_dir}/negative-app-hash.stderr"

# A HAL client stub that is not on the exact permitted list must still fail.
printf 'fixture\n' > "${fixture}/SYSTEM/lib64/android.hardware.wifi@1.0.so"
negative_unlisted_stub="${work_dir}/negative-unlisted-stub.zip"
(cd "${fixture}" && zip -qr "${negative_unlisted_stub}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_unlisted_stub}" \
    > "${work_dir}/negative-unlisted-stub.stdout" \
    2> "${work_dir}/negative-unlisted-stub.stderr"; then
  echo "unlisted HAL interface library unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'SYSTEM/lib64/android.hardware.wifi@1.0.so' \
  "${work_dir}/negative-unlisted-stub.stderr"
rm "${fixture}/SYSTEM/lib64/android.hardware.wifi@1.0.so"

# The permitted list exempts client stubs only; a HAL server binary of the
# same family must still fail.
printf 'fixture\n' \
  > "${fixture}/VENDOR/bin/hw/android.hardware.sensors@1.0-service"
negative_hal_service="${work_dir}/negative-hal-service.zip"
(cd "${fixture}" && zip -qr "${negative_hal_service}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_hal_service}" \
    > "${work_dir}/negative-hal-service.stdout" \
    2> "${work_dir}/negative-hal-service.stderr"; then
  echo "sensor HAL service binary unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'VENDOR/bin/hw/android.hardware.sensors@1.0-service' \
  "${work_dir}/negative-hal-service.stderr"
rm "${fixture}/VENDOR/bin/hw/android.hardware.sensors@1.0-service"

printf '%s\n' 'require board=crosshatch|blueline' \
  > "${fixture}/OTA/android-info.txt"
negative_broad_board="${work_dir}/negative-broad-board.zip"
(cd "${fixture}" && zip -qr "${negative_broad_board}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_broad_board}" \
    > "${work_dir}/negative-broad-board.stdout" \
    2> "${work_dir}/negative-broad-board.stderr"; then
  echo "crosshatch/blueline board fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'android-info.txt must allow exactly crosshatch' \
  "${work_dir}/negative-broad-board.stderr"
printf '%s\n' 'require board=crosshatch' \
  > "${fixture}/OTA/android-info.txt"

mv "${fixture}/VENDOR/etc/permissions/android.hardware.usb.accessory.xml" \
  "${fixture}/VENDOR/etc/permissions/android.hardware.usb.accessory.xml.absent"
negative_missing_accessory="${work_dir}/negative-missing-accessory.zip"
(cd "${fixture}" && zip -qr "${negative_missing_accessory}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_missing_accessory}" \
    > "${work_dir}/negative-missing-accessory.stdout" \
    2> "${work_dir}/negative-missing-accessory.stderr"; then
  echo "missing accessory feature fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'Android Open Accessory feature is not declared' \
  "${work_dir}/negative-missing-accessory.stderr"
mv "${fixture}/VENDOR/etc/permissions/android.hardware.usb.accessory.xml.absent" \
  "${fixture}/VENDOR/etc/permissions/android.hardware.usb.accessory.xml"

sed -i.bak 's/^avb_vbmeta_args=.*/avb_vbmeta_args=--flags 3 --padding_size 4096 --rollback_index 1785542400/' \
  "${fixture}/META/misc_info.txt"
negative_disabled_avb="${work_dir}/negative-disabled-avb.zip"
(cd "${fixture}" && zip -qr "${negative_disabled_avb}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_disabled_avb}" \
    > "${work_dir}/negative-disabled-avb.stdout" \
    2> "${work_dir}/negative-disabled-avb.stderr"; then
  echo "verification-disabled vbmeta fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'top-level vbmeta disables verification or hashtree enforcement' \
  "${work_dir}/negative-disabled-avb.stderr"
mv "${fixture}/META/misc_info.txt.bak" "${fixture}/META/misc_info.txt"

sed -i.bak 's/^avb_vbmeta_args=.*/avb_vbmeta_args=--padding_size 4096 --rollback_index 0/' \
  "${fixture}/META/misc_info.txt"
negative_zero_rollback="${work_dir}/negative-zero-rollback.zip"
(cd "${fixture}" && zip -qr "${negative_zero_rollback}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_zero_rollback}" \
    > "${work_dir}/negative-zero-rollback.stdout" \
    2> "${work_dir}/negative-zero-rollback.stderr"; then
  echo "zero rollback-index fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'top-level vbmeta lacks a positive rollback index' \
  "${work_dir}/negative-zero-rollback.stderr"
mv "${fixture}/META/misc_info.txt.bak" "${fixture}/META/misc_info.txt"

mkdir -p "${fixture}/SYSTEM/priv-app"
mv "${fixture}/SYSTEM/app/PhoneVault" "${fixture}/SYSTEM/priv-app/PhoneVault"
negative_privileged_app="${work_dir}/negative-privileged-app.zip"
(cd "${fixture}" && zip -qr "${negative_privileged_app}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_privileged_app}" \
    > "${work_dir}/negative-privileged-app.stdout" \
    2> "${work_dir}/negative-privileged-app.stderr"; then
  echo "privileged PhoneVault fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'PhoneVault must not receive implicit priv-app authority' \
  "${work_dir}/negative-privileged-app.stderr"
mv "${fixture}/SYSTEM/priv-app/PhoneVault" "${fixture}/SYSTEM/app/PhoneVault"
rmdir "${fixture}/SYSTEM/priv-app"

printf 'forbidden fixture\n' > "${fixture}/SYSTEM/bin/wpa_supplicant"
negative="${work_dir}/negative.zip"
(cd "${fixture}" && zip -qr "${negative}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" "${negative}" \
    > "${work_dir}/negative.stdout" 2> "${work_dir}/negative.stderr"; then
  echo "negative fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'SYSTEM/bin/wpa_supplicant' "${work_dir}/negative.stderr"

rm "${fixture}/SYSTEM/bin/wpa_supplicant"
mkdir -p "${fixture}/SYSTEM/apex"
mkdir -p "${fixture}/SYSTEM/apex/com.android.tethering/bin"
printf 'forbidden embedded daemon fixture\n' \
  > "${fixture}/SYSTEM/apex/com.android.tethering/bin/ot-daemon"
negative_tethering="${work_dir}/negative-tethering.zip"
(cd "${fixture}" && zip -qr "${negative_tethering}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" "${negative_tethering}" \
    > "${work_dir}/negative-tethering.stdout" \
    2> "${work_dir}/negative-tethering.stderr"; then
  echo "embedded tethering daemon fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'SYSTEM/apex/com.android.tethering/bin/ot-daemon' \
  "${work_dir}/negative-tethering.stderr"
rm -rf "${fixture}/SYSTEM/apex/com.android.tethering"

printf 'forbidden remote provisioning fixture\n' \
  > "${fixture}/SYSTEM/apex/com.android.rkpd.apex"
negative_rkpd="${work_dir}/negative-rkpd.zip"
(cd "${fixture}" && zip -qr "${negative_rkpd}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" "${negative_rkpd}" \
    > "${work_dir}/negative-rkpd.stdout" \
    2> "${work_dir}/negative-rkpd.stderr"; then
  echo "remote key provisioning APEX unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'SYSTEM/apex/com.android.rkpd.apex' \
  "${work_dir}/negative-rkpd.stderr"
rm "${fixture}/SYSTEM/apex/com.android.rkpd.apex"

printf 'forbidden DNS resolver fixture\n' \
  > "${fixture}/SYSTEM/apex/com.android.resolv.apex"
negative_resolver="${work_dir}/negative-resolver.zip"
(cd "${fixture}" && zip -qr "${negative_resolver}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" "${negative_resolver}" \
    > "${work_dir}/negative-resolver.stdout" \
    2> "${work_dir}/negative-resolver.stderr"; then
  echo "DNS resolver APEX unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'SYSTEM/apex/com.android.resolv.apex' \
  "${work_dir}/negative-resolver.stderr"
rm "${fixture}/SYSTEM/apex/com.android.resolv.apex"

# Linux integration runs can inject an ext4 APEX to exercise the shared payload
# extractor. The ordinary portable fixture suite leaves this unset.
if [[ -n "${PHONEVAULT_TEST_MEDIA_APEX:-}" ]]; then
  [[ -s "${PHONEVAULT_TEST_MEDIA_APEX}" ]] || {
    echo "PHONEVAULT_TEST_MEDIA_APEX does not name a readable APEX" >&2
    exit 1
  }
  injected_media_path="${fixture}/SYSTEM/apex/com.android.media.apex"
  if [[ "${PHONEVAULT_TEST_MEDIA_APEX}" == *.capex ]]; then
    injected_media_path="${fixture}/SYSTEM/apex/com.android.media.capex"
  fi
  cp "${PHONEVAULT_TEST_MEDIA_APEX}" "${injected_media_path}"
  negative_embedded_apex="${work_dir}/negative-embedded-apex.zip"
  (cd "${fixture}" && zip -qr "${negative_embedded_apex}" .)
  if "${ROOT}/scripts/verify-appliance-target-files.sh" \
      "${negative_embedded_apex}" \
      > "${work_dir}/negative-embedded-apex.stdout" \
      2> "${work_dir}/negative-embedded-apex.stderr"; then
    echo "embedded media APEX runtime fixture unexpectedly passed" >&2
    exit 1
  fi
  grep -Fq 'forbidden consumer runtime remains inside com.android.media APEX' \
    "${work_dir}/negative-embedded-apex.stderr"
  rm "${injected_media_path}"
fi

rmdir "${fixture}/SYSTEM/apex"

printf 'forbidden fixture\n' > "${fixture}/VENDOR/lib64/libcdsprpc.so"
negative_proprietary_library="${work_dir}/negative-proprietary-library.zip"
(cd "${fixture}" && zip -qr "${negative_proprietary_library}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_proprietary_library}" \
    > "${work_dir}/negative-proprietary-library.stdout" \
    2> "${work_dir}/negative-proprietary-library.stderr"; then
  echo "forbidden proprietary-library fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'VENDOR/lib64/libcdsprpc.so' \
  "${work_dir}/negative-proprietary-library.stderr"
rm "${fixture}/VENDOR/lib64/libcdsprpc.so"

printf '%s\n' 'CONFIG_WLAN=y' >> "${fixture}/META/kernel_configs.txt"
negative_kernel_radio="${work_dir}/negative-kernel-radio.zip"
(cd "${fixture}" && zip -qr "${negative_kernel_radio}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_kernel_radio}" \
    > "${work_dir}/negative-kernel-radio.stdout" \
    2> "${work_dir}/negative-kernel-radio.stderr"; then
  echo "enabled kernel-radio fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'forbidden appliance kernel drivers remain enabled' \
  "${work_dir}/negative-kernel-radio.stderr"
sed -i.bak '/^CONFIG_WLAN=y$/d' "${fixture}/META/kernel_configs.txt"
rm "${fixture}/META/kernel_configs.txt.bak"

sed -i.bak '/^CONFIG_CITADEL=y$/d' "${fixture}/META/kernel_configs.txt"
negative_missing_titan="${work_dir}/negative-missing-titan.zip"
(cd "${fixture}" && zip -qr "${negative_missing_titan}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_missing_titan}" \
    > "${work_dir}/negative-missing-titan.stdout" \
    2> "${work_dir}/negative-missing-titan.stderr"; then
  echo "missing Citadel kernel setting unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'missing required appliance kernel setting: CONFIG_CITADEL=y' \
  "${work_dir}/negative-missing-titan.stderr"
mv "${fixture}/META/kernel_configs.txt.bak" \
  "${fixture}/META/kernel_configs.txt"

printf '%s\n' 'CONFIG_USB_CONFIGFS_F_QDSS=y' \
  >> "${fixture}/META/kernel_configs.txt"
negative_kernel_usb="${work_dir}/negative-kernel-usb.zip"
(cd "${fixture}" && zip -qr "${negative_kernel_usb}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_kernel_usb}" \
    > "${work_dir}/negative-kernel-usb.stdout" \
    2> "${work_dir}/negative-kernel-usb.stderr"; then
  echo "enabled diagnostic USB kernel function unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'CONFIG_USB_CONFIGFS_F_QDSS=y' \
  "${work_dir}/negative-kernel-usb.stderr"
sed -i.bak '/^CONFIG_USB_CONFIGFS_F_QDSS=y$/d' \
  "${fixture}/META/kernel_configs.txt"
rm "${fixture}/META/kernel_configs.txt.bak"

printf '%s\n' 'persist.radio.VT_ENABLE=1' >> "${fixture}/VENDOR/build.prop"
negative_radio_property="${work_dir}/negative-radio-property.zip"
(cd "${fixture}" && zip -qr "${negative_radio_property}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_radio_property}" \
    > "${work_dir}/negative-radio-property.stdout" \
    2> "${work_dir}/negative-radio-property.stderr"; then
  echo "forbidden radio-property fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'forbidden consumer/radio properties remain' \
  "${work_dir}/negative-radio-property.stderr"
sed -i.bak '/^persist\.radio\.VT_ENABLE=1$/d' "${fixture}/VENDOR/build.prop"
rm "${fixture}/VENDOR/build.prop.bak"

printf '%s\n' 'ro.product.product.brand=PhoneVault' \
  'persist.vendor.data.iwlan.enable=true' \
  'bluetooth.profile.a2dp.source.enabled=true' \
  'persist.rild.nitz_plmn=' \
  'telephony.lteOnCdmaDevice=1' \
  'ro.qti.sensors.dev_ori=true' \
  > "${fixture}/PRODUCT/etc/build.prop"
negative_product_property="${work_dir}/negative-product-property.zip"
(cd "${fixture}" && zip -qr "${negative_product_property}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_product_property}" \
    > "${work_dir}/negative-product-property.stdout" \
    2> "${work_dir}/negative-product-property.stderr"; then
  echo "forbidden product-property fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'forbidden consumer/radio properties remain' \
  "${work_dir}/negative-product-property.stderr"
for stock_property in 'persist.vendor.data.iwlan.enable=true' \
    'bluetooth.profile.a2dp.source.enabled=true' 'persist.rild.nitz_plmn=' \
    'telephony.lteOnCdmaDevice=1' 'ro.qti.sensors.dev_ori=true'; do
  grep -Fqx "${stock_property}" \
    "${work_dir}/negative-product-property.stderr" || {
    echo "gate did not flag stock property: ${stock_property}" >&2
    exit 1
  }
done
printf '%s\n' 'ro.product.product.brand=PhoneVault' \
  > "${fixture}/PRODUCT/etc/build.prop"

# A generic (non-appliance) product brand must fail.
printf '%s\n' 'ro.product.product.brand=Android' \
  > "${fixture}/PRODUCT/etc/build.prop"
negative_product_brand="${work_dir}/negative-product-brand.zip"
(cd "${fixture}" && zip -qr "${negative_product_brand}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_product_brand}" \
    > "${work_dir}/negative-product-brand.stdout" \
    2> "${work_dir}/negative-product-brand.stderr"; then
  echo "generic product brand fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'missing product partition appliance brand' \
  "${work_dir}/negative-product-brand.stderr"
printf '%s\n' 'ro.product.product.brand=PhoneVault' \
  > "${fixture}/PRODUCT/etc/build.prop"

sed -i.bak '/<\/permissions>/i\
    <feature name="android.hardware.bluetooth" />' \
  "${fixture}/VENDOR/etc/permissions/handheld_core_hardware.xml"
rm "${fixture}/VENDOR/etc/permissions/handheld_core_hardware.xml.bak"
negative_features="${work_dir}/negative-features.zip"
(cd "${fixture}" && zip -qr "${negative_features}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" "${negative_features}" \
    > "${work_dir}/negative-features.stdout" \
    2> "${work_dir}/negative-features.stderr"; then
  echo "forbidden hardware feature fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'core hardware declarations do not match the Phone Vault allowlist' \
  "${work_dir}/negative-features.stderr"

cp "${ROOT}/vendor/phonevault/prebuilt/phonevault_core_hardware.xml" \
  "${fixture}/VENDOR/etc/permissions/handheld_core_hardware.xml"
printf '%s\n' \
  '<?xml version="1.0" encoding="utf-8"?>' \
  '<permissions><feature name="android.hardware.wifi" /></permissions>' \
  > "${fixture}/VENDOR/etc/permissions/innocuous-name.xml"
negative_disguised_feature="${work_dir}/negative-disguised-feature.zip"
(cd "${fixture}" && zip -qr "${negative_disguised_feature}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_disguised_feature}" \
    > "${work_dir}/negative-disguised-feature.stdout" \
    2> "${work_dir}/negative-disguised-feature.stderr"; then
  echo "disguised forbidden feature fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'forbidden capabilities declared by installed feature XML' \
  "${work_dir}/negative-disguised-feature.stderr"

rm "${fixture}/VENDOR/etc/permissions/innocuous-name.xml"
printf '%s\n' \
  '<manifest version="1.0" type="device" target-level="5">' \
  '  <hal format="hidl"><name>android.hardware.radio</name></hal>' \
  '</manifest>' \
  > "${fixture}/SYSTEM_EXT/etc/vintf/innocuous-name.xml"
negative_disguised_hal="${work_dir}/negative-disguised-hal.zip"
(cd "${fixture}" && zip -qr "${negative_disguised_hal}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_disguised_hal}" \
    > "${work_dir}/negative-disguised-hal.stdout" \
    2> "${work_dir}/negative-disguised-hal.stderr"; then
  echo "disguised forbidden HAL fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'forbidden HALs remain in installed VINTF declarations' \
  "${work_dir}/negative-disguised-hal.stderr"
rm "${fixture}/SYSTEM_EXT/etc/vintf/innocuous-name.xml"

# The device-owned framework matrix and the device compatibility matrix are
# project files and remain in scope even though the numbered stock matrices
# are not.
printf '%s\n' \
  '<compatibility-matrix version="1.0" type="framework" level="5">' \
  '  <hal format="hidl" optional="true"><name>android.hardware.radio</name></hal>' \
  '</compatibility-matrix>' \
  > "${fixture}/SYSTEM/etc/vintf/compatibility_matrix.device.xml"
negative_device_matrix="${work_dir}/negative-device-matrix.zip"
(cd "${fixture}" && zip -qr "${negative_device_matrix}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_device_matrix}" \
    > "${work_dir}/negative-device-matrix.stdout" \
    2> "${work_dir}/negative-device-matrix.stderr"; then
  echo "device-owned framework matrix with radio HAL unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'forbidden HALs remain in installed VINTF declarations' \
  "${work_dir}/negative-device-matrix.stderr"
rm "${fixture}/SYSTEM/etc/vintf/compatibility_matrix.device.xml"

printf '%s\n' \
  'on boot' \
  '    start netd' \
  > "${fixture}/SYSTEM_EXT/etc/init/innocuous-name.rc"
negative_disguised_init="${work_dir}/negative-disguised-init.zip"
(cd "${fixture}" && zip -qr "${negative_disguised_init}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_disguised_init}" \
    > "${work_dir}/negative-disguised-init.stdout" \
    2> "${work_dir}/negative-disguised-init.stderr"; then
  echo "disguised forbidden init fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'forbidden runtime policy remains in installed init files' \
  "${work_dir}/negative-disguised-init.stderr"
rm "${fixture}/SYSTEM_EXT/etc/init/innocuous-name.rc"

sed -i.bak \
  's/on early-boot && property:ro.debuggable=1/on early-boot/' \
  "${fixture}/VENDOR/etc/init/hw/init.sdm845.usb.rc"
rm "${fixture}/VENDOR/etc/init/hw/init.sdm845.usb.rc.bak"
negative_adb_endpoint="${work_dir}/negative-adb-endpoint.zip"
(cd "${fixture}" && zip -qr "${negative_adb_endpoint}" .)
if "${ROOT}/scripts/verify-appliance-target-files.sh" \
    "${negative_adb_endpoint}" \
    > "${work_dir}/negative-adb-endpoint.stdout" \
    2> "${work_dir}/negative-adb-endpoint.stderr"; then
  echo "unconditional ADB endpoint fixture unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'ADB endpoint setup is not confined to immutable userdebug policy' \
  "${work_dir}/negative-adb-endpoint.stderr"
sed -i.bak \
  's/^on early-boot$/on early-boot \&\& property:ro.debuggable=1/' \
  "${fixture}/VENDOR/etc/init/hw/init.sdm845.usb.rc"
rm "${fixture}/VENDOR/etc/init/hw/init.sdm845.usb.rc.bak"

# DWC3: dual-role is required (rung 2d-d), the host-only mode is forbidden, and
# the dwc3 "id" node (host-mode switch) must stay root-only.
expect_appliance_failure() {
  local name="$1" expected="$2" archive="${work_dir}/$1.zip"
  (cd "${fixture}" && zip -qr "${archive}" .)
  if "${ROOT}/scripts/verify-appliance-target-files.sh" "${archive}" \
      > "${work_dir}/${name}.stdout" 2> "${work_dir}/${name}.stderr"; then
    echo "${name} fixture unexpectedly passed" >&2
    exit 1
  fi
  grep -Fq -- "${expected}" "${work_dir}/${name}.stderr" || {
    echo "${name} failed for the wrong reason:" >&2
    cat "${work_dir}/${name}.stderr" >&2
    exit 1
  }
}
"${ROOT}/scripts/verify-appliance-target-files.sh" \
  "$(cd "${fixture}" && zip -qr "${work_dir}/dual-role-positive.zip" . && echo "${work_dir}/dual-role-positive.zip")"

cp "${fixture}/META/kernel_configs.txt" "${work_dir}/kernel_configs.saved"
sed 's/^CONFIG_USB_DWC3_DUAL_ROLE=y$/CONFIG_USB_DWC3_HOST=y/' \
  "${work_dir}/kernel_configs.saved" > "${fixture}/META/kernel_configs.txt"
expect_appliance_failure negative-dwc3-host 'CONFIG_USB_DWC3_HOST=y'
sed 's/^CONFIG_USB_DWC3_DUAL_ROLE=y$/CONFIG_USB_DWC3_GADGET=y/' \
  "${work_dir}/kernel_configs.saved" > "${fixture}/META/kernel_configs.txt"
expect_appliance_failure negative-dwc3-gadget-only \
  'missing required appliance kernel setting: CONFIG_USB_DWC3_DUAL_ROLE=y'
cp "${work_dir}/kernel_configs.saved" "${fixture}/META/kernel_configs.txt"

printf '%s\n' \
  'on post-fs' \
  '    chown root system /sys/devices/platform/soc/a600000.ssusb/id' \
  '    chmod 664 /sys/devices/platform/soc/a600000.ssusb/id' \
  > "${fixture}/VENDOR/etc/init/android.hardware.usb.gadget-service.crosshatch.rc"
expect_appliance_failure negative-dwc3-id-node \
  'init grants non-root access to the DWC3 host-mode id node'
rm "${fixture}/VENDOR/etc/init/android.hardware.usb.gadget-service.crosshatch.rc"
"${ROOT}/scripts/verify-appliance-target-files.sh" \
  "$(cd "${fixture}" && zip -qr "${work_dir}/final-positive.zip" . && echo "${work_dir}/final-positive.zip")"
echo "Appliance gate positive and negative tests passed."
