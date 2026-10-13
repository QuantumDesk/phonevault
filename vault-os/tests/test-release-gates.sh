#!/usr/bin/env bash
# Release gates that run before anything is signed:
#   - verify-release-source.sh: no development deviation in the release configuration
#     (the 2026-08 DEBUG-38/41 leftovers: persist.sys.usb.config=adb, an early-adbd init
#     script, DEBUG-NN markers, tracked *.rel-bak/*.b38-bak copies);
#   - verify-rollback-index.sh: project-owned AVB rollback index, strictly increasing over the
#     previous signed release manifest;
#   - dev-ladder/check-overrides.sh release: no overridden module left in the target-files.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VAULT="${ROOT}/vault-os"
SOURCE_GATE="${VAULT}/scripts/verify-release-source.sh"
ROLLBACK_GATE="${VAULT}/scripts/verify-rollback-index.sh"
OVERRIDES_GATE="${VAULT}/dev-ladder/check-overrides.sh"
work_dir="$(mktemp -d -t phone-vault-release-gates.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT

expect_failure() {  # NAME EXPECTED_STDERR_SUBSTRING COMMAND...
  local name="$1" expected="$2"; shift 2
  if "$@" > "${work_dir}/${name}.stdout" 2> "${work_dir}/${name}.stderr"; then
    echo "${name}: gate unexpectedly passed" >&2
    exit 1
  fi
  grep -Fq -- "${expected}" "${work_dir}/${name}.stderr" || {
    echo "${name}: gate failed for the wrong reason:" >&2
    cat "${work_dir}/${name}.stderr" >&2
    exit 1
  }
}

# ---------------------------------------------------------------- source gate
make_source_fixture() {
  local fixture="$1"
  mkdir -p "${fixture}/vault-os/scripts" "${fixture}/vault-os/patches"
  cp -R "${VAULT}/vendor" "${VAULT}/device" "${fixture}/vault-os/"
  cp -R "${VAULT}/patches/bootable-recovery" "${fixture}/vault-os/patches/"
  cp "${VAULT}/scripts/install-overlay.sh" "${fixture}/vault-os/scripts/"
}
source_case() {  # NAME EXPECTED MUTATION...
  local name="$1" expected="$2"; shift 2
  local fixture="${work_dir}/src-${name}"
  make_source_fixture "${fixture}"
  ( cd "${fixture}/vault-os" && eval "$@" )
  expect_failure "source-${name}" "${expected}" "${SOURCE_GATE}" "${fixture}"
}

"${SOURCE_GATE}" "${ROOT}"
make_source_fixture "${work_dir}/src-clean"
"${SOURCE_GATE}" "${work_dir}/src-clean"

common=vendor/phonevault/config/common.mk
# DEBUG-38 exactly as it was committed.
source_case persist-adb 'persist.sys.usb.config must be none' \
  "sed -i.x 's|persist.sys.usb.config=none|persist.sys.usb.config=adb   # DEBUG-38: temporary, revert to none for release|' ${common} && rm ${common}.x"
source_case debug-marker 'development marker in release configuration' \
  "printf '# DEBUG-39: FusedLocation+Telecom restored\n' >> ${common}"
source_case debug-marker-nodash 'development marker in release configuration' \
  "printf '    // DEBUG48: overrides disabled\n' >> vendor/phonevault/prebuilt/Android.bp"
# DEBUG-41: the early-adb rc and its install line.
source_case zzz-rc 'development leftover file in release configuration' \
  "printf 'on post-fs\n    start adbd\n' > vendor/phonevault/prebuilt/zzz-debug-earlyadb.rc"
source_case zzz-install 'installs a debug init script' \
  "printf 'PRODUCT_COPY_FILES += \\\\\n    vendor/phonevault/prebuilt/x.rc:\$(TARGET_COPY_OUT_SYSTEM)/etc/init/zzz-debug-earlyadb.rc\n' >> ${common}"
source_case early-adbd-rc 'release init script starts adbd' \
  "printf 'on post-fs\n    mkdir /dev/usb-ffs/adb 0770 shell shell\n    start adbd\n' > vendor/phonevault/prebuilt/init.vault.extra.rc"
source_case ungated-ffs 'ADB endpoint outside a ro.debuggable=1 trigger' \
  "sed -i.x 's/^on early-boot && property:ro.debuggable=1\$/on early-boot/' vendor/phonevault/prebuilt/init.phonevault.usb.rc && rm vendor/phonevault/prebuilt/init.phonevault.usb.rc.x"
source_case rel-bak 'development leftover file in release configuration' \
  "cp ${common} ${common}.rel-bak"
source_case b38-bak 'development leftover file in release configuration' \
  "cp ${common} ${common}.b38-bak"
source_case adb-keys 'adb key/insecure-adb setting' \
  "printf 'PRODUCT_ADB_KEYS := vendor/phonevault/config/debug_adbkey.pub\n' >> ${common}"
source_case adb-insecure 'ro.adb.secure must not be relaxed' \
  "printf 'PRODUCT_PROPERTY_OVERRIDES += \\\\\n    persist.adb.notify=0 \\\\\n    ro.adb.secure=0\n' >> ${common}"
source_case device-product-adb 'USB configuration property enables adb' \
  "printf 'PRODUCT_SYSTEM_PROPERTIES += sys.usb.config=mtp,adb\n' >> device/phonevault/crosshatch/vault_crosshatch.mk"
source_case rollback-missing 'BoardConfigVault.mk lacks: BOARD_AVB_ROLLBACK_INDEX' \
  "sed -i.x '/^BOARD_AVB_ROLLBACK_INDEX/d' vendor/phonevault/config/BoardConfigVault.mk"
source_case rollback-format 'PHONEVAULT_AVB_ROLLBACK_INDEX must be YYYYMMDDNN' \
  "sed -i.x 's/^PHONEVAULT_AVB_ROLLBACK_INDEX := .*/PHONEVAULT_AVB_ROLLBACK_INDEX := 7/' vendor/phonevault/config/release-version.mk && rm vendor/phonevault/config/release-version.mk.x"
source_case voice-capable 'framework overlay must set config_voice_capable=false' \
  "sed -i.x '/config_voice_capable/d' vendor/phonevault/overlay/frameworks/base/core/res/res/values/config.xml && rm vendor/phonevault/overlay/frameworks/base/core/res/res/values/config.xml.x"
source_case recovery-patch 'lacks the user-build recovery hardening patch' \
  "rm patches/bootable-recovery/*.patch"
source_case recovery-not-applied 'does not apply patches/bootable-recovery' \
  "sed -i.x 's#patches/bootable-recovery#patches/elsewhere#' scripts/install-overlay.sh"
echo "Release source gate negative fixtures passed."

# -------------------------------------------------------------- rollback gate
version_mk="${VAULT}/vendor/phonevault/config/release-version.mk"
project_index="$(sed -n 's/^PHONEVAULT_AVB_ROLLBACK_INDEX := //p' "${version_mk}")"
lower_index=$(( project_index - 1 ))
openssl genpkey -algorithm ed25519 -out "${work_dir}/metadata.pem" 2>/dev/null
openssl pkey -in "${work_dir}/metadata.pem" -pubout -out "${work_dir}/metadata-public.pem"
openssl genpkey -algorithm ed25519 -out "${work_dir}/other.pem" 2>/dev/null
make_previous() {  # DIR INDEX [SIGNING_KEY]
  mkdir -p "$1"
  printf 'channel=production\nvbmeta_rollback_index=%s\n' "$2" > "$1/RELEASE-MANIFEST.txt"
  openssl pkeyutl -sign -rawin -inkey "${3:-${work_dir}/metadata.pem}" \
    -in "$1/RELEASE-MANIFEST.txt" -out "$1/RELEASE-MANIFEST.sig"
}
make_previous "${work_dir}/prev-lower" "${lower_index}"
make_previous "${work_dir}/prev-equal" "${project_index}"
make_previous "${work_dir}/prev-higher" "$(( project_index + 1 ))"
make_previous "${work_dir}/prev-forged" 1 "${work_dir}/other.pem"
pub="${work_dir}/metadata-public.pem"

"${ROLLBACK_GATE}" "${project_index}" "${version_mk}" "${work_dir}/prev-lower" "${pub}"
"${ROLLBACK_GATE}" "${project_index}" "${version_mk}" --first-release
expect_failure rollback-equal 'is not greater than the previous release' \
  "${ROLLBACK_GATE}" "${project_index}" "${version_mk}" "${work_dir}/prev-equal" "${pub}"
expect_failure rollback-lower 'is not greater than the previous release' \
  "${ROLLBACK_GATE}" "${project_index}" "${version_mk}" "${work_dir}/prev-higher" "${pub}"
expect_failure rollback-forged 'signature does not verify' \
  "${ROLLBACK_GATE}" "${project_index}" "${version_mk}" "${work_dir}/prev-forged" "${pub}"
expect_failure rollback-not-project 'is not the project index' \
  "${ROLLBACK_GATE}" 1785542400 "${version_mk}" --first-release
expect_failure rollback-no-previous 'needs the release-metadata public key' \
  "${ROLLBACK_GATE}" "${project_index}" "${version_mk}" "${work_dir}/prev-lower"
# Decimal comparison, not string or 64-bit-overflowing arithmetic.
printf 'PHONEVAULT_AVB_ROLLBACK_INDEX := 100000000000000000000\n' > "${work_dir}/big.mk"
make_previous "${work_dir}/prev-99" 99999999999999999999
"${ROLLBACK_GATE}" 100000000000000000000 "${work_dir}/big.mk" "${work_dir}/prev-99" "${pub}"
printf 'PHONEVAULT_AVB_ROLLBACK_INDEX := 9\n' > "${work_dir}/nine.mk"
make_previous "${work_dir}/prev-10" 10
expect_failure rollback-string-order 'is not greater than the previous release' \
  "${ROLLBACK_GATE}" 9 "${work_dir}/nine.mk" "${work_dir}/prev-10" "${pub}"
echo "Rollback-index gate positive and negative fixtures passed."

# ------------------------------------------------------- release overrides gate
tf="${work_dir}/tf"
mkdir -p "${tf}/SYSTEM/app/PhoneVault" "${tf}/SYSTEM/priv-app/Settings" \
  "${tf}/PRODUCT/app/LatinIME"
printf 'x' > "${tf}/SYSTEM/app/PhoneVault/PhoneVault.apk"
printf 'x' > "${tf}/SYSTEM/priv-app/Settings/Settings.apk"
printf 'x' > "${tf}/PRODUCT/app/LatinIME/LatinIME.apk"
(cd "${tf}" && zip -qr "${work_dir}/tf-clean.zip" .)
"${OVERRIDES_GATE}" release "${work_dir}/tf-clean.zip" > /dev/null
mkdir -p "${tf}/SYSTEM_EXT/priv-app/TrebuchetQuickStep" "${tf}/PRODUCT/overlay/IconPackKaiLauncher"
printf 'x' > "${tf}/SYSTEM_EXT/priv-app/TrebuchetQuickStep/TrebuchetQuickStep.apk"
(cd "${tf}" && zip -qr "${work_dir}/tf-launcher.zip" .)
if "${OVERRIDES_GATE}" release "${work_dir}/tf-launcher.zip" > "${work_dir}/tf-launcher.out" 2>&1; then
  echo "release overrides gate passed with a packaged launcher" >&2
  exit 1
fi
grep -Fq 'TrebuchetQuickStep: SYSTEM_EXT/priv-app/TrebuchetQuickStep/TrebuchetQuickStep.apk' \
  "${work_dir}/tf-launcher.out"
rm -rf "${tf}/SYSTEM_EXT"
printf 'x' > "${tf}/PRODUCT/overlay/IconPackKaiLauncher/IconPackKaiLauncherOverlay.apk"
(cd "${tf}" && zip -qr "${work_dir}/tf-overlay.zip" .)
if "${OVERRIDES_GATE}" release "${work_dir}/tf-overlay.zip" > "${work_dir}/tf-overlay.out" 2>&1; then
  echo "release overrides gate passed with a packaged icon-pack overlay" >&2
  exit 1
fi
grep -Fq 'IconPackKaiLauncherOverlay' "${work_dir}/tf-overlay.out"
echo "Release overrides gate positive and negative fixtures passed."
