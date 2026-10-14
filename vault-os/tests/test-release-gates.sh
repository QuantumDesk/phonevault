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
  ( cd "${fixture}/vault-os" && eval "$*" )
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

# Init-model and property-file cases (audit 2026-10-13). Positives first: honest release
# configuration written the ways init and the build accept must still pass.
source_pass() {  # NAME MUTATION...
  local name="$1"; shift
  local fixture="${work_dir}/src-pass-${name}"
  make_source_fixture "${fixture}"
  ( cd "${fixture}/vault-os" && eval "$*" )
  "${SOURCE_GATE}" "${fixture}" > /dev/null 2> "${work_dir}/src-pass-${name}.stderr" || {
    echo "source positive ${name} was rejected:" >&2
    cat "${work_dir}/src-pass-${name}.stderr" >&2
    exit 1
  }
}
# shellcheck disable=SC2016  # literal init syntax below
{
source_pass safe-prop-file \
  "printf '%s\n' '# vault properties' ' ro.vendor.phonevault.example = 1' 'persist.sys.usb.config = none' > vendor/phonevault/config/vault.prop && printf 'TARGET_VENDOR_PROP += vendor/phonevault/config/vault.prop\n' >> vendor/phonevault/config/BoardConfigVault.mk"
source_pass safe-rc-idioms \
  "printf '%s\n' 'service vaultd /system/bin/vaultd \\' '        --flag' '    class main' '  on boot' '    enable vaultd' '    setprop sys.usb.controller \"a600000.dwc3\"' '    write /config/usb_gadget/g1/strings/0x409/serialnumber \${ro.serialno}' > vendor/phonevault/prebuilt/vault-late.rc"
source_pass adb-keys-comment \
  "printf '# Never install adb_keys here; see verify-release-source.sh.\n' >> ${common}"
source_case prop-file-spaced-debuggable 'release configuration must not make the build debuggable' \
  "printf '  ro.debuggable = 1\n' > device/phonevault/bluejay/vault.prop"
source_case prop-file-outside 'release property file is not in the release configuration' \
  "printf 'TARGET_SYSTEM_PROP += device/google/bluejay/debug.prop\n' >> vendor/phonevault/config/BoardConfigVault.mk"
source_case prop-file-import 'property import in release configuration' \
  "printf 'import /data/local.prop\n' > vendor/phonevault/config/vault.prop"
source_case rc-continued-start 'release init script starts adbd' \
  "printf '%s\n' 'on boot' '    start \\' '        adbd' > vendor/phonevault/prebuilt/vault-late.rc"
source_case rc-exec-start 'release init script starts adbd' \
  "printf '%s\n' 'on boot' '    exec_start adbd' > vendor/phonevault/prebuilt/vault-late.rc"
source_case rc-start-expanded 'release init script starts adbd' \
  "printf '%s\n' 'on boot' '    start \${ro.vendor.vault.svc}' > vendor/phonevault/prebuilt/vault-late.rc"
source_case rc-setprop-expanded 'init selects adb as USB function' \
  "printf '%s\n' 'on boot' '    setprop persist.sys.usb.config \${ro.vendor.vault.usb}' > vendor/phonevault/prebuilt/vault-late.rc"
source_case rc-import-writable 'imports from a writable or unresolved location' \
  "printf '%s\n' 'import /data/vault/late.rc' > vendor/phonevault/prebuilt/vault-late.rc"
source_case rc-installed-under-other-suffix 'release init script starts adbd' \
  "printf 'on boot\n    start adbd\n' > vendor/phonevault/prebuilt/vault-late.conf && printf 'PRODUCT_COPY_FILES += vendor/phonevault/prebuilt/vault-late.conf:\$(TARGET_COPY_OUT_VENDOR)/etc/init/vault-late.rc\n' >> ${common}"
source_case adb-key-soong-filename 'installs a pre-authorised adb host key' \
  "printf '%s\n' 'prebuilt_root {' '    name: \"vault_owner_key\",' '    src: \"owner.pub\",' '    filename: \"adb_keys\",' '}' >> vendor/phonevault/prebuilt/Android.bp"
}
echo "Release source gate init-model and property-file fixtures passed."

# --------------------------------------------- install-overlay patch markers
# apply_versioned_patch accepts a recorded patch that neither applies nor reverse-applies
# only when later recorded patches of the same series overlap it and undoing them (newest
# first) on a scratch copy leaves this patch reverse-applicable.
marker_dir="${work_dir}/markers"
mkdir -p "${marker_dir}/tree" "${marker_dir}/series" "${marker_dir}/state"
sed -n '/^apply_versioned_patch() {/,/^}/p' "${VAULT}/scripts/install-overlay.sh" \
  > "${marker_dir}/apply.sh"
(
  cd "${marker_dir}/tree" && git init -q . \
    && printf '%s\n' a b c d e f g > policy.rc && git add . \
    && git -c user.name=t -c user.email=t@t commit -qm upstream \
    && sed 's/^c$/C/' policy.rc > policy.rc.new && mv policy.rc.new policy.rc \
    && git diff > "${marker_dir}/series/0001-first.patch" \
    && git -c user.name=t -c user.email=t@t commit -qam first \
    && sed 's/^d$/D/' policy.rc > policy.rc.new && mv policy.rc.new policy.rc \
    && git diff > "${marker_dir}/series/0002-second.patch" \
    && git -c user.name=t -c user.email=t@t commit -qam second
) || exit 1
cp "${marker_dir}/series/0001-first.patch" "${marker_dir}/state/t-0001-first.patch"
cp "${marker_dir}/series/0002-second.patch" "${marker_dir}/state/t-0002-second.patch"
run_marker() {
  # shellcheck source=/dev/null
  ( source "${marker_dir}/apply.sh" \
      && apply_versioned_patch "${marker_dir}/tree" "${marker_dir}/series/0001-first.patch" \
           "${marker_dir}/state/t-0001-first.patch" "marker test" )
}
git -C "${marker_dir}/tree" apply --check "${marker_dir}/series/0001-first.patch" 2>/dev/null \
  && { echo "marker fixture: 0001 must not apply standalone" >&2; exit 1; }
git -C "${marker_dir}/tree" apply --reverse --check "${marker_dir}/series/0001-first.patch" 2>/dev/null \
  && { echo "marker fixture: 0001 must not reverse-apply standalone" >&2; exit 1; }
run_marker > "${work_dir}/marker-overlap.out" 2>&1 || {
  echo "recorded patch under a recorded overlapping later patch was rejected:" >&2
  cat "${work_dir}/marker-overlap.out" >&2
  exit 1
}
grep -Fq 'verified under 1 later overlapping patch' "${work_dir}/marker-overlap.out"
mv "${marker_dir}/state/t-0002-second.patch" "${marker_dir}/state/t-0002-second.saved"
expect_failure marker-later-unrecorded 'recorded as applied but neither applies nor is present' run_marker
mv "${marker_dir}/state/t-0002-second.saved" "${marker_dir}/state/t-0002-second.patch"
printf '%s\n' a b X Y e f g > "${marker_dir}/tree/policy.rc"
expect_failure marker-tree-lost-patches 'recorded as applied but neither applies nor is present' run_marker
echo "install-overlay patch marker fixtures passed."

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
