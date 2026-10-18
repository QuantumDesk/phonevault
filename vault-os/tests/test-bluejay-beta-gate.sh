#!/usr/bin/env bash
# verify-release-source.sh --bluejay-beta: the resolved bluejay beta configuration
# (release-bluejay/BETA over its dev-ladder-bluejay base rung) carries no development deviation
# and keeps the beta invariants (beta AVB key, never the dev key; project rollback index; no
# serial/early console or printk.devkmsg; usbcore.authorized_default=0; recovery hardening).
# Also checks resolve-beta.sh layering (files replace, expect-build.txt appends).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VAULT="${ROOT}/vault-os"
GATE="${VAULT}/scripts/verify-release-source.sh"
work_dir="$(mktemp -d -t phone-vault-bluejay-beta.XXXXXX)"
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
make_fixture() {
  local fixture="$1"
  mkdir -p "${fixture}/vault-os/scripts" "${fixture}/vault-os/patches"
  cp -R "${VAULT}/vendor" "${VAULT}/device" "${VAULT}/release-bluejay" "${VAULT}/dev-ladder-bluejay" \
    "${fixture}/vault-os/"
  cp -R "${VAULT}/patches/bootable-recovery" "${fixture}/vault-os/patches/"
  cp "${VAULT}/scripts/install-overlay.sh" "${fixture}/vault-os/scripts/"
}
beta_case() {  # NAME EXPECTED MUTATION...
  local name="$1" expected="$2"; shift 2
  local fixture="${work_dir}/${name}"
  make_fixture "${fixture}"
  ( cd "${fixture}/vault-os" && eval "$*" )
  expect_failure "${name}" "${expected}" "${GATE}" "${fixture}" --bluejay-beta beta1
}

# The shipped betas pass (beta1 with the documented voice-capable warning).
"${GATE}" "${ROOT}" --bluejay-beta beta1 2> "${work_dir}/beta1.stderr"
grep -Fq 'leaves config_voice_capable at its default' "${work_dir}/beta1.stderr"
"${GATE}" "${ROOT}" --bluejay-beta beta1-novoice 2> "${work_dir}/novoice.stderr"
! grep -Fq 'config_voice_capable' "${work_dir}/novoice.stderr"
expect_failure missing-beta 'missing or looping BASE' "${GATE}" "${ROOT}" --bluejay-beta no-such-beta

common=release-bluejay/beta1/common.mk
board=release-bluejay/beta1/BoardConfigVault.mk
beta_case dev-usb 'persist.sys.usb.config must be none' \
  "printf 'PRODUCT_PRODUCT_PROPERTIES += persist.sys.usb.config=adb\n' >> ${common}"
beta_case insecure-adb 'ro.adb.secure must not be relaxed' \
  "printf 'PRODUCT_PROPERTY_OVERRIDES += ro.adb.secure=0\n' >> ${common}"
beta_case adb-keys 'adb key/insecure-adb setting' \
  "printf 'PRODUCT_ADB_KEYS := \$(PV_DEV_ADB_KEY)\n' >> ${common}"
beta_case usb-none-missing 'must set persist.sys.usb.config=none' \
  "sed -i.x '/persist.sys.usb.config=none/d' ${common} && rm ${common}.x"
beta_case marker 'development marker in the beta configuration' \
  "printf '# DEBUG-12: try this\n' >> ${common}"
beta_case backup-file 'development leftover file' "cp ${common} ${common}.bak"
beta_case dev-avb-key 'PHONEVAULT_AVB_KEY must be exactly' \
  "sed -i.x 's|keys/avb_bluejay_beta.pem|keys/avb_bluejay_dev.pem|' ${board} && rm ${board}.x"
beta_case console-kept 'kernel command line keeps console=' \
  "sed -i.x 's| console=% | |' ${board} && rm ${board}.x"
beta_case cmdline-not-filtered 'is not filtered out of BOARD_KERNEL_CMDLINE' \
  "sed -i.x '/^BOARD_KERNEL_CMDLINE := \$(filter-out/d' ${board} && rm ${board}.x"
beta_case usbcore-dropped 'usbcore.authorized_default=0 (rung b2) is missing' \
  "sed -i.x 's|^PHONEVAULT_KERNEL_CMDLINE := usbcore.authorized_default=0|PHONEVAULT_KERNEL_CMDLINE :=|' ${board} && rm ${board}.x"
beta_case rollback-index 'lacks: BOARD_AVB_ROLLBACK_INDEX' \
  "sed -i.x '/^BOARD_AVB_ROLLBACK_INDEX :=/d' ${board} && rm ${board}.x"
beta_case no-recovery 'does not apply patches/bootable-recovery' \
  "sed -i.x 's|patches/bootable-recovery|patches/none|g' release-bluejay/sync-beta.sh && rm release-bluejay/sync-beta.sh.x"
# A beta that drops its own common.mk inherits the dev rung's: adb as the USB default.
beta_case inherits-dev-common 'persist.sys.usb.config must be none' "rm ${common}"

# resolve-beta.sh: beta files replace the rung's, expect-build.txt is appended.
bash "${VAULT}/release-bluejay/resolve-beta.sh" beta1-novoice "${work_dir}/resolved" > /dev/null
cmp -s "${work_dir}/resolved/Android.bp" "${VAULT}/dev-ladder-bluejay/rung-b4d-1/Android.bp"
cmp -s "${work_dir}/resolved/common.mk" "${VAULT}/release-bluejay/beta1/common.mk"
cmp -s "${work_dir}/resolved/config.xml" "${VAULT}/release-bluejay/beta1-novoice/config.xml"
grep -Fq 'absent VENDOR/bin/hw/rild_exynos' "${work_dir}/resolved/expect-build.txt"
grep -Fq 'grep SYSTEM/build.prop ^ro\.build\.type=user$' "${work_dir}/resolved/expect-build.txt"
grep -Fxq 'rung b4d-1 (dev-ladder-bluejay/rung-b4d-1)' "${work_dir}/resolved/RESOLVED.txt"

echo "Bluejay beta gate tests passed."
