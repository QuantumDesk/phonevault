#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERIFY="${ROOT}/vault-os/scripts/verify-owner-provisioning-policy.sh"
INSTALLER="${ROOT}/vault-os/scripts/install-overlay.sh"
work_dir="$(mktemp -d -t phone-vault-owner-policy.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT

make_fixture() {
  local fixture="$1"
  mkdir -p \
    "${fixture}/app/src/main/res/xml" \
    "${fixture}/vault-os/vendor/phonevault/overlay/frameworks/base/core/res/res/values" \
    "${fixture}/vault-os/vendor/phonevault/prebuilt" \
    "${fixture}/vault-os/vendor/phonevault/config" \
    "${fixture}/vault-os/device/phonevault/crosshatch" \
    "${fixture}/vault-os/patches/frameworks-base"
  cp "${ROOT}/app/build.gradle" "${fixture}/app/build.gradle"
  cp "${ROOT}/app/src/main/AndroidManifest.xml" \
    "${fixture}/app/src/main/AndroidManifest.xml"
  cp "${ROOT}/app/src/main/res/xml/device_admin.xml" \
    "${fixture}/app/src/main/res/xml/device_admin.xml"
  cp "${ROOT}/vault-os/vendor/phonevault/overlay/frameworks/base/core/res/res/values/config.xml" \
    "${fixture}/vault-os/vendor/phonevault/overlay/frameworks/base/core/res/res/values/config.xml"
  cp "${ROOT}/vault-os/vendor/phonevault/prebuilt/Android.bp" \
    "${fixture}/vault-os/vendor/phonevault/prebuilt/Android.bp"
  cp "${ROOT}/vault-os/vendor/phonevault/config/common.mk" \
    "${fixture}/vault-os/vendor/phonevault/config/common.mk"
  cp "${ROOT}/vault-os/device/phonevault/crosshatch/vault_crosshatch.mk" \
    "${fixture}/vault-os/device/phonevault/crosshatch/vault_crosshatch.mk"
  cp "${ROOT}/vault-os/patches/frameworks-base/0003-provision-configured-appliance-owner.patch" \
    "${fixture}/vault-os/patches/frameworks-base/0003-provision-configured-appliance-owner.patch"
  cp "${ROOT}/vault-os/patches/frameworks-base/0004-export-fixed-function-owner-resource.patch" \
    "${fixture}/vault-os/patches/frameworks-base/0004-export-fixed-function-owner-resource.patch"
}

expect_failure() {
  local fixture="$1"
  local expected="$2"
  if "${VERIFY}" "${fixture}" > "${fixture}.stdout" 2> "${fixture}.stderr"; then
    echo "invalid owner policy fixture unexpectedly passed: ${expected}" >&2
    exit 1
  fi
  grep -Fq -- "${expected}" "${fixture}.stderr"
}

"${VERIFY}" "${ROOT}"
# This is an intentional literal source invariant; OVERLAY must expand only
# when the installer runs inside the build container.
# shellcheck disable=SC2016
grep -Fq '"${OVERLAY}/scripts/verify-owner-provisioning-policy.sh"' \
  "${INSTALLER}" || {
  echo "overlay installer does not enforce owner provisioning policy" >&2
  exit 1
}

wrong_owner="${work_dir}/wrong-owner"
make_fixture "${wrong_owner}"
sed -i.bak 's#dev.phonevault.signer/.VaultDeviceAdminReceiver#dev.phonevault.signer/.OtherAdmin#' \
  "${wrong_owner}/vault-os/vendor/phonevault/overlay/frameworks/base/core/res/res/values/config.xml"
expect_failure "${wrong_owner}" 'configured owner is not exactly'

privileged="${work_dir}/privileged"
make_fixture "${privileged}"
sed -i.bak 's/privileged: false/privileged: true/' \
  "${privileged}/vault-os/vendor/phonevault/prebuilt/Android.bp"
expect_failure "${privileged}" 'does not enforce privileged: false'

late_owner="${work_dir}/late-owner"
make_fixture "${late_owner}"
sed -i.bak '/^+                    || hasUserSetupCompleted(UserHandle.USER_SYSTEM))/d' \
  "${late_owner}/vault-os/patches/frameworks-base/0003-provision-configured-appliance-owner.patch"
expect_failure "${late_owner}" 'hasUserSetupCompleted(UserHandle.USER_SYSTEM)'

non_system="${work_dir}/non-system"
make_fixture "${non_system}"
sed -i.bak 's/ownerInfo == null || !ownerInfo.isSystemApp()/ownerInfo == null/' \
  "${non_system}/vault-os/patches/frameworks-base/0003-provision-configured-appliance-owner.patch"
expect_failure "${non_system}" 'ownerInfo == null || !ownerInfo.isSystemApp()'

mismatched_existing="${work_dir}/mismatched-existing"
make_fixture "${mismatched_existing}"
sed -i.bak '/^+                if (!admin.equals(mOwners.getDeviceOwnerComponent())) {/d' \
  "${mismatched_existing}/vault-os/patches/frameworks-base/0003-provision-configured-appliance-owner.patch"
expect_failure "${mismatched_existing}" 'admin.equals(mOwners.getDeviceOwnerComponent())'

missing_home="${work_dir}/missing-home"
make_fixture "${missing_home}"
sed -i.bak '/android.intent.category.HOME/d' \
  "${missing_home}/app/src/main/AndroidManifest.xml"
expect_failure "${missing_home}" 'MainActivity is not an exact MAIN/HOME/DEFAULT target'

late_overlay="${work_dir}/late-overlay"
make_fixture "${late_overlay}"
printf '\nPRODUCT_PACKAGE_OVERLAYS += \\\n    vendor/phonevault/overlay\n' \
  >> "${late_overlay}/vault-os/vendor/phonevault/config/common.mk"
expect_failure "${late_overlay}" 'common.mk must not add the resource overlay'

overlay_after_inherit="${work_dir}/overlay-after-inherit"
make_fixture "${overlay_after_inherit}"
python3 - "${overlay_after_inherit}/vault-os/device/phonevault/crosshatch/vault_crosshatch.mk" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
block = "PRODUCT_PACKAGE_OVERLAYS += \\\n    vendor/phonevault/overlay\n"
assert block in text
path.write_text(text.replace(block, "") + "\n" + block)
PY
expect_failure "${overlay_after_inherit}" 'must be added before the first inherit-product'

echo "Owner provisioning policy negative fixtures passed."
