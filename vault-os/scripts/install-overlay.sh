#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f /.dockerenv ]]; then
  echo "Run this inside the Phone Vault build container." >&2
  exit 2
fi
if [[ ! -d /home/builder/android/lineage/build ]]; then
  echo "Lineage source has not been synced." >&2
  exit 1
fi

SOURCE=/home/builder/android/lineage
OVERLAY=/workspace/phone-vault/vault-os
PATCH_STATE="${SOURCE}/.repo/phonevault-patches"

# Bind the product overlay, framework provisioning hook, and actual signer
# manifest to one exact ordinary-system-app owner/HOME identity before any
# source-tree mutation begins.
"${OVERLAY}/scripts/verify-owner-provisioning-policy.sh" \
  /workspace/phone-vault
"${OVERLAY}/scripts/verify-patch-provenance.sh" \
  /workspace/phone-vault
"${OVERLAY}/scripts/verify-release-source.sh" \
  /workspace/phone-vault

apply_versioned_patch() {
  local source_root="$1"
  local patch_file="$2"
  local state_file="$3"
  local label="$4"

  mkdir -p "$(dirname "${state_file}")"
  if [[ -s "${state_file}" ]] && cmp -s "${state_file}" "${patch_file}"; then
    # A prior installer checked reverse applicability first. For deletion-only
    # patches that can be a false positive because Git may accept inserting a
    # duplicate block. Prefer the forward check and repair stale state markers.
    if git -C "${source_root}" apply --check "${patch_file}" >/dev/null 2>&1; then
      echo "repairing recorded-but-missing ${label} patch"
      git -C "${source_root}" apply "${patch_file}"
    elif git -C "${source_root}" apply --reverse --check "${patch_file}" >/dev/null 2>&1; then
      echo "${label} patch recorded as applied"
    else
      # Later patches in the ordered series may modify the same context and
      # make both standalone checks impossible. The byte-identical marker is
      # retained, while release/source residue gates verify final invariants.
      echo "${label} patch recorded as applied (overlapping later context)"
    fi
    return
  fi
  if [[ -s "${state_file}" ]]; then
    if git -C "${source_root}" apply --check "${state_file}" >/dev/null 2>&1; then
      echo "recorded ${label} patch was not present"
    elif git -C "${source_root}" apply --reverse --check "${state_file}" >/dev/null 2>&1; then
      echo "replacing prior ${label} patch revision"
      git -C "${source_root}" apply --reverse "${state_file}"
    else
      echo "recorded ${label} patch state does not match the source tree" >&2
      exit 1
    fi
  fi

  if git -C "${source_root}" apply --check "${patch_file}" >/dev/null 2>&1; then
    git -C "${source_root}" apply "${patch_file}"
  elif git -C "${source_root}" apply --reverse --check "${patch_file}" >/dev/null 2>&1; then
    echo "${label} patch already applied"
  else
    echo "${label} patch cannot be applied or verified as present" >&2
    exit 1
  fi
  install -m 0644 "${patch_file}" "${state_file}"
}

mkdir -p "${SOURCE}/device/phonevault" "${SOURCE}/vendor/phonevault"
rsync -a --delete "${OVERLAY}/device/phonevault/" "${SOURCE}/device/phonevault/"
rsync -a --delete "${OVERLAY}/vendor/phonevault/" "${SOURCE}/vendor/phonevault/"

DEVICE_SOURCE="${SOURCE}/device/google/crosshatch"
for device_patch in "${OVERLAY}"/patches/device-crosshatch/*.patch; do
  patch_name="$(basename "${device_patch}")"
  apply_versioned_patch "${DEVICE_SOURCE}" "${device_patch}" \
    "${PATCH_STATE}/device-${patch_name}" "crosshatch ${patch_name}"
done

KERNEL_SOURCE="${SOURCE}/kernel/google/msm-4.9"
for kernel_patch in "${OVERLAY}"/patches/kernel-crosshatch/*.patch; do
  patch_name="$(basename "${kernel_patch}")"
  apply_versioned_patch "${KERNEL_SOURCE}" "${kernel_patch}" \
    "${PATCH_STATE}/kernel-${patch_name}" "crosshatch kernel ${patch_name}"
done

# Recovery: on user builds (ro.debuggable=0) no "Install anyway?" for unverified
# or downgrade packages and no recovery ADB. Userdebug keeps upstream behavior.
RECOVERY_SOURCE="${SOURCE}/bootable/recovery"
for recovery_patch in "${OVERLAY}"/patches/bootable-recovery/*.patch; do
  patch_name="$(basename "${recovery_patch}")"
  apply_versioned_patch "${RECOVERY_SOURCE}" "${recovery_patch}" \
    "${PATCH_STATE}/recovery-${patch_name}" "recovery ${patch_name}"
done

for appliance_patch in "${OVERLAY}"/patches/appliance/*.patch; do
  patch_name="$(basename "${appliance_patch}")"
  apply_versioned_patch "${SOURCE}" "${appliance_patch}" \
    "${PATCH_STATE}/appliance-${patch_name}" "appliance ${patch_name}"
done

BOARD_CONFIG="${SOURCE}/device/google/crosshatch/crosshatch/BoardConfigLineage.mk"
VAULT_BOARD_INCLUDE='include vendor/phonevault/config/BoardConfigVault.mk'
if ! grep -Fqx "${VAULT_BOARD_INCLUDE}" "${BOARD_CONFIG}"; then
  printf '\n# Phone Vault product AVB policy\n%s\n' "${VAULT_BOARD_INCLUDE}" >> "${BOARD_CONFIG}"
fi

AVB_KEY="${OVERLAY}/keys/development/avb.pem"
if [[ ! -s "${AVB_KEY}" ]]; then
  echo "Missing development AVB key: ${AVB_KEY}" >&2
  echo "Run scripts/generate-development-avb-key.sh on the host." >&2
  exit 1
fi
install -d -m 0700 "${SOURCE}/vendor/phonevault/keys"
install -m 0600 "${AVB_KEY}" "${SOURCE}/vendor/phonevault/keys/avb.pem"

APK="${PHONEVAULT_SIGNER_APK:-/workspace/phone-vault/app/build/outputs/apk/appliance/app-appliance.apk}"
if [[ ! -s "${APK}" ]]; then
  echo "Build the signer APK first: phone-vault/tools/build.sh" >&2
  exit 1
fi
"${OVERLAY}/scripts/verify-signer-apk.sh" \
  "${APK}" "${PHONEVAULT_SIGNER_CERT_SHA256:-}"
if [[ -n "${PHONEVAULT_SIGNER_APK:-}" ]]; then
  [[ -n "${PHONEVAULT_SIGNER_CERT_SHA256:-}" ]] || {
    echo "PHONEVAULT_SIGNER_CERT_SHA256 is required with a release APK" >&2
    exit 1
  }
fi
cp "${APK}" "${SOURCE}/vendor/phonevault/prebuilt/PhoneVault.apk"

if [[ -n "${PHONEVAULT_SIGNER_APK:-}" ]]; then
  echo "Vault OS overlay installed with verified release signer APK."
else
  echo "Vault OS overlay installed with a development-signed, non-debuggable appliance APK."
fi
