#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f /.dockerenv ]]; then
  echo "Run inside the isolated Phone Vault build container." >&2
  exit 2
fi
if [[ $# -ne 3 || "$2" != /release-keys ]]; then
  echo "usage: $0 INPUT_TARGET_FILES_ZIP /release-keys OUTPUT_DIRECTORY" >&2
  exit 2
fi

SOURCE=/home/builder/android/lineage
PROJECT=/workspace/phone-vault
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INPUT_TARGET_FILES="$1"
KEY_DIR="$2"
OUTPUT_DIR="$3"
SIGN_TOOL="${SOURCE}/out/host/linux-x86/bin/sign_target_files_apks"
OTA_TOOL="${SOURCE}/out/host/linux-x86/bin/ota_from_target_files"
OTA_VERIFY_TOOL="${SOURCE}/out/host/linux-x86/bin/check_ota_package_signature"
[[ -s "${INPUT_TARGET_FILES}" && -s "${KEY_DIR}/avb.pem" \
    && -s "${KEY_DIR}/apex.pem" && -s "${KEY_DIR}/apex.avbpubkey" \
    && -s "${KEY_DIR}/releasekey.pk8" \
    && -s "${KEY_DIR}/module.pk8" \
    && -s "${KEY_DIR}/module.x509.pem" \
    && -s "${KEY_DIR}/metadata.pem" \
    && -s "${KEY_DIR}/metadata-public.pem" \
    && -s "${KEY_DIR}/phonevault-app.x509.pem" ]] || {
  echo "target files or release keyset is incomplete" >&2
  exit 1
}
[[ -x "${SIGN_TOOL}" && -x "${OTA_TOOL}" && -x "${OTA_VERIFY_TOOL}" ]] || {
  echo "build target-files-package and check_ota_package_signature first; hermetic Android releasetools are missing" >&2
  exit 1
}
mountpoint -q "${KEY_DIR}" || {
  echo "/release-keys must be an external bind mount" >&2
  exit 1
}

# Rosetta development builds may intentionally use WITH_DEXPREOPT=false to
# avoid an emulation-only ART address-space failure. Never promote one of those
# archives into a signed release: production must come from native x86-64 Linux
# with the ARM64 boot image fully preoptimized.
target_files_listing="$(unzip -Z1 "${INPUT_TARGET_FILES}")"
for boot_image_part in art oat vdex; do
  grep -Eq "^SYSTEM/(system/)?framework/arm64/boot\\.${boot_image_part}$" \
    <<<"${target_files_listing}" || {
      echo "release target-files lacks dexpreoptimized boot.${boot_image_part}" >&2
      exit 1
    }
done
mkdir -p "${OUTPUT_DIR}"

expected_app_cert="$(openssl x509 -in "${KEY_DIR}/phonevault-app.x509.pem" \
  -outform DER | sha256sum | awk '{print $1}')"
[[ "${expected_app_cert}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "could not derive Phone Vault app certificate digest" >&2
  exit 1
}
input_app_sha="$(unzip -p "${INPUT_TARGET_FILES}" \
  SYSTEM/app/PhoneVault/PhoneVault.apk | sha256sum | awk '{print $1}')"
[[ "${input_app_sha}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "could not derive Phone Vault APK digest from target-files" >&2
  exit 1
}

# APEX payload keys are not covered by sign_target_files_apks -d mappings.
# Explicitly replace every non-presigned payload and its APK container so a
# release cannot silently retain AOSP/Lineage development module keys.
apex_signing_args=()
while IFS= read -r apex_line; do
  [[ -n "${apex_line}" ]] || continue
  apex_name="$(sed -n 's/^name="\([^"]*\)".*/\1/p' <<<"${apex_line}")"
  [[ -n "${apex_name}" ]] || {
    echo "could not parse META/apexkeys.txt: ${apex_line}" >&2
    exit 1
  }
  if [[ "${apex_line}" == *'private_key="PRESIGNED"'* ]]; then
    continue
  fi
  apex_signing_args+=(
    --extra_apex_payload_key "${apex_name}=${KEY_DIR}/apex.pem"
    -e "${apex_name}=${KEY_DIR}/module"
  )
done < <(unzip -p "${INPUT_TARGET_FILES}" META/apexkeys.txt)
(( ${#apex_signing_args[@]} > 0 )) || {
  echo "no signable APEX modules were found in target-files" >&2
  exit 1
}

signed_target_files="${OUTPUT_DIR}/phone-vault-signed-target_files.zip"
release_ota="${OUTPUT_DIR}/phone-vault-signed-ota.zip"
release_manifest="${OUTPUT_DIR}/RELEASE-MANIFEST.txt"
release_manifest_signature="${OUTPUT_DIR}/RELEASE-MANIFEST.sig"
source_inventory="${OUTPUT_DIR}/SOURCE-INVENTORY.txt"
public_key_dir="${OUTPUT_DIR}/public-keys"
public_key_inventory="${OUTPUT_DIR}/PUBLIC-KEY-INVENTORY.txt"
release_checksums="${OUTPUT_DIR}/SHA256SUMS"
for output in "${signed_target_files}" "${release_ota}" \
    "${release_manifest}" "${release_manifest_signature}" \
    "${source_inventory}" "${public_key_dir}" \
    "${public_key_inventory}" "${release_checksums}"; do
  [[ ! -e "${output}" ]] || {
    echo "refusing to overwrite ${output}" >&2
    exit 1
  }
done

# PRESIGNED APKs are not replaced by sign_target_files_apks. Refuse to begin a
# release if the input archive does not already contain the dedicated app key.
"${SCRIPT_DIR}/verify-production-target-files.sh" "${INPUT_TARGET_FILES}"
"${SCRIPT_DIR}/verify-appliance-target-files.sh" \
  "${INPUT_TARGET_FILES}" "vendor/phonevault/keys/avb.pem" \
  "${expected_app_cert}" "${input_app_sha}"

"${SIGN_TOOL}" -o -d "${KEY_DIR}" \
  "${apex_signing_args[@]}" \
  --avb_vbmeta_key "${KEY_DIR}/avb.pem" \
  --avb_vbmeta_algorithm SHA256_RSA4096 \
  --avb_vbmeta_system_key "${KEY_DIR}/avb.pem" \
  --avb_vbmeta_system_algorithm SHA256_RSA4096 \
  --avb_boot_key "${KEY_DIR}/avb.pem" \
  --avb_boot_algorithm SHA256_RSA4096 \
  --avb_dtbo_key "${KEY_DIR}/avb.pem" \
  --avb_dtbo_algorithm SHA256_RSA4096 \
  --avb_system_key "${KEY_DIR}/avb.pem" \
  --avb_system_algorithm SHA256_RSA4096 \
  --avb_vendor_key "${KEY_DIR}/avb.pem" \
  --avb_vendor_algorithm SHA256_RSA4096 \
  "${INPUT_TARGET_FILES}" "${signed_target_files}"

"${SCRIPT_DIR}/verify-appliance-target-files.sh" \
  "${signed_target_files}" "${KEY_DIR}/avb.pem" \
  "${expected_app_cert}" "${input_app_sha}"
"${SCRIPT_DIR}/verify-production-target-files.sh" \
  "${signed_target_files}" release-keys
"${SCRIPT_DIR}/verify-signed-avb.sh" \
  "${signed_target_files}" "${KEY_DIR}/avb.pem" \
  "${SOURCE}/external/avb/avbtool.py"
"${SCRIPT_DIR}/verify-owned-package-keys.sh" \
  "${signed_target_files}" "${KEY_DIR}" "${KEY_DIR}/apex.avbpubkey"

"${OTA_TOOL}" -k "${KEY_DIR}/releasekey" \
  "${signed_target_files}" "${release_ota}"
"${SCRIPT_DIR}/verify-ota-package.sh" \
  "${signed_target_files}" "${release_ota}" \
  "${KEY_DIR}/releasekey.x509.pem" "${OTA_VERIFY_TOOL}"

release_work_dir="$(mktemp -d -t phone-vault-release-manifest.XXXXXX)"
trap 'rm -rf -- "${release_work_dir}"' EXIT
unzip -q "${signed_target_files}" 'IMAGES/vbmeta*.img' \
  -d "${release_work_dir}"
release_vbmeta="${release_work_dir}/IMAGES/vbmeta.img"
[[ -s "${release_vbmeta}" ]] || {
  echo "signed target-files lacks root vbmeta for release metadata" >&2
  exit 1
}
vbmeta_digest="$(python3 "${SOURCE}/external/avb/avbtool.py" \
  calculate_vbmeta_digest --image "${release_vbmeta}")"
vbmeta_info="$(python3 "${SOURCE}/external/avb/avbtool.py" \
  info_image --image "${release_vbmeta}")"
rollback_index="$(sed -n \
  's/^Rollback Index:[[:space:]]*\([0-9][0-9]*\)$/\1/p' \
  <<<"${vbmeta_info}")"
[[ "${vbmeta_digest}" =~ ^[0-9a-f]{64}$ \
    && "${rollback_index}" =~ ^[0-9]+$ \
    && "${rollback_index}" != 0 ]] || {
  echo "could not derive trusted release vbmeta metadata" >&2
  exit 1
}

build_fingerprint=''
for build_prop in SYSTEM/build.prop SYSTEM/system/build.prop; do
  if unzip -Z1 "${signed_target_files}" | grep -Fqx "${build_prop}"; then
    build_fingerprint="$(unzip -p "${signed_target_files}" "${build_prop}" | \
      sed -n \
        -e 's/^ro\.build\.fingerprint=//p' \
        -e 's/^ro\.system\.build\.fingerprint=//p' | head -1)"
    [[ -n "${build_fingerprint}" ]] && break
  fi
done
[[ -n "${build_fingerprint}" ]] || {
  echo "could not derive signed build fingerprint" >&2
  exit 1
}

target_files_sha="$(sha256sum "${signed_target_files}" | awk '{print $1}')"
ota_sha="$(sha256sum "${release_ota}" | awk '{print $1}')"
avb_public_key_sha="$(openssl pkey -in "${KEY_DIR}/avb.pem" -pubout \
  -outform DER | sha256sum | awk '{print $1}')"
release_cert_sha="$(openssl x509 -in "${KEY_DIR}/releasekey.x509.pem" \
  -outform DER | sha256sum | awk '{print $1}')"
metadata_public_key_sha="$(openssl pkey -pubin \
  -in "${KEY_DIR}/metadata-public.pem" -outform DER | \
  sha256sum | awk '{print $1}')"
[[ "${metadata_public_key_sha}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "could not derive release-metadata public-key identity" >&2
  exit 1
}

public_key_sources=(
  "${KEY_DIR}"/*.x509.pem
  "${KEY_DIR}/avb-public.pem"
  "${KEY_DIR}/avb_pkmd.bin"
  "${KEY_DIR}/apex-public.pem"
  "${KEY_DIR}/apex.avbpubkey"
  "${KEY_DIR}/metadata-public.pem"
)
for public_key_source in "${public_key_sources[@]}"; do
  [[ -s "${public_key_source}" ]] || {
    echo "public release-key artifact is missing: ${public_key_source}" >&2
    exit 1
  }
done
mkdir "${public_key_dir}"
for public_key_source in "${public_key_sources[@]}"; do
  install -m 0644 "${public_key_source}" \
    "${public_key_dir}/$(basename "${public_key_source}")"
done
(
  cd "${OUTPUT_DIR}"
  find public-keys -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) > "${public_key_inventory}"
public_key_inventory_sha="$(sha256sum "${public_key_inventory}" | awk '{print $1}')"

[[ -d "${PROJECT}/app/src" && -d "${PROJECT}/vault-os/patches" ]] || {
  echo "read-only Phone Vault source mount is missing" >&2
  exit 1
}
(
  cd "${PROJECT}"
  inventory_roots=(
    .gitignore
    README.md
    app/build.gradle
    app/gradle.lockfile
    app/proguard-rules.pro
    app/src
    build.gradle
    gradle/verification-metadata.xml
    gradle.properties
    settings.gradle
    tools
    vault-os
  )
  find "${inventory_roots[@]}" -type f \
      ! -path '*/__pycache__/*' ! -name '*.pyc' \
      ! -path 'vault-os/keys/development/*' -print0 | \
    LC_ALL=C sort -z | xargs -0 sha256sum
) > "${source_inventory}"
source_inventory_sha="$(sha256sum "${source_inventory}" | awk '{print $1}')"

{
  printf 'channel=production\n'
  printf 'created_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'build_fingerprint=%s\n' "${build_fingerprint}"
  printf 'phonevault_app_cert_sha256=%s\n' "${expected_app_cert}"
  printf 'phonevault_app_sha256=%s\n' "${input_app_sha}"
  printf 'avb_public_key_der_sha256=%s\n' "${avb_public_key_sha}"
  printf 'vbmeta_digest_sha256=%s\n' "${vbmeta_digest}"
  printf 'vbmeta_rollback_index=%s\n' "${rollback_index}"
  printf 'ota_release_cert_sha256=%s\n' "${release_cert_sha}"
  printf 'release_metadata_public_key_der_sha256=%s\n' \
    "${metadata_public_key_sha}"
  printf 'public_key_inventory_sha256=%s\n' "${public_key_inventory_sha}"
  printf 'source_inventory_sha256=%s\n' "${source_inventory_sha}"
  printf 'signed_target_files_sha256=%s\n' "${target_files_sha}"
  printf 'signed_ota_sha256=%s\n' "${ota_sha}"
} > "${release_manifest}"

openssl pkeyutl -sign -rawin -inkey "${KEY_DIR}/metadata.pem" \
  -in "${release_manifest}" -out "${release_manifest_signature}"
[[ "$(wc -c < "${release_manifest_signature}" | tr -d ' ')" == 64 ]] || {
  echo "release manifest Ed25519 signature has an unexpected size" >&2
  exit 1
}
openssl pkeyutl -verify -pubin -rawin \
  -inkey "${KEY_DIR}/metadata-public.pem" -in "${release_manifest}" \
  -sigfile "${release_manifest_signature}" >/dev/null

(
  cd "${OUTPUT_DIR}"
  sha256sum \
    "$(basename "${signed_target_files}")" \
    "$(basename "${release_ota}")" \
    "$(basename "${source_inventory}")" \
    "$(basename "${public_key_inventory}")" \
    "$(basename "${release_manifest}")" \
    "$(basename "${release_manifest_signature}")"
) > "${release_checksums}"
"${SCRIPT_DIR}/verify-release-bundle-metadata.sh" \
  "${OUTPUT_DIR}" "${SOURCE}/external/avb/avbtool.py"
echo "Signed target files and offline OTA written to ${OUTPUT_DIR}."
