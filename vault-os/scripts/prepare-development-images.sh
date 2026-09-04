#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f /.dockerenv ]]; then
  echo "Run inside the isolated Phone Vault build container." >&2
  exit 2
fi
if [[ $# -ne 3 || "$2" != /artifacts ]]; then
  echo "usage: $0 TARGET_FILES_ZIP /artifacts EXPECTED_APP_CERT_SHA256" >&2
  exit 2
fi

SOURCE=/home/builder/android/lineage
PROJECT=/workspace/phone-vault/vault-os
TARGET_FILES="$1"
OUTPUT_DIR="$2"
EXPECTED_APP_CERT="$3"
AVB_KEY="${PROJECT}/keys/development/avb.pem"
AVB_PUBLIC_KEY="${PROJECT}/keys/development/avb-public.pem"
SIGNER_APK=/workspace/phone-vault/app/build/outputs/apk/appliance/app-appliance.apk
AVBTOOL="${SOURCE}/external/avb/avbtool.py"
IMG_TOOL="${SOURCE}/out/host/linux-x86/bin/img_from_target_files"

[[ -s "${TARGET_FILES}" && -s "${AVB_KEY}" && -s "${AVB_PUBLIC_KEY}" \
    && -s "${SIGNER_APK}" ]] || {
  echo "target-files archive, signer APK, or development AVB keypair is missing" >&2
  exit 1
}
[[ "${EXPECTED_APP_CERT}" =~ ^[0-9a-fA-F]{64}$ ]] || {
  echo "expected app certificate must be a 64-digit SHA-256 digest" >&2
  exit 1
}
[[ -f "${AVBTOOL}" && -x "${IMG_TOOL}" ]] || {
  echo "build target-files-package first; Android host tools are missing" >&2
  exit 1
}
mountpoint -q "${OUTPUT_DIR}" || {
  echo "/artifacts must be an external writable bind mount" >&2
  exit 1
}
[[ -w "${OUTPUT_DIR}" ]] || {
  echo "/artifacts is not writable" >&2
  exit 1
}
if find "${OUTPUT_DIR}" -mindepth 1 -print -quit | grep -q .; then
  echo "refusing non-empty artifact directory: ${OUTPUT_DIR}" >&2
  exit 1
fi

expected_app_sha="$(sha256sum "${SIGNER_APK}" | awk '{print $1}')"
"${PROJECT}/scripts/verify-appliance-target-files.sh" \
  "${TARGET_FILES}" vendor/phonevault/keys/avb.pem "${EXPECTED_APP_CERT,,}" \
  "${expected_app_sha}"
"${PROJECT}/scripts/verify-signed-avb.sh" \
  "${TARGET_FILES}" "${AVB_KEY}" "${AVBTOOL}"

image_zip="${OUTPUT_DIR}/phone-vault-development-images.zip"
"${IMG_TOOL}" "${TARGET_FILES}" "${image_zip}"
mkdir "${OUTPUT_DIR}/images"
unzip -q "${image_zip}" -d "${OUTPUT_DIR}/images"
[[ -s "${OUTPUT_DIR}/images/android-info.txt" ]] || {
  echo "generated fastboot archive lacks android-info.txt" >&2
  exit 1
}
generated_android_info="$(tr -d '\r' \
  < "${OUTPUT_DIR}/images/android-info.txt")"
[[ "${generated_android_info}" == 'require board=crosshatch' ]] || {
  echo "generated fastboot bundle does not allow exactly crosshatch" >&2
  exit 1
}

"${PROJECT}/scripts/verify-release.sh" \
  "${OUTPUT_DIR}/images" "${AVBTOOL}"
vbmeta_digest="$(python3 "${AVBTOOL}" calculate_vbmeta_digest \
  --image "${OUTPUT_DIR}/images/vbmeta.img")"
[[ "${vbmeta_digest}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "could not derive complete vbmeta digest" >&2
  exit 1
}
python3 "${AVBTOOL}" extract_public_key \
  --key "${AVB_KEY}" --output "${OUTPUT_DIR}/avb_pkmd.bin"
cp "${AVB_PUBLIC_KEY}" "${OUTPUT_DIR}/avb-public.pem"

{
  printf 'development_only=true\n'
  printf 'target_files=%s\n' "$(basename "${TARGET_FILES}")"
  printf 'phonevault_app_cert_sha256=%s\n' "${EXPECTED_APP_CERT,,}"
  printf 'phonevault_app_sha256=%s\n' "${expected_app_sha}"
  printf 'vbmeta_digest_sha256=%s\n' "${vbmeta_digest}"
  printf 'created_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  openssl pkey -pubin -in "${AVB_PUBLIC_KEY}" -outform DER | \
    sha256sum | awk '{print "avb_public_key_der_sha256=" $1}'
} > "${OUTPUT_DIR}/MANIFEST.txt"

(
  cd "${OUTPUT_DIR}"
  checksum_file="$(mktemp -t phone-vault-development-checksums.XXXXXX)"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | \
    xargs -0 sha256sum > "${checksum_file}"
  mv "${checksum_file}" SHA256SUMS
)

checksum_manifest_sha="$(sha256sum \
  "${OUTPUT_DIR}/SHA256SUMS" | awk '{print $1}')"
[[ "${checksum_manifest_sha}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "could not derive development checksum-manifest digest" >&2
  exit 1
}

echo "Verified development fastboot bundle written to ${OUTPUT_DIR}."
echo "Record this digest outside the artifact directory before physical use:"
echo "checksum_manifest_sha256=${checksum_manifest_sha}"
echo "This script did not unlock, wipe, flash, or relock a device."
