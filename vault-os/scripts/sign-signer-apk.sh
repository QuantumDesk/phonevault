#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f /.dockerenv ]]; then
  echo "Run inside the isolated Phone Vault build container." >&2
  exit 2
fi
if [[ $# -ne 3 || "$2" != /release-keys ]]; then
  echo "usage: $0 UNSIGNED_APK /release-keys OUTPUT_APK" >&2
  exit 2
fi

SOURCE=/home/builder/android/lineage
PROJECT=/workspace/phone-vault/vault-os
UNSIGNED_APK="$1"
KEY_DIR="$2"
OUTPUT_APK="$3"
APKSIGNER="${SOURCE}/prebuilts/sdk/tools/linux/bin/apksigner"
[[ -s "${UNSIGNED_APK}" && -s "${KEY_DIR}/phonevault-app.pk8" \
    && -s "${KEY_DIR}/phonevault-app.x509.pem" && -x "${APKSIGNER}" ]] || {
  echo "unsigned APK, dedicated app key, or apksigner is missing" >&2
  exit 1
}
mountpoint -q "${KEY_DIR}" || {
  echo "/release-keys must be an external bind mount" >&2
  exit 1
}
[[ ! -e "${OUTPUT_APK}" ]] || {
  echo "refusing to overwrite ${OUTPUT_APK}" >&2
  exit 1
}

read -r -s -p "Password for phonevault-app.pk8 (blank if unencrypted): " key_password
echo
if [[ -n "${key_password}" ]]; then
  printf '%s\n' "${key_password}" | "${APKSIGNER}" sign \
    --key "${KEY_DIR}/phonevault-app.pk8" \
    --cert "${KEY_DIR}/phonevault-app.x509.pem" \
    --min-sdk-version 21 \
    --v1-signing-enabled false \
    --v2-signing-enabled true \
    --v3-signing-enabled false \
    --key-pass stdin --out "${OUTPUT_APK}" "${UNSIGNED_APK}"
else
  "${APKSIGNER}" sign \
    --key "${KEY_DIR}/phonevault-app.pk8" \
    --cert "${KEY_DIR}/phonevault-app.x509.pem" \
    --min-sdk-version 21 \
    --v1-signing-enabled false \
    --v2-signing-enabled true \
    --v3-signing-enabled false \
    --out "${OUTPUT_APK}" "${UNSIGNED_APK}"
fi
unset key_password
expected_cert="$(openssl x509 -in "${KEY_DIR}/phonevault-app.x509.pem" \
  -outform DER | sha256sum | awk '{print $1}')"
"${PROJECT}/scripts/verify-signer-apk.sh" "${OUTPUT_APK}" "${expected_cert}"
