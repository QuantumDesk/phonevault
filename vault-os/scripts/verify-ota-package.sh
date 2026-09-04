#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 SIGNED_TARGET_FILES_ZIP OTA_ZIP RELEASE_CERT CHECK_OTA_TOOL" >&2
  exit 2
fi

TARGET_FILES="$1"
OTA_PACKAGE="$2"
RELEASE_CERT="$3"
CHECK_OTA_TOOL="$4"
[[ -s "${TARGET_FILES}" && -s "${OTA_PACKAGE}" && -s "${RELEASE_CERT}" \
    && -x "${CHECK_OTA_TOOL}" ]] || {
  echo "signed target-files, OTA, release certificate, or verifier is missing" >&2
  exit 1
}

work_dir="$(mktemp -d -t phone-vault-ota-verification.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT

certificate_digest() {
  local certificate="$1"
  if openssl x509 -in "${certificate}" -outform DER 2>/dev/null; then
    return
  fi
  openssl x509 -inform DER -in "${certificate}" -outform DER
}

expected_cert_digest="$(certificate_digest "${RELEASE_CERT}" | \
  sha256sum | awk '{print $1}')"
[[ "${expected_cert_digest}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "could not derive release certificate digest" >&2
  exit 1
}

recovery_cert_archives=()
while IFS= read -r recovery_cert_archive; do
  recovery_cert_archives+=("${recovery_cert_archive}")
done < <(unzip -Z1 "${TARGET_FILES}" | \
  grep -E '^SYSTEM/(system/)?etc/security/otacerts\.zip$' || true)
[[ ${#recovery_cert_archives[@]} -eq 1 ]] || {
  echo "expected exactly one installed recovery OTA certificate archive" >&2
  exit 1
}
recovery_cert_zip="${work_dir}/otacerts.zip"
unzip -p "${TARGET_FILES}" "${recovery_cert_archives[0]}" \
  > "${recovery_cert_zip}"
recovery_cert_entries=()
while IFS= read -r recovery_cert_entry; do
  recovery_cert_entries+=("${recovery_cert_entry}")
done < <(unzip -Z1 "${recovery_cert_zip}" | \
  grep -Ev '/$' || true)
[[ ${#recovery_cert_entries[@]} -eq 1 ]] || {
  echo "recovery must trust exactly one OTA certificate" >&2
  exit 1
}
recovery_cert="${work_dir}/recovery-ota-cert"
unzip -p "${recovery_cert_zip}" "${recovery_cert_entries[0]}" \
  > "${recovery_cert}"
recovery_cert_digest="$(certificate_digest "${recovery_cert}" | \
  sha256sum | awk '{print $1}')"
[[ "${recovery_cert_digest}" == "${expected_cert_digest}" ]] || {
  echo "recovery OTA trust certificate is not the project release key" >&2
  exit 1
}

ota_cert_path='META-INF/com/android/otacert'
ota_cert_count="$(unzip -Z1 "${OTA_PACKAGE}" | \
  grep -Fxc "${ota_cert_path}" || true)"
[[ "${ota_cert_count}" == 1 ]] || {
  echo "OTA package must contain exactly one embedded public certificate" >&2
  exit 1
}
ota_cert="${work_dir}/ota-cert"
unzip -p "${OTA_PACKAGE}" "${ota_cert_path}" > "${ota_cert}"
ota_cert_digest="$(certificate_digest "${ota_cert}" | \
  sha256sum | awk '{print $1}')"
[[ "${ota_cert_digest}" == "${expected_cert_digest}" ]] || {
  echo "OTA embedded certificate is not the project release key" >&2
  exit 1
}

# The AOSP checker validates both the recovery-compatible whole-file signature
# and, for A/B packages, the update_engine payload signature with
# delta_generator. Keep its required host binaries beside it on PATH.
PATH="$(dirname "${CHECK_OTA_TOOL}"):${PATH}" \
  "${CHECK_OTA_TOOL}" "${RELEASE_CERT}" "${OTA_PACKAGE}"

echo "Verified OTA package, payload signatures, and sole recovery trust key."
