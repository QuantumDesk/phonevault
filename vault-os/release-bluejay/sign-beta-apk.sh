#!/usr/bin/env bash
# Sign the signer app's RELEASE build with the BETA-TEST app key, on the build host:
#   sign-beta-apk.sh UNSIGNED_APK OUTPUT_APK [KEY_DIR]
#     UNSIGNED_APK  app/build/outputs/apk/release/app-release-unsigned.apk (`gradle :app:assembleRelease`;
#                   the release build type has no signingConfig, so it comes out unsigned)
#     KEY_DIR       default $HOME/.phonevault-keys/beta (gen-beta-keys.sh)
# Same signature shape as scripts/sign-signer-apk.sh (the release-container path): zipaligned,
# APK Signature Scheme v2 only, one signer, API-21 signing floor (deterministic RSA PKCS#1).
# Then scripts/verify-signer-apk.sh: release variant marker, not debuggable, permission and
# manifest allowlist, and the certificate must be the beta key's.
# Tools come from the Lineage tree ($LINEAGE_TREE, default /build/lineage-24): prebuilt
# zipalign and aapt, the host apksigner (out/host/linux-x86/bin, from any earlier build of the
# tree) and the prebuilt JDK 21. The key is read by apksigner only, never printed.
set -euo pipefail
IN="${1:?usage: sign-beta-apk.sh UNSIGNED_APK OUTPUT_APK [KEY_DIR]}"
OUT="${2:?usage: sign-beta-apk.sh UNSIGNED_APK OUTPUT_APK [KEY_DIR]}"
KEY_DIR="${3:-${HOME}/.phonevault-keys/beta}"
TREE="${LINEAGE_TREE:-/build/lineage-24}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS="${TREE}/prebuilts/sdk/tools/linux"
export PATH="${TREE}/prebuilts/jdk/jdk21/linux-x86/bin:${PATH}"
KEY="${KEY_DIR}/phonevault-app-BETA.pk8"
CERT="${KEY_DIR}/phonevault-app-BETA.x509.pem"
[[ -s "${IN}" ]] || { echo "no unsigned APK: ${IN}" >&2; exit 1; }
[[ -s "${KEY}" && -s "${CERT}" ]] || { echo "beta app key missing in ${KEY_DIR} (gen-beta-keys.sh)" >&2; exit 1; }
[[ ! -e "${OUT}" ]] || { echo "refusing to overwrite ${OUT}" >&2; exit 1; }
"${TREE}/out/host/linux-x86/bin/apksigner" version >/dev/null \
  || { echo "apksigner does not run (out/host/linux-x86/bin/apksigner, JDK 21 on PATH)" >&2; exit 1; }
# An APK that is already signed is not the release build's unsigned output.
if "${TREE}/out/host/linux-x86/bin/apksigner" verify "${IN}" >/dev/null 2>&1; then
  echo "input APK is already signed; expected the unsigned release build" >&2; exit 1
fi

aligned="$(mktemp --suffix=.apk)"
trap 'rm -f "${aligned}"' EXIT
"${TOOLS}/bin/zipalign" -p -f 4 "${IN}" "${aligned}"
"${TREE}/out/host/linux-x86/bin/apksigner" sign \
  --key "${KEY}" --cert "${CERT}" \
  --min-sdk-version 21 \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled false \
  --v4-signing-enabled false \
  --out "${OUT}" "${aligned}"
"${TOOLS}/bin/zipalign" -c -p 4 "${OUT}"
expected_cert="$(openssl x509 -in "${CERT}" -outform DER | sha256sum | cut -c1-64)"
PHONEVAULT_AAPT="${TOOLS}/bin/aapt" PHONEVAULT_APKSIGNER="${TREE}/out/host/linux-x86/bin/apksigner" \
  "${SCRIPT_DIR}/../scripts/verify-signer-apk.sh" "${OUT}" "${expected_cert}"
