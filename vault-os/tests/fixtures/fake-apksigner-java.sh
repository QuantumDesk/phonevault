#!/usr/bin/env bash
set -euo pipefail

arguments=("$@")
package_file="${arguments[${#arguments[@]} - 1]}"
if marker="$(unzip -p "${package_file}" marker 2>/dev/null)" \
    && [[ -n "${marker}" ]]; then
  :
else
  marker="$(head -n 1 "${package_file}")"
fi
case "${marker}" in
  PHONEVAULT)
    digest="${FAKE_PHONEVAULT_DIGEST:?}"
    ;;
  SYSTEMTHING)
    digest="${FAKE_SYSTEMTHING_DIGEST:?}"
    ;;
  APEX)
    digest="${FAKE_APEX_DIGEST:?}"
    ;;
  *)
    echo "unknown synthetic package marker: ${marker}" >&2
    exit 1
    ;;
esac
printf '%s\n' \
  'Verifies' \
  'Verified using v2 scheme (APK Signature Scheme v2): true' \
  'Number of signers: 1' \
  "Signer #1 certificate SHA-256 digest: ${digest}"
