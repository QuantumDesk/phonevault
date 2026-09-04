#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
work_dir="$(mktemp -d -t phone-vault-production-gate.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT
fixture="${work_dir}/fixture"
mkdir -p "${fixture}/META" "${fixture}/SYSTEM" \
  "${fixture}/BOOT/RAMDISK"
printf '%s\n' 'build_type=user' > "${fixture}/META/misc_info.txt"
printf '%s\n' \
  'ro.system.build.tags=release-keys' \
  > "${fixture}/SYSTEM/build.prop"
printf '%s\n' \
  'ro.debuggable=0' \
  'ro.secure=1' \
  'ro.adb.secure=1' \
  > "${fixture}/BOOT/RAMDISK/prop.default"

positive="${work_dir}/positive.zip"
(cd "${fixture}" && zip -qr "${positive}" .)
"${ROOT}/scripts/verify-production-target-files.sh" "${positive}"
"${ROOT}/scripts/verify-production-target-files.sh" \
  "${positive}" release-keys

sed -i.bak 's/^build_type=user$/build_type=userdebug/' \
  "${fixture}/META/misc_info.txt"
negative_userdebug="${work_dir}/negative-userdebug.zip"
(cd "${fixture}" && zip -qr "${negative_userdebug}" .)
if "${ROOT}/scripts/verify-production-target-files.sh" \
    "${negative_userdebug}" > /dev/null 2>&1; then
  echo "userdebug production fixture unexpectedly passed" >&2
  exit 1
fi
mv "${fixture}/META/misc_info.txt.bak" "${fixture}/META/misc_info.txt"

printf '%s\n' 'ro.debuggable=1' >> "${fixture}/BOOT/RAMDISK/prop.default"
negative_debuggable="${work_dir}/negative-debuggable.zip"
(cd "${fixture}" && zip -qr "${negative_debuggable}" .)
if "${ROOT}/scripts/verify-production-target-files.sh" \
    "${negative_debuggable}" > /dev/null 2>&1; then
  echo "debuggable production fixture unexpectedly passed" >&2
  exit 1
fi
sed -i.bak '/^ro\.debuggable=1$/d' \
  "${fixture}/BOOT/RAMDISK/prop.default"
rm "${fixture}/BOOT/RAMDISK/prop.default.bak"

sed -i.bak 's/release-keys/test-keys/' "${fixture}/SYSTEM/build.prop"
negative_tags="${work_dir}/negative-tags.zip"
(cd "${fixture}" && zip -qr "${negative_tags}" .)
if "${ROOT}/scripts/verify-production-target-files.sh" \
    "${negative_tags}" release-keys > /dev/null 2>&1; then
  echo "test-key production fixture unexpectedly passed" >&2
  exit 1
fi

release_script="${ROOT}/scripts/sign-release.sh"
# These are literal source snippets; the variables must not expand in the test.
# shellcheck disable=SC2016
for required_release_evidence in \
    'public_key_dir="${OUTPUT_DIR}/public-keys"' \
    'public_key_inventory="${OUTPUT_DIR}/PUBLIC-KEY-INVENTORY.txt"' \
    '"${KEY_DIR}/avb_pkmd.bin"' \
    '"${KEY_DIR}/apex.avbpubkey"' \
    'cd "${OUTPUT_DIR}"' \
    '"${OUTPUT_DIR}" "${SOURCE}/external/avb/avbtool.py"' \
    "printf 'public_key_inventory_sha256=%s\\n'"; do
  grep -Fq -- "${required_release_evidence}" "${release_script}" || {
    echo "release bundle omits public verification evidence: ${required_release_evidence}" >&2
    exit 1
  }
done
public_export_block="$(sed -n '/^public_key_sources=(/,/^)/p' "${release_script}")"
if grep -Eq '(\.pk8|/avb\.pem|/apex\.pem)' <<<"${public_export_block}"; then
  echo "release bundle public export includes private key material" >&2
  exit 1
fi

keyset_script="${ROOT}/scripts/generate-release-keyset.sh"
# These are literal source snippets; variables must not expand in the test.
# shellcheck disable=SC2016
for required_keyset_invariant in \
    'mountpoint -q "${KEY_DIR}"' \
    'for name in releasekey platform shared media networkstack sdk_sandbox bluetooth nfc module phonevault-app' \
    'run_make_key "${name}"' \
    'trap '\''rm -rf \${tmpdir}; echo; exit 1'\'' EXIT INT QUIT' \
    'openssl asn1parse -inform DER' \
    'openssl x509 -in "${KEY_DIR}/${name}.x509.pem" -noout' \
    'cd "${KEY_DIR}"' \
    'sha256sum "${public_files[@]}"' \
    'chmod 0600 "${KEY_DIR}"/*.pk8 "${KEY_DIR}/avb.pem" "${KEY_DIR}/apex.pem"'; do
  grep -Fq -- "${required_keyset_invariant}" "${keyset_script}" || {
    echo "release keyset generator lacks invariant: ${required_keyset_invariant}" >&2
    exit 1
  }
done

echo "Production target-files and public release-bundle gates passed."
