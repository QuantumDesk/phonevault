#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 APK [EXPECTED_CERT_SHA256]" >&2
  exit 2
fi

APK="$1"
EXPECTED_CERT="${2:-}"
SDK_ROOT="${ANDROID_SDK_ROOT:-$(cd "$(dirname "$0")/../../.." && pwd)/.tools/android-sdk}"
SOURCE_ROOT="${ANDROID_BUILD_TOP:-/home/builder/android/lineage}"
SOURCE_TOOLS="${SOURCE_ROOT}/prebuilts/sdk/tools/linux"
SOURCE_JAVA="${SOURCE_ROOT}/prebuilts/jdk/jdk21/linux-x86/bin/java"
if [[ -x "${PHONEVAULT_AAPT:-}" && -x "${PHONEVAULT_APKSIGNER:-}" ]]; then
  AAPT=("${PHONEVAULT_AAPT}")
  APKSIGNER=("${PHONEVAULT_APKSIGNER}")
elif [[ -f /.dockerenv && -x "${SOURCE_TOOLS}/bin/aapt" \
    && -s "${SOURCE_TOOLS}/lib/apksigner.jar" && -x "${SOURCE_JAVA}" ]]; then
  AAPT=("${SOURCE_TOOLS}/bin/aapt")
  APKSIGNER=("${SOURCE_JAVA}" -jar "${SOURCE_TOOLS}/lib/apksigner.jar")
else
  AAPT=("$(find "${SDK_ROOT}/build-tools" -type f -name aapt -perm -111 | sort -V | tail -1)")
  APKSIGNER=("$(find "${SDK_ROOT}/build-tools" -type f -name apksigner -perm -111 | sort -V | tail -1)")
fi

[[ -s "${APK}" ]] || { echo "APK not found: ${APK}" >&2; exit 1; }
[[ -x "${AAPT[0]}" ]] || { echo "aapt was not found" >&2; exit 1; }
command -v "${APKSIGNER[0]}" >/dev/null || { echo "apksigner runtime was not found" >&2; exit 1; }

BADGING="$("${AAPT[@]}" dump badging "${APK}")"
PERMISSIONS="$("${AAPT[@]}" dump permissions "${APK}")"
MANIFEST="$("${AAPT[@]}" dump xmltree "${APK}" AndroidManifest.xml)"

grep -q "package: name='dev.phonevault.signer'" <<<"${BADGING}" || {
  echo "unexpected APK package name" >&2
  exit 1
}
if grep -q "application-debuggable" <<<"${BADGING}"; then
  echo "release APK must not be debuggable" >&2
  exit 1
fi
# Exact allowlist. USE_BIOMETRIC (reviewed 2026-09-24): opens the credential-only system prompt
# that has the Titan M verify the vault PIN. Any other permission is a release blocker.
ALLOWED_PERMISSIONS_RE="^uses-permission: name='android\.permission\.USE_BIOMETRIC'$"
unexpected="$(grep -E "uses-permission:|uses-permission-sdk-" <<<"${PERMISSIONS}" | grep -Ev "${ALLOWED_PERMISSIONS_RE}" || true)"
if [[ -n "${unexpected}" ]]; then
  echo "signer APK requests permissions outside the reviewed allowlist:" >&2
  echo "${unexpected}" >&2
  exit 1
fi
for required_manifest_entry in \
    'android:allowBackup(0x01010280)=(type 0x12)0x0' \
    'android:usesCleartextTraffic(0x010104ec)=(type 0x12)0x0' \
    'android:name(0x01010003)="android.hardware.usb.accessory"' \
    'android:name(0x01010003)="android.intent.category.HOME"' \
    'android:permission(0x01010006)="android.permission.BIND_DEVICE_ADMIN"'; do
  grep -Fq "${required_manifest_entry}" <<<"${MANIFEST}" || {
    echo "signer APK is missing manifest invariant: ${required_manifest_entry}" >&2
    exit 1
  }
done
if grep -Eq 'android:(debuggable|testOnly).*0xffffffff' <<<"${MANIFEST}"; then
  echo "signer APK is debuggable or test-only" >&2
  exit 1
fi
# Build-variant marker (app/build.gradle manifestPlaceholders). Only the release build type
# compiles the no-op DevTools stub; debug/appliance builds contain UI-dump code that writes the
# screen (including the recovery phrase) to disk. Anything but "release" is refused here.
VARIANT_MARKER="$(grep -F -A1 'android:name(0x01010003)="dev.phonevault.variant"' <<<"${MANIFEST}" \
  | sed -n 's/.*android:value(0x01010024)="\([^"]*\)".*/\1/p' | head -1)"
if [[ "${VARIANT_MARKER}" != "release" ]]; then
  echo "signer APK build-variant marker is '${VARIANT_MARKER:-missing}', expected 'release'" >&2
  echo "(debug/appliance builds embed screen-dump code; only the release build type is eligible)" >&2
  exit 1
fi

SIGNATURE_REPORT="$("${APKSIGNER[@]}" verify --verbose --print-certs "${APK}")"
printf '%s\n' "${SIGNATURE_REPORT}"
if ! grep -Eq '^Verified using v(2|3|3\.1|4) scheme .*: true$' \
    <<<"${SIGNATURE_REPORT}"; then
  echo "signer APK must use APK Signature Scheme v2 or newer" >&2
  exit 1
fi
grep -Fqx 'Number of signers: 1' <<<"${SIGNATURE_REPORT}" || {
  echo "signer APK must have exactly one signing identity" >&2
  exit 1
}
ACTUAL_CERT="$("${APKSIGNER[@]}" verify --print-certs "${APK}" \
  | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -1)"
[[ -n "${ACTUAL_CERT}" ]] || { echo "certificate digest was not found" >&2; exit 1; }
ACTUAL_CERT_LOWER="$(printf '%s' "${ACTUAL_CERT}" | tr '[:upper:]' '[:lower:]')"
EXPECTED_CERT_LOWER="$(printf '%s' "${EXPECTED_CERT}" | tr '[:upper:]' '[:lower:]')"
if [[ -n "${EXPECTED_CERT}" && "${ACTUAL_CERT_LOWER}" != "${EXPECTED_CERT_LOWER}" ]]; then
  echo "certificate mismatch: expected ${EXPECTED_CERT}, got ${ACTUAL_CERT}" >&2
  exit 1
fi

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "${APK}"
else
  sha256sum "${APK}"
fi
echo "Signer APK verification passed; certificate SHA-256: ${ACTUAL_CERT}"
