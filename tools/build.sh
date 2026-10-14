#!/bin/sh
# Build and unit-test the signer app (debug + development appliance), then re-sign the appliance
# APK deterministically. Needs, from the environment:
#   JAVA_HOME         a JDK 17 or newer (CI uses 21)
#   ANDROID_SDK_ROOT  the Android SDK with build-tools 35.0.0 (ANDROID_HOME is accepted too)
#   gradle            Gradle 8.10.2 on PATH (the repo has no wrapper), or GRADLE=/path/to/gradle
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

die() { echo "tools/build.sh: $*" >&2; exit 2; }
: "${ANDROID_SDK_ROOT:=${ANDROID_HOME:-}}"
[ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ] || die "set JAVA_HOME to a JDK (17 or newer)"
[ -n "$ANDROID_SDK_ROOT" ] && [ -d "$ANDROID_SDK_ROOT" ] \
    || die "set ANDROID_SDK_ROOT (or ANDROID_HOME) to the Android SDK"
gradle="${GRADLE:-gradle}"
command -v "$gradle" >/dev/null 2>&1 || die "Gradle 8.10.2 not found: put gradle on PATH or set GRADLE"
export JAVA_HOME ANDROID_SDK_ROOT

"$gradle" \
    -p "$project_dir" testDebugUnitTest testApplianceUnitTest assembleDebug assembleAppliance "$@"

# AGP selects randomized RSA-PSS for this API-28 APK. Re-sign the development
# appliance as v2-only with the same debug identity and an API-21 signature
# compatibility floor, which selects deterministic RSA PKCS#1. The manifest's
# actual minSdk remains 28. This makes clean builds byte-comparable without
# adding legacy v1 signatures.
appliance_apk="$project_dir/app/build/outputs/apk/appliance/app-appliance.apk"
apksigner="$ANDROID_SDK_ROOT/build-tools/35.0.0/apksigner"
[ -x "$apksigner" ] || die "apksigner not found: install build-tools;35.0.0 in $ANDROID_SDK_ROOT"
debug_keystore="${PHONEVAULT_DEBUG_KEYSTORE:-${HOME}/.android/debug.keystore}"
signed_apk=$(mktemp "${TMPDIR:-/tmp}/phone-vault-appliance.XXXXXX")
trap 'rm -f "$signed_apk"' EXIT HUP INT TERM
"$apksigner" sign \
    --ks "$debug_keystore" \
    --ks-key-alias androiddebugkey \
    --ks-pass pass:android \
    --key-pass pass:android \
    --min-sdk-version 21 \
    --v1-signing-enabled false \
    --v2-signing-enabled true \
    --v3-signing-enabled false \
    --out "$signed_apk" \
    "$appliance_apk"
mv "$signed_apk" "$appliance_apk"
trap - EXIT HUP INT TERM
