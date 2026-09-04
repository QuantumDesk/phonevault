#!/bin/sh
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
workspace_dir=$(CDPATH='' cd -- "$project_dir/.." && pwd)

: "${JAVA_HOME:=$workspace_dir/.tools/jdk17/current/Contents/Home}"
: "${ANDROID_SDK_ROOT:=$workspace_dir/.tools/android-sdk}"
export JAVA_HOME ANDROID_SDK_ROOT

"$workspace_dir/.tools/gradle/gradle-8.10.2/bin/gradle" \
    -p "$project_dir" testDebugUnitTest testApplianceUnitTest assembleDebug assembleAppliance "$@"

# AGP selects randomized RSA-PSS for this API-28 APK. Re-sign the development
# appliance as v2-only with the same debug identity and an API-21 signature
# compatibility floor, which selects deterministic RSA PKCS#1. The manifest's
# actual minSdk remains 28. This makes clean builds byte-comparable without
# adding legacy v1 signatures.
appliance_apk="$project_dir/app/build/outputs/apk/appliance/app-appliance.apk"
apksigner="$ANDROID_SDK_ROOT/build-tools/35.0.0/apksigner"
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
