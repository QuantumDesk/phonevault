#!/usr/bin/env bash
# Build the dev appliance APK on the build box (no lock/verification rewriting).
set -uo pipefail
export JAVA_HOME="${JAVA_HOME:-/root/lineage-src/prebuilts/jdk/jdk21/linux-x86}"
export ANDROID_HOME="${ANDROID_HOME:-/root/android-sdk}"
cd "${PV_ROOT:-/root/pv-root}" || exit 1
"${GRADLE:-/root/gradle-8.10.2/bin/gradle}" --no-daemon :app:assembleAppliance 2>&1
echo "GRADLE_RC=$?"
