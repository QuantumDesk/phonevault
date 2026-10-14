#!/usr/bin/env bash
# Build the dev appliance, install over the kiosk, ensure device-owner provisioning, launch,
# pull the first UI dump.
#   JAVA_HOME     required: a JDK 21 (e.g. the Lineage tree's prebuilts/jdk/jdk21/linux-x86)
#   ANDROID_HOME  required (or ANDROID_SDK_ROOT): the Android SDK
#   PV_ROOT       the Phone Vault checkout to build (default: this repo)
#   GRADLE        the Gradle launcher (default: gradle on PATH)
# Build/install logs go to $PV_LOG_DIR (env.sh).
# NOTE: never --write-locks here — the reviewed lockfile only changes via an explicit,
# reviewed `gradle --write-locks --write-verification-metadata sha256` run.
#
# Guards (tools/dev-device/lib.sh): PV_THROWAWAY_DEVICE=1 is required (this reinstalls the app and
# may reset provisioning state), exactly one device must be attached (or ANDROID_SERIAL set), the
# device must run a userdebug/eng dev image, and an already-installed app must be the dev
# appliance build — never a release install.
set -uo pipefail
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
[[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]] || { echo "set JAVA_HOME to a JDK 21" >&2; exit 2; }
[[ -n "${ANDROID_HOME}" && -d "${ANDROID_HOME}" ]] || { echo "set ANDROID_HOME (or ANDROID_SDK_ROOT) to the Android SDK" >&2; exit 2; }
export JAVA_HOME
PV_ROOT="${PV_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
GRADLE="${GRADLE:-gradle}"
command -v "$GRADLE" >/dev/null || { echo "no Gradle: put gradle on PATH or set GRADLE" >&2; exit 2; }
ADB="${ADB:-adb}"
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
set +e  # lib.sh enables errexit; this script checks its steps explicitly
require_throwaway   # includes require_single_device
require_dev_image
if "$ADB" shell pm path "$PKG" 2>/dev/null | grep -q '^package:'; then
  require_dev_appliance
fi
cd "$PV_ROOT" || exit 1
BUILD_LOG="$PV_LOG_DIR/buildapp.log"; INSTALL_LOG="$PV_LOG_DIR/install.log"
"$GRADLE" --no-daemon :app:assembleAppliance > "$BUILD_LOG" 2>&1 || { echo "BUILD_FAIL (log: $BUILD_LOG)"; grep -A5 "error:" "$BUILD_LOG" | head; exit 1; }
echo BUILD_OK
APK="$PV_ROOT/app/build/outputs/apk/appliance/app-appliance.apk"
"$ADB" install -r -d "$APK" > "$INSTALL_LOG" 2>&1; echo "INSTALL_RC=$? $(grep -iE 'Success|Failure|INSTALL_FAILED' "$INSTALL_LOG" | head -1)"
# No `adb root` (see lib.sh require_dev_appliance): everything below works as the shell user.
# ensure device owner (set with provisioned=0 if not already)
if ! "$ADB" shell dumpsys device_policy 2>/dev/null | grep -q "dev.phonevault.signer/.VaultDeviceAdminReceiver"; then
  "$ADB" shell settings put global device_provisioned 0 >/dev/null 2>&1
  "$ADB" shell settings put secure user_setup_complete 0 >/dev/null 2>&1
  "$ADB" shell dpm set-device-owner dev.phonevault.signer/.VaultDeviceAdminReceiver 2>&1 | head -1
  "$ADB" shell settings put global device_provisioned 1 >/dev/null 2>&1
  "$ADB" shell settings put secure user_setup_complete 1 >/dev/null 2>&1
fi
"$ADB" shell cmd package set-home-activity dev.phonevault.signer/.MainActivity >/dev/null 2>&1
"$ADB" shell locksettings set-disabled true >/dev/null 2>&1
"$ADB" shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1; sleep 1
"$ADB" shell am start -n dev.phonevault.signer/.MainActivity >/dev/null 2>&1
sleep 4
# The app's private dump needs a root adbd (insecure-adb rung images run one from boot); this
# script never switches adbd to root itself.
if adb_is_root; then
  DUMP="$PV_LOG_DIR/dump.png"
  "$ADB" exec-out cat /data/data/dev.phonevault.signer/files/vault_dump.png > "$DUMP" 2>/dev/null
  echo "DUMP_BYTES=$(wc -c < "$DUMP" | tr -d ' ') ($DUMP)"
else
  echo "DUMP skipped: adbd is not root (scripts never run 'adb root')"
fi
"$ADB" shell dumpsys activity activities 2>/dev/null | grep -iE mLockTaskModeState | head -1
