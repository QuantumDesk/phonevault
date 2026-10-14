#!/usr/bin/env bash
# Build the dev appliance, install over the kiosk, ensure device-owner provisioning, launch,
# pull the first UI dump. Build-box paths; adjust JAVA_HOME/ANDROID_HOME/PV_ROOT as needed.
# NOTE: never --write-locks here — the reviewed lockfile only changes via an explicit,
# reviewed `gradle --write-locks --write-verification-metadata sha256` run.
#
# Guards (tools/dev-device/lib.sh): PV_THROWAWAY_DEVICE=1 is required (this reinstalls the app and
# may reset provisioning state), exactly one device must be attached (or ANDROID_SERIAL set), the
# device must run a userdebug/eng dev image, and an already-installed app must be the dev
# appliance build — never a release install.
set -uo pipefail
export JAVA_HOME="${JAVA_HOME:-/root/lineage-src/prebuilts/jdk/jdk21/linux-x86}"
export ANDROID_HOME="${ANDROID_HOME:-/root/android-sdk}"
PV_ROOT="${PV_ROOT:-/root/pv-root}"
GRADLE="${GRADLE:-/root/gradle-8.10.2/bin/gradle}"
ADB="${ADB:-adb}"
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
set +e  # lib.sh enables errexit; this script checks its steps explicitly
require_throwaway
require_single_device
require_dev_image
if "$ADB" shell pm path "$PKG" 2>/dev/null | grep -q '^package:'; then
  require_dev_appliance
fi
cd "$PV_ROOT" || exit 1
"$GRADLE" --no-daemon :app:assembleAppliance > /root/buildapp.log 2>&1 || { echo BUILD_FAIL; grep -A5 "error:" /root/buildapp.log | head; exit 1; }
echo BUILD_OK
APK="$PV_ROOT/app/build/outputs/apk/appliance/app-appliance.apk"
"$ADB" install -r -d "$APK" > /root/install.log 2>&1; echo "INSTALL_RC=$? $(grep -iE 'Success|Failure|INSTALL_FAILED' /root/install.log | head -1)"
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
  "$ADB" exec-out cat /data/data/dev.phonevault.signer/files/vault_dump.png > /root/dump.png 2>/dev/null
  echo "DUMP_BYTES=$(stat -c%s /root/dump.png 2>/dev/null)"
else
  echo "DUMP skipped: adbd is not root (scripts never run 'adb root')"
fi
"$ADB" shell dumpsys activity activities 2>/dev/null | grep -iE mLockTaskModeState | head -1
