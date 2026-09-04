#!/bin/bash
# Build the app, install over the kiosk, ensure provisioning, launch, pull the UI dump.
export JAVA_HOME=/root/lineage-src/prebuilts/jdk/jdk21/linux-x86
export ANDROID_HOME=/root/android-sdk
cd /root/pv-root
/root/gradle-8.10.2/bin/gradle --no-daemon --write-locks :app:assembleAppliance > /root/buildapp.log 2>&1 || { echo BUILD_FAIL; grep -A5 "error:" /root/buildapp.log | head; exit 1; }
echo BUILD_OK
APK=/root/pv-root/app/build/outputs/apk/appliance/app-appliance.apk
adb install -r -d "$APK" > /root/install.log 2>&1; echo "INSTALL_RC=$? $(grep -iE 'Success|Failure|INSTALL_FAILED' /root/install.log | head -1)"
adb root >/dev/null 2>&1; sleep 2
# ensure device owner (set with provisioned=0 if not already)
if ! adb shell dumpsys device_policy 2>/dev/null | grep -q "dev.phonevault.signer/.VaultDeviceAdminReceiver"; then
  adb shell settings put global device_provisioned 0 >/dev/null 2>&1
  adb shell settings put secure user_setup_complete 0 >/dev/null 2>&1
  adb shell dpm set-device-owner dev.phonevault.signer/.VaultDeviceAdminReceiver 2>&1 | head -1
  adb shell settings put global device_provisioned 1 >/dev/null 2>&1
  adb shell settings put secure user_setup_complete 1 >/dev/null 2>&1
fi
adb shell cmd package set-home-activity dev.phonevault.signer/.MainActivity >/dev/null 2>&1
adb shell locksettings set-disabled true >/dev/null 2>&1
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1; sleep 1
adb shell am start -n dev.phonevault.signer/.MainActivity >/dev/null 2>&1
sleep 4
adb shell cat /data/data/dev.phonevault.signer/files/vault_dump.png > /root/dump.png 2>/dev/null
echo "DUMP_BYTES=$(stat -c%s /root/dump.png 2>/dev/null)"
adb shell dumpsys activity activities 2>/dev/null | grep -iE mLockTaskModeState | head -1
