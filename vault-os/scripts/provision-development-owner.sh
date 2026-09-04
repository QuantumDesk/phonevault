#!/usr/bin/env bash
set -euo pipefail

ADB_BIN="${ADB_BIN:-adb}"
PACKAGE="dev.phonevault.signer"
ADMIN="${PACKAGE}/.VaultDeviceAdminReceiver"

cat <<'EOF'
This development-only procedure requires a freshly factory-reset device with no
accounts or users configured. It changes device policy but does not unlock or
flash the bootloader. Press Enter to continue or Ctrl-C to stop.
EOF
read -r

"${ADB_BIN}" shell dpm set-device-owner "${ADMIN}"
"${ADB_BIN}" shell cmd package set-home-activity "${PACKAGE}/.MainActivity"
"${ADB_BIN}" shell am start -n "${PACKAGE}/.MainActivity"
"${ADB_BIN}" shell dpm list-owners
