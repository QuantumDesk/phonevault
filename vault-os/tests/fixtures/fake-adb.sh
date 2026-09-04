#!/usr/bin/env bash
set -euo pipefail

mode="${PHONEVAULT_FAKE_ADB_MODE:-positive}"
if [[ "${1:-}" == version ]]; then
  echo 'Android Debug Bridge version 1.0.41'
  exit 0
fi
[[ "${1:-}" == -s && "${2:-}" == TESTSERIAL ]] || exit 2
shift 2
if [[ "${1:-}" == get-state ]]; then
  echo device
  exit 0
fi
if [[ "${1:-}" == exec-out && "${2:-}" == cat \
    && "${3:-}" == /system/app/PhoneVault/PhoneVault.apk ]]; then
  printf 'fixture-apk\n'
  exit 0
fi
[[ "${1:-}" == shell ]] || exit 2
shift

case "${1:-}" in
  getprop)
    if [[ $# -eq 1 ]]; then
      cat <<'EOF'
[ro.product.device]: [crosshatch]
[ro.product.brand]: [PhoneVault]
[ro.phonevault.offline]: [true]
[ro.vendor.phonevault.offline]: [true]
[ro.radio.noril]: [true]
[ro.secure]: [1]
[ro.adb.secure]: [1]
[ro.debuggable]: [1]
[ro.build.type]: [userdebug]
[ro.boot.veritymode]: [enforcing]
[ro.boot.vbmeta.digest]: [aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]
[ro.boot.verifiedbootstate]: [orange]
[ro.boot.flash.locked]: [0]
[ro.boot.vbmeta.device_state]: [unlocked]
EOF
      exit 0
    fi
    case "$2" in
      ro.product.device) echo crosshatch ;;
      ro.product.brand) echo PhoneVault ;;
      ro.phonevault.offline|ro.vendor.phonevault.offline|ro.radio.noril) echo true ;;
      ro.secure|ro.adb.secure|ro.debuggable) echo 1 ;;
      ro.build.type) echo userdebug ;;
      ro.boot.veritymode) echo enforcing ;;
      ro.boot.vbmeta.digest) printf '%064d\n' 0 | tr 0 a ;;
      ro.boot.verifiedbootstate) echo orange ;;
      ro.boot.flash.locked) echo 0 ;;
      ro.boot.vbmeta.device_state) echo unlocked ;;
      sys.usb.config|sys.usb.state) echo accessory,adb ;;
      *) exit 1 ;;
    esac
    ;;
  ps)
    printf 'USER PID NAME\nroot 1 init\nsystem 2 system_server\n'
    ;;
  service)
    echo '0 activity: [android.app.IActivityManager]'
    ;;
  dumpsys)
    case "${2:-}" in
      package)
        echo 'codePath=/system/app/PhoneVault'
        ;;
      activity)
        if [[ "${mode}" == not-locked ]]; then
          printf '  mLockTaskModeState=NONE\n  mLockTaskPackages (userId:packages)=\n'
        else
          printf '  mResumedActivity: dev.phonevault.signer/.MainActivity\n'
          printf '  mLockTaskModeState=LOCKED\n'
          printf '  mLockTaskPackages (userId:packages)=\n'
          printf '    u0:[dev.phonevault.signer]\n'
        fi
        ;;
      usb)
        echo 'USB fixture'
        ;;
      *) exit 2 ;;
    esac
    ;;
  dpm)
    [[ "${2:-}" == list-owners ]] || exit 2
    case "${mode}" in
      profile-owner)
        printf '1 owner:\nUser  0: admin=dev.phonevault.signer/.VaultDeviceAdminReceiver,ProfileOwner\n'
        ;;
      extra-owner)
        printf '2 owners:\nUser  0: admin=dev.phonevault.signer/.VaultDeviceAdminReceiver,DeviceOwner,Affiliated\nUser 10: admin=other/.Admin,ProfileOwner\n'
        ;;
      *)
        printf '1 owner:\nUser  0: admin=dev.phonevault.signer/.VaultDeviceAdminReceiver,DeviceOwner,Affiliated\n'
        ;;
    esac
    ;;
  cmd)
    [[ "${2:-}" == package && "${3:-}" == resolve-activity ]] || exit 2
    if [[ "${mode}" == wrong-home ]]; then
      echo 'other.launcher/.Home'
    else
      echo 'dev.phonevault.signer/.MainActivity'
    fi
    ;;
  pm)
    [[ "${2:-}" == list && "${3:-}" == features ]] || exit 2
    echo 'feature:android.hardware.usb.accessory'
    ;;
  settings)
    [[ "${2:-}" == get ]] || exit 2
    if [[ "${mode}" == setup-incomplete ]]; then
      echo 0
    else
      echo 1
    fi
    ;;
  getenforce)
    echo Enforcing
    ;;
  *)
    # The audit sends two fixed Android-shell snippets for network interfaces
    # and remote subsystems as one argument after `shell`.
    if [[ "${1:-}" == *'/sys/class/net/'* ]]; then
      echo lo
    elif [[ "${1:-}" == *'/sys/bus/msm_subsys/devices/'* ]]; then
      :
    else
      exit 2
    fi
    ;;
esac
