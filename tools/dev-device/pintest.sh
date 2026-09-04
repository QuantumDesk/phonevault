#!/bin/bash
# Drive the PIN flow with taps and capture a dump after each step.
A=/root/android-sdk/platform-tools/adb
DUMP=/data/data/dev.phonevault.signer/files/vault_dump.png
declare -A K=([1]="300 1971" [2]="719 1971" [3]="1138 1971" [4]="300 2223" [5]="719 2223" [6]="1138 2223" [7]="300 2475" [8]="719 2475" [9]="1138 2475" [b]="300 2726" [0]="719 2726")
tap(){ for d in $(echo "$1" | sed "s/./& /g"); do $A shell input tap ${K[$d]}; sleep 0.35; done; }
snap(){ sleep ${2:-2.5}; $A exec-out cat $DUMP > /root/shots/$1.png; echo "$1 $(stat -c%s /root/shots/$1.png)B"; }
mkdir -p /root/shots
$A root >/dev/null 2>&1; sleep 1
tap 123;            snap 01_partial
tap 456;            snap 02_confirm
tap 123457;         snap 03_mismatch 3
tap 123456; sleep 1; tap 123456; snap 04_home 5
$A shell input keyevent KEYCODE_SLEEP; sleep 2; $A shell input keyevent KEYCODE_WAKEUP; sleep 1
$A shell input tap 700 1500;  snap 05_locked
tap 999999;         snap 06_wrong 4
tap 123456;         snap 07_unlocked 5
$A shell dumpsys activity activities | grep -E "mLockTaskModeState|mResumedActivity" | head -2
$A shell settings get system screen_off_timeout
$A logcat -d -s Vault VaultDump | tail -8
