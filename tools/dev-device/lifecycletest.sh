#!/bin/bash
# Re-audit round 2 device checks: stop-during-PIN-verify race, normal unlock, reveal, wrong PIN.
A=/root/android-sdk/platform-tools/adb
declare -A K=([1]="300 1971" [2]="719 1971" [3]="1138 1971" [4]="300 2223" [5]="719 2223" [6]="1138 2223" [7]="300 2475" [8]="719 2475" [9]="1138 2475" [b]="300 2726" [0]="719 2726")
tap(){ for d in $(echo "$1" | sed "s/./& /g"); do $A shell input tap ${K[$d]}; sleep 0.3; done; }
uidump(){ $A shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; $A exec-out cat /sdcard/ui.xml > /root/ui.xml; }
texts(){ uidump; grep -o "text=\"[^\"]\{1,32\}\"" /root/ui.xml | grep -v "text=\"\"" | head -${1:-5} | tr "\n" " "; echo; }
tapText(){ uidump; b=$(grep -o -i "text=\"$1\"[^>]*bounds=\"\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]\"" /root/ui.xml | head -1 | sed -E "s/.*bounds=\"\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]\".*/\1 \2 \3 \4/"); [ -z "$b" ] && { echo "NOT FOUND: $1"; return 1; }; read x1 y1 x2 y2 <<<"$b"; $A shell input tap $(( (x1+x2)/2 )) $(( (y1+y2)/2 )); echo "tapped [$1]"; }
addr(){ uidump; grep -o "text=\"0x[0-9a-fA-F]*" /root/ui.xml | head -1 | cut -c7-; }
$A root >/dev/null 2>&1; sleep 1; $A shell svc power stayon usb; $A shell input keyevent KEYCODE_WAKEUP; sleep 1; $A logcat -c
echo "== start: $(texts 3)"
echo "== RACE: 6th digit then immediate SLEEP while PBKDF2 runs"
tap 12345; $A shell "input tap ${K[6]}; input keyevent KEYCODE_SLEEP"; sleep 3
$A shell input keyevent KEYCODE_WAKEUP; sleep 2; $A shell input tap 700 1200; sleep 1.5
echo "== after wake: $(texts 3)"
echo "== creds published while hidden? (Vault log):"; $A logcat -d -s Vault:* | grep -E "refused|discarded|Vault" | tail -4
echo "== NORMAL unlock"; tap 123456; sleep 6; echo "== $(texts 4)"; echo "ADDR: $(addr)"
echo "== REVEAL"; tapText "Recovery phrase"; sleep 1.5; echo "== dialog: $(texts 4)"; tapText "Show" || tapText "Reveal"; sleep 4; echo "== $(texts 4)"; tapText "Hide phrase"; sleep 2; echo "== $(texts 3)"
echo "== LOCK via sleep, WRONG then RIGHT"; $A shell input keyevent KEYCODE_SLEEP; sleep 2; $A shell input keyevent KEYCODE_WAKEUP; sleep 2; $A shell input tap 700 1200; sleep 1
tap 999999; sleep 4; echo "== $(texts 4)"; tap 123456; sleep 6; echo "== $(texts 3)"; echo "ADDR: $(addr)"
$A shell dumpsys activity activities | grep -E "mLockTaskModeState" | head -1
$A logcat -d -s AndroidRuntime:E | grep -c FATAL
$A shell svc power stayon false
