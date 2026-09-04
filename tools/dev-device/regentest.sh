#!/bin/bash
# Tier-0 device test: PIN unlock, then two-phase regenerate (cancel path, then activate path).
A=/root/android-sdk/platform-tools/adb
DUMP=/data/data/dev.phonevault.signer/files/vault_dump.png
declare -A K=([1]="300 1971" [2]="719 1971" [3]="1138 1971" [4]="300 2223" [5]="719 2223" [6]="1138 2223" [7]="300 2475" [8]="719 2475" [9]="1138 2475" [b]="300 2726" [0]="719 2726")
tap(){ for d in $(echo "$1" | sed "s/./& /g"); do $A shell input tap ${K[$d]}; sleep 0.35; done; }
snap(){ sleep ${2:-4}; $A exec-out cat $DUMP > /root/shots/$1.png; echo "$1 $(stat -c%s /root/shots/$1.png)B"; }
uidump(){ $A shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; $A exec-out cat /sdcard/ui.xml > /root/ui.xml; }
texts(){ uidump; grep -o "text=\"[^\"]\{1,40\}\"" /root/ui.xml | grep -v "text=\"\"" | tr "\n" " " | cut -c1-400; echo; }
tapText(){ uidump
  b=$(grep -o -i "text=\"$1\"[^>]*bounds=\"\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]\"" /root/ui.xml | head -1 | sed -E "s/.*bounds=\"\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]\".*/\1 \2 \3 \4/")
  if [ -z "$b" ]; then echo "NOT FOUND: $1"; return 1; fi
  read x1 y1 x2 y2 <<<"$b"; $A shell input tap $(( (x1+x2)/2 )) $(( (y1+y2)/2 )); echo "tapped [$1] @ $(( (x1+x2)/2 )),$(( (y1+y2)/2 ))"; }
addr(){ uidump; grep -o "text=\"0x[0-9a-fA-F]*" /root/ui.xml | head -1 | cut -c7-; }
mkdir -p /root/shots; $A root >/dev/null 2>&1; sleep 1; $A shell svc power stayon usb; $A shell input keyevent KEYCODE_WAKEUP; sleep 1
$A shell input tap 700 1200; sleep 1
echo "screen: $(texts)"
snap 20_gate 1
tap 123456; sleep 5
echo "screen: $(texts)"
snap 21_unlocked 1
A0=$(addr); echo "ADDR BEFORE: $A0"
tapText "Regenerate wallet"; sleep 1.5; echo "screen: $(texts)"; tapText "Continue"; snap 22_new_phrase 5
echo "screen: $(texts)"
tapText "Cancel · keep current wallet"; snap 23_after_cancel 3
A1=$(addr); echo "ADDR AFTER CANCEL: $A1  (same as before: $([ "$A0" = "$A1" ] && echo YES || echo NO))"
tapText "Regenerate wallet"; sleep 1.5; tapText "Continue"; sleep 5; tapText "Activate new wallet"; snap 24_after_activate 5
A2=$(addr); echo "ADDR AFTER ACTIVATE: $A2  (changed: $([ "$A0" != "$A2" ] && echo YES || echo NO))"
$A shell input keyevent KEYCODE_SLEEP; sleep 2; $A shell input keyevent KEYCODE_WAKEUP; sleep 2; $A shell input tap 700 1200; sleep 1
echo "after sleep/wake: $(texts)"
tap 123456; sleep 5; A3=$(addr); echo "ADDR AFTER RELOCK+UNLOCK: $A3  (persisted new wallet: $([ "$A2" = "$A3" ] && echo YES || echo NO))"
$A shell dumpsys activity activities | grep -E "mLockTaskModeState" | head -1
$A logcat -d -s Vault:* VaultDump:* AndroidRuntime:E | tail -8
