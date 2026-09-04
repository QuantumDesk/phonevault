#!/bin/bash
# Navigate Home -> "Recovery phrase" -> "Show" and pull the app-rendered dump of the seed screen.
# Finds buttons by text via uiautomator so it survives layout changes.
tapText() {
  adb shell "uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; cat /sdcard/ui.xml" 2>/dev/null \
    | grep -oE "text=\"$1\"[^>]*bounds=\"\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]\"" | head -1 \
    | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/' \
    | awk '{printf "%d %d\n", ($1+$3)/2, ($2+$4)/2}'
}
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1; sleep 1
adb shell am start -n dev.phonevault.signer/.MainActivity >/dev/null 2>&1; sleep 3
c=$(tapText "Recovery phrase"); [ -z "$c" ] && { echo "NO_RECOVERY_BUTTON"; exit 1; }
adb shell input tap $c; sleep 2
c=$(tapText "Show"); [ -z "$c" ] && { echo "NO_SHOW_BUTTON"; exit 1; }
adb shell input tap $c; sleep 3
adb root >/dev/null 2>&1; sleep 1
adb shell cat /data/data/dev.phonevault.signer/files/vault_dump.png > /root/backup.png 2>/dev/null
echo "BACKUP_BYTES=$(stat -c%s /root/backup.png 2>/dev/null)"
# return to home so the seed isn't left on screen
c=$(tapText "Hide phrase"); [ -n "$c" ] && adb shell input tap $c
