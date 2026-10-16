#!/usr/bin/env bash
# Shared guards and helpers for the development-device scripts (0.3.0 UI). Source, don't run.
#
#   PV_THROWAWAY_DEVICE=1   required: the phone's wallet holds nothing and may be wiped
#   PV_TEST_PIN=nnnnnn      the current (or, for firstrun.sh, the to-be-set) 6-digit PIN;
#                           prompted for silently if unset; never printed or logged
#   PV_WORDS_FILE=path      a 0600 file holding a THROWAWAY 24-word phrase, one word per line or
#                           space-separated; read by backupcheck/restore scripts, never echoed
#   ADB=/path/to/adb        optional override
#   ANDROID_SERIAL=serial   names the target when more than one device is attached
#   host paths (Python, USB client, pairing file, logs): see env.sh
#
# Every tap is found by the widget's text and live bounds (uiautomator). No coordinates are
# guessed. uiautomator only lists VISIBLE nodes, so scroll before tapping anything below the fold.
set -euo pipefail

A="${ADB:-adb}"
PKG=dev.phonevault.signer
# shellcheck source=env.sh
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

# Recovery-phrase words never reach a log. While a restore/backup flow is typing or checking words
# (PV_SECRET_SCREEN=1, set by type_words / spot_check), every word of WORDS in a failure message is
# masked; texts() withholds the text of any recovery-phrase screen (see SECRET_SCREEN_RE).
die()  {
  local msg="$*" w
  if [[ "${PV_SECRET_SCREEN:-}" == "1" ]]; then
    for w in ${WORDS[@]+"${WORDS[@]}"}; do [[ -n "$w" ]] && msg="${msg//"$w"/[word withheld]}"; done
  fi
  echo "FAIL: $msg" >&2; exit 1
}
pass() { echo "PASS: $*"; }

# Every script that acts on the phone starts here: the phone must be a throwaway AND the only
# possible target (see require_single_device), so nothing ever lands on an ambiguous device.
require_throwaway() {
  [[ "${PV_THROWAWAY_DEVICE:-}" == "1" ]] || die "refusing: set PV_THROWAWAY_DEVICE=1 only for a dev phone whose wallet holds nothing (every wrong PIN counts toward the 10-attempt erase)"
  require_single_device
}

require_dev_appliance() {
  local version
  version="$("$A" shell dumpsys package "$PKG" 2>/dev/null | grep -m1 'versionName=' | tr -d '\r' || true)"
  [[ "$version" == *dev-appliance* ]] || die "installed build is not the dev appliance (${version:-not installed}); these scripts only target it"
  [[ "$version" == *0.3.*dev-appliance* ]] || die "harness targets the 0.3.x UI (installed: $version)"
  # NEVER call `adb root` here. On LineageOS it is gated by the "Rooted debugging" developer
  # toggle (adbroot service), which a fresh /data resets; the refused call is harmless, but
  # chasing it by toggling adb_enabled remotely can disable adb on a kiosk that has no UI to
  # turn it back on.
}

# Exactly one target: either ANDROID_SERIAL names an attached device (adb honours it for every
# call), or exactly one device is on the bus. A second phone (say the owner's real wallet on a
# charger port) must never receive an install, a provisioning reset or a wipe.
require_single_device() {
  local attached
  attached="$("$A" devices 2>/dev/null | awk 'NR>1 && NF>=2 {print $1}')"
  if [[ -n "${ANDROID_SERIAL:-}" ]]; then
    grep -qxF -- "$ANDROID_SERIAL" <<<"$attached" || die "ANDROID_SERIAL=$ANDROID_SERIAL is not attached (attached: $(tr '\n' ' ' <<<"$attached"))"
    return 0
  fi
  [[ "$(grep -c . <<<"$attached" || true)" == "1" ]] || die "refusing: expected exactly one attached device, found [$(tr '\n' ' ' <<<"$attached")]; unplug the others or set ANDROID_SERIAL"
}

# Development images only: a production (user) build is never a deploy/test target.
require_dev_image() {
  local type; type="$("$A" shell getprop ro.build.type 2>/dev/null | tr -d '\r')"
  [[ "$type" == userdebug || "$type" == eng ]] || die "refusing: ro.build.type=${type:-unknown}; these scripts only target userdebug dev images"
}

adb_is_root() { "$A" shell id 2>/dev/null | grep -q "uid=0"; }

require_pin() {
  if [[ -z "${PV_TEST_PIN:-}" ]]; then
    read -r -s -p "Test PIN (6 digits; never logged): " PV_TEST_PIN; echo
  fi
  [[ "$PV_TEST_PIN" =~ ^[0-9]{6}$ ]] || die "PIN must be exactly 6 digits"
}

# A PIN that differs from the test PIN in its first digit (for deliberate wrong entries).
wrong_pin() { printf '%d%s' "$(( (10#${PV_TEST_PIN:0:1} + 1) % 10 ))" "${PV_TEST_PIN:1}"; }

# The throwaway phrase: 12, 15, 18, 21 or 24 lowercase words (firstrun.sh writes 24); the file
# must be private to the caller.
require_words() {
  [[ -n "${PV_WORDS_FILE:-}" && -s "$PV_WORDS_FILE" ]] || die "set PV_WORDS_FILE to a 0600 file holding the THROWAWAY recovery phrase"
  local mode; mode="$(stat -c %a "$PV_WORDS_FILE" 2>/dev/null || stat -f %Lp "$PV_WORDS_FILE")"  # GNU or BSD/macOS
  [[ "$mode" =~ ^[0-7]00$ ]] || die "$PV_WORDS_FILE must be mode 0600 (it is a recovery phrase)"
  mapfile -t WORDS < <(tr -s ' ' '\n' < "$PV_WORDS_FILE" | grep -v '^$')
  [[ "${#WORDS[@]}" =~ ^(12|15|18|21|24)$ ]] || die "words file must hold 12, 15, 18, 21 or 24 words (has ${#WORDS[@]})"
}

# adb drops for a few seconds when the device owner (re)applies USB restrictions or the gadget
# is reset for an accessory switch; wait for it instead of dying on the first failed command.
wait_adb() { local i; for i in $(seq 1 "${1:-24}"); do "$A" get-state >/dev/null 2>&1 && return 0; sleep 5; done; die "adb did not come back"; }
wait_boot() { local i; for i in $(seq 1 "${1:-40}"); do "$A" get-state >/dev/null 2>&1 && [[ "$("$A" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]] && return 0; sleep 5; done; die "device did not finish booting"; }

# /data/local/tmp: /sdcard is not always readable from the shell on a fresh device.
# `|| true`: under pipefail, `uidump | grep -q` would otherwise fail whenever grep exits on the first
# match before adb has written the whole dump (adb dies of SIGPIPE → 141 → "not on screen").
uidump() { "$A" shell "rm -f /data/local/tmp/ui.xml; uiautomator dump /data/local/tmp/ui.xml" >/dev/null 2>&1; "$A" exec-out cat /data/local/tmp/ui.xml || true; }
# Page kickers/titles of the screens that show (or take) recovery-phrase words: restore entry and
# confirm, the phrase pages (incl. a not-yet-active replacement's), SeedQR, and the backup spot check.
SECRET_SCREEN_RE='text="[^"]*(RESTORE|RECOVERY PHRASE|BACKUP CHECK|NEW WALLET · NOT ACTIVE|SEEDQR)'
SECRET_SCREEN_PLACEHOLDER='[screen text withheld: recovery-phrase screen]'
# The first $1 (default 6) texts on screen, for failure messages; a placeholder instead on any
# recovery-phrase screen or while PV_SECRET_SCREEN=1.
texts()  {
  local dump
  if [[ "${PV_SECRET_SCREEN:-}" == "1" ]]; then echo "$SECRET_SCREEN_PLACEHOLDER"; return 0; fi
  dump="$(uidump)"
  if grep -qE "$SECRET_SCREEN_RE" <<<"$dump"; then echo "$SECRET_SCREEN_PLACEHOLDER"; return 0; fi
  grep -o 'text="[^"]\{1,70\}"' <<<"$dump" | sed 's/^text=//; s/"//g' | grep -vE '^[0-9⌫a-z]$' | head -"${1:-6}" | tr '\n' '|' || true
}
has_text() { uidump | grep -q "text=\"$1"; }
expect_screen() { has_text "$1" || die "expected '$1' on screen, saw: $(texts)"; }
expect_not()    { has_text "$1" && die "did not expect '$1' on screen: $(texts)"; return 0; }
# Scroll down (up to 6 swipes) until a widget whose text starts with $1 is visible; a page that is
# rebuilt after a tap starts at the top again, so anything below the fold needs this.
find_text() { local i; for i in 1 2 3 4 5 6; do has_text "$1" && return 0; scroll_down; sleep 0.8; done; has_text "$1"; }
expect_below()  { find_text "$1" || die "expected '$1' on screen (scrolled), saw: $(texts 10)"; }

# Bounds "x1 y1 x2 y2" of the first visible widget whose text matches exactly (XML-escaped: use
# &amp; for '&'). Empty when not visible.
bounds_of() {
  uidump | grep -o -i "text=\"$1\"[^>]*bounds=\"\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]\"" | head -1 \
    | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/' || true
}
tap_bounds() { local x1 y1 x2 y2; read -r x1 y1 x2 y2 <<<"$1"; "$A" shell input tap $(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 )) </dev/null; }
# Tap a widget by exact text; scrolls down once and retries if it is below the fold.
tap_text() {
  local b; b="$(bounds_of "$1")"
  if [[ -z "$b" ]]; then scroll_down; sleep 0.8; b="$(bounds_of "$1")"; fi
  [[ -n "$b" ]] || die "button '$1' not found on screen: $(texts)"
  tap_bounds "$b"
}
scroll_down() { "$A" shell input swipe 720 2300 720 700 350 </dev/null; }
scroll_top()  { "$A" shell input swipe 720 700 720 2300 350 </dev/null; sleep 0.5; "$A" shell input swipe 720 700 720 2300 350 </dev/null; }
# Optional review screenshots for visual QA: with PV_QA_SHOTS set to a directory, save the
# current screen and each page below it as <name>-<n>.png (dev builds allow screenshots).
qa_shots() {
  [[ -n "${PV_QA_SHOTS:-}" ]] || return 0
  mkdir -p "$PV_QA_SHOTS"; local n
  for n in 1 2 3 4 5 6; do
    "$A" exec-out screencap -p > "$PV_QA_SHOTS/$1-$n.png"
    has_text "Reject request" && [[ $n -gt 1 ]] && break
    scroll_down; sleep 0.8
  done
  scroll_top
}

# Bounds of the first visible UNticked checkbox (empty when none is visible).
unticked_box() {
  uidump | grep -o 'checkable="true" checked="false"[^>]*bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' | head -1 \
    | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/' || true
}
# Ready a review for Approve: scroll to its END (Approve stays disabled until the bottom of the
# review has been on screen), then tick every review checkbox — "I verified…" and, on a review with
# a DANGER row, the second "I understand: …" box above it. Returns 1 if no box was ticked or one is
# still unticked. The caller then taps the Approve button by its text.
tick_review() {
  local i b n=0
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do has_text "Reject request" && break; scroll_down; sleep 0.6; done
  scroll_down; sleep 0.8   # the very bottom, below Reject
  for i in 1 2 3; do
    b="$(unticked_box)"; [[ -n "$b" ]] || break
    tap_bounds "$b"; sleep 0.8; n=$((n + 1))
  done
  if [[ $n -lt 2 ]]; then  # the danger box may sit just above the fold on a small screen: look once higher
    "$A" shell input swipe 720 1200 720 1700 300 </dev/null; sleep 0.8
    b="$(unticked_box)"; [[ -n "$b" ]] && { tap_bounds "$b"; sleep 0.8; n=$((n + 1)); }
    scroll_down; sleep 0.8
  fi
  [[ $n -gt 0 ]] || return 1
  [[ -z "$(unticked_box)" ]]
}
# An EVM address as the phone shows it: "0x51dd 9Afd 5f32 …" (0x + groups of four, case kept).
evm_grouped() { local a="${1#0x}"; printf '0x%s' "${a:0:4}"; local i; for (( i = 4; i < ${#a}; i += 4 )); do printf ' %s' "${a:$i:4}"; done; }

# Digits are buttons whose text is the digit itself (PinScreen); `⌫` is backspace.
tap_digits() { local i; for (( i = 0; i < ${#1}; i++ )); do tap_text "${1:$i:1}"; sleep 0.2; done; }
clear_entry() { local i b; b="$(bounds_of "⌫")"; [[ -n "$b" ]] || return 0; for i in 1 2 3 4 5 6; do tap_bounds "$b"; sleep 0.15; done; }

# The first 0x address on screen, ungrouped: the phone shows "0x51dd 9Afd …" in groups of four and
# the home card breaks it into two lines (the dump encodes the break as &#10;).
addr() { uidump | grep -o 'text="0x[0-9a-fA-F &#;]*' | head -1 | sed 's/^text="//; s/&#10;//g; s/ //g' || true; }

wake()   { "$A" shell svc power stayon usb; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 2; nudge; }  # nudge: a dim screen about to time out must not lock mid-start
unwake() { "$A" shell svc power stayon false; }
# Screen off → onStop locks the vault.
# Credential mode shows our "Phone Vault is locked" page and then the system PIN prompt; app-PIN mode "LOCKED".
relock() { "$A" shell input keyevent KEYCODE_SLEEP; sleep 2; "$A" shell input keyevent KEYCODE_WAKEUP; sleep 3; local i; for i in 1 2 3 4 5; do locked_now && return 0; sleep 1.5; done; die "expected a locked vault after screen-off, saw: $(texts)"; }
# Credential mode: the vault PIN is the device PIN and the system shows its own PIN prompt
# (window "BiometricPrompt", secure: uiautomator cannot read it, so we key the PIN in blind).
focus_window() { "$A" shell dumpsys window | grep -oE "mCurrentFocus=Window\{[^}]*\}" | head -1 | sed 's/.* u0 //; s/}//' || true; }
# The system PIN prompt: its window is named BiometricPrompt on most builds; on some it is drawn
# readable, with the title "Enter your PIN to unlock", and the focus name differs.
system_prompt_up() { [[ "$(focus_window)" == "BiometricPrompt" ]] || uidump | grep -q 'text="Enter your PIN to unlock'; }
enter_system_pin() {
  local i; for i in $(seq 1 12); do system_prompt_up && break; sleep 1; done
  system_prompt_up || return 1
  "$A" shell input text "$PV_TEST_PIN" </dev/null; "$A" shell input keyevent KEYCODE_ENTER </dev/null; sleep 7
}
locked_now() { system_prompt_up || has_text LOCKED || has_text "Phone Vault is locked"; }
unlock() {
  locked_now || die "expected a locked vault, saw: $(texts)"
  if system_prompt_up || has_text "Phone Vault is locked"; then
    system_prompt_up || tap_text "Unlock"; enter_system_pin || die "system PIN prompt did not appear"
  else
    tap_digits "$PV_TEST_PIN"; sleep 6
  fi
  expect_screen "PHONE VAULT"; expect_not LOCKED
}
unlock_if_locked() {
  # The locked page opens the system PIN prompt a moment after it appears; let it settle so a
  # lock that is still being drawn is not mistaken for "unlocked".
  # One dump per probe: uiautomator dumps take seconds here, and this wait touches nothing, so it
  # spends the vault's idle-lock budget (see go_home).
  local i; for i in 1 2 3 4; do system_prompt_up && break; uidump | grep -q -e 'text="Phone Vault is locked' -e 'text="LOCKED' && break; sleep 1; done
  if system_prompt_up || has_text "Phone Vault is locked"; then system_prompt_up || tap_text "Unlock"; enter_system_pin || die "system PIN prompt did not appear"
  elif has_text LOCKED; then clear_entry; tap_digits "$PV_TEST_PIN"; sleep 6; expect_not LOCKED; fi
}
# Navigation is a ☰ header menu (0.3.x): open it, then pick a section. Screens without the menu
# (PIN gate, sensitive flows, approvals) are left alone; callers assert what they expect.
# Right after an unlock the wallet is still loading ("Opening Phone Vault", no menu): give it a few s.
open_menu() {
  system_prompt_up && { enter_system_pin || true; }
  local b i; for i in 1 2 3 4 5; do b="$(bounds_of "☰")"; [[ -n "$b" ]] && break; [[ $i -eq 2 ]] && scroll_top; sleep 1.5; done
  [[ -n "$b" ]] || return 1; tap_bounds "$b"; sleep 1.2; has_text "Where to?"
}
go_section() { # go_section "Wallet" | "Security" | "Display &amp; auto-lock" | "Device information" | "Coming next"
  local b; b="$(bounds_of "Back to Security")"; [[ -n "$b" ]] && { tap_bounds "$b"; sleep 1.2; }
  open_menu || return 1; tap_text "$1"; sleep 1.5
}
# Always ends with a touch: the vault's idle lock (2 min) counts only user interaction, and the
# USB steps after go_home (gadget reset, AOA switch, adb restart, lock-settle probes) touch nothing.
go_home() {
  if has_text "Your offline wallet" || has_text "Back up your wallet"; then scroll_top; return 0; fi
  go_section "Wallet" || true; return 0
}
go_security() { has_text "DEVICE &amp; WALLET" && return 0; go_section "Security"; }

# Switching accounts derives from the seed: the system PIN prompt may appear (seed-key window).
pin_if_asked() { sleep 2; if system_prompt_up; then enter_system_pin; fi; sleep 3; }
# The host pairing (usbsigntest.sh) pins Account 1 of the standard wallet, so every script that
# signs or asks for the address must start with it active; a script that switches accounts
# (accountstest.sh) restores it on exit. ☰ → Accounts; closes an open passphrase wallet first.
ensure_account1() {
  unlock_if_locked
  local l b; for l in "Back to Wallet" "Continue"; do  # a receipt or notice left by a failed step
    has_text "☰" && break; b="$(bounds_of "$l")"; [[ -n "$b" ]] && { tap_bounds "$b"; sleep 1.2; }
  done
  go_section "Accounts" || { unlock_if_locked; go_section "Accounts"; } || die "menu did not open: $(texts 8) (focus $(focus_window))"
  if has_text "Passphrase wallet accounts"; then
    go_section "Passphrase wallet · open" || die "menu did not open"
    tap_text "Close · back to standard wallet"; sleep 2
    go_section "Accounts" || { unlock_if_locked; go_section "Accounts"; } || die "menu did not open: $(texts 8) (focus $(focus_window))"
  fi
  expect_screen "Your accounts"
  if ! has_text "● Account 1 · "; then
    local b; b="$(bounds_of 'Account 1 · [^"]*')"
    if [[ -z "$b" ]]; then  # hidden (only possible while another account is active)
      tap_text 'Hidden accounts ([0-9]*)'; sleep 1.2; b="$(bounds_of 'Account 1 · [^"]*')"
    fi
    [[ -n "$b" ]] || die "Account 1 not found in the accounts list: $(texts 10)"
    tap_bounds "$b"; sleep 1.2
    tap_text "Use this account"; pin_if_asked
    go_section "Accounts" || { unlock_if_locked; go_section "Accounts"; } || die "menu did not open: $(texts 8) (focus $(focus_window))"
    has_text "● Account 1 · " || die "could not make Account 1 active: $(texts 10)"
    echo "  (switched the phone back to Account 1)"
  fi
  go_home
}

# Answer the 3-word spot check ("Find word N") from WORDS, then confirm the account.
spot_check() {
  local i n PV_SECRET_SCREEN=1
  for i in 1 2 3; do
    n="$(uidump | grep -o 'Find word [0-9]*' | head -1 | awk '{print $3}' || true)"
    [[ -n "$n" ]] || die "no spot-check challenge on screen at round $i: $(texts)"
    tap_text "${WORDS[$((n - 1))]}"; sleep 1.2
  done
  expect_screen "3 OF 3 WORDS CHECKED"
}

# Type every word of WORDS on the on-device restore keyboard (letters by live key bounds, word by text).
type_words() {
  declare -A K; local l x1 y1 x2 y2 w i PV_SECRET_SCREEN=1
  while read -r l x1 y1 x2 y2; do K[$l]="$(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 ))"; done \
    < <(uidump | grep -o 'text="[a-z⌫]"[^>]*bounds="[^"]*"' | sed -E 's/text="(.)".*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]"/\1 \2 \3 \4 \5/')
  [[ ${#K[@]} -ge 26 ]] || die "restore keyboard not fully visible (${#K[@]} keys)"
  for w in "${WORDS[@]}"; do
    # shellcheck disable=SC2086
    for (( i = 0; i < ${#w}; i++ )); do "$A" shell input tap ${K[${w:$i:1}]} </dev/null; sleep 0.25; done
    sleep 0.6; tap_text "$w"; sleep 0.5
  done
}

# Only OUR process counts: the dev image still ships vendor apps that crash for lack of GSF.
no_crashes() { [[ "$("$A" logcat -d -s AndroidRuntime:E | grep -A1 FATAL | grep -c "Process: $PKG" || true)" == "0" ]] || die "app crashed (see logcat AndroidRuntime:E)"; }
kiosk_locked() { "$A" shell dumpsys activity activities | grep -q 'mLockTaskModeState=LOCKED' || die "kiosk is not LOCKED"; }

# USB: the app opens an accessory transport only on a FRESH ACCESSORY_ATTACHED. Reset the gadget
# to plain adb so the host's AOA switch produces one; the host adb server must be down during the
# switch (it holds the device), and comes back once the phone is in accessory+adb mode.
usb_reset() { nudge; "$A" shell svc usb setFunctions >/dev/null 2>&1 || true; sleep 6; wait_adb 12; }
# A touch on the header title (a plain label on every page, the locked page included): it does
# nothing but restart the vault's idle lock. The default 1-minute screen timeout caps the idle lock
# at 1 minute, and a getAddress + the next request's gadget reset, adb restart and lock-settle
# probes touch nothing for about that long: the vault then locked between two steps (and a lock
# forgets an open passphrase wallet, by design).
# Never while the system PIN prompt is up: a tap outside it could cancel it.
nudge() { system_prompt_up && return 0; local b; b="$(bounds_of "PHONE VAULT")"; [[ -n "$b" ]] && tap_bounds "$b"; return 0; }
