#!/usr/bin/env bash
# Migration support on a THROWAWAY dev phone, WITHOUT changing its wallet (no restore, no wipe):
#   1. getAddress names Account 1 with Standard numbering (no "scheme" field)
#   2. list-addresses standard 5: "Share 5 addresses with your Mac?" lists them; Share → 5 EIP-55
#      addresses, Account 1 == the getAddress address (and the pinned pairing, if any)
#   3. list-addresses ledger-live 3 → Don't share → a clean "rejected" (exit 2)
#   4. list-addresses ledger-live 5 → Share: Account 1 is the same, Account 2 differs from Standard's
#   5. ☰ → Accounts → Account numbering → Switch to Ledger Live: the check screen shows Account 2 at
#      m/44'/60'/1'/0/0 with the address step 4 listed; confirm → getAddress says "scheme":
#      "ledger-live", Account 1 unchanged; Device information shows the numbering
#   6. add (or reuse) Account 2 under Ledger Live: getAddress account "2" == Ledger Live #2
#   7. relock + unlock: still Ledger Live, Account 2 (the setting survives a relock)
#   8. switch back to Standard: getAddress has no "scheme" and is Account 1 again
# Rerunnable, and the phone is ALWAYS left on Standard numbering, Account 1 (EXIT trap), which the
# host pairing of the other scripts pins. Nothing is signed or broadcast.
#
# Needs PV_HOST_PY (venv python with pyusb) and PV_HOST_CLIENT (tools/aoa_client.py with list-addresses).
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
wake
pid=""
OUT="${PV_MIGRATION_OUT:-$PV_LOG_DIR/migrationtest}"
[[ -x "$PY" && -s "$CLIENT" ]] || die "host client not staged ($PY / $CLIENT)"

field() { "$PY" -c 'import json,sys; t=open(sys.argv[1]).read(); d=json.loads(t[:t.rindex("}")+1]); print(d.get(sys.argv[2], ""), end="")' "$1" "$2"; }
addr_n() { "$PY" -c 'import json,sys; t=open(sys.argv[1]).read(); d=json.loads(t[:t.rindex("}")+1]); print(d["addresses"].split(",")[int(sys.argv[2])], end="")' "$1" "$2"; }

ask() { # ask <name> <client args…>: one exchange in the foreground (getAddress needs no tap)
  local name="$1"; shift
  usb_reset; unlock_if_locked; go_home
  "$A" kill-server; sleep 1
  "$PY" "$CLIENT" "$@" > "$OUT.$name" 2>&1 || true
  sleep 4; "$A" start-server >/dev/null 2>&1; wait_adb 12; nudge; unlock_if_locked
}
start_request() { # in the background (the share screen needs a tap), sets $pid
  local name="$1"; shift
  usb_reset; unlock_if_locked; go_home
  "$A" kill-server; sleep 1
  "$PY" "$CLIENT" "$@" > "$OUT.$name" 2>&1 &
  pid=$!
  sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked
}
wait_share() { # the share screen is up (a PIN prompt for the seed key may come first)
  local name="$1"
  for _ in $(seq 1 25); do
    sleep 2; kill -0 "$pid" 2>/dev/null || break
    system_prompt_up && { enter_system_pin; continue; }
    has_text "Share [0-9]* address" && return 0
  done
  kill "$pid" 2>/dev/null || true; die "$name: no share screen: $(texts 10)"
}
finish() { # finish <name> <button> <expected exit>
  local name="$1" button="$2" want="$3" rc=0
  find_text "$button" || { kill "$pid" 2>/dev/null || true; die "$name: no '$button' button: $(texts 10)"; }
  tap_text "$button"; sleep 2
  wait "$pid" || rc=$?
  pid=""
  [[ $rc -eq $want ]] || { tail -5 "$OUT.$name"; die "$name: client exit $rc, expected $want"; }
}
go_accounts() { go_section "Accounts" || die "menu did not open"; expect_screen "Your accounts"; }

# set_numbering standard|ledger-live: ☰ → Accounts → Account numbering → switch if needed
set_numbering() {
  local want="$1" label other
  if [[ "$want" == "standard" ]]; then label="Standard"; other="Ledger Live"; else label="Ledger Live"; other="Standard"; fi
  unlock_if_locked
  go_accounts
  find_text "Account numbering · " || die "no Account numbering entry: $(texts 12)"
  has_text "Account numbering · ${label}" && { go_home; return 0; }
  tap_text "Account numbering · ${other}"; sleep 1.2
  expect_screen "Account numbering"
  tap_text "Switch to ${label} numbering"; pin_if_asked
  expect_screen "Switch to ${label} numbering?"
  CHECK_SCREEN="$(uidump)"
  tap_text "Switch to ${label} numbering"; pin_if_asked
  sleep 2; go_accounts
  find_text "Account numbering · ${label}" || die "numbering did not switch to ${label}: $(texts 12)"
  go_home
}

restore_standard() {
  local rc=$?
  trap - EXIT
  [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  [[ $rc -eq 0 ]] || echo "  (restoring Standard numbering and Account 1 after the failure)"
  ensure_account1
  set_numbering standard
  ensure_account1
  unwake
  exit $rc
}
trap restore_standard EXIT

# An earlier failed run may have left Ledger Live on (the EXIT trap of this run fixes it too).
ensure_account1
set_numbering standard
ensure_account1

echo "== 1. getAddress: Account 1, Standard numbering"
ask a1 address
[[ "$(field "$OUT.a1" account)" == "1" && "$(field "$OUT.a1" wallet)" == "standard" ]] || { cat "$OUT.a1"; die "getAddress did not name Account 1 / standard"; }
[[ -z "$(field "$OUT.a1" scheme)" ]] || { cat "$OUT.a1"; die "Standard numbering must not send a scheme"; }
A1="$(field "$OUT.a1" address)"
pass "account 1: $A1 (Standard)"

echo "== 2. share 5 Standard addresses"
start_request std list-addresses --scheme standard --count 5 --expect-first "$A1"
wait_share std
expect_screen "Share 5 addresses with your Mac?"
find_text "Account 2 · m/44&apos;/60&apos;/0&apos;/0/1" || find_text "Account 2 · m/44'/60'/0'/0/1" || die "std: Account 2 path not shown: $(texts 12)"
scroll_top
finish std "Share with your Mac" 0
grep -q '"status": "ok"' "$OUT.std" || { cat "$OUT.std"; die "std: not ok"; }
S1="$(addr_n "$OUT.std" 1)"
[[ "$(addr_n "$OUT.std" 0 | tr 'A-F' 'a-f')" == "${A1,,}" ]] || die "std: Account 1 differs from getAddress"
pass "5 Standard addresses shared; Account 2 = $S1"

echo "== 3. decline"
start_request no list-addresses --scheme ledger-live --count 3 --expect-first "$A1"
wait_share no
expect_screen "Share 3 addresses with your Mac?"
finish no "Don't share" 2
grep -q '"status": "rejected"' "$OUT.no" || { cat "$OUT.no"; die "decline: not a clean rejection"; }
pass "declined: nothing shared"

echo "== 4. share 5 Ledger Live addresses"
start_request ll list-addresses --scheme ledger-live --count 5 --expect-first "$A1"
wait_share ll
find_text "Ledger Live" || die "ll: numbering not named on the share screen"
scroll_top
finish ll "Share with your Mac" 0
L1="$(addr_n "$OUT.ll" 1)"
[[ "$(addr_n "$OUT.ll" 0 | tr 'A-F' 'a-f')" == "${A1,,}" ]] || die "ll: Account 1 is not the same under Ledger Live numbering"
[[ "${L1,,}" != "${S1,,}" ]] || die "ll: Ledger Live Account 2 equals Standard Account 2"
pass "5 Ledger Live addresses shared; Account 2 = $L1"

echo "== 5. switch to Ledger Live numbering"
set_numbering ledger-live
grep -qF "m/44&apos;/60&apos;/1&apos;/0/0" <<<"$CHECK_SCREEN" || die "the check screen did not show Account 2's Ledger Live path"
tr -d ' ' <<<"$CHECK_SCREEN" | grep -qiF "${L1#0x}" || die "the check screen did not show Ledger Live Account 2 ($L1)"
ask ll1 address
[[ "$(field "$OUT.ll1" scheme)" == "ledger-live" && "$(field "$OUT.ll1" account)" == "1" ]] || { cat "$OUT.ll1"; die "getAddress does not report Ledger Live numbering"; }
[[ "$(field "$OUT.ll1" address | tr 'A-F' 'a-f')" == "${A1,,}" ]] || die "Account 1 changed with the numbering"
go_section "Device information" || die "menu did not open"
find_text "Ledger Live · m/44" || die "Device information does not show the numbering: $(texts 12)"
go_home
pass "Ledger Live numbering on; getAddress reports it; Account 1 unchanged"

echo "== 6. Account 2 under Ledger Live"
go_accounts
if has_text "+ Add Account 2"; then tap_text "+ Add Account 2"; sleep 1; find_text "m/44&apos;/60&apos;/1&apos;/0/0" || die "Add Account 2 does not name the Ledger Live path"; tap_text "Add and switch"
else
  b="$(bounds_of '[● ]*Account 2 · [^"]*')"
  if [[ -z "$b" ]] && has_text "Hidden accounts ("; then tap_text 'Hidden accounts ([0-9]*)'; sleep 1.2; b="$(bounds_of 'Account 2 · [^"]*')"; fi
  [[ -n "$b" ]] || die "Account 2 neither addable nor listed: $(texts 12)"
  tap_bounds "$b"; sleep 1.2
  has_text "Use this account" && tap_text "Use this account"
fi
pin_if_asked
ask ll2 address
[[ "$(field "$OUT.ll2" account)" == "2" && "$(field "$OUT.ll2" scheme)" == "ledger-live" ]] || { cat "$OUT.ll2"; die "getAddress did not name Ledger Live Account 2"; }
[[ "$(field "$OUT.ll2" address | tr 'A-F' 'a-f')" == "${L1,,}" ]] || die "Ledger Live Account 2 is not m/44'/60'/1'/0/0 ($L1)"
pass "Ledger Live Account 2 active: $L1"

echo "== 7. relock keeps the numbering"
relock; unlock
ask ll3 address
[[ "$(field "$OUT.ll3" scheme)" == "ledger-live" && "$(field "$OUT.ll3" account)" == "2" ]] || { cat "$OUT.ll3"; die "after relock: numbering or account lost"; }
pass "after relock: Ledger Live, Account 2"

echo "== 8. back to Standard"
set_numbering standard
ensure_account1
ask back address
[[ -z "$(field "$OUT.back" scheme)" && "$(field "$OUT.back" account)" == "1" ]] || { cat "$OUT.back"; die "back on Standard: getAddress still names another numbering"; }
[[ "$(field "$OUT.back" address | tr 'A-F' 'a-f')" == "${A1,,}" ]] || die "back on Standard: not Account 1"
pass "Standard numbering and Account 1 again"

kiosk_locked; no_crashes
pass "migrationtest complete"
