#!/usr/bin/env bash
# Multiple accounts + BIP-39 passphrase wallet on a THROWAWAY dev phone:
#   1. getAddress names Account 1 / standard; Home shows "ACCOUNT 1"
#   2. ☰ → Accounts → + Add Account 2 → Add and switch: Home "ACCOUNT 2", getAddress account "2",
#      a different address
#   3. a request whose "from" is Account 1 while Account 2 is active → refused before review,
#      "Switch to the right account on the phone" (host error + phone screen)
#   4. a request for Account 2 → review shows "Signing with" "Account 2"; reject
#   5. rename Account 2 → "Savings" on the phone keyboard; Home shows "SAVINGS"
#   6. switch back to Account 1; hide Savings; the list shows "Hidden accounts (1)"
#   7. ☰ → Passphrase wallet → type "pv test" → preview shows a fingerprint → Use this wallet:
#      Home "Passphrase wallet · fingerprint", getAddress wallet "passphrase", another address;
#      a personal_sign review shows "(passphrase wallet)"; reject
#   8. relock + unlock: back on the standard wallet's Account 1 (passphrase forgotten), Savings
#      still hidden in the saved list
# Nothing is broadcast. Throwaway passphrase only; never use a real one here.
# Rerunnable: an Account 2 left by an earlier run (renamed, hidden or active) is reset first, and
# the phone is always left on the standard wallet's Account 1 (EXIT trap), which the host pairing
# of the other scripts pins.
#
# Needs PV_HOST_PY (venv python with pyusb) and PV_HOST_CLIENT (tools/aoa_client.py with --from).
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
wake
pid=""
restore_account1() {
  local rc=$?
  trap - EXIT
  [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  [[ $rc -eq 0 ]] || echo "  (restoring Account 1 after the failure)"
  ensure_account1
  unwake
  exit $rc
}
trap restore_account1 EXIT
OUT="${PV_ACCOUNTS_OUT:-$PV_LOG_DIR/accountstest}"
[[ -x "$PY" && -s "$CLIENT" ]] || die "host client not staged ($PY / $CLIENT)"
PASS_PHRASE="pv test"   # throwaway; typed on the phone keyboard below

field() { "$PY" -c 'import json,sys; t=open(sys.argv[1]).read(); print(json.loads(t[:t.rindex("}")+1])[sys.argv[2]], end="")' "$1" "$2"; }

# ask <name> <client args…>: one exchange in the foreground (getAddress needs no tap)
ask() {
  local name="$1"; shift
  usb_reset; unlock_if_locked; go_home
  "$A" kill-server; sleep 1
  "$PY" "$CLIENT" "$@" > "$OUT.$name" 2>&1 || true
  sleep 4; "$A" start-server >/dev/null 2>&1; wait_adb 12; nudge; unlock_if_locked
}
# start_request <name> <client args…>: in the background (the review needs taps), sets $pid
start_request() {
  local name="$1"; shift
  usb_reset; unlock_if_locked; go_home
  "$A" kill-server; sleep 1
  "$PY" "$CLIENT" "$@" > "$OUT.$name" 2>&1 &
  pid=$!
  sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked
}
see() { # see <name> <fragment…>: the open review shows every fragment (scrolling)
  local name="$1" f i seen; shift
  # Wait for the review's top ("Signing with" row), not "Reject request": that button is below the
  # fold, and waiting for it without a touch let the 1-minute idle lock close the review.
  for _ in $(seq 1 25); do sleep 2; kill -0 $pid 2>/dev/null || break
    uidump | grep -qi -e 'text="Signing with' -e 'text="Reject request' && break; done
  for f in "$@"; do
    seen=0
    for i in 1 2 3 4 5 6; do uidump | grep -qiF "$f" && { seen=1; break; }; scroll_down; sleep 0.6; done
    [[ $seen -eq 1 ]] || { kill $pid 2>/dev/null || true; die "$name: review lacks '$f': $(texts 14)"; }
    scroll_top
  done
}
reject() {
  local name="$1" rc=0
  for _ in 1 2 3 4 5 6; do has_text "Reject request" && break; scroll_down; sleep 0.6; done
  tap_text "Reject request"; sleep 2
  wait $pid || rc=$?
  [[ $rc -eq 2 ]] && grep -q '"status": "rejected"' "$OUT.$name" || { tail -3 "$OUT.$name"; die "$name: expected a clean rejection (exit $rc)"; }
  tap_text "Back to Wallet" 2>/dev/null || true
}
go_accounts() { go_section "Accounts" || die "menu did not open"; expect_screen "Your accounts"; }
# open_account2: the Account 2 page, wherever an earlier run left it (visible or hidden, any name)
open_account2() {
  go_accounts
  local b; b="$(bounds_of '[● ]*\(Account 2\|Savings\) · [^"]*')"
  if [[ -z "$b" ]] && has_text "Hidden accounts ("; then
    tap_text 'Hidden accounts ([0-9]*)'; sleep 1.2; b="$(bounds_of '\(Account 2\|Savings\) · [^"]*')"
  fi
  [[ -n "$b" ]] || return 1
  tap_bounds "$b"; sleep 1.2; expect_screen "ACCOUNTS / ACCOUNT 2"
}
type_keys() { local i c; for (( i = 0; i < ${#1}; i++ )); do c="${1:$i:1}"; [[ "$c" == " " ]] && c="space"; tap_text "$c"; sleep 0.3; done; }

ensure_account1
if open_account2; then  # an earlier run's Account 2: shown, default name, not active
  if has_text "Show in the list again"; then tap_text "Show in the list again"; sleep 1.2; fi
  if ! has_text "Account 2\""; then
    tap_text "Rename"; sleep 1
    for _ in $(seq 1 12); do has_text 'Account 2"' && break; tap_text "⌫"; sleep 0.3; done
    tap_text "Save name"; sleep 1.2
  fi
  expect_screen 'Account 2"'
  echo "  (reset Account 2 from an earlier run)"
fi
go_home

echo "== 1. Account 1"
ask a1 address
[[ "$(field "$OUT.a1" account)" == "1" && "$(field "$OUT.a1" wallet)" == "standard" ]] || { cat "$OUT.a1"; die "getAddress did not name Account 1 / standard"; }
A1="$(field "$OUT.a1" address)"
go_home; expect_screen "ACCOUNT 1"
pass "account 1: $A1"

echo "== 2. add Account 2"
go_accounts
if has_text "+ Add Account 2"; then tap_text "+ Add Account 2"; sleep 1; tap_text "Add and switch"
else open_account2 || die "Account 2 neither addable nor listed"; tap_text "Use this account"; fi
pin_if_asked
expect_screen "ACCOUNT 2"
ask a2 address
[[ "$(field "$OUT.a2" account)" == "2" ]] || { cat "$OUT.a2"; die "getAddress did not name Account 2"; }
A2="$(field "$OUT.a2" address)"
[[ "${A2,,}" != "${A1,,}" ]] || die "Account 2 has Account 1's address"
pass "account 2: $A2 (active)"

echo "== 3. request for Account 1 while Account 2 is active"
start_request wrong sign-test --chain-id 0x1 --from "$A1" --expect-address "$A1"
rc=0; wait $pid || rc=$?
[[ $rc -ne 0 ]] && grep -qF "Switch to the right account on the phone" "$OUT.wrong" || { tail -4 "$OUT.wrong"; die "wrong account: not refused (exit $rc)"; }
sleep 2; expect_screen "Switch to the right account on the phone"
tap_text "Continue" 2>/dev/null || true
pass "a request for another account is refused before review"

echo "== 4. request for Account 2"
start_request right sign-test --chain-id 0x1 --from "$A2" --expect-address "$A2"
see right "SIGNING WITH" "Account 2"
reject right
pass "review names the signing account"

echo "== 5. rename"
go_accounts
tap_text '● Account 2 · [^"]*'; sleep 1
tap_text "Rename"; sleep 1
has_text "⇧ON" || tap_text "⇧"; type_keys "Savings"
tap_text "Save name"; sleep 1
expect_screen "Savings"
go_home; expect_screen "SAVINGS"
pass "renamed to Savings on the phone"

echo "== 6. back to Account 1, hide Savings"
go_accounts
tap_text 'Account 1 · [^"]*'; sleep 1
tap_text "Use this account"; pin_if_asked
expect_screen "ACCOUNT 1"
go_accounts
tap_text 'Savings · [^"]*'; sleep 1
tap_text "Hide from the list"; sleep 1
expect_screen "Hidden accounts (1)"
pass "Account 1 active again; Savings hidden"

echo "== 7. passphrase wallet"
go_section "Passphrase wallet" || die "menu did not open"
expect_screen "A wrong passphrase opens a different wallet"
expect_screen "Not part of your backup"
tap_text "Enter passphrase"; sleep 1
type_keys "$PASS_PHRASE"
expect_screen "PASSPHRASE WALLET · ${#PASS_PHRASE} CHARACTERS"
tap_text "Open passphrase wallet"; pin_if_asked
expect_screen "Is this the wallet you expect?"
expect_screen "Fingerprint"
tap_text "Use this wallet"; pin_if_asked
expect_screen "Passphrase wallet · fingerprint"
ask pp address
[[ "$(field "$OUT.pp" wallet)" == "passphrase" && "$(field "$OUT.pp" account)" == "1" ]] || { cat "$OUT.pp"; die "getAddress did not name the passphrase wallet"; }
PP="$(field "$OUT.pp" address)"
[[ "${PP,,}" != "${A1,,}" ]] || die "the passphrase wallet has the standard wallet's address"
start_request ppmsg sign-message --text "accounts test" --chain-id 0x1 --from "$PP" --expect-address "$PP"
see ppmsg "(passphrase wallet)"
reject ppmsg
pass "passphrase wallet open: $PP; reviews say so"

echo "== 8. relock forgets the passphrase"
relock; unlock
go_home; expect_not "Passphrase wallet · fingerprint"; expect_screen "ACCOUNT 1"
ask after address
[[ "$(field "$OUT.after" wallet)" == "standard" && "${A1,,}" == "$(field "$OUT.after" address | tr 'A-F' 'a-f')" ]] || { cat "$OUT.after"; die "after unlock: not the standard Account 1"; }
go_accounts; expect_screen "Hidden accounts (1)"
pass "after relock: standard wallet, Account 1, saved list kept, passphrase gone"

kiosk_locked; no_crashes
pass "accountstest complete"
