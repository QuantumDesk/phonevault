#!/usr/bin/env bash
# Bitcoin helpers shared by btctest.sh and btc-signet-e2e.sh. Source AFTER lib.sh, with OUT (host
# client logs) set and, optionally, WORK (a scratch directory removed on exit).
PY="${PV_HOST_PY:-/root/pv-host/.venv/bin/python}"
CLIENT="${PV_HOST_CLIENT:-/root/pv-host/tools/aoa_client.py}"
TOOL="${PV_BTC_TOOL:-/root/pv-host/tools/btc_psbt_tool.py}"
[[ -x "$PY" && -s "$CLIENT" && -s "$TOOL" ]] || die "host tools not staged ($PY / $CLIENT / $TOOL)"
"$PY" -c 'import embit, usb' 2>/dev/null || die "$PY needs pyusb and embit==0.8.0"
mkdir -p "$OUT"
STEP="setup"; CLIENT_PID=""
# Every abort says so, including a failing command under set -e that printed nothing itself.
cleanup() {
  local rc=$?
  [[ -n "$CLIENT_PID" ]] && { kill "$CLIENT_PID" 2>/dev/null || true; }
  "$A" start-server >/dev/null 2>&1 || true
  [[ -n "${WORK:-}" ]] && rm -rf "$WORK"
  [[ $rc -eq 0 ]] || echo "FAIL: step '$STEP' aborted (exit $rc); host client output in $OUT" >&2
}
trap cleanup EXIT
step() { STEP="$*"; echo "== $*"; }

# A tap that may legitimately find nothing. NOT `tap_text … 2>/dev/null || true`: tap_text dies
# (exit 1) when the button is missing and the redirect hides the FAIL line, so the script used to
# stop silently right after "PASS: account shared" (the share outcome page has "Continue", not
# "Back to Wallet").
try_tap() { local b; b="$(bounds_of "$1")"; [[ -n "$b" ]] || return 1; tap_bounds "$b"; }
# Leave an outcome page (receipt, notice) for Home; the button may be below the fold.
leave_outcome() {
  local l
  for l in "Back to Wallet" "Continue"; do try_tap "$l" && { sleep 1.2; return 0; }; done
  scroll_down; sleep 0.8
  for l in "Back to Wallet" "Continue"; do try_tap "$l" && { sleep 1.2; return 0; }; done
  go_home
}

# client <name> <args…>: run aoa_client in the background (adb is stopped while it owns USB)
start_client() {
  local name="$1"; shift
  usb_reset; unlock_if_locked; go_home
  "$A" kill-server; sleep 1
  "$PY" "$CLIENT" "$@" > "$OUT/$name.out" 2>&1 &
  CLIENT_PID=$!
  sleep 6; "$A" start-server >/dev/null 2>&1; wait_adb 12; unlock_if_locked
}

# wait_screen <title>: the request's screen appears (a PIN prompt for the seed key is answered)
wait_screen() {
  local i
  for i in $(seq 1 30); do
    sleep 2
    system_prompt_up && { enter_system_pin || true; }
    has_text "$1" && return 0
    kill -0 "$CLIENT_PID" 2>/dev/null || break
    nudge
  done
  kill "$CLIENT_PID" 2>/dev/null || true
  tail -3 "$OUT/$STEP.out" 2>/dev/null || true
  die "screen '$1' never appeared: $(texts 10)"
}

# finish_client <name> <expected exit>: wait for the host client, answering a seed-key PIN prompt
# (signing, or a session whose Bitcoin accounts are not derived yet) and keeping the idle lock away.
finish_client() {
  local i rc=0
  for i in $(seq 1 45); do
    kill -0 "$CLIENT_PID" 2>/dev/null || break
    if system_prompt_up; then enter_system_pin || true; else nudge; fi
    sleep 2
  done
  kill -0 "$CLIENT_PID" 2>/dev/null && { kill "$CLIENT_PID" 2>/dev/null || true; }
  wait "$CLIENT_PID" || rc=$?
  CLIENT_PID=""
  [[ $rc -eq $2 ]] || { tail -5 "$OUT/$1.out"; die "$1: host client exited $rc, expected $2"; }
}

json_of() { "$PY" -c 'import json,sys; t=open(sys.argv[1]).read(); print(json.dumps(json.loads(t[t.index("{"):t.rindex("}")+1])))' "$1"; }

# ☰ → Bitcoin sharing: stop sharing every remembered account (or only those matching $1).
open_btc_sharing() {
  go_section "Bitcoin sharing" || { unlock_if_locked; go_section "Bitcoin sharing"; } \
    || die "☰ → Bitcoin sharing not found (app older than the revoke control?): $(texts 10)"
  expect_screen "Bitcoin sharing"
}
btc_unshare() {
  local pattern="${1:-}" i b
  open_btc_sharing
  for i in $(seq 1 12); do
    if [[ -z "$pattern" ]]; then
      has_text "Nothing shared" && break
      b="$(bounds_of "Stop sharing all")"; [[ -n "$b" ]] || b="$(bounds_of 'Stop sharing · [^"]*')"
      if [[ -z "$b" ]]; then find_text "Stop sharing" >/dev/null || true; b="$(bounds_of "Stop sharing all")"; [[ -n "$b" ]] || b="$(bounds_of 'Stop sharing · [^"]*')"; fi
    else
      b="$(bounds_of "Stop sharing · $pattern")"
      [[ -n "$b" ]] || { find_text "Stop sharing · $pattern" >/dev/null || true; b="$(bounds_of "Stop sharing · $pattern")"; }
      [[ -n "$b" ]] || break
    fi
    [[ -n "$b" ]] || die "Bitcoin sharing: no 'Stop sharing' button and no 'Nothing shared': $(texts 10)"
    tap_bounds "$b"; sleep 1.5
  done
  if [[ -z "$pattern" ]]; then has_text "Nothing shared" || die "sharing not cleared: $(texts 10)"
  else scroll_top; find_text "Stop sharing · $pattern" && die "still shared: $pattern"; fi
  go_home
}

# Tick the review checkbox (scrolling to it) and tap Approve & sign.
approve_review() {
  local box="" i
  for i in 1 2 3 4 5 6 7 8; do
    box="$(uidump | grep -o 'checkable="true"[^>]*bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"' | head -1 | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/' || true)"
    [[ -n "$box" ]] && break
    scroll_down; sleep 0.6
  done
  [[ -n "$box" ]] || { kill "$CLIENT_PID" 2>/dev/null || true; die "review checkbox not visible: $(texts 10)"; }
  tap_bounds "$box"; sleep 1
  uidump | grep -q 'checked="true"' || { kill "$CLIENT_PID" 2>/dev/null || true; die "review checkbox did not tick"; }
  try_tap "Approve &amp; sign" || tap_text "Approve & sign"; sleep 2
}

# share_if_asked: for a btc-account request that may be remembered already: tap "Share with the
# Mac" if the phone asks, otherwise let the client finish. Sets SHARED_HOW=asked|remembered.
share_if_asked() {
  local i
  for i in $(seq 1 30); do
    sleep 2
    system_prompt_up && { enter_system_pin || true; }
    if has_text "Share Bitcoin account with the Mac?"; then
      find_text "Share with the Mac" || die "no Share button: $(texts 10)"
      tap_text "Share with the Mac"; sleep 2; SHARED_HOW=asked; return 0
    fi
    kill -0 "$CLIENT_PID" 2>/dev/null || { SHARED_HOW=remembered; return 0; }
    nudge
  done
  kill "$CLIENT_PID" 2>/dev/null || true
  die "neither a share screen nor an answer: $(texts 10)"
}
