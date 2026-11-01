#!/usr/bin/env bash
# Host-side paths for the development-device scripts. Sourced by lib.sh; source, don't run.
# Every value is an environment override with a default that works from a checkout of this repo:
#
#   PV_HOST_PY       Python with pyusb (and embit==0.8.0 for the Bitcoin scripts)
#                    default: python3 on PATH (e.g. point it at a venv built from
#                    tools/requirements.txt with --require-hashes)
#   PV_HOST_CLIENT   the USB host client                 default: <repo>/tools/aoa_client.py
#   PV_BTC_TOOL      the PSBT helper                      default: <repo>/tools/btc_psbt_tool.py
#   PV_STATE_DIR     persistent harness state (0700)      default: ${XDG_STATE_HOME:-~/.local/state}/phonevault
#   PV_PAIRING_FILE  the host pairing usbsigntest.sh pins default: $PV_STATE_DIR/paired-signer.json
#   PV_LOG_DIR       per-run host logs (0700)             default: ${TMPDIR:-/tmp}/phonevault
#   PV_TEST_PIN      the throwaway phones' 6-digit test PIN default: PV_DEFAULT_TEST_PIN below
#
# The test PIN is defined here, once. It is NOT a pattern: from beta5 the app refuses PINs a thief
# tries first when a PIN is chosen (all-same digits, straight runs, repeated groups, the common
# list: app GuessablePins), so firstrun.sh could not set the old harness PIN any more. Unlock never
# applies that check: a phone set up before beta5 with another PIN keeps working, by exporting
# PV_TEST_PIN=<its PIN> before running the scripts (the variable always wins over the default).
# Like every test PIN, it is burned: never use it on a phone that holds anything.
# shellcheck disable=SC2034  # the variables below are read by the scripts that source lib.sh

PV_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PV_DEFAULT_TEST_PIN=380275
PV_TEST_PIN="${PV_TEST_PIN:-$PV_DEFAULT_TEST_PIN}"

PY="${PV_HOST_PY:-python3}"
PY="$(command -v -- "$PY" 2>/dev/null || printf '%s' "$PY")"   # a bare command name → its path
CLIENT="${PV_HOST_CLIENT:-${PV_REPO_ROOT}/tools/aoa_client.py}"
TOOL="${PV_BTC_TOOL:-${PV_REPO_ROOT}/tools/btc_psbt_tool.py}"

PV_STATE_DIR="${PV_STATE_DIR:-${XDG_STATE_HOME:-${HOME}/.local/state}/phonevault}"
PAIRING="${PV_PAIRING_FILE:-${PV_STATE_DIR}/paired-signer.json}"
pv_tmp="${TMPDIR:-/tmp}"
PV_LOG_DIR="${PV_LOG_DIR:-${pv_tmp%/}/phonevault}"
unset pv_tmp

# macOS: adb's default libusb backend (platform-tools 35) resets the phone's USB port every time
# the server starts (the phone logs DISCONNECTED on each `adb start-server`). The scripts restart the
# server around every USB exchange, so the reset knocked a live accessory session off the bus
# (reconnecttest: "[Errno 5] Input/Output Error" for a request held behind the lock) and once left
# the server without the device. The native IOKit backend does not reset it. Linux hosts are
# unaffected. An explicit ADB_LIBUSB from the caller wins.
if [[ "$(uname -s)" == Darwin ]]; then export ADB_LIBUSB="${ADB_LIBUSB:-0}"; fi

mkdir -p "$PV_STATE_DIR" "$PV_LOG_DIR" "$(dirname "$PAIRING")"
chmod 700 "$PV_STATE_DIR" "$PV_LOG_DIR"
