#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 2 && -s "$1" && -s "$2" ]] || {
  echo "fake OTA checker received invalid arguments" >&2
  exit 1
}
[[ "${FAKE_OTA_CHECK_FAIL:-0}" != 1 ]] || {
  echo "synthetic whole-file/payload verification failure" >&2
  exit 1
}
if [[ -n "${FAKE_OTA_CHECK_LOG:-}" ]]; then
  printf '%s\n%s\n' "$1" "$2" > "${FAKE_OTA_CHECK_LOG}"
fi
