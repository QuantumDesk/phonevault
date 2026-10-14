#!/usr/bin/env bash
# Release overrides gate: every module in the release `overrides` list
# (vault-os/vendor/phonevault/prebuilt/Android.bp) is absent from the target-files, as an app
# (<PARTITION>/app|priv-app/<name>/), an overlay APK or the app's auto-generated RRO. An
# override is silently defeated when an installed module `required`s its target, so the image,
# not the Android.bp, is the proof. sign-release.sh runs it on the input target-files before
# anything is signed.
#   verify-release-overrides.sh TARGET_FILES_ZIP [REPOSITORY_ROOT]
# Fails (exit 1) when an overridden module is still packaged, and when the release Android.bp
# has no active override at all: the release list is never empty, so an empty parse proves
# nothing. Parsing and matching: vaultgates/overrides.py.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || -z "$1" ]]; then
  echo "usage: $0 TARGET_FILES_ZIP [REPOSITORY_ROOT]" >&2
  exit 2
fi
TARGET_FILES="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPOSITORY_ROOT="${2:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
BLUEPRINT="${REPOSITORY_ROOT}/vault-os/vendor/phonevault/prebuilt/Android.bp"
[[ -s "${BLUEPRINT}" ]] || {
  echo "missing release overrides: ${BLUEPRINT}" >&2
  exit 1
}
[[ -s "${TARGET_FILES}" ]] || {
  echo "missing target-files archive: ${TARGET_FILES}" >&2
  exit 1
}
echo "release overrides: ${TARGET_FILES}"
python3 "${SCRIPT_DIR}/vaultgate.py" overrides check \
  "${BLUEPRINT}" "${TARGET_FILES}" --require-overrides
