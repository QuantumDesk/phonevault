#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f /.dockerenv ]]; then
  echo "Run this inside the Phone Vault build container." >&2
  exit 2
fi

SOURCE=/home/builder/android/lineage
PROJECT=/workspace/phone-vault
OUTPUT="${1:-${PROJECT}/vault-os/manifest/lineage-22.2-pinned.xml}"

[[ -d "${SOURCE}/.repo" ]] || {
  echo "Lineage source has not been synced: ${SOURCE}" >&2
  exit 1
}

python3 "${PROJECT}/vault-os/scripts/generate-pinned-manifest.py" \
  "${SOURCE}" "${OUTPUT}"
(
  cd "$(dirname "${OUTPUT}")"
  sha256sum "$(basename "${OUTPUT}")"
) > "${OUTPUT}.sha256"
