#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f /.dockerenv ]]; then
  echo "Run this inside the Phone Vault build container." >&2
  exit 2
fi

cd /home/builder/android/lineage
du -sh . .repo 2>/dev/null || true
df -h .
if [[ -d .repo ]]; then
  repo manifest -r -o /tmp/phone-vault-pinned-manifest.xml
  sha256sum /tmp/phone-vault-pinned-manifest.xml
  repo status
fi
