#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
docker volume inspect phone-vault-lineage >/dev/null 2>&1 \
  || docker volume create phone-vault-lineage >/dev/null

exec docker run --rm -it \
  --platform linux/amd64 \
  --name phone-vault-lineage-shell \
  --volume phone-vault-lineage:/home/builder/android/lineage \
  --volume "${ROOT}:/workspace/phone-vault:ro" \
  phone-vault-lineage-builder:24.04 "$@"
