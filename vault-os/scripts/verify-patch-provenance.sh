#!/usr/bin/env bash
# Patch provenance (vaultgates/patch_provenance.py): every imported patch is a pinned,
# reviewed allowlist record; every other patch is Phone Vault's own. Run by
# install-overlay.sh before any patch is applied.
#   verify-patch-provenance.sh [REPOSITORY_ROOT]
set -euo pipefail

REPOSITORY_ROOT="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"

python3 "$(dirname "$0")/vaultgate.py" patch-provenance "${REPOSITORY_ROOT}"
