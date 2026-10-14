#!/usr/bin/env bash
# Owner provisioning policy (vaultgates/owner_provisioning.py): the signer is an ordinary
# system app with an exact device-admin/HOME component, and first-boot provisioning of that
# owner is fail-closed. Run by install-overlay.sh before any source-tree mutation.
#   verify-owner-provisioning-policy.sh [REPOSITORY_ROOT]
set -euo pipefail

REPOSITORY_ROOT="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"

python3 "$(dirname "$0")/vaultgate.py" owner-provisioning-policy "${REPOSITORY_ROOT}"
