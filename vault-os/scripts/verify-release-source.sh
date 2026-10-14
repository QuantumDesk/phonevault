#!/usr/bin/env bash
# Release-source gate: the release configuration (vault-os/vendor/phonevault,
# vault-os/device/phonevault) carries no development deviation. Run by
# install-overlay.sh before a release tree is prepared and by sign-release.sh
# before anything is signed.
#   verify-release-source.sh [REPOSITORY_ROOT]
#
# Development-only settings (adb as the default USB function, insecure adb,
# pre-authorised adb keys, early-boot adb init scripts, DEBUG-NN bisection
# markers, backup copies of release files such as *.rel-bak) belong in
# vault-os/dev-ladder*/ rung directories only.
set -euo pipefail

REPOSITORY_ROOT="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"

python3 "$(dirname "$0")/vaultgate.py" release-source "${REPOSITORY_ROOT}"
