#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNNER="${ROOT}/vault-os/scripts/container-run.sh"

[[ -x "${RUNNER}" ]] || {
  echo "container runner is missing or not executable: ${RUNNER}" >&2
  exit 1
}

expected_mount="--volume \"\${ROOT}:/workspace/phone-vault:ro\""
grep -Fq -- "${expected_mount}" "${RUNNER}" || {
  echo "container runner must expose the repository at /workspace/phone-vault" >&2
  exit 1
}

for script in \
    apply-hardening-patches.sh \
    install-overlay.sh \
    prepare-development-images.sh \
    sign-release.sh \
    sign-signer-apk.sh; do
  if grep -Eq '/workspace/phone-vault(/|$)' \
      "${ROOT}/vault-os/scripts/${script}"; then
    continue
  fi
  echo "${script} does not use the canonical /workspace/phone-vault mount" >&2
  exit 1
done

echo "Container workspace layout matches all build and signing scripts."
