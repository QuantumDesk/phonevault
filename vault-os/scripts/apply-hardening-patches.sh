#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f /.dockerenv ]]; then
  echo "Run this inside the Phone Vault build container." >&2
  exit 2
fi

SOURCE=/home/builder/android/lineage/frameworks/base
PATCH_DIR=/workspace/phone-vault/vault-os/patches/frameworks-base
[[ -d "${SOURCE}/.git" || -f "${SOURCE}/.git" ]] || {
  echo "frameworks/base has not been synced" >&2
  exit 1
}

cd "${SOURCE}"
if [[ -d "$(git rev-parse --git-path rebase-apply)" ]]; then
  echo "aborting interrupted patch application"
  git am --abort
fi
for patch in "${PATCH_DIR}"/*.patch; do
  if git apply --reverse --check "${patch}" >/dev/null 2>&1; then
    echo "already applied: $(basename "${patch}")"
    continue
  fi
  git apply --check "${patch}"
  git -c user.name='Phone Vault Build' \
    -c user.email='build@phonevault.invalid' \
    am --3way "${patch}"
done

git log --format='%H %an <%ae> %s' -2
