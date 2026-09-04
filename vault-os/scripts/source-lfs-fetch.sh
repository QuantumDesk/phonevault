#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f /.dockerenv ]]; then
  echo "Run this inside the Phone Vault build container." >&2
  exit 2
fi

cd /home/builder/android/lineage
git lfs install --force --skip-repo
unset GIT_LFS_SKIP_SMUDGE

mapfile -t LFS_REPOSITORIES < <(
  while IFS= read -r -d '' attributes; do
    if grep -q 'filter=lfs' "${attributes}"; then
      git -C "$(dirname "${attributes}")" rev-parse --show-toplevel
    fi
  done < <(find . \
    -path './.repo' -prune -o \
    -path '*.partial-*' -prune -o \
    -name .gitattributes -print0)
)
mapfile -t LFS_REPOSITORIES < <(printf '%s\n' "${LFS_REPOSITORIES[@]}" | sort -u)
if [[ ${#LFS_REPOSITORIES[@]} -eq 0 ]]; then
  echo "No Git LFS repositories were discovered." >&2
  exit 1
fi
printf 'Discovered LFS repository: %s\n' "${LFS_REPOSITORIES[@]}"

for attempt in 1 2 3; do
  echo "LFS hydration attempt ${attempt}/3"
  failed=0
  for repository in "${LFS_REPOSITORIES[@]}"; do
    echo "hydrating ${repository}"
    git -C "${repository}" lfs pull || failed=1
    git -C "${repository}" lfs fsck || failed=1
    if git -C "${repository}" lfs ls-files | grep -Eq '^[0-9a-f]+ - ';
    then
      echo "unhydrated LFS pointer remains in ${repository}" >&2
      failed=1
    fi
  done
  if [[ ${failed} -eq 0 ]]; then
    echo "All Git LFS repositories hydrated and verified."
    exit 0
  fi
done

echo "Git LFS hydration failed after three attempts." >&2
exit 1
