#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f /.dockerenv ]]; then
  echo "Run this inside the Phone Vault build container." >&2
  exit 2
fi

cd /home/builder/android/lineage
git config --global user.name "Phone Vault Builder"
git config --global user.email "builder@phonevault.invalid"
git config --global trailer.changeid.key Change-Id
git lfs install --skip-repo

# Docker Desktop's x86 emulation has produced intermittent TLS failures while
# LFS smudge downloads run in parallel with checkout. Complete the Git checkout
# first; source-lfs-fetch.sh hydrates and verifies every LFS object afterward.
git config --global filter.lfs.smudge "git-lfs smudge --skip -- %f"
git config --global filter.lfs.process "git-lfs filter-process --skip"
export GIT_LFS_SKIP_SMUDGE=1

if [[ ! -d .repo ]]; then
  repo init \
    -u https://github.com/LineageOS/android.git \
    -b lineage-22.2 \
    --git-lfs \
    --no-clone-bundle \
    --depth=1
fi

repo sync -c -j4 --force-sync --force-checkout --no-tags
