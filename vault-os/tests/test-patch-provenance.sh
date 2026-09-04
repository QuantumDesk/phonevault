#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERIFY="${ROOT}/vault-os/scripts/verify-patch-provenance.sh"
work_dir="$(mktemp -d -t phone-vault-patch-provenance.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT

make_fixture() {
  local fixture="$1"
  mkdir -p "${fixture}/vault-os"
  cp -R "${ROOT}/vault-os/patches" "${fixture}/vault-os/patches"
}

expect_failure() {
  local fixture="$1"
  local expected="$2"
  if "${VERIFY}" "${fixture}" > "${fixture}.stdout" 2> "${fixture}.stderr"; then
    echo "invalid patch provenance fixture unexpectedly passed: ${expected}" >&2
    exit 1
  fi
  grep -Fq -- "${expected}" "${fixture}.stderr"
}

"${VERIFY}" "${ROOT}"

changed="${work_dir}/changed"
make_fixture "${changed}"
printf '\n# local mutation\n' >> \
  "${changed}/vault-os/patches/frameworks-base/0001-reject-ambiguous-recovery-signatures.patch"
expect_failure "${changed}" 'reviewed bytes changed'

missing_url="${work_dir}/missing-url"
make_fixture "${missing_url}"
sed -i.bak 's#https://github.com/GrapheneOS/platform_frameworks_base/commit/4a3b6b70826c2a6efdbba28c87c9a88f52a33850#https://invalid.example/removed#' \
  "${missing_url}/vault-os/patches/README.md"
expect_failure "${missing_url}" 'catalog lacks upstream URL'

unregistered="${work_dir}/unregistered"
make_fixture "${unregistered}"
printf '%s\n' \
  'From: External Author <external@example.invalid>' \
  'Subject: [PATCH] unreviewed import' \
  > "${unregistered}/vault-os/patches/frameworks-base/9999-unreviewed.patch"
expect_failure "${unregistered}" 'unregistered external author'

echo "Patch provenance negative fixtures passed."
