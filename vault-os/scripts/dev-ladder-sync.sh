#!/usr/bin/env bash
# Sync the release overlay into a Lineage tree, then apply one dev-ladder rung's deviations.
#   dev-ladder-sync.sh RUNG /path/to/lineage-src [/path/to/app-appliance.apk]
# See vault-os/dev-ladder/README.md. Development images only.
set -euo pipefail

RUNG="${1:?rung number}"
TREE="${2:?lineage source tree}"
APK="${3:-}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OVERLAY="${ROOT}/vault-os"
RUNG_DIR="${OVERLAY}/dev-ladder/rung-${RUNG}"
[[ -d "${RUNG_DIR}" ]] || { echo "no such rung: ${RUNG_DIR}" >&2; exit 2; }
[[ -d "${TREE}/build" ]] || { echo "not a Lineage tree: ${TREE}" >&2; exit 2; }

echo "== release overlay → tree"
mkdir -p "${TREE}/device/phonevault" "${TREE}/vendor/phonevault"
rsync -a --delete "${OVERLAY}/device/phonevault/" "${TREE}/device/phonevault/"
rsync -a --delete --exclude 'keys/' --exclude 'prebuilt/PhoneVault.apk' \
  "${OVERLAY}/vendor/phonevault/" "${TREE}/vendor/phonevault/"

echo "== rung ${RUNG} deviations"
declare -A TARGET=(
  [common.mk]="vendor/phonevault/config/common.mk"
  [BoardConfigVault.mk]="vendor/phonevault/config/BoardConfigVault.mk"
  [Android.bp]="vendor/phonevault/prebuilt/Android.bp"
  [config.xml]="vendor/phonevault/overlay/frameworks/base/core/res/res/values/config.xml"
  [debug_adbkey.pub]="vendor/phonevault/config/debug_adbkey.pub"
)
for name in "${!TARGET[@]}"; do
  if [[ -f "${RUNG_DIR}/${name}" ]]; then
    install -m 0644 "${RUNG_DIR}/${name}" "${TREE}/${TARGET[$name]}"
    echo "   override: ${TARGET[$name]}"
  else
    echo "   release : ${TARGET[$name]}"
  fi
done

KCONF="${TREE}/kernel/google/msm-4.9/arch/arm64/configs"
for frag in "${RUNG_DIR}"/*.config; do
  [[ -f "${frag}" ]] || continue
  install -m 0644 "${frag}" "${KCONF}/$(basename "${frag}")"
  echo "   kernel fragment: $(basename "${frag}") → arch/arm64/configs/  (kernel fragments are per-rung slices)"
done

KERNEL="${TREE}/kernel/google/msm-4.9"
# Each rung carries exactly its own kernel patches: drop any a previous rung left applied (a stale
# patch can add Kconfig symbols the current rung's config does not answer, and the kernel build
# then waits forever on an interactive prompt — seen 2026-09-24 going 2d-c → 2d-b).
if ! git -C "${KERNEL}" diff --quiet; then
  echo "   kernel tree had tracked changes from another rung: reset"
  git -C "${KERNEL}" diff --stat | tail -1
  git -C "${KERNEL}" checkout -- .
fi
for kp in "${RUNG_DIR}"/kernel-*.patch; do
  [[ -f "${kp}" ]] || continue
  if git -C "${KERNEL}" apply --reverse --check "${kp}" >/dev/null 2>&1; then
    echo "   kernel patch already applied: $(basename "${kp}")"
  elif git -C "${KERNEL}" apply --check "${kp}" >/dev/null 2>&1; then
    git -C "${KERNEL}" apply "${kp}"; echo "   kernel patch applied: $(basename "${kp}")"
  else
    echo "kernel patch neither applies nor reverses cleanly: ${kp}" >&2; exit 1
  fi
done

# Upstream device / proprietary-vendor trees: like the kernel, each rung carries exactly its own
# edits. Restore the ladder-managed paths to upstream, then apply the rung's diff (if any). A
# "reverse-applies → already applied" test is not enough: going 2d-c2 → 2d-c, 2d-c's diff
# reverse-applies while 2d-c2's extra hunks would silently stay in the tree.
#   sync_tree_diff NAME DIR DIFF PATHSPEC...
sync_tree_diff() {
  local name="$1" dir="$2" diff="$3"; shift 3
  if ! git -C "${dir}" diff --quiet -- "$@"; then
    git -C "${dir}" checkout -- "$@"
    echo "   ${name} tree restored to upstream before applying this rung"
  fi
  if [[ -s "${diff}" ]]; then
    git -C "${dir}" apply --check "${diff}" || { echo "${name} diff does not apply: ${diff}" >&2; exit 1; }
    git -C "${dir}" apply "${diff}"; echo "   ${name} diff applied"
  fi
}
# BoardConfigLineage.mk only carries the BoardConfigVault include appended below.
sync_tree_diff device "${TREE}/device/google/crosshatch" "${RUNG_DIR}/device-google-crosshatch.diff" \
  . ':(exclude)crosshatch/BoardConfigLineage.mk'
# Proprietary blobs: only the extract-utils makefiles are ladder-managed (the tree's radio/ images
# are deliberately locally modified and never touched here).
sync_tree_diff vendor "${TREE}/vendor/google/crosshatch" "${RUNG_DIR}/vendor-google-crosshatch.diff" \
  crosshatch-vendor.mk Android.bp Android.mk BoardConfigVendor.mk

BOARD="${TREE}/device/google/crosshatch/crosshatch/BoardConfigLineage.mk"
INCLUDE='include vendor/phonevault/config/BoardConfigVault.mk'
if ! grep -Fqx "${INCLUDE}" "${BOARD}"; then
  printf '\n# Phone Vault product board policy\n%s\n' "${INCLUDE}" >> "${BOARD}"
  echo "   appended BoardConfigVault include to $(basename "${BOARD}")"
fi

if [[ -n "${APK}" ]]; then
  [[ -s "${APK}" ]] || { echo "APK not found: ${APK}" >&2; exit 1; }
  install -m 0644 "${APK}" "${TREE}/vendor/phonevault/prebuilt/PhoneVault.apk"
  echo "   baked signer APK $(sha256sum "${APK}" | cut -c1-16)…"
fi
echo "== rung ${RUNG} synced"
