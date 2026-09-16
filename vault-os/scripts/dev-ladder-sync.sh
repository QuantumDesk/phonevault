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

DEVICE="${TREE}/device/google/crosshatch"
DIFF="${RUNG_DIR}/device-google-crosshatch.diff"
if [[ -s "${DIFF}" ]]; then
  if git -C "${DEVICE}" apply --reverse --check "${DIFF}" >/dev/null 2>&1; then
    echo "   device diff already applied"
  elif git -C "${DEVICE}" apply --check "${DIFF}" >/dev/null 2>&1; then
    git -C "${DEVICE}" apply "${DIFF}"; echo "   device diff applied"
  else
    echo "device diff neither applies nor reverses cleanly: ${DIFF}" >&2; exit 1
  fi
else
  if ! git -C "${DEVICE}" diff --quiet; then
    echo "   rung carries no device diff but the tree has local device changes:" >&2
    git -C "${DEVICE}" diff --stat >&2; exit 1
  fi
fi

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
