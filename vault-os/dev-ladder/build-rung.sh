#!/usr/bin/env bash
# Build one ladder rung on the native build box: target-files → OTA zip.
#   build-rung.sh RUNG [insecure-adb=1]
# Runs as the tree owner (never root). Output: $PV_OUT_DIR/rung-RUNG-ota.zip.
# No `set -u`: build/envsetup.sh and lunch reference unset variables by design.
set -o pipefail
RUNG="${1:?rung}"
INSECURE="${2:-1}"
TREE="${PV_TREE:-/root/lineage-src}"
# NOTE: lunch exports OUT and OUT_DIR itself — never reuse those names here.
PV_OTA_DIR="${PV_OUT_DIR:-${HOME}}"   # the tree owner's home: this script must run as the tree owner
PV_OTA="${PV_OTA_DIR}/rung-${RUNG}-ota.zip"
cd "${TREE}" || exit 9
export LC_ALL=C
# shellcheck disable=SC1091
source build/envsetup.sh
lunch vault_crosshatch-bp1a-userdebug
[[ -n "${TARGET_PRODUCT:-}" ]] || { echo "LUNCH FAILED"; exit 8; }
echo "=== RUNG ${RUNG} BUILD START $(date) product=${TARGET_PRODUCT} variant=${TARGET_BUILD_VARIANT}"
export DISABLE_DEXPREOPT_CHECK=true
[[ "${INSECURE}" == "1" ]] && export WITH_ADB_INSECURE=true
m target-files-package -j24
rc=$?
echo "=== target-files rc=${rc} $(date)"
[[ ${rc} -eq 0 ]] || { echo "TARGET-FILES FAILED"; exit "${rc}"; }
TF="$(ls -t out/target/product/crosshatch/obj/PACKAGING/target_files_intermediates/*target_files*.zip | head -1)"
echo "TF=${TF}"
./out/host/linux-x86/bin/ota_from_target_files --skip_compatibility_check "${TF}" "${PV_OTA}" 2>&1 | tail -20
ota_rc=${PIPESTATUS[0]}
echo "=== OTA rc=${ota_rc} $(date)"
[[ ${ota_rc} -eq 0 && -s "${PV_OTA}" ]] || { echo "OTA FAILED"; exit 1; }
sha256sum "${PV_OTA}" | cut -c1-16
echo "=== ALL DONE $(date)"
