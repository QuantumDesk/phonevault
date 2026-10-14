#!/usr/bin/env bash
# Build one ladder rung on a native Linux build host: target-files → OTA zip.
#   build-rung.sh RUNG [insecure-adb=1]
# Runs as the tree owner (never root). Tree: $LINEAGE_TREE (required). Output:
# $PV_OUT_DIR/rung-RUNG-ota.zip ($PV_OUT_DIR defaults to the tree owner's home).
# No `set -u`: build/envsetup.sh and lunch reference unset variables by design.
set -o pipefail
RUNG="${1:?rung}"
INSECURE="${2:-1}"
TREE="${LINEAGE_TREE:?set LINEAGE_TREE to the LineageOS 22.2 crosshatch source tree}"
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
# Scrub stale app dirs from the staging tree before building. An app with embedded JNI libs gets
# lib/<abi>/*.so symlinks to absolute *device* paths (/product/lib64/...). When the app stops being
# installed, soong_ui's stale-install cleaner (cleanOldFiles in build/soong/ui/build/cleanbuild.go)
# os.Stat()s each old path, which follows the symlink, finds nothing on the host and skips it: the
# APK and odex go, the dangling symlinks stay, and target-files / the partition images copy the
# staging dir wholesale, and check-overrides.sh then flags the overridden app as still present.
# Removed here: every app dir without an APK (a leftover
# from an earlier build), and every app dir named in the rung's active `overrides` (removed this
# rung; the APK is still there until soong_ui's cleaner runs). If an overridden module really is
# still installed, ninja simply re-creates it and check-overrides.sh fails as it should.
PV_PRODUCT_OUT="out/target/product/crosshatch"
mapfile -t PV_OVERRIDES < <(awk '/^[[:space:]]*\/\//{next} /overrides:[[:space:]]*\[/{f=1;next}
  f && /^[[:space:]]*\]/{f=0} f' vendor/phonevault/prebuilt/Android.bp | grep -o '"[^"]*"' | tr -d '"')
for d in "${PV_PRODUCT_OUT}"/{system,system_ext,product,vendor,odm}/{app,priv-app}/*/; do
  [[ -d "${d}" ]] || continue
  name="$(basename "${d}")"
  if ! compgen -G "${d}*.apk" >/dev/null; then
    echo "   scrub stale app dir (no APK): ${d}"; rm -rf "${d}"
  elif printf '%s\n' "${PV_OVERRIDES[@]}" | grep -Fqx "${name}"; then
    echo "   scrub overridden app dir: ${d}"; rm -rf "${d}"
  fi
done
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
