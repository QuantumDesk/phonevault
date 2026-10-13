#!/usr/bin/env bash
# Build one bluejay rung on the native build box: target-files → firmware-free fastboot image zip
# plus the loose images, with SHA256SUMS.
#   build-rung.sh RUNG [TREE] [OUT]
#     TREE default /build/lineage-24, OUT default /build/out-RUNG
# Run as the tree owner (aipg), after sync-rung.sh. No `set -u`: envsetup/lunch use unset vars.
set -o pipefail
RUNG="${1:?rung}"
TREE="${2:-/build/lineage-24}"
PV_DEST="${3:-/build/out-${RUNG}}"     # lunch exports OUT/OUT_DIR: never reuse those names
JOBS="${PV_JOBS:-24}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${TREE}" || exit 9
export LC_ALL=C
# shellcheck disable=SC1091
source build/envsetup.sh
lunch vault_bluejay-cp2a-userdebug
[[ -n "${TARGET_PRODUCT:-}" ]] || { echo "LUNCH FAILED"; exit 8; }
echo "=== BLUEJAY RUNG ${RUNG} BUILD START $(date) product=${TARGET_PRODUCT} variant=${TARGET_BUILD_VARIANT}"
# Scrub stale app dirs from the staging tree before building (crosshatch rung 4a finding, see
# dev-ladder/README.md "Stale staging leftovers"): an app with JNI libs leaves dangling lib/<abi>
# symlinks that soong_ui's stale-install cleaner cannot delete, and target files copy the staging
# dir wholesale. Removed here: every app dir without an APK, and every app dir named in the rung's
# active `overrides` (if such a module really is still installed, ninja re-creates it and
# check-build.sh fails as it should).
PV_PRODUCT_OUT="out/target/product/bluejay"
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
# Same problem for kernel modules leaving the vendor_boot ramdisk (b4a, 2026-10-13): the dlkm
# fragment's staging dirs are filled by per-file copy rules and never pruned, so a module dropped
# from BOARD_VENDOR_RAMDISK_KERNEL_MODULES stayed in vendor_boot (no load list named it, but the
# .ko was there). Both dirs are regenerated from the current module list on every build.
for d in "${PV_PRODUCT_OUT}"/obj/PACKAGING/vendor_ramdisk_fragment-stage-*_intermediates \
         "${PV_PRODUCT_OUT}"/obj/PACKAGING/depmod_vendor_ramdisk*_intermediates; do
  [[ -d "${d}" ]] && { echo "   scrub ramdisk module staging: ${d}"; rm -rf "${d}"; }
done
export DISABLE_DEXPREOPT_CHECK=true
# Lineage: without this, userdebug gets ro.adb.secure=1 and ro.debuggable=0 (dev rungs need adb).
export WITH_ADB_INSECURE=true
# img_from_target_files is a host tool that target-files-package does not pull in.
m target-files-package img_from_target_files -j"${JOBS}"
rc=$?
echo "=== target-files rc=${rc} $(date)"
[[ ${rc} -eq 0 ]] || { echo "TARGET-FILES FAILED"; exit "${rc}"; }
TF="$(ls -t out/target/product/bluejay/obj/PACKAGING/target_files_intermediates/*target_files*.zip | head -1)"
echo "TF=${TF}"

mkdir -p "${PV_DEST}"
IMG="${PV_DEST}/vault_bluejay-img-${RUNG}.zip"
rm -f "${IMG}"
./out/host/linux-x86/bin/img_from_target_files "${TF}" "${IMG}.full" 2>&1 | tail -5
[[ -s "${IMG}.full" ]] || { echo "IMG FAILED"; exit 1; }

# Firmware is never ours to write (port-bluejay.md §8): drop the nine bootloader/radio images
# unconditionally, then require exactly the OS image set.
python3 - "${IMG}.full" "${IMG}" <<'PY'
import sys, zipfile
src, dst = sys.argv[1], sys.argv[2]
firmware = {f"{n}.img" for n in "abl bl1 bl2 bl31 gsa ldfw pbl tzsw modem".split()}
# Also never in the zip:
#   system_other.img  `fastboot update` writes it to the OTHER slot's system: that slot is the
#                     stock fallback and must stay untouched;
#   userdata.img      `fastboot -w` formats userdata instead of flashing a build-host image;
#   unsparse_super_empty.img  host-side duplicate of super_empty.img;
#   fastboot-info.txt newer fastboot follows it instead of the legacy flow, and it lists the
#                     images dropped here.
not_ours = firmware | {"system_other.img", "userdata.img", "unsparse_super_empty.img",
                       "fastboot-info.txt"}
allowed = {"android-info.txt", "super_empty.img"} | {
    f"{n}.img" for n in ("boot dtbo pvmfw vendor_boot vbmeta vbmeta_system vbmeta_vendor "
                         "system system_ext product vendor vendor_dlkm").split()}
required = allowed - {"super_empty.img", "pvmfw.img"}
with zipfile.ZipFile(src) as zin:
    names = zin.namelist()
    dropped = sorted(n for n in names if n in not_ours)
    kept = [n for n in names if n not in not_ours]
    extra = sorted(set(kept) - allowed)
    missing = sorted(required - set(kept))
    if extra or missing:
        sys.exit(f"image zip content wrong: extra={extra} missing={missing}")
    info = zin.read("android-info.txt").decode()
    for line in ("require board=bluejay",
                 "require version-bootloader=bluejay-17.0-15199431",
                 "require version-baseband=g5123b-145971-260414-B-15201439"):
        if line not in info.splitlines():
            sys.exit(f"android-info.txt lacks: {line}\n{info}")
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zout:
        for n in kept:
            zout.writestr(zin.getinfo(n), zin.read(n))
print("dropped:", dropped or "none present")
print("kept:", " ".join(sorted(kept)))
PY
[[ $? -eq 0 && -s "${IMG}" ]] || { echo "IMG CHECK FAILED"; exit 1; }
rm -f "${IMG}.full"

# Loose images for per-partition flashing of the current slot.
( cd "${PV_DEST}" && rm -rf images && mkdir images && cd images && unzip -q "../$(basename "${IMG}")" )

# No init_boot on bluejay: boot.img must carry the generic ramdisk with first-stage init.
UB="$(mktemp -d)"
./out/host/linux-x86/bin/unpack_bootimg --boot_img "${PV_DEST}/images/boot.img" --out "${UB}" >/dev/null \
  || { echo "BOOT CHECK FAILED: unpack"; exit 1; }
if ! ./out/host/linux-x86/bin/lz4 -dc "${UB}/ramdisk" 2>/dev/null \
    | ./out/host/linux-x86/bin/toybox cpio -t 2>/dev/null | grep -qx 'init'; then
  echo "BOOT CHECK FAILED: boot.img ramdisk has no /init"; exit 1
fi
echo "boot.img: kernel $(stat -c%s "${UB}/kernel") B, ramdisk $(stat -c%s "${UB}/ramdisk") B with /init"
rm -rf "${UB}"
cp "${TF}" "${PV_DEST}/vault_bluejay-target_files-${RUNG}.zip"

if [[ "${RUNG}" != b0 ]]; then
  # b1+: AVB is ours. vbmeta and the three chained partitions must carry the dev key, and
  # vbmeta's flags must be 0 (verification on).
  AVBTOOL=./out/host/linux-x86/bin/avbtool
  KEY=vendor/phonevault/keys/avb_bluejay_dev.pem
  "${AVBTOOL}" extract_public_key --key "${KEY}" --output "${PV_DEST}/avb_pkmd_bluejay_DEV.bin" \
    || { echo "AVB CHECK FAILED: cannot read ${KEY}"; exit 1; }
  want="$(sha1sum "${PV_DEST}/avb_pkmd_bluejay_DEV.bin" | cut -c1-40)"
  for img in vbmeta boot vbmeta_system vbmeta_vendor; do
    got="$("${AVBTOOL}" info_image --image "${PV_DEST}/images/${img}.img" | awk '/^Public key \(sha1\):/{print $4; exit}')"
    [[ "${got}" == "${want}" ]] || { echo "AVB CHECK FAILED: ${img}.img key ${got:-none} != ${want}"; exit 1; }
  done
  "${AVBTOOL}" info_image --image "${PV_DEST}/images/vbmeta.img" > "${PV_DEST}/avb-vbmeta-info.txt"
  [[ "$(awk '/^Flags:/{print $2; exit}' "${PV_DEST}/avb-vbmeta-info.txt")" == 0 ]] \
    || { echo "AVB CHECK FAILED: vbmeta flags are not 0"; grep '^Flags' "${PV_DEST}/avb-vbmeta-info.txt"; exit 1; }
  for img in boot vbmeta_system vbmeta_vendor; do
    { echo "== ${img}.img"; "${AVBTOOL}" info_image --image "${PV_DEST}/images/${img}.img"; } >> "${PV_DEST}/avb-vbmeta-info.txt"
  done
  echo "AVB: vbmeta/boot/vbmeta_system/vbmeta_vendor signed by key sha1 ${want}, vbmeta flags 0"

  # b1+: no launcher; the signer is never scanned stopped; no Lineage Trust.
  if unzip -l "${TF}" | grep -E 'Launcher3QuickStep|Launcher3Overlay|/Trebuchet'; then
    echo "OVERRIDE CHECK FAILED: launcher still in the image"; exit 1
  fi
  for f in PRODUCT/etc/sysconfig/phonevault-initial-package-state.xml \
           PRODUCT/etc/sysconfig/phonevault-no-lineage-trust.xml; do
    unzip -l "${TF}" "${f}" >/dev/null 2>&1 || { echo "MISSING in target files: ${f}"; exit 1; }
  done
  echo "product RROs:"; unzip -l "${TF}" 'PRODUCT/overlay/*' | awk '{print $4}' | grep -i -E 'systemui|lineage|platform|framework-res' || true

  # The Mac flashes from the bootloader only (fastbootd writes fail on macOS): a ready sparse
  # super.img with slot a populated, built from these target files.
  PATH="${TREE}/out/host/linux-x86/bin:${PATH}" python3 build/make/tools/releasetools/build_super_image.py \
    "${TF}" "${PV_DEST}/super.img" > "${PV_DEST}/super-build.log" 2>&1 \
    || { echo "SUPER IMAGE FAILED"; tail -20 "${PV_DEST}/super-build.log"; exit 1; }
  ls -la "${PV_DEST}/super.img"
  install -m 0755 "${SCRIPT_DIR}/flash-mac.sh" "${PV_DEST}/flash-${RUNG}-mac.sh"
fi

# b2+: the rung's own artifact gate (kernel modules, cmdline, overrides, expect-build.txt).
if [[ "${RUNG}" != b0 && "${RUNG}" != b1 ]]; then
  bash "${SCRIPT_DIR}/check-build.sh" "${RUNG}" "${PV_DEST}/vault_bluejay-target_files-${RUNG}.zip" \
    "${PV_DEST}" "${TREE}" | tee "${PV_DEST}/check-build.txt"
  [[ ${PIPESTATUS[0]} -eq 0 ]] || { echo "RUNG CHECK FAILED (see ${PV_DEST}/check-build.txt)"; exit 1; }
fi
( cd "${PV_DEST}" && find . -type f ! -name SHA256SUMS | sed 's#^\./##' | sort | xargs sha256sum > SHA256SUMS )
cat "${PV_DEST}/SHA256SUMS"
echo "=== ALL DONE $(date)"
