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
cd "${TREE}" || exit 9
export LC_ALL=C
# shellcheck disable=SC1091
source build/envsetup.sh
lunch vault_bluejay-cp2a-userdebug
[[ -n "${TARGET_PRODUCT:-}" ]] || { echo "LUNCH FAILED"; exit 8; }
echo "=== BLUEJAY RUNG ${RUNG} BUILD START $(date) product=${TARGET_PRODUCT} variant=${TARGET_BUILD_VARIANT}"
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
( cd "${PV_DEST}" && find . -type f ! -name SHA256SUMS | sed 's#^\./##' | sort | xargs sha256sum > SHA256SUMS )
cat "${PV_DEST}/SHA256SUMS"
echo "=== ALL DONE $(date)"
