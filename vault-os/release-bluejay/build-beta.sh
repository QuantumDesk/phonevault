#!/usr/bin/env bash
# Build one Phone Vault bluejay BETA (a `user` build) on the native Linux build host, after
# sync-beta.sh: target files -> firmware-free image set, sparse super.img, the Mac flash script,
# SHA256SUMS and manifest.json, then every gate that applies to bluejay today.
#   build-beta.sh BETA [TREE] DEST
#     TREE  the synced LineageOS 24.0 bluejay tree (default: $LINEAGE_TREE)
#     DEST  output directory (e.g. /build/out-beta1)
# Environment: PV_BETA_KEY_DIR (default $HOME/.phonevault-keys/beta; public parts only are read
# here), PV_JOBS (default 24).
# Run as the tree owner. No `set -u`: envsetup/lunch use unset variables.
set -o pipefail
BETA="${1:?usage: build-beta.sh BETA TREE DEST}"
TREE="${2:-${LINEAGE_TREE:-}}"
PV_DEST="${3:?usage: build-beta.sh BETA TREE DEST}"   # lunch exports OUT/OUT_DIR: never reuse those names
[[ -n "${TREE}" ]] || { echo "usage: build-beta.sh BETA TREE DEST" >&2; exit 2; }
JOBS="${PV_JOBS:-24}"
KEY_DIR="${PV_BETA_KEY_DIR:-${HOME}/.phonevault-keys/beta}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OVERLAY="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT="$(cd "${OVERLAY}/.." && pwd)"
GATES="${OVERLAY}/scripts"
fail() { echo "BETA BUILD FAILED: $*"; exit 1; }
cd "${TREE}" || exit 9
export LC_ALL=C
# A beta is never built with the dev rungs' adb conveniences.
unset PV_DEV_ADB_KEY WITH_ADB_INSECURE PV_AVB_KEY_DIR

mkdir -p "${PV_DEST}"
CONFIG="${PV_DEST}/beta-config"
bash "${SCRIPT_DIR}/resolve-beta.sh" "${BETA}" "${CONFIG}" || fail "resolve ${BETA}"
# The tree must carry exactly the resolved beta (sync-beta.sh): a stale dev rung sync would
# otherwise build silently.
for pair in common.mk:vendor/phonevault/config/common.mk \
            BoardConfigVault.mk:vendor/phonevault/config/BoardConfigVault.mk \
            Android.bp:vendor/phonevault/prebuilt/Android.bp \
            config.xml:vendor/phonevault/overlay/frameworks/base/core/res/res/values/config.xml; do
  f="${pair%%:*}"; t="${pair#*:}"
  [[ -f "${CONFIG}/${f}" ]] || continue
  cmp -s "${CONFIG}/${f}" "${t}" || fail "${t} is not ${BETA}'s ${f}: run sync-beta.sh ${BETA} first"
done
[[ ! -e vendor/phonevault/config/debug_adbkey.pub ]] || fail "dev adb key in the tree: run sync-beta.sh"
[[ ! -e vendor/phonevault/keys/avb_bluejay_dev.pem ]] || fail "dev AVB key link in the tree: run sync-beta.sh"
for rp in "${OVERLAY}"/patches/bootable-recovery/*.patch; do
  git -C bootable/recovery apply --reverse --check "${rp}" 2>/dev/null \
    || fail "recovery hardening not applied in the tree: $(basename "${rp}")"
done
for fp in "${OVERLAY}"/patches/frameworks-base-a17/*.patch; do
  git -C frameworks/base apply --reverse --check "${fp}" 2>/dev/null \
    || fail "frameworks/base patch not applied in the tree: $(basename "${fp}") (run sync-beta.sh)"
done

# shellcheck disable=SC1091
source build/envsetup.sh
lunch vault_bluejay-cp2a-user
[[ "${TARGET_PRODUCT:-}" == vault_bluejay && "${TARGET_BUILD_VARIANT:-}" == user ]] \
  || fail "lunch did not select vault_bluejay user (${TARGET_PRODUCT:-?}-${TARGET_BUILD_VARIANT:-?})"
echo "=== BLUEJAY BETA ${BETA} BUILD START $(date) product=${TARGET_PRODUCT} variant=${TARGET_BUILD_VARIANT}"

# Switching from the userdebug rungs: drop everything staged for the previous variant (the build
# also does this when previous_build_config.mk changes; explicit here so no userdebug-only file,
# adb_keys or debug ramdisk payload can survive into the user images).
# PV_BETA_NO_INSTALLCLEAN=1 skips it when re-running a beta whose previous build was already this
# user variant (previous_build_config.mk must say so).
PV_PRODUCT_OUT="out/target/product/bluejay"
if [[ "${PV_BETA_NO_INSTALLCLEAN:-}" == 1 ]]; then
  grep -qx 'PREVIOUS_BUILD_CONFIG := vault_bluejay-user' "${PV_PRODUCT_OUT}/previous_build_config.mk" \
    || fail "PV_BETA_NO_INSTALLCLEAN=1 but the out dir was last built as another variant"
  echo "   installclean skipped (out dir already vault_bluejay-user)"
else
  m installclean || fail "installclean"
fi
mapfile -t PV_OVERRIDES < <(python3 "${GATES}/vaultgate.py" overrides list vendor/phonevault/prebuilt/Android.bp)
for d in "${PV_PRODUCT_OUT}"/{system,system_ext,product,vendor,odm}/{app,priv-app}/*/; do
  [[ -d "${d}" ]] || continue
  name="$(basename "${d}")"
  if ! compgen -G "${d}*.apk" >/dev/null || printf '%s\n' "${PV_OVERRIDES[@]}" | grep -Fqx "${name}"; then
    echo "   scrub app dir: ${d}"; rm -rf "${d}"
  fi
done
for d in "${PV_PRODUCT_OUT}"/obj/PACKAGING/vendor_ramdisk_fragment-stage-*_intermediates \
         "${PV_PRODUCT_OUT}"/obj/PACKAGING/depmod_vendor_ramdisk*_intermediates; do
  [[ -d "${d}" ]] && { echo "   scrub ramdisk module staging: ${d}"; rm -rf "${d}"; }
done
export DISABLE_DEXPREOPT_CHECK=true
m target-files-package img_from_target_files -j"${JOBS}"
rc=$?
echo "=== target-files rc=${rc} $(date)"
[[ ${rc} -eq 0 ]] || fail "target-files-package (rc ${rc})"
TF_BUILT="$(ls -t "${PV_PRODUCT_OUT}"/obj/PACKAGING/target_files_intermediates/*target_files*.zip | head -1)"
echo "TF=${TF_BUILT}"
TF="${PV_DEST}/vault_bluejay-target_files-${BETA}.zip"
cp "${TF_BUILT}" "${TF}"

IMG="${PV_DEST}/vault_bluejay-img-${BETA}.zip"
rm -f "${IMG}" "${IMG}.full"
./out/host/linux-x86/bin/img_from_target_files "${TF}" "${IMG}.full" 2>&1 | tail -5
[[ -s "${IMG}.full" ]] || fail "img_from_target_files"
# Firmware is never ours to write: drop the nine bootloader/radio images, require exactly the OS
# image set (as dev-ladder-bluejay/build-rung.sh).
python3 - "${IMG}.full" "${IMG}" <<'PY' || fail "image zip content"
import sys, zipfile
src, dst = sys.argv[1], sys.argv[2]
firmware = {f"{n}.img" for n in "abl bl1 bl2 bl31 gsa ldfw pbl tzsw modem".split()}
not_ours = firmware | {"system_other.img", "userdata.img", "unsparse_super_empty.img", "fastboot-info.txt"}
allowed = {"android-info.txt", "super_empty.img"} | {
    f"{n}.img" for n in ("boot dtbo pvmfw vendor_boot vbmeta vbmeta_system vbmeta_vendor "
                         "system system_ext product vendor vendor_dlkm").split()}
required = allowed - {"super_empty.img", "pvmfw.img"}
with zipfile.ZipFile(src) as zin:
    names = zin.namelist()
    kept = [n for n in names if n not in not_ours]
    extra, missing = sorted(set(kept) - allowed), sorted(required - set(kept))
    if extra or missing:
        sys.exit(f"image zip content wrong: extra={extra} missing={missing}")
    info = zin.read("android-info.txt").decode()
    for line in ("require board=bluejay", "require version-bootloader=bluejay-17.0-15199431",
                 "require version-baseband=g5123b-145971-260414-B-15201439"):
        if line not in info.splitlines():
            sys.exit(f"android-info.txt lacks: {line}")
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zout:
        for n in kept:
            zout.writestr(zin.getinfo(n), zin.read(n))
print("kept:", " ".join(sorted(kept)))
PY
rm -f "${IMG}.full"
( cd "${PV_DEST}" && rm -rf images && mkdir images && cd images && unzip -q "../$(basename "${IMG}")" )

HOSTBIN="${TREE}/out/host/linux-x86/bin"
REPORT="${PV_DEST}/beta-checks.txt"
: > "${REPORT}"
note() { echo "$*" | tee -a "${REPORT}"; }

# ---- boot.img: generic ramdisk with first-stage init (no init_boot on bluejay) ----
UB="$(mktemp -d)"
"${HOSTBIN}/unpack_bootimg" --boot_img "${PV_DEST}/images/boot.img" --out "${UB}" > "${UB}/info.txt" \
  || fail "unpack boot.img"
"${HOSTBIN}/lz4" -dc "${UB}/ramdisk" 2>/dev/null | "${HOSTBIN}/toybox" cpio -t 2>/dev/null | grep -qx init \
  || fail "boot.img ramdisk has no /init"
BOOT_CMDLINE="$(sed -n 's/^command line args: *//p' "${UB}/info.txt" | head -1)"
rm -rf "${UB}"
# ---- kernel command line: vendor_boot cmdline + bootconfig ----
UV="$(mktemp -d)"
"${HOSTBIN}/unpack_bootimg" --boot_img "${PV_DEST}/images/vendor_boot.img" --out "${UV}" > "${UV}/info.txt" 2>&1 \
  || fail "unpack vendor_boot.img"
VENDOR_CMDLINE="$(grep -i 'vendor command line args' "${UV}/info.txt" | head -1 | sed 's/^[^:]*: *//')"
BOOTCONFIG="$(cat "${UV}/bootconfig" 2>/dev/null | tr '\n' ' ')"
rm -rf "${UV}"
ALL_CMDLINE="${BOOT_CMDLINE} ${VENDOR_CMDLINE} ${BOOTCONFIG}"
note "kernel cmdline (vendor_boot): ${VENDOR_CMDLINE}"
note "kernel cmdline (boot):        ${BOOT_CMDLINE:-<empty>}"
note "bootconfig (vendor_boot):     ${BOOTCONFIG:-<empty>}"
for bad in earlycon= console= androidboot.console= printk.devkmsg=; do
  for w in ${ALL_CMDLINE}; do [[ "${w}" == ${bad}* ]] && fail "kernel command line still has ${w}"; done
done
grep -qw 'usbcore.authorized_default=0' <<<"${VENDOR_CMDLINE}" || fail "usbcore.authorized_default=0 missing"
note "OK   kernel cmdline: no earlycon/console/androidboot.console/printk.devkmsg; usbcore.authorized_default=0"

# ---- AVB: beta key on vbmeta + the three chained partitions, flags 0, project rollback index ----
AVBTOOL="${HOSTBIN}/avbtool"
"${AVBTOOL}" extract_public_key --key vendor/phonevault/keys/avb_bluejay_beta.pem \
  --output "${PV_DEST}/avb_pkmd_bluejay_BETA.bin" || fail "cannot read the beta AVB key"
want="$(sha1sum "${PV_DEST}/avb_pkmd_bluejay_BETA.bin" | cut -c1-40)"
cmp -s "${PV_DEST}/avb_pkmd_bluejay_BETA.bin" "${KEY_DIR}/avb_pkmd_bluejay_BETA.bin" \
  || fail "tree's AVB key is not the beta key in ${KEY_DIR}"
DEV_AVB_SHA1=af09b166ade90fb31a184e9ab6c59819cd33fc8a   # the dev key (dev-ladder-bluejay/README.md)
[[ "${want}" != "${DEV_AVB_SHA1}" ]] || fail "the beta AVB key is the dev key"
want_index="$(sed -n 's/^PHONEVAULT_AVB_ROLLBACK_INDEX := *//p' vendor/phonevault/config/release-version.mk)"
: > "${PV_DEST}/avb-info.txt"
for img in vbmeta boot vbmeta_system vbmeta_vendor; do
  info="$("${AVBTOOL}" info_image --image "${PV_DEST}/images/${img}.img")" || fail "avbtool ${img}"
  { echo "== ${img}.img"; echo "${info}"; } >> "${PV_DEST}/avb-info.txt"
  got="$(awk '/^Public key \(sha1\):/{print $4; exit}' <<<"${info}")"
  [[ "${got}" == "${want}" ]] || fail "${img}.img signed by ${got:-nothing}, not the beta key ${want}"
  idx="$(awk '/^Rollback Index:/{print $3; exit}' <<<"${info}")"
  [[ "${idx}" == "${want_index}" ]] || fail "${img}.img rollback index ${idx} != ${want_index}"
done
[[ "$(awk '/^Flags:/{print $2; exit}' "${PV_DEST}/avb-info.txt")" == 0 ]] || fail "vbmeta flags are not 0"
note "OK   AVB: vbmeta/boot/vbmeta_system/vbmeta_vendor signed by the BETA key (pkmd sha1 ${want}), flags 0, rollback index ${want_index}"

# ---- signer app: release build, beta app certificate ----
APP_CERT_WANT="$(openssl x509 -in "${KEY_DIR}/phonevault-app-BETA.x509.pem" -outform DER | sha256sum | cut -c1-64)"
APK_TMP="$(mktemp --suffix=.apk)"
unzip -p "${TF}" PRODUCT/app/PhoneVault/PhoneVault.apk > "${APK_TMP}" || fail "no PRODUCT/app/PhoneVault/PhoneVault.apk"
TOOLS="${TREE}/prebuilts/sdk/tools/linux"
PATH="${TREE}/prebuilts/jdk/jdk21/linux-x86/bin:${PATH}" \
PHONEVAULT_AAPT="${TOOLS}/bin/aapt" PHONEVAULT_APKSIGNER="${TREE}/out/host/linux-x86/bin/apksigner" \
  "${GATES}/verify-signer-apk.sh" "${APK_TMP}" "${APP_CERT_WANT}" > "${PV_DEST}/signer-apk.txt" 2>&1 \
  || { cat "${PV_DEST}/signer-apk.txt"; fail "signer APK in the image is not the beta-signed release build"; }
APP_SHA="$(sha256sum "${APK_TMP}" | cut -c1-64)"
APP_VERSION="$("${TOOLS}/bin/aapt" dump badging "${APK_TMP}" | sed -n "s/.*versionName='\([^']*\)'.*/\1/p" | head -1)"
rm -f "${APK_TMP}"
note "OK   signer app: release variant, cert ${APP_CERT_WANT} (beta app key), apk sha256 ${APP_SHA}, version ${APP_VERSION}"

# ---- recovery: hardened source in the tree (step 7 of sync-beta.sh) ----
note "OK   recovery: $(ls "${OVERLAY}"/patches/bootable-recovery/*.patch | xargs -n1 basename) applied to bootable/recovery (recovery binary in VENDOR_BOOT/RAMDISK/system/bin/recovery)"

# ---- USB charging composition (frameworks-base-a17 0006): the compiled overlay carries the
# beta's value. With it true, the no-adb charging composition is the accessory function. ----
USB_RES=config_usbChargingFunctionsAccessory
if grep -Eq "<bool name=\"${USB_RES}\">true</bool>" "${CONFIG}/config.xml" 2>/dev/null; then
  RES_TMP="$(mktemp -d)"
  unzip -q -o "${TF}" SYSTEM/framework/framework-res.apk \
    "PRODUCT/overlay/framework-res__vault_bluejay__auto_generated_rro_product.apk" -d "${RES_TMP}" \
    || fail "framework-res.apk / its product RRO missing from the target files"
  "${TOOLS}/bin/aapt" dump resources "${RES_TMP}/SYSTEM/framework/framework-res.apk" \
    | grep -Eq "android:bool/${USB_RES}: t=0x12 d=0x00000000 " \
    || fail "framework-res.apk lacks ${USB_RES} (default false): frameworks-base-a17 0006 not built"
  rro="$("${TOOLS}/bin/aapt" dump resources \
    "${RES_TMP}/PRODUCT/overlay/framework-res__vault_bluejay__auto_generated_rro_product.apk" \
    | grep -E "bool/${USB_RES}: t=0x12 ")"
  rm -rf "${RES_TMP}"
  [[ -n "${rro}" ]] && ! grep -q 'd=0x00000000' <<<"${rro}" \
    || fail "product RRO does not set ${USB_RES}=true: ${rro:-<absent>}"
  note "OK   USB: ${USB_RES}=true in the product RRO (charging composition without adb = accessory, 18d1:2d00)"
fi

# ---- release gates ----
echo "== gate: production target files (user build, adb, props, init, debug ramdisk)"
"${GATES}/verify-production-target-files.sh" "${TF}" 2>&1 | tee "${PV_DEST}/gate-production.txt"
[[ ${PIPESTATUS[0]} -eq 0 ]] || fail "production target-files gate"
note "OK   gate verify-production-target-files.sh"
echo "== gate: release source (bluejay beta ${BETA})"
"${GATES}/verify-release-source.sh" "${ROOT}" --bluejay-beta "${BETA}" 2>&1 | tee "${PV_DEST}/gate-release-source.txt"
[[ ${PIPESTATUS[0]} -eq 0 ]] || fail "release-source gate"
note "OK   gate verify-release-source.sh --bluejay-beta ${BETA}"
echo "== gate: release overrides (${BETA}'s Android.bp)"
"${GATES}/verify-release-overrides.sh" "${TF}" "${ROOT}" "${CONFIG}/Android.bp" 2>&1 | tee "${PV_DEST}/gate-overrides.txt"
[[ ${PIPESTATUS[0]} -eq 0 ]] || fail "release overrides gate"
note "OK   gate verify-release-overrides.sh (${CONFIG}/Android.bp)"
echo "== gate: bluejay artifact checks (b2..b4d-1 + beta expectations)"
bash "${OVERLAY}/dev-ladder-bluejay/check-build.sh" "${CONFIG}" "${TF}" "${PV_DEST}" "${TREE}" \
  | tee "${PV_DEST}/check-build.txt"
[[ ${PIPESTATUS[0]} -eq 0 ]] || fail "check-build (see ${PV_DEST}/check-build.txt)"
note "OK   check-build.sh (kernel modules, cmdline, overrides, expect-build.txt)"

# ---- the Mac flashes from the bootloader only: sparse super.img + flash script ----
PATH="${HOSTBIN}:${PATH}" python3 build/make/tools/releasetools/build_super_image.py \
  "${TF}" "${PV_DEST}/super.img" > "${PV_DEST}/super-build.log" 2>&1 \
  || { tail -20 "${PV_DEST}/super-build.log"; fail "super.img"; }
install -m 0755 "${OVERLAY}/dev-ladder-bluejay/flash-mac.sh" "${PV_DEST}/flash-${BETA}-mac.sh"

# ---- manifest.json (machine-readable, for a future web installer) + SHA256SUMS ----
BUILD_PROP="$(unzip -p "${TF}" SYSTEM/build.prop)"
prop() { sed -n "s/^$1=//p" <<<"${BUILD_PROP}" | head -1; }
python3 - "${PV_DEST}" "${BETA}" <<PY || fail "manifest.json"
import hashlib, json, os, sys
dest, beta = sys.argv[1], sys.argv[2]
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
def entry(rel):
    p = os.path.join(dest, rel)
    return {"file": rel, "size": os.path.getsize(p), "sha256": sha(p)}
slot = ["boot", "vendor_boot", "dtbo", "pvmfw", "vbmeta", "vbmeta_system", "vbmeta_vendor"]
m = {
  "schema": "phonevault-image-manifest/1",
  "channel": "beta", "variant": beta,
  "product": "vault_bluejay", "device": "bluejay", "model": "Pixel 6a",
  "build": {
    "type": "$(prop ro.build.type)", "id": "$(prop ro.build.id)",
    "incremental": "$(prop ro.build.version.incremental)",
    "fingerprint": "$(prop ro.system.build.fingerprint)",
    "tags": "$(prop ro.build.tags)", "date_utc": "$(prop ro.build.date.utc)",
    "security_patch": "$(prop ro.build.version.security_patch)",
    "phonevault_version": "$(sed -n 's/^PHONEVAULT_VERSION := *//p' vendor/phonevault/config/common.mk)",
  },
  "requires": {"product": "bluejay", "bootloader": "bluejay-17.0-15199431",
               "baseband": "g5123b-145971-260414-B-15201439", "unlocked": True},
  "avb": {"algorithm": "SHA256_RSA4096", "key": "BETA-TEST (build host)",
          "public_key_blob": entry("avb_pkmd_bluejay_BETA.bin"),
          "public_key_blob_sha1": "${want}", "rollback_index": ${want_index}, "vbmeta_flags": 0},
  "app": {"package": "dev.phonevault.signer", "variant": "release", "version": "${APP_VERSION}",
          "cert_sha256": "${APP_CERT_WANT}", "key": "BETA-TEST (build host)", "apk_sha256": "${APP_SHA}"},
  "flash": {
    "method": "bootloader-only (no fastbootd); slot a; firmware, bootloader, radio and avb_custom_key untouched",
    "steps": [{"op": "flash", "partition": p, "slot": "a", **entry(f"images/{p}.img")} for p in slot]
             + [{"op": "flash", "partition": "super", **entry("super.img")},
                {"op": "erase", "partition": "metadata"},
                {"op": "wipe-userdata"},
                {"op": "set-active", "slot": "a"},
                {"op": "reboot"}],
  },
  "images": [entry(os.path.join("images", n)) for n in sorted(os.listdir(os.path.join(dest, "images")))]
            + [entry("super.img")],
  "target_files": entry(f"vault_bluejay-target_files-{beta}.zip"),
  "image_zip": entry(f"vault_bluejay-img-{beta}.zip"),
}
with open(os.path.join(dest, "manifest.json"), "w") as f:
    json.dump(m, f, indent=2); f.write("\n")
print("manifest.json:", m["build"]["fingerprint"])
PY
( cd "${PV_DEST}" && find . -type f ! -name SHA256SUMS | sed 's#^\./##' | sort | xargs sha256sum > SHA256SUMS )
cat "${REPORT}"
cat "${PV_DEST}/SHA256SUMS"
echo "=== ALL DONE $(date)"
