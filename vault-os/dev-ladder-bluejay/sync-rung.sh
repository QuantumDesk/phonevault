#!/usr/bin/env bash
# Sync the Phone Vault product into the Pixel 6a (bluejay) LineageOS 24.0 tree and apply one
# bluejay rung's deviations. Never touches the crosshatch lineage-22.2 tree.
#   sync-rung.sh RUNG [TREE] [APK] [KERNEL_DIST]
#     RUNG         b0, b1, … (directory dev-ladder-bluejay/rung-RUNG)
#     TREE         default /build/lineage-24 (the real path; /root/lineage-24 is a symlink)
#     APK          signer APK to bake as vendor/phonevault/prebuilt/PhoneVault.apk
#     KERNEL_DIST  Kleaf dist dir, default /build/gs-6.1-kernel/out/bluejay/dist
# Run as the tree owner (aipg). Development images only. See dev-ladder-bluejay/README.md.
set -euo pipefail

RUNG="${1:?rung (b0, b1, …)}"
TREE="${2:-/build/lineage-24}"
APK="${3:-}"
KDIST="${4:-/build/gs-6.1-kernel/out/bluejay/dist}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OVERLAY="${ROOT}/vault-os"
RUNG_DIR="${OVERLAY}/dev-ladder-bluejay/rung-${RUNG}"
[[ -d "${RUNG_DIR}" ]] || { echo "no such rung: ${RUNG_DIR}" >&2; exit 2; }
[[ -d "${TREE}/build" && -d "${TREE}/device/google/bluejay" ]] \
  || { echo "not a Lineage bluejay tree: ${TREE}" >&2; exit 2; }

echo "== release product → tree (bluejay only)"
mkdir -p "${TREE}/device/phonevault/bluejay" "${TREE}/vendor/phonevault"
rsync -a --delete "${OVERLAY}/device/phonevault/bluejay/" "${TREE}/device/phonevault/bluejay/"
# keys/ is never synced (and, excluded, never deleted): rung b1+ reads the AVB dev key through
# the tree-local symlink vendor/phonevault/keys/avb_bluejay_dev.pem (see README).
# The SystemUI overlay (config_phonevaultHideKeyguardClock) ships since b1, when frameworks/base
# 0005 was rebased to Android 17 (patches/frameworks-base-a17/0005).
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

# Upstream trees: each rung carries exactly its own edits. Every tree below is restored to
# upstream (tracked files only: the kernel dir's untracked Kleaf dist and vendor/google/bluejay's
# LFS blobs stay), then the rung's diff for it, if any, is applied:
#   device-google-bluejay.diff          device/google/bluejay        (b4a+: eSE VINTF entry)
#   device-google-gs101.diff            device/google/gs101          (b3+: features, b4a+: BT VINTF)
#   vendor-google-bluejay.diff          vendor/google/bluejay        (b3+: USB rc/ueventd, b4a+: radio rc)
#   device-google-bluejay-kernels.diff  device/google/bluejay-kernels (b4a+: the tracked module lists)
# Then the BoardConfigVault include is appended to bluejay/BoardConfig.mk (the one standing edit).
DEV="${TREE}/device/google/bluejay"
for repo in device/google/bluejay device/google/gs101 vendor/google/bluejay device/google/bluejay-kernels; do
  dir="${TREE}/${repo}"
  diff_file="${RUNG_DIR}/${repo//\//-}.diff"
  [[ -d "${dir}/.git" || -f "${dir}/.git" ]] || { echo "not a git checkout: ${dir}" >&2; exit 2; }
  if ! git -C "${dir}" diff --quiet; then
    git -C "${dir}" checkout -- .
    echo "   ${repo} restored to upstream"
  fi
  if [[ -s "${diff_file}" ]]; then
    git -C "${dir}" apply --check "${diff_file}"
    git -C "${dir}" apply "${diff_file}"
    echo "   ${repo}: $(basename "${diff_file}") applied"
  fi
done
BOARD="${DEV}/bluejay/BoardConfig.mk"
INCLUDE='include vendor/phonevault/config/BoardConfigVault.mk'
printf '\n# Phone Vault product board policy (after every upstream board setting)\n%s\n' \
  "${INCLUDE}" >> "${BOARD}"
echo "   appended BoardConfigVault include to bluejay/BoardConfig.mk"

# Android 17 rebases of the release frameworks/base patches (patches/frameworks-base-a17). The
# Android 15 series in patches/frameworks-base does not apply to this tree.
FWB="${TREE}/frameworks/base"
for fp in "${OVERLAY}"/patches/frameworks-base-a17/*.patch; do
  [[ -f "${fp}" ]] || continue
  # A tree that carries an older revision of a patch (b1 extended 0003) fails both checks:
  # `git -C frameworks/base checkout -- <its files>` first, then re-run.
  if git -C "${FWB}" apply --reverse --check "${fp}" >/dev/null 2>&1; then
    echo "   frameworks/base patch present: $(basename "${fp}")"
  elif git -C "${FWB}" apply --check "${fp}" >/dev/null 2>&1; then
    git -C "${FWB}" apply "${fp}"; echo "   frameworks/base patch applied: $(basename "${fp}")"
  else
    echo "frameworks/base patch neither applies nor reverses cleanly: ${fp}" >&2; exit 1
  fi
done

# Kernel: Lineage 24.0 ships no kernel prebuilts. Copy the Kleaf dist (boot.img, dtbo.img,
# dtb.img, *.ko, …: everything the kernels repo .gitignore lists) into the kernel dir. The four
# tracked list files are the stripping lever of later rungs: never overwrite them, only report
# when the fresh dist disagrees.
KDIR="${TREE}/device/google/bluejay-kernels/6.1"
if [[ -d "${KDIST}" ]]; then
  [[ -s "${KDIST}/boot.img" ]] || { echo "kernel dist has no boot.img: ${KDIST}" >&2; exit 1; }
  TRACKED=(modules.load vendor_dlkm.modules.load vendor_dlkm.modules.blocklist init.insmod.bluejay.cfg)
  excl=(); for f in "${TRACKED[@]}"; do excl+=(--exclude "/${f}"); done
  rsync -a "${excl[@]}" "${KDIST}/" "${KDIR}/"
  for f in "${TRACKED[@]}"; do
    if [[ -f "${KDIST}/${f}" ]] && ! cmp -s "${KDIST}/${f}" "${KDIR}/${f}"; then
      echo "   NOTE kernel list differs from dist (tracked copy kept): ${f}"
    fi
  done
  echo "   kernel dist → bluejay-kernels/6.1 ($(ls "${KDIR}"/*.ko | wc -l) modules," \
    "boot.img $(sha256sum "${KDIR}/boot.img" | cut -c1-16)…)"
else
  [[ -s "${KDIR}/boot.img" ]] || { echo "no kernel dist (${KDIST}) and no boot.img in ${KDIR}" >&2; exit 1; }
  echo "   kernel: keeping existing prebuilts in bluejay-kernels/6.1"
fi

if [[ -n "${APK}" ]]; then
  [[ -s "${APK}" ]] || { echo "APK not found: ${APK}" >&2; exit 1; }
  install -m 0644 "${APK}" "${TREE}/vendor/phonevault/prebuilt/PhoneVault.apk"
  echo "   baked signer APK $(sha256sum "${APK}" | cut -c1-16)…"
fi
[[ -s "${TREE}/vendor/phonevault/prebuilt/PhoneVault.apk" ]] \
  || { echo "no PhoneVault.apk in the tree: pass APK" >&2; exit 1; }
echo "== bluejay rung ${RUNG} synced"
