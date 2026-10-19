#!/usr/bin/env bash
# Sync one Phone Vault bluejay BETA configuration into the LineageOS 24.0 bluejay tree.
#   sync-beta.sh BETA [TREE] APK [KERNEL_DIST]
#     BETA         release-bluejay/BETA (beta1, beta1-novoice, ...), resolved by resolve-beta.sh
#     TREE         the LineageOS 24.0 bluejay tree (default: $LINEAGE_TREE)
#     APK          the signer app RELEASE build signed with the beta app key (sign-beta-apk.sh);
#                  required: a beta never bakes whatever APK a dev rung left in the tree
#     KERNEL_DIST  Kleaf dist dir (default: $PV_KERNEL_DIST); without one the tree's kernel
#                  prebuilts are kept
# Environment:
#     PV_BETA_KEY_DIR  directory holding phonevault_bluejay_avb_BETA_rsa4096.pem and
#                      phonevault-app-BETA.x509.pem (default: $HOME/.phonevault-keys/beta)
# Run as the tree owner. Unlike dev-ladder-bluejay/sync-rung.sh this takes NO adb key
# (PV_DEV_ADB_KEY is neither needed nor read) and no dev AVB key: it removes both from the tree.
#
# What it does to the tree (the same steps as sync-rung.sh, plus 4b and 7):
#   1. release gate: scripts/verify-release-source.sh --bluejay-beta BETA (no dev deviation);
#   2. rsync device/phonevault/bluejay and vendor/phonevault from the repo (deletes the dev
#      rungs' vendor/phonevault/config/debug_adbkey.pub), never keys/ or the APK;
#   3. AVB: vendor/phonevault/keys/avb_bluejay_beta.pem -> the beta key; the dev key's link
#      vendor/phonevault/keys/avb_bluejay_dev.pem is removed (sync-rung.sh re-creates it from
#      PV_AVB_KEY_DIR for the next dev rung);
#   4. the resolved beta files over their targets (common.mk, BoardConfigVault.mk, Android.bp,
#      config.xml); 4b. no adb key file anywhere under vendor/phonevault or device/phonevault;
#   5. device/google/{bluejay,gs101}, vendor/google/bluejay, device/google/bluejay-kernels
#      restored to upstream, then the resolved diffs, then the BoardConfigVault include;
#   6. patches/frameworks-base-a17 (0003 owner provisioning, 0004 resource export, 0005 keyguard
#      clock): present or applied, as on every rung;
#   7. bootable/recovery restored to upstream, then patches/bootable-recovery (user-build
#      recovery: no "Install anyway?", no recovery adbd, no Enable-ADB/mount/format items);
#   8. the Kleaf dist, if given (the four tracked list files are never overwritten);
#   9. the APK, after scripts/verify-signer-apk.sh against the beta app certificate.
# To go back to a dev rung afterwards: sync-rung.sh RUNG (it resets steps 2-6 itself). The
# recovery patch is inert on userdebug (it keys on ro.debuggable), but for byte-identical dev
# rungs restore it too: git -C $TREE/bootable/recovery checkout -- .
set -euo pipefail

BETA="${1:?usage: sync-beta.sh BETA TREE APK [KERNEL_DIST]}"
TREE="${2:-${LINEAGE_TREE:?usage: sync-beta.sh BETA TREE APK [KERNEL_DIST]}}"
APK="${3:?usage: sync-beta.sh BETA TREE APK [KERNEL_DIST] (APK = beta-signed release build)}"
KDIST="${4:-${PV_KERNEL_DIST:-}}"
KEY_DIR="${PV_BETA_KEY_DIR:-${HOME}/.phonevault-keys/beta}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OVERLAY="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT="$(cd "${OVERLAY}/.." && pwd)"
[[ -d "${TREE}/build" && -d "${TREE}/device/google/bluejay" ]] \
  || { echo "not a Lineage bluejay tree: ${TREE}" >&2; exit 2; }
unset PV_DEV_ADB_KEY PV_AVB_KEY_DIR

echo "== 1. release-source gate (bluejay beta ${BETA})"
"${OVERLAY}/scripts/verify-release-source.sh" "${ROOT}" --bluejay-beta "${BETA}"

RESOLVED="$(mktemp -d)"
trap 'rm -rf "${RESOLVED}"' EXIT
bash "${SCRIPT_DIR}/resolve-beta.sh" "${BETA}" "${RESOLVED}"

echo "== 2. release product -> tree (bluejay only)"
mkdir -p "${TREE}/device/phonevault/bluejay" "${TREE}/vendor/phonevault"
rsync -a --delete "${OVERLAY}/device/phonevault/bluejay/" "${TREE}/device/phonevault/bluejay/"
rsync -a --delete --exclude 'keys/' --exclude 'prebuilt/PhoneVault.apk' \
  "${OVERLAY}/vendor/phonevault/" "${TREE}/vendor/phonevault/"

echo "== 3. AVB beta key"
AVB_KEY="${KEY_DIR}/phonevault_bluejay_avb_BETA_rsa4096.pem"
APP_CERT="${KEY_DIR}/phonevault-app-BETA.x509.pem"
[[ -r "${AVB_KEY}" && -s "${APP_CERT}" ]] \
  || { echo "beta keys missing in ${KEY_DIR}: run release-bluejay/gen-beta-keys.sh on this host" >&2; exit 2; }
KEYS="${TREE}/vendor/phonevault/keys"
install -d -m 0700 "${KEYS}"
rm -f "${KEYS}/avb_bluejay_dev.pem"
ln -sfn "${AVB_KEY}" "${KEYS}/avb_bluejay_beta.pem"
echo "   vendor/phonevault/keys/avb_bluejay_beta.pem -> ${AVB_KEY} (dev key link removed)"

echo "== 4. beta ${BETA} configuration"
sed -n '/^\(rung\|beta\) /p' "${RESOLVED}/RESOLVED.txt" | sed 's/^/   layer: /'
declare -A TARGET=(
  [common.mk]="vendor/phonevault/config/common.mk"
  [BoardConfigVault.mk]="vendor/phonevault/config/BoardConfigVault.mk"
  [Android.bp]="vendor/phonevault/prebuilt/Android.bp"
  [config.xml]="vendor/phonevault/overlay/frameworks/base/core/res/res/values/config.xml"
)
for name in "${!TARGET[@]}"; do
  if [[ -f "${RESOLVED}/${name}" ]]; then
    install -m 0644 "${RESOLVED}/${name}" "${TREE}/${TARGET[$name]}"
    echo "   beta    : ${TARGET[$name]}"
  else
    echo "   release : ${TARGET[$name]}"
  fi
done
leftover="$(find "${TREE}/vendor/phonevault" "${TREE}/device/phonevault" \
  \( -name 'debug_adbkey*' -o -name 'adb_keys*' -o -name 'adbkey*' \) -print)"
[[ -z "${leftover}" ]] || { echo "adb key file in the tree: ${leftover}" >&2; exit 1; }
echo "   no adb key file under vendor/phonevault or device/phonevault"

echo "== 5. upstream device/vendor trees"
DEV="${TREE}/device/google/bluejay"
for repo in device/google/bluejay device/google/gs101 vendor/google/bluejay device/google/bluejay-kernels; do
  dir="${TREE}/${repo}"
  diff_file="${RESOLVED}/${repo//\//-}.diff"
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
printf '\n# Phone Vault product board policy (after every upstream board setting)\n%s\n' \
  'include vendor/phonevault/config/BoardConfigVault.mk' >> "${DEV}/bluejay/BoardConfig.mk"
echo "   appended BoardConfigVault include to bluejay/BoardConfig.mk"

echo "== 6. frameworks/base (Android 17 rebases)"
FWB="${TREE}/frameworks/base"
for fp in "${OVERLAY}"/patches/frameworks-base-a17/*.patch; do
  if git -C "${FWB}" apply --reverse --check "${fp}" >/dev/null 2>&1; then
    echo "   present: $(basename "${fp}")"
  elif git -C "${FWB}" apply --check "${fp}" >/dev/null 2>&1; then
    git -C "${FWB}" apply "${fp}"; echo "   applied: $(basename "${fp}")"
  else
    echo "frameworks/base patch neither applies nor reverses cleanly: ${fp}" >&2; exit 1
  fi
done

echo "== 7. bootable/recovery (user-build recovery hardening)"
REC="${TREE}/bootable/recovery"
if ! git -C "${REC}" diff --quiet; then
  git -C "${REC}" checkout -- .
  echo "   bootable/recovery restored to upstream"
fi
for rp in "${OVERLAY}"/patches/bootable-recovery/*.patch; do
  git -C "${REC}" apply --check "${rp}"
  git -C "${REC}" apply "${rp}"
  git -C "${REC}" apply --reverse --check "${rp}"
  echo "   applied: $(basename "${rp}")"
done

echo "== 8. kernel"
KDIR="${TREE}/device/google/bluejay-kernels/6.1"
if [[ -n "${KDIST}" && -d "${KDIST}" ]]; then
  [[ -s "${KDIST}/boot.img" ]] || { echo "kernel dist has no boot.img: ${KDIST}" >&2; exit 1; }
  TRACKED=(modules.load vendor_dlkm.modules.load vendor_dlkm.modules.blocklist init.insmod.bluejay.cfg)
  excl=(); for f in "${TRACKED[@]}"; do excl+=(--exclude "/${f}"); done
  rsync -a "${excl[@]}" "${KDIST}/" "${KDIR}/"
  echo "   kernel dist -> bluejay-kernels/6.1"
else
  [[ -s "${KDIR}/boot.img" && -s "${KDIR}/Image.lz4" ]] \
    || { echo "no kernel dist and no kernel prebuilts in ${KDIR}" >&2; exit 1; }
  echo "   keeping the tree's kernel prebuilts (Image.lz4 $(sha256sum "${KDIR}/Image.lz4" | cut -c1-16)...)"
fi

echo "== 9. signer app (release build, beta app key)"
expected_cert="$(openssl x509 -in "${APP_CERT}" -outform DER | sha256sum | cut -c1-64)"
TOOLS="${TREE}/prebuilts/sdk/tools/linux"
PATH="${TREE}/prebuilts/jdk/jdk21/linux-x86/bin:${PATH}" \
PHONEVAULT_AAPT="${TOOLS}/bin/aapt" PHONEVAULT_APKSIGNER="${TREE}/out/host/linux-x86/bin/apksigner" \
  "${OVERLAY}/scripts/verify-signer-apk.sh" "${APK}" "${expected_cert}" | tail -2
install -m 0644 "${APK}" "${TREE}/vendor/phonevault/prebuilt/PhoneVault.apk"
echo "   baked signer APK $(sha256sum "${APK}" | cut -c1-16)... (cert ${expected_cert})"
echo "== bluejay beta ${BETA} synced"
