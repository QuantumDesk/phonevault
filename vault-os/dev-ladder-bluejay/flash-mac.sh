#!/usr/bin/env bash
# Flash one bluejay rung to SLOT A of an unlocked Pixel 6a from macOS, from the BOOTLOADER only.
# build-rung.sh installs this as <DEST>/flash-<rung>-mac.sh next to images/ and
# super.img; copy the whole out directory to the Mac and run it from there:
#   ./flash-b1-mac.sh            pre-flight, verify hashes, ask, flash, wipe, set slot a, reboot
#   ./flash-b1-mac.sh --check    pre-flight + hashes only, writes nothing
#
# Why bootloader only: userspace fastboot (fastbootd) enumerates on macOS but every write fails
# ("Write to device failed"), so `fastboot update` / `flashall` cannot be used from the Mac. The
# bootloader flashes super as one sparse image instead (dev-ladder-bluejay/README.md, b0).
# Never written here: bootloader, radio, any firmware partition, avb_custom_key, lock state.
# The data wipe (-w + erase metadata) makes the next boot a genuine factory first boot.
set -euo pipefail
cd "$(dirname "$0")"
FASTBOOT="${FASTBOOT:-fastboot}"

WANT_PRODUCT=bluejay
WANT_BOOTLOADER=bluejay-17.0-15199431
WANT_BASEBAND=g5123b-145971-260414-B-15201439     # upper-case B: fastboot compares exactly
SLOT_IMAGES=(boot vendor_boot dtbo pvmfw vbmeta vbmeta_system vbmeta_vendor)

die() { echo "ABORT: $*" >&2; exit 1; }
getvar() { "${FASTBOOT}" getvar "$1" 2>&1 | awk -v k="$1" -F': ' '$1==k {print $2; exit}' | tr -d '\r'; }

command -v "${FASTBOOT}" >/dev/null || die "no fastboot in PATH"
for i in "${SLOT_IMAGES[@]}"; do [[ -s "images/${i}.img" ]] || die "missing images/${i}.img"; done
[[ -s super.img ]] || die "missing super.img"
[[ -s images/android-info.txt ]] || die "missing images/android-info.txt"

echo "== hashes"
files=(super.img images/android-info.txt)
for i in "${SLOT_IMAGES[@]}"; do files+=("images/${i}.img"); done
for f in "${files[@]}"; do
  line="$(grep -E "  ${f}\$" SHA256SUMS)" || die "${f} not in SHA256SUMS"
  echo "${line}" | shasum -a 256 -c - || die "hash mismatch: ${f}"
done

echo "== pre-flight (bootloader fastboot, read-only)"
devs="$("${FASTBOOT}" devices | awk 'NF' | wc -l | tr -d ' ')"
[[ "${devs}" == 1 ]] || die "expected exactly one device in fastboot, found ${devs}"
product="$(getvar product)"; bootloader="$(getvar version-bootloader)"
baseband="$(getvar version-baseband)"; unlocked="$(getvar unlocked)"
userspace="$(getvar is-userspace)"; current="$(getvar current-slot)"
echo "product=${product} bootloader=${bootloader} baseband=${baseband}"
echo "unlocked=${unlocked} is-userspace=${userspace} current-slot=${current}"
[[ "${product}" == "${WANT_PRODUCT}" ]] || die "product ${product} != ${WANT_PRODUCT}"
[[ "${bootloader}" == "${WANT_BOOTLOADER}" ]] || die "bootloader ${bootloader} != ${WANT_BOOTLOADER}"
[[ "${baseband}" == "${WANT_BASEBAND}" ]] || die "baseband ${baseband} != ${WANT_BASEBAND}"
[[ "${unlocked}" == yes ]] || die "bootloader is locked"
[[ "${userspace}" != yes ]] || die "this is fastbootd; reboot to the bootloader (fastboot reboot bootloader)"
for line in "require board=${WANT_PRODUCT}" "require version-bootloader=${WANT_BOOTLOADER}" \
            "require version-baseband=${WANT_BASEBAND}"; do
  grep -qx "${line}" images/android-info.txt || die "android-info.txt lacks: ${line}"
done

if [[ "${1:-}" == --check ]]; then echo "== check only: nothing written"; exit 0; fi
echo
echo "About to flash slot a (boot partitions + super), ERASE metadata and userdata, and make"
read -r -p "slot a active. Firmware is not touched. Type FLASH to continue: " answer
[[ "${answer}" == FLASH ]] || die "not confirmed"

set -x
for i in "${SLOT_IMAGES[@]}"; do
  "${FASTBOOT}" --slot=a flash "${i}" "images/${i}.img"
done
"${FASTBOOT}" flash super super.img
"${FASTBOOT}" erase metadata
"${FASTBOOT}" -w
"${FASTBOOT}" --set-active=a
"${FASTBOOT}" reboot
set +x
echo "== flashed. First boot takes about a minute; it must land on SET PIN with no tap."
