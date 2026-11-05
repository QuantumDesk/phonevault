#!/usr/bin/env bash
# Phone Vault 0.1.0-beta5 (Pixel 6a): install from the GitHub release assets on a Mac.
#
# Put these release assets in one folder, then run this script from anywhere:
#   super.img.part-aa  super.img.part-ab  PhoneVault-beta5-images-bluejay.zip
#   flash-beta5-mac.sh  manifest.json  SHA256SUMS  install-beta5-mac.sh
#
#   bash install-beta5-mac.sh                 join, unzip, verify, read-only phone check, then flash
#   bash install-beta5-mac.sh --verify-only   join, unzip, verify; never runs fastboot
#
# It never writes the bootloader, the radio firmware or the lock state. The flash itself is done by
# flash-beta5-mac.sh, which reads the phone first and asks you to type FLASH before it writes.
# Flashing ERASES everything on the phone.
set -euo pipefail
cd "$(dirname "$0")"

FASTBOOT="${FASTBOOT:-fastboot}"
# SHA-256 of the build's own SHA256SUMS (also listed in SHA256SUMS-assets and in
# vault-os/release-bluejay/README.md). Everything else is checked against that file.
SUMS_SHA256=2d9840dc1dc8ebe187f5380d8171960208c3d90620ad333db8a2ce89fa828c95
SLOT_IMAGES=(boot vendor_boot dtbo pvmfw vbmeta vbmeta_system vbmeta_vendor)
PARTS=(super.img.part-aa super.img.part-ab)
ZIP=PhoneVault-beta5-images-bluejay.zip

die() { echo "ABORT: $*" >&2; exit 1; }
mode="${1:-}"
case "${mode}" in ""|--verify-only) ;; *) die "unknown option ${mode} (use --verify-only or nothing)";; esac

echo "== Phone Vault 0.1.0-beta5 installer (Pixel 6a)"

if [[ "${mode}" != --verify-only ]]; then
  command -v "${FASTBOOT}" >/dev/null || die "fastboot not found. Install it with:  brew install android-platform-tools
       (Homebrew: https://brew.sh), or Google's SDK Platform Tools, then run this script again."
  echo "fastboot: $(command -v "${FASTBOOT}")"
fi
command -v shasum >/dev/null || die "shasum not found (it ships with macOS)"
command -v unzip >/dev/null || die "unzip not found (it ships with macOS)"

echo "== SHA256SUMS"
[[ -s SHA256SUMS ]] || die "missing SHA256SUMS (download it from the release page)"
got="$(shasum -a 256 SHA256SUMS | awk '{print $1}')"
[[ "${got}" == "${SUMS_SHA256}" ]] || die "SHA256SUMS is not the beta5 file (sha256 ${got})"
echo "SHA256SUMS: OK"

want_super="$(awk '$2=="super.img" {print $1}' SHA256SUMS)"
[[ -n "${want_super}" ]] || die "super.img not listed in SHA256SUMS"

echo "== super.img"
if [[ -s super.img ]] && [[ "$(shasum -a 256 super.img | awk '{print $1}')" == "${want_super}" ]]; then
  echo "super.img already joined and matches"
else
  for p in "${PARTS[@]}"; do [[ -s "${p}" ]] || die "missing ${p} (download both super.img parts)"; done
  free_kb="$(df -Pk . | awk 'NR==2 {print $4}')"
  [[ "${free_kb}" -gt 2500000 ]] || die "need about 2.5 GB free in this folder to join super.img"
  echo "joining ${PARTS[*]} -> super.img (2.4 GB, takes a moment)"
  rm -f super.img.joining
  cat "${PARTS[@]}" > super.img.joining
  mv -f super.img.joining super.img
fi

echo "== images"
if [[ -s "${ZIP}" ]]; then
  unzip -o -q "${ZIP}" -d .
elif [[ -d "${ZIP%.zip}/images" ]]; then
  # Safari's "Open safe files after downloading" unpacks the zip into a folder of the same name.
  echo "using the folder ${ZIP%.zip}/ (the browser already unpacked the zip)"
  mkdir -p images
  cp -f "${ZIP%.zip}"/images/* images/
else
  die "missing ${ZIP}"
fi
for i in "${SLOT_IMAGES[@]}"; do [[ -s "images/${i}.img" ]] || die "missing images/${i}.img after unzip"; done
[[ -s images/android-info.txt ]] || die "missing images/android-info.txt after unzip"

echo "== verify against SHA256SUMS"
files=(super.img images/android-info.txt flash-beta5-mac.sh manifest.json)
for i in "${SLOT_IMAGES[@]}"; do files+=("images/${i}.img"); done
for f in "${files[@]}"; do
  [[ -s "${f}" ]] || die "missing ${f}"
  line="$(grep -E "  ${f}\$" SHA256SUMS)" || die "${f} not listed in SHA256SUMS"
  echo "${line}" | shasum -a 256 -c - || die "hash mismatch: ${f} (download it again)"
done
echo "all ${#files[@]} files match SHA256SUMS"

if [[ "${mode}" == --verify-only ]]; then
  echo "== verify only: no fastboot command was run, the phone was not touched"
  exit 0
fi

cat <<'EOF'

== next: read-only check of the phone
The phone must be in its bootloader: power it off, then hold Volume Down + Power until the
bootloader screen appears, and connect it straight to this Mac with a USB-C data cable.
EOF
read -r -p "Press Return when the phone shows the bootloader screen (Ctrl-C to stop): " _
bash ./flash-beta5-mac.sh --check

cat <<'EOF'

== the phone passed the check
The next step ERASES everything on the phone and installs Vault OS 0.1.0-beta5.
Make sure any funds are moved out or that you have the recovery phrase of any wallet on it.
flash-beta5-mac.sh checks everything again and asks you to type FLASH before it writes.
EOF
bash ./flash-beta5-mac.sh
