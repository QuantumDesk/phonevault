#!/usr/bin/env bash
# Artifact gate for one bluejay rung (b2+): proves on the built target files and images that the
# rung did what its files say, before anything goes near the phone. build-rung.sh runs it; it can
# also be run by hand on the build host:
#   check-build.sh RUNG TARGET_FILES.zip OUT_DIR [TREE]   (TREE default: $LINEAGE_TREE)
# Checks, each only when the rung dir carries the input:
#   1. kernel  PHONEVAULT_KMODS_REMOVED (BoardConfigVault.mk): no such .ko anywhere in the target
#              files (vendor_dlkm, vendor_boot ramdisk), no load list names one, and every
#              modules.dep in the target files resolves (no kept module depends on a removed one);
#   2. cmdline PHONEVAULT_KERNEL_CMDLINE is in vendor_boot.img's command line;
#   3. overrides every module in Android.bp `overrides` is absent: app/priv-app dir, overlay APK or
#              auto-generated RRO, vendor binary (bin/, bin/hw/), VINTF fragment, permissions XML
#              (an override is silently defeated when an installed module `required`s it);
#   4. expect  rung-RUNG/expect-build.txt, one check per line:
#                absent  PATH            PATH is not in the target files
#                present PATH            PATH is in the target files
#                grep    PATH  REGEX     PATH's content matches REGEX (Python re, MULTILINE)
#                nogrep  PATH  REGEX     PATH's content does not match REGEX
# Exit 1 on the first failed section, listing every failure in it.
set -euo pipefail
RUNG="${1:?rung}"
TF="${2:?target files zip}"
OUTD="${3:?out dir (images/)}"
TREE="${4:-${LINEAGE_TREE:?usage: check-build.sh RUNG TARGET_FILES.zip OUT_DIR TREE (or set LINEAGE_TREE)}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# RUNG is a rung name (b2, b4d-1, ...) or a directory with a rung's layout (release-bluejay's
# resolved beta config, written by resolve-beta.sh).
if [[ "${RUNG}" == */* ]]; then RUNG_DIR="${RUNG}"; else RUNG_DIR="${SCRIPT_DIR}/rung-${RUNG}"; fi
[[ -d "${RUNG_DIR}" ]] || { echo "no such rung: ${RUNG_DIR}" >&2; exit 2; }
[[ -s "${TF}" ]] || { echo "target files not found: ${TF}" >&2; exit 2; }

CMDLINE=""
if [[ -s "${OUTD}/images/vendor_boot.img" ]]; then
  UB="$(mktemp -d)"
  "${TREE}/out/host/linux-x86/bin/unpack_bootimg" --boot_img "${OUTD}/images/vendor_boot.img" \
    --out "${UB}" > "${UB}/info.txt" 2>&1 || true
  CMDLINE="$(grep -i 'vendor command line args' "${UB}/info.txt" | head -1 | sed 's/^[^:]*: *//')"
  rm -rf "${UB}"
fi

python3 "${SCRIPT_DIR}/../scripts/vaultgate.py" bluejay-check-build "${RUNG_DIR}" "${TF}" "${CMDLINE}"
