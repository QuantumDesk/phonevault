#!/usr/bin/env bash
# Artifact gate for the app-strip rungs: every module named in the rung's active (uncommented)
# Android.bp `overrides` list must be absent from the built target-files, as an app
# (<PARTITION>/app|priv-app/<name>/) or an overlay (<PARTITION>/overlay/<name>.apk or
# overlay/<name>/, or the app's auto-generated RRO). Run on the build host after build-rung.sh, before sideloading:
#   check-overrides.sh RUNG [target_files.zip]   (default: newest in $LINEAGE_TREE/out)
# Exit 1 lists the survivors. An override can be silently defeated when another installed module
# names the target in `required` (Trebuchet survives its override that way), so this is the
# proof a rung did what its Android.bp says. Also prints the APKs that remain, for the README.
# Non-app modules (e.g. android.software.webview.prebuilt.xml) are not matched here; check those
# on the phone (`pm list features`). Parsing and matching: vault-os/scripts/vaultgates/overrides.py.
# The release list is checked by vault-os/scripts/verify-release-overrides.sh (sign-release.sh
# runs it); `check-overrides.sh release TARGET_FILES` runs that gate.
set -euo pipefail
RUNG="${1:?rung}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [[ "${RUNG}" == release ]]; then
  exec "${ROOT}/vault-os/scripts/verify-release-overrides.sh" "${@:2}"
fi
BP="${ROOT}/vault-os/dev-ladder/rung-${RUNG}/Android.bp"
[[ -f "${BP}" ]] || { echo "no Android.bp for rung ${RUNG}" >&2; exit 2; }
if [[ -n "${2:-}" ]]; then
  TF="$2"
else
  : "${LINEAGE_TREE:?pass the target_files.zip, or set LINEAGE_TREE to the crosshatch source tree}"
  TF="$(ls -t "${LINEAGE_TREE}"/out/target/product/crosshatch/obj/PACKAGING/target_files_intermediates/*target_files*.zip | head -1)"
fi
[[ -s "${TF}" ]] || { echo "target-files not found: ${TF}" >&2; exit 2; }
echo "rung ${RUNG}: ${TF}"
python3 "${ROOT}/vault-os/scripts/vaultgate.py" overrides check "${BP}" "${TF}"
