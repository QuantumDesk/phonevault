#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 OUT_DIR [AVBTOOL]" >&2
  exit 2
fi

OUT_DIR="$1"
AVBTOOL="${2:-avbtool}"
required=(boot.img dtbo.img product.img super_empty.img system.img system_ext.img vbmeta.img vendor.img)
for image in "${required[@]}"; do
  [[ -s "${OUT_DIR}/${image}" ]] || {
    echo "missing image: ${OUT_DIR}/${image}" >&2
    exit 1
  }
  shasum -a 256 "${OUT_DIR}/${image}"
done

[[ -s "${OUT_DIR}/android-info.txt" ]] || {
  echo "missing image: ${OUT_DIR}/android-info.txt" >&2
  exit 1
}
android_info="$(tr -d '\r' < "${OUT_DIR}/android-info.txt")"
[[ "${android_info}" == 'require board=crosshatch' ]] || {
  echo "fastboot metadata must allow exactly crosshatch: ${android_info}" >&2
  exit 1
}

if [[ "${AVBTOOL}" == */* ]]; then
  [[ -f "${AVBTOOL}" ]] || {
    echo "missing avbtool: ${AVBTOOL}" >&2
    exit 1
  }
  avbtool_command=(python3 "${AVBTOOL}")
else
  command -v "${AVBTOOL}" >/dev/null || {
    echo "avbtool is required to verify AVB metadata" >&2
    exit 1
  }
  avbtool_command=("${AVBTOOL}")
fi
vbmeta_info="$("${avbtool_command[@]}" info_image \
  --image "${OUT_DIR}/vbmeta.img")"
printf '%s\n' "${vbmeta_info}"
grep -Eq '^Flags:[[:space:]]+0$' <<<"${vbmeta_info}" || {
  echo "fastboot root vbmeta disables verification or hashtree enforcement" >&2
  exit 1
}
rollback_index="$(sed -n 's/^Rollback Index:[[:space:]]*\([0-9][0-9]*\)$/\1/p' \
  <<<"${vbmeta_info}")"
[[ "${rollback_index}" =~ ^[0-9]+$ && "${rollback_index}" != 0 ]] || {
  echo "fastboot root vbmeta lacks a positive rollback index" >&2
  exit 1
}
if [[ -s "${OUT_DIR}/vbmeta_system.img" ]]; then
  "${avbtool_command[@]}" info_image --image "${OUT_DIR}/vbmeta_system.img"
fi

echo "Static image checks passed. Boot, USB, radio, rollback, and relock tests remain mandatory."
