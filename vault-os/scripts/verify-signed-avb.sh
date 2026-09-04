#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 SIGNED_TARGET_FILES_ZIP AVB_PRIVATE_OR_PUBLIC_KEY AVBTOOL" >&2
  exit 2
fi

TARGET_FILES="$1"
AVB_KEY="$2"
AVBTOOL="$3"
[[ -s "${TARGET_FILES}" && -s "${AVB_KEY}" && -f "${AVBTOOL}" ]] || {
  echo "signed target-files, AVB key, or avbtool is missing" >&2
  exit 1
}

work_dir="$(mktemp -d -t phone-vault-signed-avb.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT
unzip -q "${TARGET_FILES}" 'IMAGES/*.img' -d "${work_dir}"

root_vbmeta="${work_dir}/IMAGES/vbmeta.img"
[[ -s "${root_vbmeta}" ]] || {
  echo "no root vbmeta image found in target-files" >&2
  exit 1
}
python3 "${AVBTOOL}" verify_image \
  --image "${root_vbmeta}" --key "${AVB_KEY}" --follow_chain_partitions
vbmeta_info="$(python3 "${AVBTOOL}" info_image --image "${root_vbmeta}")"
grep -Eq '^Flags:[[:space:]]+0$' <<<"${vbmeta_info}" || {
  echo "root vbmeta disables verification or hashtree enforcement" >&2
  exit 1
}
rollback_index="$(sed -n 's/^Rollback Index:[[:space:]]*\([0-9][0-9]*\)$/\1/p' \
  <<<"${vbmeta_info}")"
[[ "${rollback_index}" =~ ^[0-9]+$ && "${rollback_index}" != 0 ]] || {
  echo "root vbmeta does not carry a positive rollback index" >&2
  exit 1
}
echo "Verified root vbmeta signature, chained vbmeta, and partition descriptors."
