#!/usr/bin/env bash
# AVB rollback-index gate for a production release.
#   verify-rollback-index.sh CANDIDATE_INDEX RELEASE_VERSION_MK \
#       (PREVIOUS_RELEASE_DIR METADATA_PUBLIC_KEY | --first-release)
#
# CANDIDATE_INDEX must equal PHONEVAULT_AVB_ROLLBACK_INDEX in the project-owned
# release-version.mk, and must be strictly greater than the
# vbmeta_rollback_index of the previous signed release (its RELEASE-MANIFEST.txt
# is verified against RELEASE-MANIFEST.sig with the release-metadata public key
# first). Equal or lower is refused: a relocked phone would either keep
# accepting the previous image (equal) or refuse to boot the new one (lower).
# --first-release is only for the very first production release; it is an
# explicit, logged operator decision.
set -euo pipefail
export LC_ALL=C

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "usage: $0 CANDIDATE_INDEX RELEASE_VERSION_MK (PREVIOUS_RELEASE_DIR METADATA_PUBLIC_KEY | --first-release)" >&2
  exit 2
fi
CANDIDATE="$1"
VERSION_MK="$2"

decimal_gt() {  # a > b for arbitrary-length non-negative decimal integers
  local a="$1" b="$2"
  a="${a#"${a%%[!0]*}"}"; b="${b#"${b%%[!0]*}"}"
  a="${a:-0}"; b="${b:-0}"
  if (( ${#a} != ${#b} )); then
    (( ${#a} > ${#b} ))
    return
  fi
  [[ "${a}" > "${b}" ]]
}

[[ "${CANDIDATE}" =~ ^[1-9][0-9]*$ ]] || {
  echo "candidate rollback index is not a positive integer: ${CANDIDATE}" >&2
  exit 1
}
[[ -s "${VERSION_MK}" ]] || {
  echo "missing project release version file: ${VERSION_MK}" >&2
  exit 1
}
project_index="$(sed -n -E \
  's/^PHONEVAULT_AVB_ROLLBACK_INDEX[[:space:]]*:=[[:space:]]*([0-9]+)[[:space:]]*$/\1/p' \
  "${VERSION_MK}")"
[[ "${project_index}" =~ ^[1-9][0-9]*$ && "$(wc -l <<<"${project_index}" | tr -d ' ')" == 1 ]] || {
  echo "release-version.mk must define exactly one PHONEVAULT_AVB_ROLLBACK_INDEX" >&2
  exit 1
}
[[ "${CANDIDATE}" == "${project_index}" ]] || {
  echo "vbmeta rollback index ${CANDIDATE} is not the project index ${project_index} (release-version.mk)" >&2
  exit 1
}

if [[ "$3" == --first-release ]]; then
  [[ $# -eq 3 ]] || { echo "--first-release takes no further arguments" >&2; exit 2; }
  echo "Rollback index ${CANDIDATE}: FIRST production release (no previous manifest to compare)."
  exit 0
fi
[[ $# -eq 4 ]] || {
  echo "a previous release directory needs the release-metadata public key" >&2
  exit 2
}
PREVIOUS_DIR="$3"
METADATA_PUBLIC_KEY="$4"
previous_manifest="${PREVIOUS_DIR}/RELEASE-MANIFEST.txt"
previous_signature="${PREVIOUS_DIR}/RELEASE-MANIFEST.sig"
[[ -s "${previous_manifest}" && -s "${previous_signature}" && -s "${METADATA_PUBLIC_KEY}" ]] || {
  echo "previous release manifest, signature or metadata public key is missing" >&2
  exit 1
}
openssl pkeyutl -verify -pubin -rawin -inkey "${METADATA_PUBLIC_KEY}" \
  -in "${previous_manifest}" -sigfile "${previous_signature}" >/dev/null 2>&1 || {
  echo "previous release manifest signature does not verify with the release-metadata key" >&2
  exit 1
}
grep -Fqx 'channel=production' "${previous_manifest}" || {
  echo "previous release manifest is not a production manifest" >&2
  exit 1
}
previous_index="$(sed -n 's/^vbmeta_rollback_index=//p' "${previous_manifest}")"
[[ "${previous_index}" =~ ^[1-9][0-9]*$ && "$(wc -l <<<"${previous_index}" | tr -d ' ')" == 1 ]] || {
  echo "previous release manifest lacks exactly one positive vbmeta_rollback_index" >&2
  exit 1
}
decimal_gt "${CANDIDATE}" "${previous_index}" || {
  echo "refusing release: rollback index ${CANDIDATE} is not greater than the previous release's ${previous_index}; bump PHONEVAULT_AVB_ROLLBACK_INDEX in release-version.mk" >&2
  exit 1
}
echo "Rollback index ${CANDIDATE} > previous release ${previous_index}."
