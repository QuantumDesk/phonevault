#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "This bridge is only for native macOS Git-LFS around Docker/Rosetta TLS failures." >&2
  exit 2
fi
command -v git-lfs >/dev/null || { echo "native git-lfs is required" >&2; exit 1; }

VOLUME="${PHONEVAULT_SOURCE_VOLUME:-phone-vault-lineage}"
IMAGE="phone-vault-lineage-builder:24.04"
TEMP_ROOT="$(mktemp -d -t phone-vault-lfs.XXXXXX)"
trap 'rm -rf "${TEMP_ROOT}"' EXIT

for architecture in arm arm64 x86 x86_64; do
  repository="android_external_chromium-webview_prebuilt_${architecture}"
  source_path="external/chromium-webview/prebuilt/${architecture}"
  revision="$(docker run --rm --platform linux/amd64 \
    --volume "${VOLUME}:/lineage" "${IMAGE}" \
    git -C "/lineage/${source_path}" rev-parse HEAD)"
  pointer="$(docker run --rm --platform linux/amd64 \
    --volume "${VOLUME}:/lineage" "${IMAGE}" \
    git -C "/lineage/${source_path}" show HEAD:webview.apk)"
  expected_hash="$(sed -n 's/^oid sha256://p' <<<"${pointer}")"
  expected_size="$(sed -n 's/^size //p' <<<"${pointer}")"
  [[ "${expected_hash}" =~ ^[0-9a-f]{64}$ && "${expected_size}" =~ ^[0-9]+$ ]] || {
    echo "invalid LFS pointer metadata for ${architecture}" >&2
    exit 1
  }

  checkout="${TEMP_ROOT}/${architecture}"
  GIT_LFS_SKIP_SMUDGE=1 git clone --quiet --filter=blob:none --no-checkout \
    "https://github.com/LineageOS/${repository}.git" "${checkout}"
  git -C "${checkout}" fetch --quiet --depth=1 origin "${revision}"
  GIT_LFS_SKIP_SMUDGE=1 git -C "${checkout}" checkout --quiet --detach FETCH_HEAD
  git -C "${checkout}" lfs pull --include webview.apk --exclude ''

  actual_hash="$(shasum -a 256 "${checkout}/webview.apk" | awk '{print $1}')"
  actual_size="$(stat -f '%z' "${checkout}/webview.apk")"
  [[ "${actual_hash}" == "${expected_hash}" ]] || {
    echo "LFS SHA-256 mismatch for ${architecture}" >&2
    exit 1
  }
  [[ "${actual_size}" == "${expected_size}" ]] || {
    echo "LFS size mismatch for ${architecture}" >&2
    exit 1
  }

  docker run --rm --platform linux/amd64 \
    --volume "${VOLUME}:/lineage" \
    --volume "${checkout}:/verified:ro" \
    "${IMAGE}" bash -c '
      set -e
      source_path="$1"
      expected_hash="$2"
      object_dir="/lineage/.repo/projects/${source_path}.git/lfs/objects/${expected_hash:0:2}/${expected_hash:2:2}"
      mkdir -p "${object_dir}"
      cp /verified/webview.apk "${object_dir}/${expected_hash}"
      cp /verified/webview.apk "/lineage/${source_path}/webview.apk"
    ' bash "${source_path}" "${expected_hash}"
  echo "hydrated ${architecture}: sha256:${actual_hash} (${actual_size} bytes)"
done

docker run --rm --platform linux/amd64 --volume "${VOLUME}:/lineage" "${IMAGE}" bash -lc '
  set -e
  cd /lineage
  for architecture in arm arm64 x86 x86_64; do
    repository="external/chromium-webview/prebuilt/${architecture}"
    git -C "${repository}" lfs fsck
    if git -C "${repository}" lfs ls-files | grep -Eq "^[0-9a-f]+ - "; then
      echo "unhydrated pointer remains in ${repository}" >&2
      exit 1
    fi
    # Refresh the index through the LFS clean filter so repo status compares
    # the hydrated payload with its tracked pointer instead of file metadata.
    git -C "${repository}" add -- webview.apk
    git -C "${repository}" diff --cached --quiet -- webview.apk
  done
  repo status
'
