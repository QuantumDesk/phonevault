#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 DEVICE_SERIAL DEVELOPMENT_ARTIFACT_DIRECTORY EXPECTED_SHA256SUMS_SHA256" >&2
  exit 2
fi

FASTBOOT_BIN="${FASTBOOT_BIN:-fastboot}"
SERIAL="$1"
ARTIFACT_DIR="$2"
EXPECTED_CHECKSUM_MANIFEST_SHA="$(printf '%s' "$3" | tr '[:upper:]' '[:lower:]')"

[[ "${SERIAL}" =~ ^[A-Za-z0-9._:-]+$ ]] || {
  echo "invalid fastboot serial" >&2
  exit 2
}
[[ "${EXPECTED_CHECKSUM_MANIFEST_SHA}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "expected SHA256SUMS hash must be a 64-digit SHA-256 digest" >&2
  exit 2
}
command -v "${FASTBOOT_BIN}" >/dev/null || {
  echo "fastboot is required" >&2
  exit 1
}
command -v openssl >/dev/null || {
  echo "openssl is required to verify the AVB public identity" >&2
  exit 1
}
[[ -d "${ARTIFACT_DIR}" && ! -L "${ARTIFACT_DIR}" ]] || {
  echo "development artifact directory is missing or is a symlink: ${ARTIFACT_DIR}" >&2
  exit 1
}

ARTIFACT_DIR="$(cd "${ARTIFACT_DIR}" && pwd -P)"
for required_file in \
    SHA256SUMS \
    MANIFEST.txt \
    avb_pkmd.bin \
    avb-public.pem \
    images/android-info.txt \
    images/boot.img \
    images/dtbo.img \
    images/product.img \
    images/super_empty.img \
    images/system.img \
    images/system_ext.img \
    images/vbmeta.img \
    images/vendor.img; do
  [[ -s "${ARTIFACT_DIR}/${required_file}" \
      && ! -L "${ARTIFACT_DIR}/${required_file}" ]] || {
    echo "missing, empty, or linked verified artifact: ${required_file}" >&2
    exit 1
  }
done

if command -v sha256sum >/dev/null; then
  actual_checksum_manifest_sha="$(sha256sum \
    "${ARTIFACT_DIR}/SHA256SUMS" | awk '{print $1}')"
else
  actual_checksum_manifest_sha="$(shasum -a 256 \
    "${ARTIFACT_DIR}/SHA256SUMS" | awk '{print $1}')"
fi
[[ "${actual_checksum_manifest_sha}" == "${EXPECTED_CHECKSUM_MANIFEST_SHA}" ]] || {
  echo "SHA256SUMS does not match the independently recorded digest" >&2
  echo "expected ${EXPECTED_CHECKSUM_MANIFEST_SHA}, found ${actual_checksum_manifest_sha}" >&2
  exit 1
}

# prepare-development-images.sh emits only relative ./ paths. Refuse absolute,
# malformed, or traversal paths before passing the file to the platform
# checksum tool. The checksum inventory must cover every regular bundle file
# exactly once; checking only listed entries would permit an omitted image to
# be replaced without detection.
if grep -Ev '^[0-9a-fA-F]{64}  \./[A-Za-z0-9][A-Za-z0-9._/-]*$' \
    "${ARTIFACT_DIR}/SHA256SUMS" | grep -q . \
    || grep -E '(^|/)\.\.(/|$)|//|/\.(/|$)' \
      "${ARTIFACT_DIR}/SHA256SUMS" | grep -q .; then
  echo "SHA256SUMS contains an unsafe or malformed entry" >&2
  exit 1
fi
inventory_dir="$(mktemp -d -t phone-vault-preflight-inventory.XXXXXX)"
trap 'rm -rf -- "${inventory_dir}"' EXIT
sed -E 's/^[0-9a-fA-F]{64}  //' "${ARTIFACT_DIR}/SHA256SUMS" \
  > "${inventory_dir}/listed-unsorted.txt"
if [[ "$(wc -l < "${inventory_dir}/listed-unsorted.txt" | tr -d ' ')" \
    != "$(LC_ALL=C sort -u "${inventory_dir}/listed-unsorted.txt" | wc -l | tr -d ' ')" ]]; then
  echo "SHA256SUMS contains duplicate paths" >&2
  exit 1
fi
LC_ALL=C sort "${inventory_dir}/listed-unsorted.txt" \
  > "${inventory_dir}/listed.txt"
(
  cd "${ARTIFACT_DIR}"
  find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort
) > "${inventory_dir}/actual.txt"
if ! cmp -s "${inventory_dir}/listed.txt" "${inventory_dir}/actual.txt"; then
  echo "SHA256SUMS inventory does not exactly match bundle files" >&2
  diff -u "${inventory_dir}/listed.txt" "${inventory_dir}/actual.txt" >&2 || true
  exit 1
fi
if find "${ARTIFACT_DIR}" -type l -print -quit | grep -q .; then
  echo "development bundle contains an unverified symbolic link" >&2
  exit 1
fi
(
  cd "${ARTIFACT_DIR}"
  if command -v sha256sum >/dev/null; then
    sha256sum --check --strict SHA256SUMS
  else
    shasum -a 256 --check SHA256SUMS
  fi
)

manifest_value() {
  local key="$1"
  local values
  values="$(sed -n "s/^${key}=//p" "${ARTIFACT_DIR}/MANIFEST.txt")"
  [[ -n "${values}" && "${values}" != *$'\n'* ]] || {
    echo "manifest key is missing or duplicated: ${key}" >&2
    exit 1
  }
  printf '%s\n' "${values}"
}

[[ "$(manifest_value development_only)" == true ]] || {
  echo "preflight accepts only a verified development bundle" >&2
  exit 1
}
for digest_key in \
    phonevault_app_cert_sha256 \
    phonevault_app_sha256 \
    vbmeta_digest_sha256 \
    avb_public_key_der_sha256; do
  digest="$(manifest_value "${digest_key}")"
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || {
    echo "manifest contains an invalid ${digest_key}" >&2
    exit 1
  }
done
if command -v sha256sum >/dev/null; then
  if ! actual_avb_public_key_sha="$(openssl pkey -pubin \
    -in "${ARTIFACT_DIR}/avb-public.pem" -outform DER 2>/dev/null | \
    sha256sum | awk '{print $1}')"; then
    echo "could not parse AVB public key" >&2
    exit 1
  fi
else
  if ! actual_avb_public_key_sha="$(openssl pkey -pubin \
    -in "${ARTIFACT_DIR}/avb-public.pem" -outform DER 2>/dev/null | \
    shasum -a 256 | awk '{print $1}')"; then
    echo "could not parse AVB public key" >&2
    exit 1
  fi
fi
[[ "${actual_avb_public_key_sha}" =~ ^[0-9a-f]{64}$ ]] || {
  echo "could not derive AVB public-key identity" >&2
  exit 1
}
[[ "${actual_avb_public_key_sha}" \
    == "$(manifest_value avb_public_key_der_sha256)" ]] || {
  echo "AVB public key does not match the development manifest identity" >&2
  exit 1
}
[[ "$(tr -d '\r' < "${ARTIFACT_DIR}/images/android-info.txt")" \
    == 'require board=crosshatch' ]] || {
  echo "fastboot bundle does not allow exactly crosshatch" >&2
  exit 1
}

mapfile_compat=()
while IFS= read -r device_line; do
  [[ -n "${device_line}" ]] && mapfile_compat+=("${device_line%%[[:space:]]*}")
done < <("${FASTBOOT_BIN}" devices)
[[ ${#mapfile_compat[@]} -eq 1 && "${mapfile_compat[0]}" == "${SERIAL}" ]] || {
  echo "expected exactly one fastboot device with serial ${SERIAL}" >&2
  printf 'observed serials: %s\n' "${mapfile_compat[*]:-<none>}" >&2
  exit 1
}

getvar() {
  local name="$1"
  local output value
  output="$("${FASTBOOT_BIN}" -s "${SERIAL}" getvar "${name}" 2>&1)" || {
    echo "fastboot could not read ${name} from ${SERIAL}" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  }
  value="$(sed -n -E \
    "s/^\(bootloader\)[[:space:]]*${name}:[[:space:]]*([^[:space:]]+).*/\\1/p; s/^${name}:[[:space:]]*([^[:space:]]+).*/\\1/p" \
    <<<"${output}" | head -1)"
  [[ -n "${value}" ]] || {
    echo "fastboot returned no parseable ${name} for ${SERIAL}" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  }
  printf '%s\n' "${value}"
}

product="$(getvar product)"
unlocked="$(getvar unlocked)"
current_slot="$(getvar current-slot)"
slot_count="$(getvar slot-count)"

[[ "${product}" == crosshatch ]] || {
  echo "refusing non-crosshatch device: ${product}" >&2
  exit 1
}
[[ "${unlocked}" == yes || "${unlocked}" == no ]] || {
  echo "unexpected bootloader unlocked state: ${unlocked}" >&2
  exit 1
}
[[ "${current_slot}" == a || "${current_slot}" == b ]] || {
  echo "unexpected current slot: ${current_slot}" >&2
  exit 1
}
[[ "${slot_count}" == 2 ]] || {
  echo "unexpected slot count: ${slot_count}" >&2
  exit 1
}

printf 'PASS: read-only Phone Vault crosshatch preflight\n'
printf 'serial=%s\n' "${SERIAL}"
printf 'product=%s\n' "${product}"
printf 'bootloader_unlocked=%s\n' "${unlocked}"
printf 'current_slot=%s\n' "${current_slot}"
printf 'slot_count=%s\n' "${slot_count}"
printf 'artifact_directory=%s\n' "${ARTIFACT_DIR}"
printf 'checksum_manifest_sha256=%s\n' "${actual_checksum_manifest_sha}"
printf 'avb_public_key_der_sha256=%s\n' "${actual_avb_public_key_sha}"
printf 'This script performed no unlock, wipe, flash, or relock operation.\n'
