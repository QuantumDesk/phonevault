#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 RELEASE_DIRECTORY [AVBTOOL]" >&2
  exit 2
fi

RELEASE_DIR="$1"
AVBTOOL="${2:-}"
[[ -d "${RELEASE_DIR}" ]] || {
  echo "release directory is missing: ${RELEASE_DIR}" >&2
  exit 1
}
for tool in awk find openssl sort unzip; do
  command -v "${tool}" >/dev/null || {
    echo "${tool} is required" >&2
    exit 1
  }
done

TARGET_FILES=phone-vault-signed-target_files.zip
OTA=phone-vault-signed-ota.zip
SOURCE_INVENTORY=SOURCE-INVENTORY.txt
PUBLIC_INVENTORY=PUBLIC-KEY-INVENTORY.txt
MANIFEST=RELEASE-MANIFEST.txt
MANIFEST_SIGNATURE=RELEASE-MANIFEST.sig
CHECKSUMS=SHA256SUMS
for required_file in "${TARGET_FILES}" "${OTA}" "${SOURCE_INVENTORY}" \
    "${PUBLIC_INVENTORY}" "${MANIFEST}" "${MANIFEST_SIGNATURE}" \
    "${CHECKSUMS}"; do
  [[ -s "${RELEASE_DIR}/${required_file}" \
      && ! -L "${RELEASE_DIR}/${required_file}" ]] || {
    echo "release bundle file is missing, empty, or a symlink: ${required_file}" >&2
    exit 1
  }
done
[[ -d "${RELEASE_DIR}/public-keys" \
    && ! -L "${RELEASE_DIR}/public-keys" ]] || {
  echo "release public-key directory is missing or a symlink" >&2
  exit 1
}

validate_checksum_file() {
  local checksum_file="$1"
  local digest path extra
  while read -r digest path extra \
      || [[ -n "${digest:-}${path:-}${extra:-}" ]]; do
    [[ -z "${extra:-}" && "${digest}" =~ ^[0-9a-f]{64}$ \
        && -n "${path:-}" && "${path}" != /* \
        && "${path}" != *'..'* && "${path}" != *\\* ]] || {
      echo "unsafe or malformed checksum entry in ${checksum_file}: ${digest} ${path:-} ${extra:-}" >&2
      return 1
    }
  done < "${checksum_file}"
}

sha256_file() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

check_checksum_file() {
  local checksum_file="$1"
  local checksum_name
  checksum_name="$(basename "${checksum_file}")"
  if command -v sha256sum >/dev/null; then
    (cd "${RELEASE_DIR}" && sha256sum --check --strict "${checksum_name}")
  else
    (cd "${RELEASE_DIR}" && shasum -a 256 --check "${checksum_name}")
  fi
}

validate_checksum_file "${RELEASE_DIR}/${CHECKSUMS}"
expected_checksum_paths="$(printf '%s\n' \
  "${MANIFEST}" "${MANIFEST_SIGNATURE}" "${PUBLIC_INVENTORY}" "${SOURCE_INVENTORY}" \
  "${OTA}" "${TARGET_FILES}" | LC_ALL=C sort)"
actual_checksum_paths="$(awk '{print $2}' "${RELEASE_DIR}/${CHECKSUMS}" | LC_ALL=C sort)"
[[ "${actual_checksum_paths}" == "${expected_checksum_paths}" ]] || {
  echo "SHA256SUMS must contain exactly the six canonical release records" >&2
  exit 1
}
check_checksum_file "${RELEASE_DIR}/${CHECKSUMS}"

validate_checksum_file "${RELEASE_DIR}/${PUBLIC_INVENTORY}"
public_inventory_paths="$(awk '{print $2}' \
  "${RELEASE_DIR}/${PUBLIC_INVENTORY}" | LC_ALL=C sort)"
actual_public_paths="$(
  cd "${RELEASE_DIR}"
  find public-keys -type f -print | LC_ALL=C sort
)"
[[ -n "${actual_public_paths}" \
    && "${public_inventory_paths}" == "${actual_public_paths}" ]] || {
  echo "public-key inventory does not exactly match exported public files" >&2
  exit 1
}
if grep -Eq '(^|/)(avb|apex)\.pem$|\.pk8$' \
    <<<"${actual_public_paths}"; then
  echo "private key material is present in the public release bundle" >&2
  exit 1
fi
while IFS= read -r public_path; do
  case "${public_path}" in
    public-keys/*.x509.pem)
      openssl x509 -in "${RELEASE_DIR}/${public_path}" -noout \
        >/dev/null 2>&1 || {
        echo "exported X.509 certificate is invalid: ${public_path}" >&2
        exit 1
      }
      ;;
    public-keys/avb-public.pem|public-keys/avb_pkmd.bin|\
    public-keys/apex-public.pem|public-keys/apex.avbpubkey|\
    public-keys/metadata-public.pem)
      ;;
    *)
      echo "unexpected file in public-key export: ${public_path}" >&2
      exit 1
      ;;
  esac
done <<<"${actual_public_paths}"
for pem_key in avb-public.pem apex-public.pem metadata-public.pem; do
  openssl pkey -pubin -in "${RELEASE_DIR}/public-keys/${pem_key}" \
    -noout >/dev/null 2>&1 || {
    echo "exported public key is invalid: ${pem_key}" >&2
    exit 1
  }
done
check_checksum_file "${RELEASE_DIR}/${PUBLIC_INVENTORY}"

for public_file in phonevault-app.x509.pem releasekey.x509.pem \
    avb-public.pem avb_pkmd.bin apex-public.pem apex.avbpubkey \
    metadata-public.pem; do
  grep -Fqx "public-keys/${public_file}" <<<"${actual_public_paths}" || {
    echo "required public verification artifact is missing: ${public_file}" >&2
    exit 1
  }
done

expected_manifest_fields="$(printf '%s\n' \
  avb_public_key_der_sha256 build_fingerprint channel created_utc \
  ota_release_cert_sha256 phonevault_app_cert_sha256 phonevault_app_sha256 \
  public_key_inventory_sha256 release_metadata_public_key_der_sha256 \
  signed_ota_sha256 signed_target_files_sha256 \
  source_inventory_sha256 vbmeta_digest_sha256 vbmeta_rollback_index | LC_ALL=C sort)"
if grep -Ev '^[a-z0-9_]+=.*$' "${RELEASE_DIR}/${MANIFEST}" | grep -q .; then
  echo "release manifest contains a malformed line" >&2
  exit 1
fi
actual_manifest_fields="$(awk -F= 'NF >= 2 {print $1}' \
  "${RELEASE_DIR}/${MANIFEST}" | LC_ALL=C sort)"
[[ "${actual_manifest_fields}" == "${expected_manifest_fields}" ]] || {
  echo "release manifest fields are missing, duplicated, or unknown" >&2
  exit 1
}

manifest_value() {
  local field="$1"
  sed -n "s/^${field}=//p" "${RELEASE_DIR}/${MANIFEST}"
}
for hash_field in avb_public_key_der_sha256 ota_release_cert_sha256 \
    phonevault_app_cert_sha256 phonevault_app_sha256 \
    public_key_inventory_sha256 release_metadata_public_key_der_sha256 \
    signed_ota_sha256 \
    signed_target_files_sha256 source_inventory_sha256 vbmeta_digest_sha256; do
  [[ "$(manifest_value "${hash_field}")" =~ ^[0-9a-f]{64}$ ]] || {
    echo "release manifest has invalid digest: ${hash_field}" >&2
    exit 1
  }
done
[[ "$(manifest_value channel)" == production ]] || {
  echo "release manifest channel is not production" >&2
  exit 1
}
[[ "$(manifest_value created_utc)" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || {
  echo "release manifest timestamp is not canonical UTC" >&2
  exit 1
}
[[ "$(manifest_value vbmeta_rollback_index)" =~ ^[1-9][0-9]*$ ]] || {
  echo "release manifest rollback index is not positive" >&2
  exit 1
}

for mapping in \
    "signed_target_files_sha256:${TARGET_FILES}" \
    "signed_ota_sha256:${OTA}" \
    "source_inventory_sha256:${SOURCE_INVENTORY}" \
    "public_key_inventory_sha256:${PUBLIC_INVENTORY}"; do
  field="${mapping%%:*}"
  path="${mapping#*:}"
  [[ "$(manifest_value "${field}")" == \
      "$(sha256_file "${RELEASE_DIR}/${path}")" ]] || {
    echo "release manifest digest mismatch: ${field}" >&2
    exit 1
  }
done

validate_checksum_file "${RELEASE_DIR}/${SOURCE_INVENTORY}"
source_paths="$(awk '{print $2}' "${RELEASE_DIR}/${SOURCE_INVENTORY}")"
for source_requirement in app/gradle.lockfile gradle/verification-metadata.xml \
    vault-os/manifest/lineage-22.2-pinned.xml \
    vault-os/scripts/sign-release.sh; do
  grep -Fqx "${source_requirement}" <<<"${source_paths}" || {
    echo "release source inventory omits ${source_requirement}" >&2
    exit 1
  }
done
if grep -Fq 'vault-os/keys/development/' <<<"${source_paths}"; then
  echo "release source inventory contains development key material" >&2
  exit 1
fi

target_listing="$(unzip -Z1 "${RELEASE_DIR}/${TARGET_FILES}")"
phonevault_path=SYSTEM/app/PhoneVault/PhoneVault.apk
[[ "$(grep -Fxc "${phonevault_path}" <<<"${target_listing}")" == 1 ]] || {
  echo "signed target-files does not contain exactly one ordinary Phone Vault APK" >&2
  exit 1
}
embedded_app_sha="$(unzip -p "${RELEASE_DIR}/${TARGET_FILES}" \
  "${phonevault_path}" | { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; } | awk '{print $1}')"
[[ "${embedded_app_sha}" == "$(manifest_value phonevault_app_sha256)" ]] || {
  echo "release manifest does not bind the embedded Phone Vault APK" >&2
  exit 1
}

build_fingerprint=''
for build_prop in SYSTEM/build.prop SYSTEM/system/build.prop; do
  if grep -Fqx "${build_prop}" <<<"${target_listing}"; then
    build_fingerprint="$(unzip -p "${RELEASE_DIR}/${TARGET_FILES}" \
      "${build_prop}" | sed -n \
        -e 's/^ro\.build\.fingerprint=//p' \
        -e 's/^ro\.system\.build\.fingerprint=//p' | head -1)"
    [[ -n "${build_fingerprint}" ]] && break
  fi
done
[[ -n "${build_fingerprint}" \
    && "${build_fingerprint}" == "$(manifest_value build_fingerprint)" ]] || {
  echo "release manifest build fingerprint does not match target-files" >&2
  exit 1
}

app_cert_sha="$(openssl x509 \
  -in "${RELEASE_DIR}/public-keys/phonevault-app.x509.pem" \
  -outform DER | { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; } | awk '{print $1}')"
ota_cert_sha="$(openssl x509 \
  -in "${RELEASE_DIR}/public-keys/releasekey.x509.pem" \
  -outform DER | { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; } | awk '{print $1}')"
avb_public_sha="$(openssl pkey -pubin \
  -in "${RELEASE_DIR}/public-keys/avb-public.pem" \
  -outform DER | { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; } | awk '{print $1}')"
metadata_public_sha="$(openssl pkey -pubin \
  -in "${RELEASE_DIR}/public-keys/metadata-public.pem" \
  -outform DER | { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; } | awk '{print $1}')"
[[ "${app_cert_sha}" == "$(manifest_value phonevault_app_cert_sha256)" \
    && "${ota_cert_sha}" == "$(manifest_value ota_release_cert_sha256)" \
    && "${avb_public_sha}" == "$(manifest_value avb_public_key_der_sha256)" \
    && "${metadata_public_sha}" \
      == "$(manifest_value release_metadata_public_key_der_sha256)" ]] || {
  echo "release manifest does not match exported public identities" >&2
  exit 1
}
[[ "$(wc -c < "${RELEASE_DIR}/${MANIFEST_SIGNATURE}" | tr -d ' ')" == 64 ]] || {
  echo "release manifest Ed25519 signature has an unexpected size" >&2
  exit 1
}
openssl pkeyutl -verify -pubin -rawin \
  -inkey "${RELEASE_DIR}/public-keys/metadata-public.pem" \
  -in "${RELEASE_DIR}/${MANIFEST}" \
  -sigfile "${RELEASE_DIR}/${MANIFEST_SIGNATURE}" >/dev/null 2>&1 || {
    echo "release manifest metadata signature is invalid" >&2
    exit 1
  }

if [[ -n "${AVBTOOL}" ]]; then
  for tool in cmp python3; do
    command -v "${tool}" >/dev/null || {
      echo "${tool} is required for public-key export verification" >&2
      exit 1
    }
  done
  if [[ "${AVBTOOL}" == */* ]]; then
    [[ -f "${AVBTOOL}" ]] || {
      echo "avbtool is missing: ${AVBTOOL}" >&2
      exit 1
    }
    avbtool_command=(python3 "${AVBTOOL}")
  else
    command -v "${AVBTOOL}" >/dev/null || {
      echo "avbtool is missing: ${AVBTOOL}" >&2
      exit 1
    }
    avbtool_command=("${AVBTOOL}")
  fi
  enrollment_dir="$(mktemp -d -t phone-vault-release-enrollment.XXXXXX)"
  trap 'rm -rf -- "${enrollment_dir}"' EXIT
  "${avbtool_command[@]}" extract_public_key \
    --key "${RELEASE_DIR}/public-keys/avb-public.pem" \
    --output "${enrollment_dir}/avb_pkmd.bin"
  cmp -s "${enrollment_dir}/avb_pkmd.bin" \
    "${RELEASE_DIR}/public-keys/avb_pkmd.bin" || {
    echo "AVB bootloader-enrollment blob does not match exported AVB public key" >&2
    exit 1
  }
  "${avbtool_command[@]}" extract_public_key \
    --key "${RELEASE_DIR}/public-keys/apex-public.pem" \
    --output "${enrollment_dir}/apex.avbpubkey"
  cmp -s "${enrollment_dir}/apex.avbpubkey" \
    "${RELEASE_DIR}/public-keys/apex.avbpubkey" || {
    echo "APEX public-key blob does not match exported APEX PEM key" >&2
    exit 1
  }
fi

echo "Release bundle metadata, inventories, public identities, and artifact bindings passed."
if [[ -n "${AVBTOOL}" ]]; then
  echo "AVB and APEX binary public-key exports match their PEM identities."
else
  echo "Pass avbtool to verify binary AVB/APEX public-key export bindings."
fi
echo "Run verify-signed-avb.sh and verify-ota-package.sh for cryptographic image and OTA verification."
