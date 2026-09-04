#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
work_dir="$(mktemp -d -t phone-vault-release-bundle-test.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT
release_dir="${work_dir}/release"
fixture="${work_dir}/target"
mkdir -p "${release_dir}/public-keys" \
  "${fixture}/SYSTEM/app/PhoneVault" "${fixture}/SYSTEM"
printf 'synthetic-apk' > "${fixture}/SYSTEM/app/PhoneVault/PhoneVault.apk"
printf '%s\n' \
  'ro.build.fingerprint=PhoneVault/crosshatch/test:15/test/release-keys' \
  > "${fixture}/SYSTEM/build.prop"
(cd "${fixture}" && zip -qr \
  "${release_dir}/phone-vault-signed-target_files.zip" .)
printf 'synthetic-ota' > "${release_dir}/phone-vault-signed-ota.zip"

openssl req -x509 -newkey rsa:2048 -nodes \
  -subj '/CN=Phone Vault App Test' -days 1 \
  -keyout "${work_dir}/app.key" \
  -out "${release_dir}/public-keys/phonevault-app.x509.pem" \
  >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes \
  -subj '/CN=Phone Vault OTA Test' -days 1 \
  -keyout "${work_dir}/ota.key" \
  -out "${release_dir}/public-keys/releasekey.x509.pem" \
  >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "${work_dir}/avb.key" >/dev/null 2>&1
openssl pkey -in "${work_dir}/avb.key" -pubout \
  -out "${release_dir}/public-keys/avb-public.pem" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "${work_dir}/apex.key" >/dev/null 2>&1
openssl pkey -in "${work_dir}/apex.key" -pubout \
  -out "${release_dir}/public-keys/apex-public.pem" >/dev/null 2>&1
openssl genpkey -algorithm ED25519 \
  -out "${work_dir}/metadata.key" >/dev/null 2>&1
openssl pkey -in "${work_dir}/metadata.key" -pubout \
  -out "${release_dir}/public-keys/metadata-public.pem" >/dev/null 2>&1
verifier_args=("${release_dir}")
if [[ -n "${PHONEVAULT_AVBTOOL:-}" ]]; then
  python3 "${PHONEVAULT_AVBTOOL}" extract_public_key \
    --key "${release_dir}/public-keys/avb-public.pem" \
    --output "${release_dir}/public-keys/avb_pkmd.bin"
  python3 "${PHONEVAULT_AVBTOOL}" extract_public_key \
    --key "${release_dir}/public-keys/apex-public.pem" \
    --output "${release_dir}/public-keys/apex.avbpubkey"
  verifier_args+=("${PHONEVAULT_AVBTOOL}")
else
  printf 'synthetic-avb-pkmd' > "${release_dir}/public-keys/avb_pkmd.bin"
  printf 'synthetic-apex-avbpubkey' \
    > "${release_dir}/public-keys/apex.avbpubkey"
fi

{
  printf '%064d  app/gradle.lockfile\n' 0
  printf '%064d  gradle/verification-metadata.xml\n' 0
  printf '%064d  vault-os/manifest/lineage-22.2-pinned.xml\n' 0
  printf '%064d  vault-os/scripts/sign-release.sh\n' 0
} > "${release_dir}/SOURCE-INVENTORY.txt"

hash_file() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

refresh_checksums() {
  (
    cd "${release_dir}"
    for path in phone-vault-signed-target_files.zip \
        phone-vault-signed-ota.zip SOURCE-INVENTORY.txt \
        PUBLIC-KEY-INVENTORY.txt RELEASE-MANIFEST.txt \
        RELEASE-MANIFEST.sig; do
      printf '%s  %s\n' "$(hash_file "${release_dir}/${path}")" "${path}"
    done
  ) > "${release_dir}/SHA256SUMS"
}

refresh_metadata() {
  (
    cd "${release_dir}"
    find public-keys -type f -print | LC_ALL=C sort | while IFS= read -r path; do
      printf '%s  %s\n' "$(hash_file "${release_dir}/${path}")" "${path}"
    done
  ) > "${release_dir}/PUBLIC-KEY-INVENTORY.txt"

  app_cert="$(openssl x509 \
    -in "${release_dir}/public-keys/phonevault-app.x509.pem" \
    -outform DER | { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; } | awk '{print $1}')"
  ota_cert="$(openssl x509 \
    -in "${release_dir}/public-keys/releasekey.x509.pem" \
    -outform DER | { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; } | awk '{print $1}')"
  avb_pub="$(openssl pkey -pubin \
    -in "${release_dir}/public-keys/avb-public.pem" \
    -outform DER | { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; } | awk '{print $1}')"
  metadata_pub="$(openssl pkey -pubin \
    -in "${release_dir}/public-keys/metadata-public.pem" \
    -outform DER | { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; } | awk '{print $1}')"
  app_sha="$(hash_file "${fixture}/SYSTEM/app/PhoneVault/PhoneVault.apk")"
  {
    echo 'channel=production'
    echo 'created_utc=2026-08-18T12:00:00Z'
    echo 'build_fingerprint=PhoneVault/crosshatch/test:15/test/release-keys'
    echo "phonevault_app_cert_sha256=${app_cert}"
    echo "phonevault_app_sha256=${app_sha}"
    echo "avb_public_key_der_sha256=${avb_pub}"
    echo "release_metadata_public_key_der_sha256=${metadata_pub}"
    printf 'vbmeta_digest_sha256=%064d\n' 1
    echo 'vbmeta_rollback_index=1'
    echo "ota_release_cert_sha256=${ota_cert}"
    echo "public_key_inventory_sha256=$(hash_file \
      "${release_dir}/PUBLIC-KEY-INVENTORY.txt")"
    echo "source_inventory_sha256=$(hash_file \
      "${release_dir}/SOURCE-INVENTORY.txt")"
    echo "signed_target_files_sha256=$(hash_file \
      "${release_dir}/phone-vault-signed-target_files.zip")"
    echo "signed_ota_sha256=$(hash_file \
      "${release_dir}/phone-vault-signed-ota.zip")"
  } > "${release_dir}/RELEASE-MANIFEST.txt"
  openssl pkeyutl -sign -rawin -inkey "${work_dir}/metadata.key" \
    -in "${release_dir}/RELEASE-MANIFEST.txt" \
    -out "${release_dir}/RELEASE-MANIFEST.sig"
  refresh_checksums
}

refresh_metadata
"${ROOT}/scripts/verify-release-bundle-metadata.sh" \
  "${verifier_args[@]}" >/dev/null

cp "${release_dir}/RELEASE-MANIFEST.sig" \
  "${work_dir}/valid-release-manifest.sig"
printf '%064d' 0 > "${release_dir}/RELEASE-MANIFEST.sig"
refresh_checksums
if "${ROOT}/scripts/verify-release-bundle-metadata.sh" \
    "${verifier_args[@]}" > /dev/null 2>&1; then
  echo "release bundle accepted an invalid metadata signature" >&2
  exit 1
fi
mv "${work_dir}/valid-release-manifest.sig" \
  "${release_dir}/RELEASE-MANIFEST.sig"
refresh_checksums

if [[ -n "${PHONEVAULT_AVBTOOL:-}" ]]; then
  printf 'wrong-enrollment-key' \
    > "${release_dir}/public-keys/avb_pkmd.bin"
  refresh_metadata
  if "${ROOT}/scripts/verify-release-bundle-metadata.sh" \
      "${verifier_args[@]}" >/dev/null 2>&1; then
    echo "release bundle accepted mismatched AVB enrollment blob" >&2
    exit 1
  fi
  python3 "${PHONEVAULT_AVBTOOL}" extract_public_key \
    --key "${release_dir}/public-keys/avb-public.pem" \
    --output "${release_dir}/public-keys/avb_pkmd.bin"
  refresh_metadata
fi

cp "${release_dir}/SHA256SUMS" "${work_dir}/safe-checksums"
sed 's#phone-vault-signed-ota.zip#../phone-vault-signed-ota.zip#' \
  "${work_dir}/safe-checksums" > "${release_dir}/SHA256SUMS"
if "${ROOT}/scripts/verify-release-bundle-metadata.sh" \
    "${verifier_args[@]}" >/dev/null 2>&1; then
  echo "release bundle accepted a path-traversal checksum" >&2
  exit 1
fi
mv "${work_dir}/safe-checksums" "${release_dir}/SHA256SUMS"

printf 'malformed-manifest-line\n' >> "${release_dir}/RELEASE-MANIFEST.txt"
(
  cd "${release_dir}"
  for path in phone-vault-signed-target_files.zip \
      phone-vault-signed-ota.zip SOURCE-INVENTORY.txt \
      PUBLIC-KEY-INVENTORY.txt RELEASE-MANIFEST.txt \
      RELEASE-MANIFEST.sig; do
    printf '%s  %s\n' "$(hash_file "${release_dir}/${path}")" "${path}"
  done
) > "${release_dir}/SHA256SUMS"
if "${ROOT}/scripts/verify-release-bundle-metadata.sh" \
    "${verifier_args[@]}" >/dev/null 2>&1; then
  echo "release bundle accepted a malformed manifest line" >&2
  exit 1
fi
sed -i.bak '/^malformed-manifest-line$/d' \
  "${release_dir}/RELEASE-MANIFEST.txt"
mv "${release_dir}/RELEASE-MANIFEST.txt.bak" \
  "${work_dir}/manifest-edit-backup"
refresh_metadata

cp "${release_dir}/public-keys/avb-public.pem" \
  "${release_dir}/public-keys/avb.pem"
refresh_metadata
if "${ROOT}/scripts/verify-release-bundle-metadata.sh" \
    "${verifier_args[@]}" >/dev/null 2>&1; then
  echo "release bundle accepted exported private-key filename" >&2
  exit 1
fi
mv "${release_dir}/public-keys/avb.pem" "${work_dir}/rejected-avb.pem"

refresh_metadata
printf 'not public key material' \
  > "${release_dir}/public-keys/unexpected.txt"
refresh_metadata
if "${ROOT}/scripts/verify-release-bundle-metadata.sh" \
    "${verifier_args[@]}" >/dev/null 2>&1; then
  echo "release bundle accepted an unexpected public-export file" >&2
  exit 1
fi
mv "${release_dir}/public-keys/unexpected.txt" \
  "${work_dir}/rejected-public-file"

refresh_metadata
cp "${release_dir}/SOURCE-INVENTORY.txt" "${work_dir}/safe-source-inventory"
printf '%064d  ../outside-source' 0 \
  >> "${release_dir}/SOURCE-INVENTORY.txt"
refresh_metadata
if "${ROOT}/scripts/verify-release-bundle-metadata.sh" \
    "${verifier_args[@]}" >/dev/null 2>&1; then
  echo "release bundle accepted path traversal in source inventory" >&2
  exit 1
fi
mv "${work_dir}/safe-source-inventory" \
  "${release_dir}/SOURCE-INVENTORY.txt"
refresh_metadata
printf '%064d  vault-os/keys/development/avb.pem\n' 0 \
  >> "${release_dir}/SOURCE-INVENTORY.txt"
refresh_metadata
if "${ROOT}/scripts/verify-release-bundle-metadata.sh" \
    "${verifier_args[@]}" >/dev/null 2>&1; then
  echo "release bundle accepted development key in source inventory" >&2
  exit 1
fi

echo "Release bundle metadata positive and negative tests passed."
