#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f /.dockerenv ]]; then
  echo "Run inside the isolated Phone Vault build container." >&2
  exit 2
fi
if [[ $# -ne 1 || "$1" != /release-keys ]]; then
  echo "usage: $0 /release-keys" >&2
  echo "Bind-mount an encrypted offline directory at exactly /release-keys." >&2
  exit 2
fi

SOURCE=/home/builder/android/lineage
KEY_DIR=/release-keys
MAKE_KEY="${SOURCE}/development/tools/make_key"
AVBTOOL="${SOURCE}/external/avb/avbtool.py"
[[ -x "${MAKE_KEY}" && -f "${AVBTOOL}" ]] || {
  echo "Android signing tools are missing from the source checkout." >&2
  exit 1
}
mountpoint -q "${KEY_DIR}" || {
  echo "/release-keys must be a dedicated external bind mount." >&2
  exit 1
}
if find "${KEY_DIR}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "/release-keys is not empty; refusing to overwrite or mix keysets." >&2
  exit 1
fi

subject="${PHONEVAULT_KEY_SUBJECT:-/C=US/O=Phone Vault/OU=Offline Release/CN=Phone Vault}"
umask 077
run_make_key() {
  local name="$1"
  local status
  set +e
  "${MAKE_KEY}" "${KEY_DIR}/${name}" "${subject}" rsa
  status=$?
  set -e

  # The pinned Lineage/AOSP helper installs one cleanup trap for EXIT, INT,
  # and QUIT whose body ends in `exit 1`. It therefore returns 1 after a
  # successful generation. Tolerate only that exact known helper defect and
  # only after both DER PKCS#8 and X.509 outputs parse; every other failure is
  # fatal. This can be removed when the pinned helper fixes its EXIT trap.
  if ((status != 0)); then
    [[ "${status}" == 1 ]] || return "${status}"
    grep -Fqx \
      "trap 'rm -rf \${tmpdir}; echo; exit 1' EXIT INT QUIT" \
      "${MAKE_KEY}" || return "${status}"
  fi
  [[ -s "${KEY_DIR}/${name}.pk8" \
      && -s "${KEY_DIR}/${name}.x509.pem" ]] || {
    echo "Android key generation did not produce both files: ${name}" >&2
    return 1
  }
  openssl asn1parse -inform DER -in "${KEY_DIR}/${name}.pk8" \
    -noout >/dev/null
  openssl x509 -in "${KEY_DIR}/${name}.x509.pem" -noout >/dev/null
}
for name in releasekey platform shared media networkstack sdk_sandbox bluetooth nfc module phonevault-app; do
  run_make_key "${name}"
done

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out "${KEY_DIR}/avb.pem"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out "${KEY_DIR}/apex.pem"
openssl genpkey -algorithm ED25519 -out "${KEY_DIR}/metadata.pem"
python3 "${AVBTOOL}" extract_public_key \
  --key "${KEY_DIR}/avb.pem" --output "${KEY_DIR}/avb_pkmd.bin"
python3 "${AVBTOOL}" extract_public_key \
  --key "${KEY_DIR}/apex.pem" --output "${KEY_DIR}/apex.avbpubkey"
openssl pkey -in "${KEY_DIR}/avb.pem" -pubout \
  -out "${KEY_DIR}/avb-public.pem"
openssl pkey -in "${KEY_DIR}/apex.pem" -pubout \
  -out "${KEY_DIR}/apex-public.pem"
openssl pkey -in "${KEY_DIR}/metadata.pem" -pubout \
  -out "${KEY_DIR}/metadata-public.pem"

{
  echo '# Phone Vault public release-key inventory'
  echo '# Keep this with release metadata; keep *.pk8, avb.pem, apex.pem, and metadata.pem offline.'
  (
    cd "${KEY_DIR}"
    public_files=(
      ./*.x509.pem
      avb-public.pem
      avb_pkmd.bin
      apex-public.pem
      apex.avbpubkey
      metadata-public.pem
    )
    sha256sum "${public_files[@]}"
  )
} > "${KEY_DIR}/public-key-inventory.txt"
chmod 0600 "${KEY_DIR}"/*.pk8 "${KEY_DIR}/avb.pem" "${KEY_DIR}/apex.pem" \
  "${KEY_DIR}/metadata.pem"
chmod 0644 "${KEY_DIR}"/*.x509.pem "${KEY_DIR}/avb-public.pem" \
  "${KEY_DIR}/avb_pkmd.bin" "${KEY_DIR}/apex-public.pem" \
  "${KEY_DIR}/apex.avbpubkey" \
  "${KEY_DIR}/metadata-public.pem" \
  "${KEY_DIR}/public-key-inventory.txt"

echo "Release keyset created at /release-keys. Disconnect and back it up offline."
