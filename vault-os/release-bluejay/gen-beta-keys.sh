#!/usr/bin/env bash
# Generate the bluejay BETA-TEST signing keys ON THE BUILD HOST, as the tree owner:
#   gen-beta-keys.sh [KEY_DIR]        (default: $HOME/.phonevault-keys/beta)
#
#   phonevault_bluejay_avb_BETA_rsa4096.pem   AVB key (vbmeta + boot/vbmeta_system/vbmeta_vendor)
#   phonevault-app-BETA.pk8 / .x509.pem       signer-app key (APK Signature Scheme v2)
#   avb_pkmd_bluejay_BETA.bin                 public AVB key blob (future avb_custom_key)
#   BETA-TEST-KEYS.txt                        label + public digests
#
# These are BETA-TEST keys: they sign only beta test images and are replaced by the
# offline-generated beta keys (generate-release-keyset.sh in the release container, on an
# offline machine) before any phone is relocked to a beta key. They are not the dev keys (the
# AVB dev key stays in ~/.phonevault-keys/avb) and not release keys. Private keys: mode 0600 in
# a 0700 directory, never printed, never committed, never copied off the host. Refuses to
# overwrite an existing key (a new key means a new identity for every installed phone).
set -euo pipefail
KEY_DIR="${1:-${HOME}/.phonevault-keys/beta}"
AVBTOOL="${PV_AVBTOOL:-${LINEAGE_TREE:-/build/lineage-24}/out/host/linux-x86/bin/avbtool}"
umask 077
[[ -x "${AVBTOOL}" ]] || { echo "avbtool not found: ${AVBTOOL} (set PV_AVBTOOL)" >&2; exit 2; }
mkdir -p "${KEY_DIR}"
chmod 0700 "${KEY_DIR}" "$(dirname "${KEY_DIR}")"

AVB="${KEY_DIR}/phonevault_bluejay_avb_BETA_rsa4096.pem"
APP="${KEY_DIR}/phonevault-app-BETA"
for f in "${AVB}" "${APP}.pk8" "${APP}.x509.pem"; do
  [[ ! -e "${f}" ]] || { echo "refusing to overwrite ${f}" >&2; exit 1; }
done

# AVB: RSA-4096 PEM (the format avbtool and the build take), the dev key's twin in shape only.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "${AVB}" 2>/dev/null
chmod 0600 "${AVB}"
"${AVBTOOL}" extract_public_key --key "${AVB}" --output "${KEY_DIR}/avb_pkmd_bluejay_BETA.bin"

# App: RSA-4096, PKCS#8 DER private key + self-signed X.509 (the layout apksigner --key/--cert
# and sign-signer-apk.sh use). The subject says what it is.
tmp_pem="$(mktemp "${KEY_DIR}/.app-key.XXXXXX")"
trap 'rm -f "${tmp_pem}"' EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "${tmp_pem}" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in "${tmp_pem}" -out "${APP}.pk8"
openssl req -new -x509 -sha256 -days 3650 -key "${tmp_pem}" -out "${APP}.x509.pem" \
  -subj "/O=Phone Vault/OU=BETA-TEST signing key - replace before release/CN=Phone Vault signer app BETA-TEST"
rm -f "${tmp_pem}"; trap - EXIT
chmod 0600 "${APP}.pk8"
chmod 0644 "${APP}.x509.pem" "${KEY_DIR}/avb_pkmd_bluejay_BETA.bin"

avb_sha1="$(sha1sum "${KEY_DIR}/avb_pkmd_bluejay_BETA.bin" | cut -c1-40)"
avb_sha256="$(sha256sum "${KEY_DIR}/avb_pkmd_bluejay_BETA.bin" | cut -c1-64)"
app_cert="$(openssl x509 -in "${APP}.x509.pem" -outform DER | sha256sum | cut -c1-64)"
cat > "${KEY_DIR}/BETA-TEST-KEYS.txt" <<EOF
Phone Vault bluejay BETA-TEST keys (generated $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname) by release-bluejay/gen-beta-keys.sh)

NOT release keys, NOT the dev keys. They sign beta test images only and are to be replaced by
the offline-generated beta keys before any phone is relocked (avb_custom_key) to a beta key.
Private keys (*.pem AVB key, *.pk8) never leave this host and are never printed or committed.

avb public key blob (avbtool extract_public_key) sha1   ${avb_sha1}
avb public key blob                              sha256 ${avb_sha256}
signer app certificate (DER)                     sha256 ${app_cert}
EOF
chmod 0644 "${KEY_DIR}/BETA-TEST-KEYS.txt"
cat "${KEY_DIR}/BETA-TEST-KEYS.txt"
ls -la "${KEY_DIR}"
