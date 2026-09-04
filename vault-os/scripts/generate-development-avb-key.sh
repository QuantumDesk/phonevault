#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEY_DIR="${ROOT}/keys/development"
PRIVATE_KEY="${KEY_DIR}/avb.pem"
PUBLIC_KEY="${KEY_DIR}/avb-public.pem"

if [[ -e "${PRIVATE_KEY}" || -e "${PUBLIC_KEY}" ]]; then
  echo "Refusing to overwrite an existing development AVB key." >&2
  exit 1
fi

umask 077
mkdir -p "${KEY_DIR}"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "${PRIVATE_KEY}"
openssl pkey -in "${PRIVATE_KEY}" -pubout -out "${PUBLIC_KEY}"
chmod 0600 "${PRIVATE_KEY}"
chmod 0644 "${PUBLIC_KEY}"

echo "Generated development-only AVB key: ${PRIVATE_KEY}"
echo "Never use this key for a public release."
