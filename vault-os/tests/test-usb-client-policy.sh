#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REQUIREMENTS="${ROOT}/tools/requirements.txt"
PYTHON="${ROOT}/.venv/bin/python"

grep -Fq "pyusb==1.3.1 \\" "${REQUIREMENTS}" || {
  echo 'USB client does not pin the reviewed PyUSB version' >&2
  exit 1
}
for digest in \
    bf9b754557af4717fe80c2b07cc2b923a9151f5c08d17bdb5345dac09d6a0430 \
    3af070b607467c1c164f49d5b0caabe8ac78dbed9298d703a8dbf9df4052d17e; do
  grep -Fq -- "--hash=sha256:${digest}" "${REQUIREMENTS}" || {
    echo "USB client dependency lacks reviewed artifact hash: ${digest}" >&2
    exit 1
  }
done
[[ -x "${PYTHON}" ]] || {
  echo "project Python environment is missing: ${PYTHON}" >&2
  exit 1
}
"${PYTHON}" -m unittest "${ROOT}/tools/test_aoa_client.py" "${ROOT}/tools/test_evm_verify.py"
"${PYTHON}" -m py_compile \
  "${ROOT}/tools/aoa_client.py" "${ROOT}/tools/test_aoa_client.py" \
  "${ROOT}/tools/evm_verify.py" "${ROOT}/tools/test_evm_verify.py"
# The host must recompute the hash and recover the signer, not trust the phone's claims.
grep -Fq "eip1559_transaction_hash(raw)" "${ROOT}/tools/aoa_client.py" || {
  echo 'USB client does not recompute transactionHash from the signed bytes' >&2
  exit 1
}
grep -Fq "recover_address(" "${ROOT}/tools/aoa_client.py" || {
  echo 'USB client does not recover and compare the signer address' >&2
  exit 1
}

echo 'USB client dependency, independent transaction-decoding, hash and signer-recovery policy passed.'
