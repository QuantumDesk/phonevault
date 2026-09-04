#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
work_dir="$(mktemp -d -t phone-vault-ota-policy-test.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT
checker="${work_dir}/check_ota_package_signature"
install -m 0755 \
  "${ROOT}/tests/fixtures/fake-check-ota-package-signature.sh" \
  "${checker}"

for identity in release other; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=${identity}" \
    -keyout "${work_dir}/${identity}.key" \
    -out "${work_dir}/${identity}.x509.pem" >/dev/null 2>&1
done

make_otacerts() {
  local output="$1"
  shift
  local cert_dir="${work_dir}/certs-$RANDOM"
  mkdir "${cert_dir}"
  local certificate
  for certificate in "$@"; do
    cp "${work_dir}/${certificate}.x509.pem" \
      "${cert_dir}/${certificate}.x509.pem"
  done
  (cd "${cert_dir}" && zip -q "${output}" ./*.x509.pem)
}

make_target_files() {
  local output="$1"
  local otacerts="$2"
  local target_dir="${work_dir}/target-$RANDOM"
  mkdir -p "${target_dir}/SYSTEM/etc/security"
  cp "${otacerts}" "${target_dir}/SYSTEM/etc/security/otacerts.zip"
  (cd "${target_dir}" && zip -qr "${output}" .)
}

make_ota() {
  local output="$1"
  local certificate="$2"
  local ota_dir="${work_dir}/ota-$RANDOM"
  mkdir -p "${ota_dir}/META-INF/com/android"
  cp "${work_dir}/${certificate}.x509.pem" \
    "${ota_dir}/META-INF/com/android/otacert"
  printf 'synthetic payload' > "${ota_dir}/payload.bin"
  (cd "${ota_dir}" && zip -qr "${output}" .)
}

release_otacerts="${work_dir}/release-otacerts.zip"
make_otacerts "${release_otacerts}" release
positive_target="${work_dir}/positive-target.zip"
positive_ota="${work_dir}/positive-ota.zip"
make_target_files "${positive_target}" "${release_otacerts}"
make_ota "${positive_ota}" release
export FAKE_OTA_CHECK_LOG="${work_dir}/checker-arguments"
"${ROOT}/scripts/verify-ota-package.sh" \
  "${positive_target}" "${positive_ota}" \
  "${work_dir}/release.x509.pem" "${checker}" >/dev/null
[[ "$(sed -n '1p' "${FAKE_OTA_CHECK_LOG}")" \
      == "${work_dir}/release.x509.pem" \
    && "$(sed -n '2p' "${FAKE_OTA_CHECK_LOG}")" == "${positive_ota}" ]] || {
  echo "OTA checker did not receive the exact release certificate and package" >&2
  exit 1
}

wrong_recovery_otacerts="${work_dir}/wrong-recovery-otacerts.zip"
make_otacerts "${wrong_recovery_otacerts}" other
wrong_recovery_target="${work_dir}/wrong-recovery-target.zip"
make_target_files "${wrong_recovery_target}" "${wrong_recovery_otacerts}"
if "${ROOT}/scripts/verify-ota-package.sh" \
    "${wrong_recovery_target}" "${positive_ota}" \
    "${work_dir}/release.x509.pem" "${checker}" >/dev/null 2>&1; then
  echo "wrong recovery OTA trust certificate unexpectedly passed" >&2
  exit 1
fi

multiple_otacerts="${work_dir}/multiple-otacerts.zip"
make_otacerts "${multiple_otacerts}" release other
multiple_target="${work_dir}/multiple-target.zip"
make_target_files "${multiple_target}" "${multiple_otacerts}"
if "${ROOT}/scripts/verify-ota-package.sh" \
    "${multiple_target}" "${positive_ota}" \
    "${work_dir}/release.x509.pem" "${checker}" >/dev/null 2>&1; then
  echo "multiple recovery OTA trust certificates unexpectedly passed" >&2
  exit 1
fi

wrong_ota="${work_dir}/wrong-ota.zip"
make_ota "${wrong_ota}" other
if "${ROOT}/scripts/verify-ota-package.sh" \
    "${positive_target}" "${wrong_ota}" \
    "${work_dir}/release.x509.pem" "${checker}" >/dev/null 2>&1; then
  echo "wrong embedded OTA certificate unexpectedly passed" >&2
  exit 1
fi

export FAKE_OTA_CHECK_FAIL=1
if "${ROOT}/scripts/verify-ota-package.sh" \
    "${positive_target}" "${positive_ota}" \
    "${work_dir}/release.x509.pem" "${checker}" >/dev/null 2>&1; then
  echo "AOSP whole-file/payload checker failure unexpectedly passed" >&2
  exit 1
fi

echo "OTA recovery trust, embedded certificate, and checker-propagation tests passed."
