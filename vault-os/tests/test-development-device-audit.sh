#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUDIT="${ROOT}/scripts/audit-development-device.sh"
FAKE_ADB="${ROOT}/tests/fixtures/fake-adb.sh"
work_dir="$(mktemp -d -t phone-vault-device-audit.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT

fixture_sha() {
  if command -v sha256sum >/dev/null; then
    printf 'fixture-apk\n' | sha256sum | awk '{print $1}'
  else
    printf 'fixture-apk\n' | shasum -a 256 | awk '{print $1}'
  fi
}

run_audit() {
  local mode="$1"
  local evidence="$2"
  PHONEVAULT_FAKE_ADB_MODE="${mode}" ADB_BIN="${FAKE_ADB}" \
    "${AUDIT}" TESTSERIAL "${evidence}" "$(fixture_sha)" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
}

run_audit positive "${work_dir}/positive" > "${work_dir}/positive.stdout"
grep -Fqx 'PASS: Phone Vault development-device static runtime audit' \
  "${work_dir}/positive/RESULT.txt"
grep -Eq '^evidence_checksum_manifest_sha256=[0-9a-f]{64}$' \
  "${work_dir}/positive.stdout"

for mode in profile-owner extra-owner wrong-home not-locked setup-incomplete; do
  evidence="${work_dir}/${mode}"
  if run_audit "${mode}" "${evidence}" \
      > "${work_dir}/${mode}.stdout" 2> "${work_dir}/${mode}.stderr"; then
    echo "invalid runtime ownership fixture unexpectedly passed: ${mode}" >&2
    exit 1
  fi
  case "${mode}" in
    profile-owner|extra-owner)
      grep -Fq 'Phone Vault is not the sole user-0 device owner' \
        "${evidence}/RESULT.txt"
      ;;
    wrong-home)
      grep -Fq 'Phone Vault is not the resolved HOME activity' \
        "${evidence}/RESULT.txt"
      ;;
    not-locked)
      grep -Fq 'appliance is not in managed lock-task mode' \
        "${evidence}/RESULT.txt"
      ;;
    setup-incomplete)
      grep -Fq 'system user setup is not complete' \
        "${evidence}/RESULT.txt"
      grep -Fq 'device is not marked provisioned' \
        "${evidence}/RESULT.txt"
      ;;
  esac
done

echo 'Development-device audit ownership/HOME negative fixtures passed.'
