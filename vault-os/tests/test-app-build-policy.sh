#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LOCK="${ROOT}/app/gradle.lockfile"
VERIFY="${ROOT}/gradle/verification-metadata.xml"

require_literal() {
  local file="$1"
  local value="$2"
  grep -Fq -- "${value}" "${file}" || {
    echo "missing app build invariant in ${file}: ${value}" >&2
    exit 1
  }
}

[[ -s "${LOCK}" && -s "${VERIFY}" ]] || {
  echo "dependency lock or verification inventory is missing" >&2
  exit 1
}
command -v xmllint >/dev/null || {
  echo "xmllint is required" >&2
  exit 1
}
xmllint --noout "${VERIFY}"

require_literal "${ROOT}/build.gradle" 'lockAllConfigurations()'
require_literal "${LOCK}" 'org.web3j:crypto:4.12.3='
require_literal "${LOCK}" 'org.bouncycastle:bcprov-jdk18on:1.85.2='
if grep -Fq 'org.bouncycastle:bcprov-jdk18on:1.78.1=' "${LOCK}"; then
  echo "vulnerable Bouncy Castle 1.78.1 is still resolved" >&2
  exit 1
fi
# No blanket web3j keep rule: R8 must strip Jackson / PQC / dump code from the release DEX.
if grep -Eq '^\s*-keep class org\.web3j\.\*\*' "${ROOT}/app/proguard-rules.pro"; then
  echo "blanket web3j keep rule retains unused crypto and Jackson in the release DEX" >&2
  exit 1
fi
RELEASE_APK="${ROOT}/app/build/outputs/apk/release/app-release-unsigned.apk"
if [[ -s "${RELEASE_APK}" ]] && command -v unzip >/dev/null; then
  DEX_DIR="$(mktemp -d)"
  trap 'rm -rf "${DEX_DIR}"' EXIT
  unzip -q -o "${RELEASE_APK}" 'classes*.dex' -d "${DEX_DIR}"
  for forbidden in 'org/bouncycastle/pqc' 'com/fasterxml/jackson' 'org/web3j/crypto/WalletFile' 'vault_dump'; do
    if cat "${DEX_DIR}"/*.dex | grep -a -q -- "${forbidden}"; then
      echo "release DEX still contains ${forbidden}" >&2
      exit 1
    fi
  done
fi
require_literal "${VERIFY}" '<verify-metadata>true</verify-metadata>'
require_literal "${VERIFY}" 'name="crypto" version="4.12.3"'
require_literal "${VERIFY}" 'aapt2-8.7.3-12006047-linux.jar'
require_literal "${VERIFY}" 'aapt2-8.7.3-12006047-osx.jar'

for signer in \
    "${ROOT}/tools/build.sh" \
    "${ROOT}/vault-os/scripts/sign-signer-apk.sh"; do
  require_literal "${signer}" '--min-sdk-version 21'
  require_literal "${signer}" '--v1-signing-enabled false'
  require_literal "${signer}" '--v2-signing-enabled true'
  require_literal "${signer}" '--v3-signing-enabled false'
done
require_literal "${ROOT}/tools/build.sh" 'assembleAppliance "$@"'
require_literal "${ROOT}/vault-os/scripts/sign-release.sh" 'app/gradle.lockfile'
require_literal "${ROOT}/vault-os/scripts/sign-release.sh" 'gradle/verification-metadata.xml'
require_literal "${ROOT}/vault-os/scripts/sign-release.sh" "! -path 'vault-os/keys/development/*'"

if grep -REn 'mktemp.*XXXXXX\.' \
    "${ROOT}/tools" "${ROOT}/vault-os/scripts"; then
  echo "mktemp template has a suffix after XXXXXX and is predictable on macOS" >&2
  exit 1
fi

echo "App dependency locking, checksum verification, offline-build support, and deterministic v2 signing policy passed."
