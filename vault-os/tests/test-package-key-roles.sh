#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
work_dir="$(mktemp -d -t phone-vault-package-role-test.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT
source_root="${work_dir}/source"
cert_dir="${work_dir}/keys"
fixture="${work_dir}/target"
mkdir -p \
  "${source_root}/prebuilts/sdk/tools/linux/lib" \
  "${source_root}/prebuilts/jdk/jdk21/linux-x86/bin" \
  "${source_root}/out/host/linux-x86/bin" \
  "${cert_dir}" "${fixture}/META" \
  "${fixture}/SYSTEM/app/PhoneVault" \
  "${fixture}/SYSTEM/app/SystemThing" \
  "${fixture}/SYSTEM/apex"
install -m 0755 "${ROOT}/tests/fixtures/fake-apksigner-java.sh" \
  "${source_root}/prebuilts/jdk/jdk21/linux-x86/bin/java"
printf 'fake apksigner jar' \
  > "${source_root}/prebuilts/sdk/tools/linux/lib/apksigner.jar"
printf '#!/usr/bin/env bash\nexit 1\n' \
  > "${source_root}/out/host/linux-x86/bin/deapexer"
chmod 0755 "${source_root}/out/host/linux-x86/bin/deapexer"

for role in phonevault-app platform module; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=${role}" \
    -keyout "${work_dir}/${role}.key" \
    -out "${cert_dir}/${role}.x509.pem" >/dev/null 2>&1
done
cert_digest() {
  openssl x509 -in "${cert_dir}/$1.x509.pem" -outform DER | \
    { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; } | \
    awk '{print $1}'
}
phonevault_digest="$(cert_digest phonevault-app)"
platform_digest="$(cert_digest platform)"
module_digest="$(cert_digest module)"
export FAKE_PHONEVAULT_DIGEST="${phonevault_digest}"
export FAKE_SYSTEMTHING_DIGEST="${platform_digest}"
export FAKE_APEX_DIGEST="${module_digest}"

printf 'PHONEVAULT\n' \
  > "${fixture}/SYSTEM/app/PhoneVault/PhoneVault.apk"
printf 'SYSTEMTHING\n' \
  > "${fixture}/SYSTEM/app/SystemThing/SystemThing.apk"
apex_dir="${work_dir}/apex"
mkdir "${apex_dir}"
printf 'APEX\n' > "${apex_dir}/marker"
printf 'expected-apex-payload-key' > "${apex_dir}/apex_pubkey"
(cd "${apex_dir}" && zip -q \
  "${fixture}/SYSTEM/apex/com.android.test.apex" marker apex_pubkey)
printf 'expected-apex-payload-key' > "${work_dir}/apex.avbpubkey"

write_metadata() {
  local system_certificate="$1"
  local apex_certificate="$2"
  printf '%s\n' \
    'name="PhoneVault.apk" certificate="PRESIGNED" private_key="PRESIGNED"' \
    "name=\"SystemThing.apk\" certificate=\"${system_certificate}\" private_key=\"unused\"" \
    > "${fixture}/META/apkcerts.txt"
  printf '%s\n' \
    "name=\"com.android.test.apex\" public_key=\"unused\" private_key=\"unused\" container_certificate=\"${apex_certificate}\" container_private_key=\"unused\"" \
    > "${fixture}/META/apexkeys.txt"
}

make_target_files() {
  local output="$1"
  (cd "${fixture}" && zip -qr "${output}" .)
}

write_metadata '/release-keys/platform.x509.pem' \
  '/release-keys/module.x509.pem'
positive="${work_dir}/positive.zip"
make_target_files "${positive}"
ANDROID_BUILD_TOP="${source_root}" \
  "${ROOT}/scripts/verify-owned-package-keys.sh" \
  "${positive}" "${cert_dir}" "${work_dir}/apex.avbpubkey" \
  >/dev/null

export FAKE_SYSTEMTHING_DIGEST="${module_digest}"
if ANDROID_BUILD_TOP="${source_root}" \
    "${ROOT}/scripts/verify-owned-package-keys.sh" \
    "${positive}" "${cert_dir}" "${work_dir}/apex.avbpubkey" \
    >/dev/null 2>&1; then
  echo "owned-but-wrong APK certificate role unexpectedly passed" >&2
  exit 1
fi
export FAKE_SYSTEMTHING_DIGEST="${platform_digest}"

export FAKE_PHONEVAULT_DIGEST="${platform_digest}"
if ANDROID_BUILD_TOP="${source_root}" \
    "${ROOT}/scripts/verify-owned-package-keys.sh" \
    "${positive}" "${cert_dir}" "${work_dir}/apex.avbpubkey" \
    >/dev/null 2>&1; then
  echo "wrong Phone Vault certificate unexpectedly passed" >&2
  exit 1
fi
export FAKE_PHONEVAULT_DIGEST="${phonevault_digest}"

write_metadata '/release-keys/platform.x509.pem' \
  '/release-keys/platform.x509.pem'
wrong_apex="${work_dir}/wrong-apex-role.zip"
make_target_files "${wrong_apex}"
if ANDROID_BUILD_TOP="${source_root}" \
    "${ROOT}/scripts/verify-owned-package-keys.sh" \
    "${wrong_apex}" "${cert_dir}" "${work_dir}/apex.avbpubkey" \
    >/dev/null 2>&1; then
  echo "wrong APEX container certificate role unexpectedly passed" >&2
  exit 1
fi

write_metadata 'PRESIGNED' '/release-keys/module.x509.pem'
presigned="${work_dir}/unexpected-presigned.zip"
make_target_files "${presigned}"
if ANDROID_BUILD_TOP="${source_root}" \
    "${ROOT}/scripts/verify-owned-package-keys.sh" \
    "${presigned}" "${cert_dir}" "${work_dir}/apex.avbpubkey" \
    >/dev/null 2>&1; then
  echo "unexpected PRESIGNED APK role unexpectedly passed" >&2
  exit 1
fi

echo "Exact APK, Phone Vault, and APEX certificate-role tests passed."
