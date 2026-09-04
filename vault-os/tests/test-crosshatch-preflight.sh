#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
work_dir="$(mktemp -d -t phone-vault-preflight-test.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT
artifacts="${work_dir}/artifacts"
fake_bin="${work_dir}/bin"
mkdir -p "${artifacts}/images" "${fake_bin}"

for image in boot dtbo product super_empty system system_ext vbmeta vendor; do
  printf '%s image\n' "${image}" > "${artifacts}/images/${image}.img"
done
printf 'require board=crosshatch\n' > "${artifacts}/images/android-info.txt"
printf 'pkmd\n' > "${artifacts}/avb_pkmd.bin"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "${work_dir}/avb-private.pem" >/dev/null 2>&1
openssl pkey -in "${work_dir}/avb-private.pem" -pubout \
  -out "${artifacts}/avb-public.pem"
avb_public_key_sha="$(openssl pkey -pubin \
  -in "${artifacts}/avb-public.pem" -outform DER | \
  shasum -a 256 | awk '{print $1}')"
printf '%s\n' \
  'development_only=true' \
  'phonevault_app_cert_sha256=1111111111111111111111111111111111111111111111111111111111111111' \
  'phonevault_app_sha256=2222222222222222222222222222222222222222222222222222222222222222' \
  'vbmeta_digest_sha256=3333333333333333333333333333333333333333333333333333333333333333' \
  "avb_public_key_der_sha256=${avb_public_key_sha}" \
  > "${artifacts}/MANIFEST.txt"
(
  cd "${artifacts}"
  checksum_file="$(mktemp -t phone-vault-preflight-checksums.XXXXXX)"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | \
    xargs -0 shasum -a 256 > "${checksum_file}"
  mv "${checksum_file}" SHA256SUMS
)

cat > "${fake_bin}/fastboot" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == devices ]]; then
  printf '%s\tfastboot\n' "${FAKE_SERIAL:-TESTSERIAL}"
  if [[ -n "${FAKE_EXTRA_SERIAL:-}" ]]; then
    printf '%s\tfastboot\n' "${FAKE_EXTRA_SERIAL}"
  fi
  exit 0
fi
[[ "$1" == -s && "$2" == "${FAKE_SERIAL:-TESTSERIAL}" \
    && "$3" == getvar ]] || exit 3
case "$4" in
  product) value="${FAKE_PRODUCT:-crosshatch}" ;;
  unlocked) value="${FAKE_UNLOCKED:-no}" ;;
  current-slot) value="${FAKE_CURRENT_SLOT:-a}" ;;
  slot-count) value="${FAKE_SLOT_COUNT:-2}" ;;
  *) exit 4 ;;
esac
printf '(bootloader) %s: %s\nFinished. Total time: 0.001s\n' "$4" "${value}" >&2
EOF
chmod +x "${fake_bin}/fastboot"

checksum_manifest_sha() {
  if command -v sha256sum >/dev/null; then
    sha256sum "${artifacts}/SHA256SUMS" | awk '{print $1}'
  else
    shasum -a 256 "${artifacts}/SHA256SUMS" | awk '{print $1}'
  fi
}

rebuild_checksum_manifest() {
  (
    cd "${artifacts}"
    checksum_file="$(mktemp -t phone-vault-preflight-rebuild.XXXXXX)"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | \
      xargs -0 shasum -a 256 > "${checksum_file}"
    mv "${checksum_file}" SHA256SUMS
  )
}

recorded_checksum_manifest_sha="$(checksum_manifest_sha)"

FASTBOOT_BIN="${fake_bin}/fastboot" \
  "${ROOT}/scripts/preflight-crosshatch.sh" TESTSERIAL "${artifacts}" \
  "${recorded_checksum_manifest_sha}" \
  > "${work_dir}/positive.stdout"
grep -Fq 'PASS: read-only Phone Vault crosshatch preflight' \
  "${work_dir}/positive.stdout"
grep -Fq 'bootloader_unlocked=no' "${work_dir}/positive.stdout"
grep -Fq "checksum_manifest_sha256=${recorded_checksum_manifest_sha}" \
  "${work_dir}/positive.stdout"
grep -Fq "avb_public_key_der_sha256=${avb_public_key_sha}" \
  "${work_dir}/positive.stdout"

if FASTBOOT_BIN="${fake_bin}/fastboot" \
    "${ROOT}/scripts/preflight-crosshatch.sh" TESTSERIAL "${artifacts}" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    > "${work_dir}/wrong-recorded-digest.stdout" \
    2> "${work_dir}/wrong-recorded-digest.stderr"; then
  echo "incorrect out-of-band checksum digest unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'SHA256SUMS does not match the independently recorded digest' \
  "${work_dir}/wrong-recorded-digest.stderr"

cp "${artifacts}/avb-public.pem" "${work_dir}/expected-avb-public.pem"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "${work_dir}/other-avb-private.pem" >/dev/null 2>&1
openssl pkey -in "${work_dir}/other-avb-private.pem" -pubout \
  -out "${artifacts}/avb-public.pem"
rebuild_checksum_manifest
if FASTBOOT_BIN="${fake_bin}/fastboot" \
    "${ROOT}/scripts/preflight-crosshatch.sh" TESTSERIAL "${artifacts}" \
    "$(checksum_manifest_sha)" \
    > "${work_dir}/wrong-avb-key.stdout" \
    2> "${work_dir}/wrong-avb-key.stderr"; then
  echo "mismatched AVB public identity unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'AVB public key does not match the development manifest identity' \
  "${work_dir}/wrong-avb-key.stderr"
cp "${work_dir}/expected-avb-public.pem" "${artifacts}/avb-public.pem"
rebuild_checksum_manifest
[[ "$(checksum_manifest_sha)" == "${recorded_checksum_manifest_sha}" ]] || {
  echo "restored preflight fixture did not reproduce its checksum root" >&2
  exit 1
}

cp "${artifacts}/SHA256SUMS" "${work_dir}/complete-checksums"
grep -v '  \./images/boot\.img$' "${work_dir}/complete-checksums" \
  > "${artifacts}/SHA256SUMS"
if FASTBOOT_BIN="${fake_bin}/fastboot" \
    "${ROOT}/scripts/preflight-crosshatch.sh" TESTSERIAL "${artifacts}" \
    "$(checksum_manifest_sha)" \
    > "${work_dir}/omitted-image.stdout" \
    2> "${work_dir}/omitted-image.stderr"; then
  echo "unchecksummed boot image unexpectedly passed preflight" >&2
  exit 1
fi
grep -Fq 'SHA256SUMS inventory does not exactly match bundle files' \
  "${work_dir}/omitted-image.stderr"
cp "${work_dir}/complete-checksums" "${artifacts}/SHA256SUMS"

printf '%s\n' "$(grep '  \./images/boot\.img$' "${artifacts}/SHA256SUMS")" \
  >> "${artifacts}/SHA256SUMS"
if FASTBOOT_BIN="${fake_bin}/fastboot" \
    "${ROOT}/scripts/preflight-crosshatch.sh" TESTSERIAL "${artifacts}" \
    "$(checksum_manifest_sha)" \
    > "${work_dir}/duplicate-image.stdout" \
    2> "${work_dir}/duplicate-image.stderr"; then
  echo "duplicate boot checksum unexpectedly passed preflight" >&2
  exit 1
fi
grep -Fq 'SHA256SUMS contains duplicate paths' \
  "${work_dir}/duplicate-image.stderr"
cp "${work_dir}/complete-checksums" "${artifacts}/SHA256SUMS"

if FAKE_PRODUCT=blueline FASTBOOT_BIN="${fake_bin}/fastboot" \
    "${ROOT}/scripts/preflight-crosshatch.sh" TESTSERIAL "${artifacts}" \
    "${recorded_checksum_manifest_sha}" \
    > "${work_dir}/wrong-product.stdout" \
    2> "${work_dir}/wrong-product.stderr"; then
  echo "non-crosshatch device unexpectedly passed preflight" >&2
  exit 1
fi
grep -Fq 'refusing non-crosshatch device: blueline' \
  "${work_dir}/wrong-product.stderr"

if FAKE_EXTRA_SERIAL=SECONDDEVICE FASTBOOT_BIN="${fake_bin}/fastboot" \
    "${ROOT}/scripts/preflight-crosshatch.sh" TESTSERIAL "${artifacts}" \
    "${recorded_checksum_manifest_sha}" \
    > "${work_dir}/multiple-devices.stdout" \
    2> "${work_dir}/multiple-devices.stderr"; then
  echo "multiple fastboot devices unexpectedly passed preflight" >&2
  exit 1
fi
grep -Fq 'expected exactly one fastboot device with serial TESTSERIAL' \
  "${work_dir}/multiple-devices.stderr"

printf 'tamper\n' >> "${artifacts}/images/boot.img"
if FASTBOOT_BIN="${fake_bin}/fastboot" \
    "${ROOT}/scripts/preflight-crosshatch.sh" TESTSERIAL "${artifacts}" \
    "${recorded_checksum_manifest_sha}" \
    > "${work_dir}/tampered.stdout" 2> "${work_dir}/tampered.stderr"; then
  echo "tampered artifact unexpectedly passed preflight" >&2
  exit 1
fi
grep -Eq 'FAILED|did NOT match' "${work_dir}/tampered.stdout" \
  "${work_dir}/tampered.stderr"

echo 'Crosshatch read-only preflight positive/negative tests passed.'
