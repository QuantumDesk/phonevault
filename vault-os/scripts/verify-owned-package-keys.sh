#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 SIGNED_TARGET_FILES_ZIP PUBLIC_CERT_DIRECTORY APEX_AVBPUBKEY" >&2
  exit 2
fi

TARGET_FILES="$1"
CERT_DIR="$2"
EXPECTED_APEX_PUBKEY="$3"
SOURCE_ROOT="${ANDROID_BUILD_TOP:-/home/builder/android/lineage}"
SOURCE_TOOLS="${SOURCE_ROOT}/prebuilts/sdk/tools/linux"
SOURCE_JAVA="${SOURCE_ROOT}/prebuilts/jdk/jdk21/linux-x86/bin/java"
DEAPEXER="${SOURCE_ROOT}/out/host/linux-x86/bin/deapexer"
APKSIGNER=("${SOURCE_JAVA}" -jar "${SOURCE_TOOLS}/lib/apksigner.jar")

[[ -s "${TARGET_FILES}" && -d "${CERT_DIR}" \
    && -s "${EXPECTED_APEX_PUBKEY}" ]] || {
  echo "signed target-files or public release keys are missing" >&2
  exit 1
}
[[ -x "${SOURCE_JAVA}" && -s "${SOURCE_TOOLS}/lib/apksigner.jar" \
    && -x "${DEAPEXER}" ]] || {
  echo "Android package/APEX verification tools are missing" >&2
  exit 1
}

work_dir="$(mktemp -d -t phone-vault-package-keys.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT
allowed_cert_digests="${work_dir}/allowed-cert-digests.txt"
: > "${allowed_cert_digests}"
shopt -s nullglob
certificates=("${CERT_DIR}"/*.x509.pem)
((${#certificates[@]} > 0)) || {
  echo "no public X.509 release certificates found in ${CERT_DIR}" >&2
  exit 1
}
for certificate in "${certificates[@]}"; do
  openssl x509 -in "${certificate}" -outform DER | \
    sha256sum | awk '{print $1}' >> "${allowed_cert_digests}"
done
sort -u -o "${allowed_cert_digests}" "${allowed_cert_digests}"

packages=()
while IFS= read -r package_path; do
  packages+=("${package_path}")
done < <(unzip -Z1 "${TARGET_FILES}" | \
  grep -E '^(SYSTEM|SYSTEM_EXT|PRODUCT|VENDOR|ODM)/.*\.(apk|apex|capex)$' | sort -u)
((${#packages[@]} > 0)) || {
  echo "no installed APK/APEX packages found in target-files" >&2
  exit 1
}
apkcerts="$(unzip -p "${TARGET_FILES}" META/apkcerts.txt)" || {
  echo "signed target-files lacks META/apkcerts.txt" >&2
  exit 1
}
apexkeys="$(unzip -p "${TARGET_FILES}" META/apexkeys.txt)" || {
  echo "signed target-files lacks META/apexkeys.txt" >&2
  exit 1
}

metadata_line() {
  local inventory="$1"
  local package_name="$2"
  local matches count
  matches="$(grep -F "name=\"${package_name}\"" <<<"${inventory}" || true)"
  if [[ -n "${matches}" ]]; then
    count="$(wc -l <<<"${matches}" | tr -d ' ')"
  else
    count=0
  fi
  [[ -n "${matches}" && "${count}" == 1 ]] || {
    echo "expected exactly one signing metadata entry for ${package_name}, found ${count}" >&2
    return 1
  }
  printf '%s\n' "${matches}"
}

certificate_attribute() {
  local metadata="$1"
  local attribute="$2"
  local value
  value="$(sed -n "s/.*${attribute}=\"\([^\"]*\)\".*/\1/p" <<<"${metadata}")"
  [[ -n "${value}" ]] || {
    echo "signing metadata lacks ${attribute}: ${metadata}" >&2
    return 1
  }
  printf '%s\n' "${value}"
}

package_count=0
apex_count=0
for package_path in "${packages[@]}"; do
  package_count=$((package_count + 1))
  package_file="${work_dir}/package-${package_count}"
  unzip -p "${TARGET_FILES}" "${package_path}" > "${package_file}"
  report="$("${APKSIGNER[@]}" verify --verbose --print-certs "${package_file}")" || {
    echo "package signature verification failed: ${package_path}" >&2
    exit 1
  }
  signer_count="$(sed -n 's/^Number of signers: //p' <<<"${report}" | head -1)"
  [[ "${signer_count}" == 1 ]] || {
    echo "package must have exactly one signer: ${package_path}" >&2
    exit 1
  }
  cert_digest="$(sed -n \
    's/^Signer #1 certificate SHA-256 digest: //p' <<<"${report}" | head -1 | \
    tr '[:upper:]' '[:lower:]')"
  grep -Fqx "${cert_digest}" "${allowed_cert_digests}" || {
    echo "package is not signed by an owned release certificate: ${package_path}" >&2
    echo "certificate SHA-256: ${cert_digest:-<missing>}" >&2
    exit 1
  }

  package_name="$(basename "${package_path}")"
  expected_certificate=''
  case "${package_path}" in
    */PhoneVault.apk)
      package_metadata="$(metadata_line "${apkcerts}" "${package_name}")"
      metadata_certificate="$(certificate_attribute \
        "${package_metadata}" certificate)"
      [[ "${metadata_certificate}" == PRESIGNED ]] || {
        echo "Phone Vault must remain PRESIGNED for its dedicated external app identity" >&2
        exit 1
      }
      expected_certificate="${CERT_DIR}/phonevault-app.x509.pem"
      ;;
    *.apk)
      package_metadata="$(metadata_line "${apkcerts}" "${package_name}")"
      metadata_certificate="$(certificate_attribute \
        "${package_metadata}" certificate)"
      [[ "${metadata_certificate}" != PRESIGNED ]] || {
        echo "unexpected PRESIGNED APK cannot be proven project-owned: ${package_path}" >&2
        exit 1
      }
      certificate_name="$(basename "${metadata_certificate}")"
      [[ "${certificate_name}" =~ ^[A-Za-z0-9_.-]+\.x509\.pem$ ]] || {
        echo "unsafe APK certificate role in metadata: ${metadata_certificate}" >&2
        exit 1
      }
      expected_certificate="${CERT_DIR}/${certificate_name}"
      ;;
    *.apex|*.capex)
      if [[ "${package_name}" == *.capex ]]; then
        apex_metadata_name="${package_name%.capex}.apex"
      else
        apex_metadata_name="${package_name}"
      fi
      package_metadata="$(metadata_line "${apexkeys}" \
        "${apex_metadata_name}")"
      metadata_certificate="$(certificate_attribute \
        "${package_metadata}" container_certificate)"
      [[ "${metadata_certificate}" != PRESIGNED \
          && "$(basename "${metadata_certificate}")" == module.x509.pem ]] || {
        echo "APEX container is not assigned to the dedicated module certificate: ${package_path}" >&2
        exit 1
      }
      expected_certificate="${CERT_DIR}/module.x509.pem"
      ;;
  esac
  [[ -s "${expected_certificate}" ]] || {
    echo "expected package-role certificate is missing: ${expected_certificate}" >&2
    exit 1
  }
  expected_cert_digest="$(openssl x509 -in "${expected_certificate}" \
    -outform DER | sha256sum | awk '{print $1}')"
  [[ "${cert_digest}" == "${expected_cert_digest}" ]] || {
    echo "package signer does not match its dedicated certificate role: ${package_path}" >&2
    echo "expected ${expected_cert_digest}, got ${cert_digest}" >&2
    exit 1
  }

  case "${package_path}" in
    *.apex|*.capex)
      apex_count=$((apex_count + 1))
      apex_file="${package_file}"
      if [[ "${package_path}" == *.capex ]]; then
        apex_file="${work_dir}/decompressed-${apex_count}.apex"
        "${DEAPEXER}" decompress --input "${package_file}" \
          --output "${apex_file}" >/dev/null
      fi
      actual_apex_pubkey="${work_dir}/apex-pubkey-${apex_count}"
      unzip -p "${apex_file}" apex_pubkey > "${actual_apex_pubkey}" || {
        echo "APEX payload public key is missing: ${package_path}" >&2
        exit 1
      }
      cmp -s "${actual_apex_pubkey}" "${EXPECTED_APEX_PUBKEY}" || {
        echo "APEX payload is not signed by the owned release key: ${package_path}" >&2
        exit 1
      }
      ;;
  esac
done

((apex_count > 0)) || {
  echo "no APEX payloads were verified" >&2
  exit 1
}
echo "Verified owned signing identities for ${package_count} packages, including ${apex_count} APEX payloads."
