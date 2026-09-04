#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 TARGET_FILES_ZIP [EXPECTED_BUILD_TAGS]" >&2
  exit 2
fi

TARGET_FILES="$1"
EXPECTED_TAGS="${2:-}"
[[ -s "${TARGET_FILES}" ]] || {
  echo "missing production target-files archive: ${TARGET_FILES}" >&2
  exit 1
}
if [[ -n "${EXPECTED_TAGS}" \
    && ! "${EXPECTED_TAGS}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "invalid expected production build tags" >&2
  exit 2
fi

listing="$(mktemp -t phone-vault-production-listing.XXXXXX)"
properties_file="$(mktemp -t phone-vault-production-properties.XXXXXX)"
trap 'rm -f "${listing}" "${properties_file}"' EXIT
unzip -Z1 "${TARGET_FILES}" > "${listing}"

misc_info='META/misc_info.txt'
grep -Fqx "${misc_info}" "${listing}" || {
  echo "production target-files lacks META/misc_info.txt" >&2
  exit 1
}
misc_policy="$(unzip -p "${TARGET_FILES}" "${misc_info}")"
grep -Fqx 'build_type=user' <<<"${misc_policy}" || {
  echo "production signing requires build_type=user" >&2
  exit 1
}

property_paths="$(grep -E \
  '(^|/)(build\.prop|default\.prop|prop\.default)$' "${listing}" || true)"
[[ -n "${property_paths}" ]] || {
  echo "production target-files lacks installed property files" >&2
  exit 1
}
while IFS= read -r property_path; do
  unzip -p "${TARGET_FILES}" "${property_path}" >> "${properties_file}"
  printf '\n' >> "${properties_file}"
done <<<"${property_paths}"

for required_property in \
    'ro.debuggable=0' \
    'ro.secure=1' \
    'ro.adb.secure=1'; do
  grep -Fqx "${required_property}" "${properties_file}" || {
    echo "production target-files lacks ${required_property}" >&2
    exit 1
  }
done
while IFS='|' read -r property_name expected_line; do
  contradictory="$(grep -E "^${property_name}=" "${properties_file}" | \
    grep -Fvx "${expected_line}" || true)"
  if [[ -n "${contradictory}" ]]; then
    echo "production target-files contains contradictory ${property_name}" >&2
    exit 1
  fi
done <<'EOF'
ro\.debuggable|ro.debuggable=0
ro\.secure|ro.secure=1
ro\.adb\.secure|ro.adb.secure=1
EOF

if [[ -n "${EXPECTED_TAGS}" ]]; then
  build_tags="$(sed -n -E \
    's/^ro(\.[a-z_]+)?\.build\.tags=([^[:space:]]+)$/\2/p' \
    "${properties_file}" | sort -u)"
  [[ "${build_tags}" == "${EXPECTED_TAGS}" ]] || {
    echo "production build tags are not exactly ${EXPECTED_TAGS}: ${build_tags:-<missing>}" >&2
    exit 1
  }
fi

echo "Production user-build policy passed."
