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
effective_file="$(mktemp -t phone-vault-production-effective.XXXXXX)"
init_report="$(mktemp -t phone-vault-production-init.XXXXXX)"
trap 'rm -f "${listing}" "${properties_file}" "${effective_file}" "${init_report}"' EXIT
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

# ---- Android init model ----------------------------------------------------
# Property files and init files are read the way Android init reads them, not with line
# greps (vaultgates/production_target_files.py, init_props.py, init_rc.py): every
# property occurrence, normalised to name=value, goes to properties_file; the value init
# ends up with goes to effective_file; init violations go to init_report. A property or
# init import that resolves outside the image (a writable location) fails here.
python3 "$(dirname "$0")/vaultgate.py" production-target-files \
  "${TARGET_FILES}" "${properties_file}" "${effective_file}" "${init_report}"

for required_property in \
    'ro.debuggable=0' \
    'ro.secure=1' \
    'ro.adb.secure=1'; do
  grep -Fqx "${required_property}" "${effective_file}" || {
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

# ---- Release ADB policy -------------------------------------------------
# A production image has no USB debugging path: adb is never the default USB
# function, no host key is pre-authorised, no debug init script ships, and no
# init file brings up adbd or its FunctionFS endpoint outside triggers that a
# user build can never satisfy. persist.sys.usb.config=adb and an early-boot
# adbd script are the development settings most likely to leak into a release.
usb_config_lines="$(grep -E '^(persist\.)?(sys|vendor)\.usb\.config=' \
  "${properties_file}" || true)"
adb_usb_config="$(grep -Ei 'adb' <<<"${usb_config_lines}" || true)"
if [[ -n "${adb_usb_config}" ]]; then
  echo "production target-files makes adb a default USB function:" >&2
  printf '%s\n' "${adb_usb_config}" | sort -u >&2
  exit 1
fi
persist_usb_values="$(sed -n 's/^persist\.sys\.usb\.config=//p' \
  <<<"${usb_config_lines}" | sort -u)"
effective_persist_usb="$(sed -n 's/^persist\.sys\.usb\.config=//p' "${effective_file}")"
[[ "${persist_usb_values}" == none && "${effective_persist_usb}" == none ]] || {
  echo "production persist.sys.usb.config must be exactly none: ${persist_usb_values:-<missing>}" >&2
  exit 1
}
debug_properties="$(grep -E \
  '^(ro\.force\.debuggable=1|service\.adb\.root=1|ro\.adb\.secure\.recovery=0|persist\.adb\.notify=0|persist\.service\.adb\.enable=1|service\.adb\.tcp\.port=)' \
  "${properties_file}" || true)"
if [[ -n "${debug_properties}" ]]; then
  echo "production target-files contains debugging properties:" >&2
  printf '%s\n' "${debug_properties}" | sort -u >&2
  exit 1
fi

# Debug ramdisk (first_stage_init.cpp): /force_debuggable makes first-stage
# init copy /adb_debug.prop to /debug_ramdisk, which property_service.cpp loads
# last (ro.debuggable=1, ro.adb.secure=0) without an unlock check; only the
# userdebug sepolicy swap is gated on unlock. None of it may ship.
debug_artifacts="$(grep -Ei \
  '(^|/)adb_keys$|zzz-debug|debug_adbkey|(^|/)(force_debuggable|adb_debug\.prop)$|^(ROOT|BOOT/RAMDISK|INIT_BOOT/RAMDISK|VENDOR_BOOT/RAMDISK|RECOVERY/RAMDISK)/(.*/)?userdebug_plat_sepolicy\.cil$' \
  "${listing}" || true)"
if [[ -n "${debug_artifacts}" ]]; then
  echo "production target-files contains debug/ADB artifacts:" >&2
  printf '%s\n' "${debug_artifacts}" >&2
  exit 1
fi

# Installed init files (etc/init/** and the ramdisks) plus every file they
# import, wherever it lives in the image. Section keywords count at any
# indentation, continuations are joined, `enable`/`exec_start` count like
# `start`, and a property-expanded service name or USB function is a violation
# unless it resolves to a build-time ro.* constant.
adb_init_violations="$(cat "${init_report}")"
if [[ -n "${adb_init_violations}" ]]; then
  echo "production init files start adbd or set up its endpoint outside ro.debuggable=1:" >&2
  printf '%s\n' "${adb_init_violations}" >&2
  exit 1
fi

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
