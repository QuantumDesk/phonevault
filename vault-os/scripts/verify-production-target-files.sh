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

# ---- Release ADB policy -------------------------------------------------
# A production image has no USB debugging path: adb is never the default USB
# function, no host key is pre-authorised, no debug init script ships, and no
# init file brings up adbd or its FunctionFS endpoint outside triggers that a
# user build can never satisfy. (DEBUG-38/41, 2026-08: a release common.mk
# carried persist.sys.usb.config=adb and an early-boot adbd script.)
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
[[ "${persist_usb_values}" == none ]] || {
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

debug_artifacts="$(grep -Ei '(^|/)adb_keys$|zzz-debug|debug_adbkey' "${listing}" || true)"
if [[ -n "${debug_artifacts}" ]]; then
  echo "production target-files contains debug/ADB artifacts:" >&2
  printf '%s\n' "${debug_artifacts}" >&2
  exit 1
fi

installed_init_rcs="$(grep -E \
  '(^|/)etc/init/.*\.rc$|^(ROOT|BOOT/RAMDISK|VENDOR_BOOT/RAMDISK|RECOVERY/RAMDISK)/.*\.rc$' \
  "${listing}" || true)"
adb_init_violations=''
while IFS= read -r init_rc; do
  [[ -n "${init_rc}" ]] || continue
  init_text="$(unzip -p "${TARGET_FILES}" "${init_rc}")"
  # The recovery ramdisk's own init.rc (bootable/recovery/etc/init.rc) prepares
  # the FunctionFS endpoint that `adb sideload` (minadbd) needs. Recovery adbd
  # itself is governed by the recovery binary (patches/bootable-recovery), so
  # only that exact file is exempt, and only when it is the recovery init.
  if [[ "${init_rc}" =~ ^(BOOT|RECOVERY)/RAMDISK/system/etc/init/hw/init\.rc$ ]] \
      && grep -Eq '^service recovery /system/bin/recovery([[:space:]]|$)' <<<"${init_text}"; then
    continue
  fi
  violations_in_file="$(awk -v file="${init_rc}" '
    function debuggable_only(t) { return t ~ /property:ro\.debuggable=1/ }
    # A trigger made only of framework USB-function properties fires when the
    # framework selects adb; the gadget HAL refuses adb on user builds and
    # persist.sys.usb.config is none, so such triggers are reachable only on
    # debuggable images.
    function usb_function_only(t,    n, parts, i, c) {
      sub(/^on[[:space:]]+/, "", t)
      n = split(t, parts, /[[:space:]]*&&[[:space:]]*/)
      if (n == 0) return 0
      for (i = 1; i <= n; i++) {
        c = parts[i]
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", c)
        if (c !~ /^property:sys\.usb\.(config|configfs|ffs\.ready)=/) return 0
      }
      return 1
    }
    /^[[:space:]]*#/ { next }
    /^on[[:space:]]/ { trigger = $0; section = "on"; next }
    /^service[[:space:]]/ {
      section = "service"; trigger = ""
      if ($3 ~ /(^|\/)adbd$/ && !(file ~ /(^|\/)etc\/init\/hw\/init\.usb\.rc$/ && $2 == "adbd")) {
        print file ": adbd service defined outside init.usb.rc: " $0
      }
      next
    }
    /^[^[:space:]]/ { trigger = ""; section = ""; next }
    section != "on" { next }
    /^[[:space:]]+(start|restart)[[:space:]]+adbd([[:space:]]|$)/ {
      if (!debuggable_only(trigger) && !usb_function_only(trigger))
        print file ": [" trigger "] " $0
      next
    }
    /^[[:space:]]+(mkdir|mount|write)[[:space:]].*(functions\/ffs\.adb|\/dev\/usb-ffs\/adb|functionfs[[:space:]]+adb)/ {
      if (!debuggable_only(trigger))
        print file ": [" trigger "] " $0
      next
    }
    /^[[:space:]]+symlink[[:space:]].*functions\/ffs\.adb/ {
      if (!debuggable_only(trigger) && !usb_function_only(trigger))
        print file ": [" trigger "] " $0
      next
    }
    /^[[:space:]]+setprop[[:space:]]+(persist\.)?(sys|vendor)\.usb\.config[[:space:]]+[^[:space:]]*adb/ {
      if (!debuggable_only(trigger))
        print file ": [" trigger "] " $0
      next
    }
  ' <<<"${init_text}")"
  if [[ -n "${violations_in_file}" ]]; then
    adb_init_violations+="${violations_in_file}"$'\n'
  fi
done <<<"${installed_init_rcs}"
if [[ -n "${adb_init_violations}" ]]; then
  echo "production init files start adbd or set up its endpoint outside ro.debuggable=1:" >&2
  printf '%s' "${adb_init_violations}" >&2
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
