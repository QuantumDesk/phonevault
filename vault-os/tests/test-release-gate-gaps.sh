#!/usr/bin/env bash
# Adversarial negatives for the release gates.
#
# Every case below builds an input that a production image must never contain and that
# Android really honours (init/property_service.cpp, init/parser.cpp, init/tokenizer.cpp,
# init/first_stage_init.cpp of the Lineage 22.2 / 24.0 trees), then runs the gate.
# A case the gate PASSES is a gate gap: it is reported as "GAP" and the script exits 1.
# The script exits 0 only when every case is rejected.
#
#   verify-production-target-files.sh  (target-files ADB/debuggable policy)
#   verify-release-source.sh           (release configuration in the repository)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VAULT="${ROOT}/vault-os"
PRODUCTION_GATE="${VAULT}/scripts/verify-production-target-files.sh"
SOURCE_GATE="${VAULT}/scripts/verify-release-source.sh"
work_dir="$(mktemp -d -t phone-vault-gate-gaps.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT
gaps=()
rejected=0

# ------------------------------------------------------- production gate fixture
# Minimal user-build target-files that the production gate accepts (same shape as
# tests/test-production-gate.sh).
make_target_fixture() {
  local fixture="$1"
  mkdir -p "${fixture}/META" "${fixture}/SYSTEM/etc/init/hw" "${fixture}/VENDOR/etc/init/hw" \
    "${fixture}/PRODUCT/etc" "${fixture}/BOOT/RAMDISK/system/etc/init/hw"
  printf '%s\n' 'build_type=user' > "${fixture}/META/misc_info.txt"
  printf '%s\n' 'ro.system.build.tags=release-keys' 'persist.sys.usb.config=none' \
    > "${fixture}/SYSTEM/build.prop"
  printf '%s\n' 'ro.vendor.build.tags=release-keys' > "${fixture}/VENDOR/build.prop"
  printf '%s\n' 'ro.product.build.tags=release-keys' > "${fixture}/PRODUCT/etc/build.prop"
  printf '%s\n' 'ro.debuggable=0' 'ro.secure=1' 'ro.adb.secure=1' \
    > "${fixture}/BOOT/RAMDISK/prop.default"
  printf '%s\n' \
    'service adbd /system/bin/adbd --root_seclabel=u:r:su:s0' \
    '    class core' \
    '    disabled' \
    > "${fixture}/SYSTEM/etc/init/hw/init.usb.rc"
}

production_case() {  # NAME DESCRIPTION MUTATION...
  local name="$1" description="$2"; shift 2
  local fixture="${work_dir}/tf-${name}" archive="${work_dir}/tf-${name}.zip"
  make_target_fixture "${fixture}"
  ( cd "${fixture}" && eval "$*" ) || { echo "fixture ${name} could not be built" >&2; exit 2; }
  (cd "${fixture}" && zip -qr "${archive}" .)
  if "${PRODUCTION_GATE}" "${archive}" release-keys > "${work_dir}/${name}.out" 2>&1; then
    echo "GAP production/${name}: ${description}"
    gaps+=("production/${name}")
  else
    echo "ok  production/${name}: rejected ($(head -1 "${work_dir}/${name}.out"))"
    rejected=$((rejected + 1))
  fi
}

# Baseline must pass, or every GAP below would be meaningless.
make_target_fixture "${work_dir}/tf-baseline"
(cd "${work_dir}/tf-baseline" && zip -qr "${work_dir}/tf-baseline.zip" .)
"${PRODUCTION_GATE}" "${work_dir}/tf-baseline.zip" release-keys > /dev/null || {
  echo "baseline user-build fixture does not pass the production gate" >&2
  exit 2
}
# Controls: the canonical spelling of each attack IS rejected, so a GAP below is caused by
# the variation alone, not by a broken fixture.
production_control() {  # NAME MUTATION...
  local name="$1"; shift
  local fixture="${work_dir}/tf-control-${name}" archive="${work_dir}/tf-control-${name}.zip"
  make_target_fixture "${fixture}"
  ( cd "${fixture}" && eval "$*" )
  (cd "${fixture}" && zip -qr "${archive}" .)
  if "${PRODUCTION_GATE}" "${archive}" release-keys > /dev/null 2>&1; then
    echo "control ${name} was not rejected: the fixture harness is broken" >&2
    exit 2
  fi
}
production_control adb-secure "printf 'ro.adb.secure=0\n' >> VENDOR/build.prop"
production_control debuggable "printf 'ro.debuggable=1\n' >> PRODUCT/etc/build.prop"
production_control persist-usb "printf 'persist.sys.usb.config=adb\n' >> PRODUCT/etc/build.prop"
production_control start-adbd "printf '%s\n' 'on boot' '    start adbd' > SYSTEM/etc/init/vault.rc"
production_control setprop-adb "printf '%s\n' 'on boot' '    setprop persist.sys.usb.config adb' > VENDOR/etc/init/vault.rc"
production_control adb-keys ": > BOOT/RAMDISK/adb_keys"

# 1-3. init's property loader strips whitespace around '=' (property_service.cpp
# LoadProperties: isspace trims on key and value) and a later partition overrides an
# earlier one (vendor, odm, product are loaded after system/boot). The gate only greps
# '^name=' so these lines are invisible to it.
production_case vendor-adb-secure-spaced \
  "VENDOR/build.prop 'ro.adb.secure = 0' (init reads ro.adb.secure=0)" \
  "printf 'ro.adb.secure = 0\n' >> VENDOR/build.prop"
production_case product-debuggable-spaced \
  "PRODUCT/etc/build.prop 'ro.debuggable = 1' overrides ro.debuggable=0" \
  "printf 'ro.debuggable = 1\n' >> PRODUCT/etc/build.prop"
production_case product-persist-usb-adb-spaced \
  "PRODUCT/etc/build.prop ' persist.sys.usb.config = adb' wins over system's none" \
  "printf ' persist.sys.usb.config = adb\n' >> PRODUCT/etc/build.prop"
production_case odm-adb-secure-leading-space \
  "ODM/etc/build.prop '  ro.adb.secure=0' (leading whitespace)" \
  "mkdir -p ODM/etc && printf '  ro.adb.secure=0\n' > ODM/etc/build.prop"

# 4. build.prop 'import <file>' (property_service.cpp: strncmp(key, \"import \", 7)) loads a
# property file of any name; the gate reads only build.prop/default.prop/prop.default.
production_case build-prop-import \
  "VENDOR/build.prop imports /vendor/etc/vault.prop with ro.debuggable=1, adb" \
  "printf 'import /vendor/etc/vault.prop\n' >> VENDOR/build.prop && printf '%s\n' ro.debuggable=1 ro.adb.secure=0 persist.sys.usb.config=adb > VENDOR/etc/vault.prop"

# 5. Debug ramdisk: first_stage_init.cpp copies /adb_debug.prop to /debug_ramdisk when
# /force_debuggable exists (no unlock check there), and property_service.cpp loads it last,
# overriding ro.debuggable/ro.adb.secure. Only the userdebug sepolicy swap is gated on unlock.
production_case boot-force-debuggable \
  "BOOT/RAMDISK/force_debuggable + adb_debug.prop (ro.debuggable=1, ro.adb.secure=0)" \
  ": > BOOT/RAMDISK/force_debuggable && printf '%s\n' ro.debuggable=1 ro.adb.secure=0 > BOOT/RAMDISK/adb_debug.prop"

# 6. 'enable adbd' (builtins.cpp do_enable -> Service::Enable): adbd is 'class core' +
# 'disabled', so class_start core marks it SVC_DISABLED_START and a later enable starts it.
production_case init-enable-adbd \
  "'enable adbd' after boot starts the disabled class-core adbd" \
  "printf '%s\n' 'on property:sys.boot_completed=1' '    enable adbd' > SYSTEM/etc/init/vault.rc"

# 7. Backslash-newline continuation (tokenizer.cpp '\\\\' case '\\n'): 'start \\ adbd'.
production_case init-line-continuation \
  "'start \\\\<newline> adbd' is one init command" \
  "printf '%s\n' 'on boot' '    start \\' '        adbd' > SYSTEM/etc/init/vault.rc"

# 8. Section keywords are recognised regardless of indentation (parser.cpp:
# section_parsers_.count(args[0])); the gate's awk treats an indented 'on' as a service option.
production_case init-indented-on \
  "indented 'on boot' after a service block, then 'start adbd'" \
  "printf '%s\n' 'service vaultd /system/bin/true' '    oneshot' '  on boot' '    start adbd' > VENDOR/etc/init/vault.rc"

# 9. 'import' of an rc outside etc/init: the gate only scans etc/init/** and ramdisk roots.
production_case init-import-outside-etc-init \
  "etc/init rc imports /vendor/etc/vault/adb.rc which starts adbd" \
  "mkdir -p VENDOR/etc/vault && printf '%s\n' 'import /vendor/etc/vault/adb.rc' > VENDOR/etc/init/vault.rc && printf '%s\n' 'on boot' '    start adbd' > VENDOR/etc/vault/adb.rc"

# 10. Builtin arguments are property-expanded (setprop is registered with expansion):
# the adb value comes from an innocuous property.
production_case init-setprop-expanded \
  "setprop persist.sys.usb.config \${ro.vendor.vault.usb} with ro.vendor.vault.usb=adb" \
  "printf 'ro.vendor.vault.usb=a%sb\n' d >> VENDOR/build.prop && printf '%s\n' 'on boot' '    setprop persist.sys.usb.config \${ro.vendor.vault.usb}' > VENDOR/etc/init/vault.rc"

# 11. Same for start: 'start \${prop}' where the property names adbd.
production_case init-start-expanded \
  "start \${ro.vendor.vault.svc} with ro.vendor.vault.svc=adbd" \
  "printf 'ro.vendor.vault.svc=adb%s\n' d >> VENDOR/build.prop && printf '%s\n' 'on boot' '    start \${ro.vendor.vault.svc}' > VENDOR/etc/init/vault.rc"

# ----------------------------------------------------------- source gate fixture
make_source_fixture() {
  local fixture="$1"
  mkdir -p "${fixture}/vault-os/scripts" "${fixture}/vault-os/patches"
  cp -R "${VAULT}/vendor" "${VAULT}/device" "${fixture}/vault-os/"
  cp -R "${VAULT}/patches/bootable-recovery" "${fixture}/vault-os/patches/"
  cp "${VAULT}/scripts/install-overlay.sh" "${fixture}/vault-os/scripts/"
  rm -rf "${fixture}/vault-os/vendor/phonevault/keys"
}
source_case() {  # NAME DESCRIPTION MUTATION...
  local name="$1" description="$2"; shift 2
  local fixture="${work_dir}/src-${name}"
  make_source_fixture "${fixture}"
  ( cd "${fixture}/vault-os" && eval "$*" ) || { echo "fixture ${name} could not be built" >&2; exit 2; }
  if "${SOURCE_GATE}" "${fixture}" > "${work_dir}/src-${name}.out" 2>&1; then
    echo "GAP source/${name}: ${description}"
    gaps+=("source/${name}")
  else
    echo "ok  source/${name}: rejected"
    rejected=$((rejected + 1))
  fi
}

make_source_fixture "${work_dir}/src-baseline"
"${SOURCE_GATE}" "${work_dir}/src-baseline" > /dev/null || {
  echo "clean release configuration does not pass the source gate" >&2
  exit 2
}
source_control() {  # NAME MUTATION...
  local name="$1"; shift
  local fixture="${work_dir}/src-control-${name}"
  make_source_fixture "${fixture}"
  ( cd "${fixture}/vault-os" && eval "$*" )
  if "${SOURCE_GATE}" "${fixture}" > /dev/null 2>&1; then
    echo "source control ${name} was not rejected: the fixture harness is broken" >&2
    exit 2
  fi
}
source_control persist-mk "printf 'PRODUCT_SYSTEM_PROPERTIES += persist.sys.usb.config=adb\n' >> vendor/phonevault/config/common.mk"
source_control start-adbd "printf '%s\n' 'on boot' '    start adbd' > vendor/phonevault/prebuilt/vault-late.rc"
source_control ffs-adb "printf '%s\n' 'on boot' '    mount functionfs adb /dev/usb-ffs/adb' > vendor/phonevault/prebuilt/vault-usb.rc"
source_control adb-keys-name ": > vendor/phonevault/prebuilt/adb_keys"

common=vendor/phonevault/config/common.mk
# S1. Properties in a .prop file (TARGET_SYSTEM_PROP / TARGET_VENDOR_PROP / copied + imported):
# the source gate checks property assignments only inside *.mk files.
source_case prop-file-adb \
  "vendor/phonevault/config/vault.prop with persist.sys.usb.config=adb, ro.adb.secure=0 via TARGET_SYSTEM_PROP" \
  "printf '%s\n' persist.sys.usb.config=adb ro.adb.secure=0 > vendor/phonevault/config/vault.prop && printf 'TARGET_SYSTEM_PROP += vendor/phonevault/config/vault.prop\n' >> vendor/phonevault/config/BoardConfigVault.mk"
# S2. 'enable adbd' in a release rc.
source_case rc-enable-adbd \
  "release rc 'enable adbd'" \
  "printf '%s\n' 'on property:sys.boot_completed=1' '    enable adbd' > vendor/phonevault/prebuilt/vault-late.rc"
# S3. Indented 'on' keeps the previous ro.debuggable=1 trigger in the source gate's view.
source_case rc-indented-on-ffs \
  "ffs.adb endpoint under an indented 'on boot' that follows a ro.debuggable=1 block" \
  "printf '%s\n' 'on property:ro.debuggable=1' '    write /dev/null 0' '  on boot' '    mkdir /dev/usb-ffs/adb 0770 shell shell' '    mount functionfs adb /dev/usb-ffs/adb uid=2000,gid=2000' > vendor/phonevault/prebuilt/vault-usb.rc"
# S4. A pre-authorised host key installed under another source name.
source_case adb-key-renamed \
  "PRODUCT_COPY_FILES installs owner.pub as /adb_keys" \
  "printf 'QAAAAfake= owner@mac\n' > vendor/phonevault/prebuilt/owner.pub && printf 'PRODUCT_COPY_FILES += vendor/phonevault/prebuilt/owner.pub:\$(TARGET_ROOT_OUT)/adb_keys\n' >> ${common}"

# ------------------------------------------------ install-overlay patch markers
# I1. install-overlay.sh apply_versioned_patch: when the recorded state file equals the patch
# but the patch neither applies nor reverse-applies (e.g. bootable/recovery moved under a repo
# sync and the hardening is gone), it reports "recorded as applied (overlapping later
# context)" and succeeds. bootable-recovery has a single patch, so there is no later patch to
# explain the overlap, and no target-files gate checks the recovery binary for the hardening.
recovery_patch="$(ls "${VAULT}"/patches/bootable-recovery/*.patch | head -1)"
install_case_dir="${work_dir}/install-recorded"
mkdir -p "${install_case_dir}/tree" "${install_case_dir}/state"
sed -n '/^apply_versioned_patch() {/,/^}/p' "${VAULT}/scripts/install-overlay.sh" \
  > "${install_case_dir}/apply.sh"
[[ -s "${install_case_dir}/apply.sh" ]] || { echo "apply_versioned_patch not found" >&2; exit 2; }
(
  cd "${install_case_dir}/tree" && git init -q . \
    && printf 'int main() { /* upstream recovery after a sync */ }\n' > recovery.cpp \
    && cp recovery.cpp recovery_main.cpp && git add . \
    && git -c user.name=t -c user.email=t@t commit -qm upstream
) || exit 2
cp "${recovery_patch}" "${install_case_dir}/state/recovery-patch"
# shellcheck source=/dev/null
if ( source "${install_case_dir}/apply.sh" \
      && apply_versioned_patch "${install_case_dir}/tree" "${recovery_patch}" \
           "${install_case_dir}/state/recovery-patch" "recovery test" ) \
    > "${work_dir}/install-recorded.out" 2>&1; then
  echo "GAP install/recovery-patch-marker-trusted: unpatched recovery accepted ($(tail -1 "${work_dir}/install-recorded.out"))"
  gaps+=("install/recovery-patch-marker-trusted")
else
  echo "ok  install/recovery-patch-marker-trusted: rejected"
  rejected=$((rejected + 1))
fi

echo
echo "${rejected} adversarial inputs rejected, ${#gaps[@]} gate gaps."
if (( ${#gaps[@]} > 0 )); then
  printf '  %s\n' "${gaps[@]}"
  exit 1
fi
echo "Release gate adversarial negatives passed."
