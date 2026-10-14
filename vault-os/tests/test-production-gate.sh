#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
work_dir="$(mktemp -d -t phone-vault-production-gate.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT
fixture="${work_dir}/fixture"
mkdir -p "${fixture}/META" "${fixture}/SYSTEM" \
  "${fixture}/BOOT/RAMDISK"
printf '%s\n' 'build_type=user' > "${fixture}/META/misc_info.txt"
printf '%s\n' \
  'ro.system.build.tags=release-keys' \
  'persist.sys.usb.config=none' \
  > "${fixture}/SYSTEM/build.prop"
printf '%s\n' \
  'ro.debuggable=0' \
  'ro.secure=1' \
  'ro.adb.secure=1' \
  'ro.recovery.usb.adb.pid=D001' \
  > "${fixture}/BOOT/RAMDISK/prop.default"

# Stock init files that legitimately mention adbd on a user build: the
# framework-selected USB function triggers (unreachable: the gadget HAL refuses
# adb when ro.debuggable=0 and persist.sys.usb.config is none), the debuggable-
# only endpoint in the Phone Vault USB rc, and the recovery ramdisk's own
# init.rc, which prepares the FunctionFS endpoint `adb sideload` needs.
mkdir -p "${fixture}/SYSTEM/etc/init/hw" "${fixture}/VENDOR/etc/init/hw" \
  "${fixture}/BOOT/RAMDISK/system/etc/init/hw"
printf '%s\n' \
  'service adbd /system/bin/adbd --root_seclabel=u:r:su:s0' \
  '    class core' \
  '    disabled' \
  '' \
  'on property:sys.usb.config=adb && property:sys.usb.configfs=0' \
  '    start adbd' \
  > "${fixture}/SYSTEM/etc/init/hw/init.usb.rc"
printf '%s\n' \
  'on property:sys.usb.config=accessory,adb && property:sys.usb.configfs=1' \
  '    start adbd' \
  '' \
  'on property:sys.usb.ffs.ready=1 && property:sys.usb.config=accessory,adb && property:sys.usb.configfs=1' \
  '    symlink /config/usb_gadget/g1/functions/ffs.adb /config/usb_gadget/g1/configs/b.1/f2' \
  > "${fixture}/SYSTEM/etc/init/hw/init.usb.configfs.rc"
printf '%s\n' \
  '# tradeinmode: never fall back to a shell on user builds' \
  'on property:persist.adb.tradeinmode=-1 && property:ro.debuggable=0' \
  '    stop adbd' \
  > "${fixture}/SYSTEM/etc/init/tradeinmode.rc"
printf '%s\n' \
  'on boot' \
  '    mkdir /config/usb_gadget/g1/functions/accessory.gs2' \
  '    write /sys/class/typec/port0/port_type sink' \
  'on early-boot && property:ro.debuggable=1' \
  '    mkdir /config/usb_gadget/g1/functions/ffs.adb' \
  '    mkdir /dev/usb-ffs/adb 0770 shell shell' \
  '    mount functionfs adb /dev/usb-ffs/adb rmode=0770' \
  > "${fixture}/VENDOR/etc/init/hw/init.sdm845.usb.rc"
printf '%s\n' \
  'on fs' \
  '    mkdir /dev/usb-ffs/adb 0770 shell shell' \
  '    mount functionfs adb /dev/usb-ffs/adb uid=2000,gid=2000' \
  'on property:service.adb.root=1' \
  '    restart adbd' \
  'service recovery /system/bin/recovery' \
  '    critical' \
  > "${fixture}/BOOT/RAMDISK/system/etc/init/hw/init.rc"

positive="${work_dir}/positive.zip"
(cd "${fixture}" && zip -qr "${positive}" .)
"${ROOT}/scripts/verify-production-target-files.sh" "${positive}"
"${ROOT}/scripts/verify-production-target-files.sh" \
  "${positive}" release-keys

sed -i.bak 's/^build_type=user$/build_type=userdebug/' \
  "${fixture}/META/misc_info.txt"
negative_userdebug="${work_dir}/negative-userdebug.zip"
(cd "${fixture}" && zip -qr "${negative_userdebug}" .)
if "${ROOT}/scripts/verify-production-target-files.sh" \
    "${negative_userdebug}" > /dev/null 2>&1; then
  echo "userdebug production fixture unexpectedly passed" >&2
  exit 1
fi
mv "${fixture}/META/misc_info.txt.bak" "${fixture}/META/misc_info.txt"

printf '%s\n' 'ro.debuggable=1' >> "${fixture}/BOOT/RAMDISK/prop.default"
negative_debuggable="${work_dir}/negative-debuggable.zip"
(cd "${fixture}" && zip -qr "${negative_debuggable}" .)
if "${ROOT}/scripts/verify-production-target-files.sh" \
    "${negative_debuggable}" > /dev/null 2>&1; then
  echo "debuggable production fixture unexpectedly passed" >&2
  exit 1
fi
sed -i.bak '/^ro\.debuggable=1$/d' \
  "${fixture}/BOOT/RAMDISK/prop.default"
rm "${fixture}/BOOT/RAMDISK/prop.default.bak"

sed -i.bak 's/release-keys/test-keys/' "${fixture}/SYSTEM/build.prop"
negative_tags="${work_dir}/negative-tags.zip"
(cd "${fixture}" && zip -qr "${negative_tags}" .)
if "${ROOT}/scripts/verify-production-target-files.sh" \
    "${negative_tags}" release-keys > /dev/null 2>&1; then
  echo "test-key production fixture unexpectedly passed" >&2
  exit 1
fi
sed -i.bak 's/test-keys/release-keys/' "${fixture}/SYSTEM/build.prop"
rm "${fixture}/SYSTEM/build.prop.bak"

# ---- Release ADB policy negatives ----------------------------------------
expect_production_failure() {
  local name="$1" expected="$2" archive="${work_dir}/$1.zip"
  (cd "${fixture}" && zip -qr "${archive}" .)
  if "${ROOT}/scripts/verify-production-target-files.sh" "${archive}" \
      > "${work_dir}/${name}.stdout" 2> "${work_dir}/${name}.stderr"; then
    echo "${name} production fixture unexpectedly passed" >&2
    exit 1
  fi
  grep -Fq -- "${expected}" "${work_dir}/${name}.stderr" || {
    echo "${name} failed for the wrong reason:" >&2
    cat "${work_dir}/${name}.stderr" >&2
    exit 1
  }
}
expect_production_pass() {
  local archive="${work_dir}/pass-$1.zip"
  (cd "${fixture}" && zip -qr "${archive}" .)
  "${ROOT}/scripts/verify-production-target-files.sh" "${archive}" release-keys
}
expect_production_pass baseline

# adb as the default USB function, in any installed property file.
cp "${fixture}/SYSTEM/build.prop" "${work_dir}/build.prop.saved"
sed -i.bak 's/^persist\.sys\.usb\.config=none$/persist.sys.usb.config=adb/' \
  "${fixture}/SYSTEM/build.prop"
expect_production_failure negative-persist-usb-adb 'makes adb a default USB function'
cp "${work_dir}/build.prop.saved" "${fixture}/SYSTEM/build.prop"
printf '%s\n' 'persist.sys.usb.config=mtp,adb' >> "${fixture}/BOOT/RAMDISK/prop.default"
expect_production_failure negative-ramdisk-usb-adb 'makes adb a default USB function'
sed -i.bak '/^persist\.sys\.usb\.config=mtp,adb$/d' "${fixture}/BOOT/RAMDISK/prop.default"
grep -v '^persist\.sys\.usb\.config=' "${work_dir}/build.prop.saved" \
  > "${fixture}/SYSTEM/build.prop"
expect_production_failure negative-persist-usb-missing \
  'persist.sys.usb.config must be exactly none'
cp "${work_dir}/build.prop.saved" "${fixture}/SYSTEM/build.prop"
printf '%s\n' 'persist.adb.notify=0' >> "${fixture}/SYSTEM/build.prop"
expect_production_failure negative-debug-property 'contains debugging properties'
cp "${work_dir}/build.prop.saved" "${fixture}/SYSTEM/build.prop"

# A pre-authorised adb host key.
printf 'QAAAA fixture-host-key\n' > "${fixture}/BOOT/RAMDISK/adb_keys"
expect_production_failure negative-adb-keys 'contains debug/ADB artifacts'
rm "${fixture}/BOOT/RAMDISK/adb_keys"

# An early-boot adb init script as a development image installs it.
zzz="${fixture}/SYSTEM/etc/init/zzz-debug-earlyadb.rc"
printf '%s\n' \
  'on post-fs' \
  '    mkdir /config/usb_gadget/g1/functions/ffs.adb' \
  '    mkdir /dev/usb-ffs/adb 0770 shell shell' \
  '    mount functionfs adb /dev/usb-ffs/adb rmode=0770,fmode=0660,uid=2000,gid=2000' \
  '    start adbd' \
  'on property:init.svc.adbd=running' \
  '    symlink /config/usb_gadget/g1/functions/ffs.adb /config/usb_gadget/g1/configs/b.1/f1' \
  > "${zzz}"
expect_production_failure negative-zzz-debug-path 'contains debug/ADB artifacts'
# The same content under an innocuous name is caught by the init-file scan.
mv "${zzz}" "${fixture}/SYSTEM/etc/init/innocuous.rc"
expect_production_failure negative-early-adbd \
  'start adbd or set up its endpoint outside ro.debuggable=1'
grep -Fq 'innocuous.rc: [on post-fs]     start adbd' "${work_dir}/negative-early-adbd.stderr"
grep -Fq 'innocuous.rc: [on property:init.svc.adbd=running]' \
  "${work_dir}/negative-early-adbd.stderr"
rm "${fixture}/SYSTEM/etc/init/innocuous.rc"

# ADB endpoint setup moved out of the ro.debuggable=1 trigger.
cp "${fixture}/VENDOR/etc/init/hw/init.sdm845.usb.rc" "${work_dir}/usb.rc.saved"
sed -i.bak 's/^on early-boot && property:ro.debuggable=1$/on early-boot/' \
  "${fixture}/VENDOR/etc/init/hw/init.sdm845.usb.rc"
expect_production_failure negative-ungated-ffs-adb \
  'start adbd or set up its endpoint outside ro.debuggable=1'
cp "${work_dir}/usb.rc.saved" "${fixture}/VENDOR/etc/init/hw/init.sdm845.usb.rc"

# start adbd behind a trigger that mixes a boot stage with a USB property.
printf '%s\n' \
  'on boot && property:sys.usb.configfs=1' \
  '    start adbd' \
  > "${fixture}/VENDOR/etc/init/mixed.rc"
expect_production_failure negative-mixed-trigger \
  'start adbd or set up its endpoint outside ro.debuggable=1'
rm "${fixture}/VENDOR/etc/init/mixed.rc"

# init forcing adb as the USB function.
printf '%s\n' \
  'on property:sys.boot_completed=1' \
  '    setprop persist.sys.usb.config adb' \
  > "${fixture}/VENDOR/etc/init/force-adb.rc"
expect_production_failure negative-setprop-adb \
  'start adbd or set up its endpoint outside ro.debuggable=1'
rm "${fixture}/VENDOR/etc/init/force-adb.rc"

# A second, non-disabled adbd service.
printf '%s\n' \
  'service vaultadb /system/bin/adbd' \
  '    class core' \
  > "${fixture}/SYSTEM/etc/init/vaultadb.rc"
expect_production_failure negative-extra-adbd-service 'adbd service defined outside init.usb.rc'
rm "${fixture}/SYSTEM/etc/init/vaultadb.rc"

# The recovery exemption covers only the real recovery init.rc.
sed -i.bak '/^service recovery/d' "${fixture}/BOOT/RAMDISK/system/etc/init/hw/init.rc"
expect_production_failure negative-fake-recovery-init \
  'start adbd or set up its endpoint outside ro.debuggable=1'
mv "${fixture}/BOOT/RAMDISK/system/etc/init/hw/init.rc.bak" \
  "${fixture}/BOOT/RAMDISK/system/etc/init/hw/init.rc"
find "${fixture}" -name '*.bak' -delete
expect_production_pass restored

# ---- Android init model: realistic layout positives, targeted negatives -----
# A stock-looking user build laid out like the bluejay (Lineage 24.0) and
# crosshatch target-files: partition-local build.props (odm/system_dlkm inside
# their parents, vendor_dlkm separate), the second-stage ramdisk build.prop,
# the recovery ramdisk in vendor_boot with a default.prop symlink, the empty
# first-stage debug_ramdisk mount point, property formatting init accepts,
# safe imports, and the stock init idioms that mention adbd, expansions,
# continuations, indented sections and `enable`.
real="${work_dir}/realistic"
rm -rf "${real}"
cp -R "${fixture}" "${real}"
mkdir -p "${real}/SYSTEM_EXT/etc" "${real}/SYSTEM/system_dlkm/etc" \
  "${real}/VENDOR/odm/etc" "${real}/VENDOR_DLKM/etc" "${real}/PRODUCT/etc" \
  "${real}/VENDOR/etc/init/hw" "${real}/BOOT/RAMDISK/system/etc/ramdisk" \
  "${real}/BOOT/RAMDISK/first_stage_ramdisk/debug_ramdisk" \
  "${real}/BOOT/RAMDISK/first_stage_ramdisk/second_stage_resources" \
  "${real}/VENDOR_BOOT/RAMDISK/system/etc/init/hw" "${real}/VENDOR/etc/vault"
printf '%s\n' \
  '# begin common build properties' \
  'ro.system.build.tags=release-keys' \
  'ro.zygote=zygote64_32' \
  'ro.secure=1' \
  'ro.debuggable = 0' \
  '#ro.debuggable=1' \
  '   # persist.sys.usb.config=adb' \
  'persist.sys.usb.config=none' \
  > "${real}/SYSTEM/build.prop"
printf '%s\n' 'ro.system_ext.build.tags=release-keys' 'ro.adb.secure=1' \
  > "${real}/SYSTEM_EXT/etc/build.prop"
printf '%s\n' 'ro.system_dlkm.build.tags=release-keys' > "${real}/SYSTEM/system_dlkm/etc/build.prop"
printf '%s\n' \
  'ro.vendor.build.tags=release-keys' \
  'ro.vendor.vault.svc=vaultd' \
  'ro.vendor.vault.usb=none' \
  'import /vendor/etc/vault/vault.prop' \
  'import /vendor/etc/vault/filtered.prop ro.vendor.vault.*' \
  > "${real}/VENDOR/build.prop"
printf '%s\n' 'ro.vendor.vault.offline=true' > "${real}/VENDOR/etc/vault/vault.prop"
printf '%s\n' 'ro.vendor.vault.extra=1' 'ro.adb.secure=0' > "${real}/VENDOR/etc/vault/filtered.prop"
printf '%s\n' 'ro.odm.build.tags=release-keys' > "${real}/VENDOR/odm/etc/build.prop"
printf '%s\n' 'ro.vendor_dlkm.build.tags=release-keys' > "${real}/VENDOR_DLKM/etc/build.prop"
printf '%s\n' 'ro.product.build.tags=release-keys' '  ro.adb.secure =  1  ' \
  > "${real}/PRODUCT/etc/build.prop"
printf '%s\n' 'ro.bootimage.build.tags=release-keys' \
  > "${real}/BOOT/RAMDISK/system/etc/ramdisk/build.prop"
printf '%s\n' 'ro.debuggable=0' 'ro.secure=1' 'ro.adb.secure=1' 'persist.sys.usb.config=none' \
  > "${real}/VENDOR_BOOT/RAMDISK/prop.default"
ln -s prop.default "${real}/VENDOR_BOOT/RAMDISK/default.prop"
mkdir -p "${real}/SYSTEM/etc/init/hw"
printf '%s\n' \
  'import /init.environ.rc' \
  'import /system/etc/init/hw/init.usb.rc' \
  'import /init.${ro.hardware}.rc' \
  'import /vendor/etc/init/hw/init.${ro.hardware}.rc' \
  'import /system/etc/init/hw/init.usb.configfs.rc' \
  'import /system/etc/init/hw/init.${ro.zygote}.rc' \
  'on early-init' \
  '    start ueventd' \
  'on boot' \
  '    setprop sys.usb.config ${persist.sys.usb.config}' \
  '    start llkd-${ro.debuggable:-0}' \
  '    enable update_engine' \
  '    start ${ro.vendor.vault.svc}' \
  '    setprop persist.sys.usb.config ${ro.vendor.vault.usb}' \
  'service vold /system/bin/vold \' \
  '        --blkid_context=u:r:blkid:s0 --blkid_untrusted_context=u:r:blkid_untrusted:s0 \' \
  '        --fsck_context=u:r:fsck:s0' \
  '    class core' \
  > "${real}/SYSTEM/etc/init/hw/init.rc"
printf '%s\n' 'service zygote /system/bin/app_process64 -Xzygote' '    class main' \
  > "${real}/SYSTEM/etc/init/hw/init.zygote64_32.rc"
printf '%s\n' \
  'on property:sys.usb.config=adb && property:sys.usb.configfs=1' \
  '    start adbd' \
  > "${real}/SYSTEM/etc/init/hw/init.usb.configfs.rc"
printf '%s\n' \
  'import /vendor/etc/init/hw/init.gs101.usb.rc' \
  '    service BIP-Channel-Manager /vendor/bin/bipchmgr' \
  '        class main' \
  'on boot' \
  '    enable vendor.citadeld' \
  '    setprop sys.usb.controller "11110000.dwc3"' \
  > "${real}/VENDOR/etc/init/hw/init.bluejay.rc"
cp "${real}/VENDOR/etc/init/hw/init.sdm845.usb.rc" "${real}/VENDOR/etc/init/hw/init.gs101.usb.rc"
mv "${real}/BOOT/RAMDISK/system/etc/init/hw/init.rc" \
  "${real}/VENDOR_BOOT/RAMDISK/system/etc/init/hw/init.rc"
sed -i.bak '1i\
import /init.recovery.${ro.hardware}.rc
' "${real}/VENDOR_BOOT/RAMDISK/system/etc/init/hw/init.rc"
rm "${real}/VENDOR_BOOT/RAMDISK/system/etc/init/hw/init.rc.bak"
printf '%s\n' 'on init' '    setprop sys.usb.configfs 1' > "${real}/VENDOR_BOOT/RAMDISK/init.recovery.bluejay.rc"

real_case() {  # NAME EXPECTED_STDERR|'' MUTATION...
  local name="$1" expected="$2"; shift 2
  local case_dir="${work_dir}/real-${name}" archive="${work_dir}/real-${name}.zip"
  rm -rf "${case_dir}"
  cp -R "${real}" "${case_dir}"
  ( cd "${case_dir}" && eval "$*" )
  (cd "${case_dir}" && zip -qry "${archive}" .)
  if [[ -z "${expected}" ]]; then
    "${ROOT}/scripts/verify-production-target-files.sh" "${archive}" release-keys > /dev/null || {
      echo "realistic positive ${name} was rejected" >&2
      "${ROOT}/scripts/verify-production-target-files.sh" "${archive}" release-keys >&2 || true
      exit 1
    }
    return
  fi
  if "${ROOT}/scripts/verify-production-target-files.sh" "${archive}" \
      > "${work_dir}/real-${name}.stdout" 2> "${work_dir}/real-${name}.stderr"; then
    echo "realistic negative ${name} unexpectedly passed" >&2
    exit 1
  fi
  grep -Fq -- "${expected}" "${work_dir}/real-${name}.stderr" || {
    echo "realistic negative ${name} failed for the wrong reason:" >&2
    cat "${work_dir}/real-${name}.stderr" >&2
    exit 1
  }
}
# shellcheck disable=SC2016  # literal init/property syntax below
{
real_case stock-layout ''
# The filtered import only loads ro.vendor.vault.*, so its ro.adb.secure=0 is ignored, as init does.
real_case filtered-import-honoured ''
real_case filtered-import-wildcard 'production target-files contains contradictory ro\.adb\.secure' \
  "sed -i.x 's/ro.vendor.vault.\\*/ro.adb.*/' VENDOR/build.prop && rm VENDOR/build.prop.x"
real_case prop-import-writable 'imports from outside the image' \
  "printf 'import /data/local/tmp/vault.prop\n' >> VENDOR/build.prop"
real_case prop-import-symlink-target 'production target-files lacks ro.debuggable=0' \
  "printf 'ro.debuggable=1\n' > VENDOR/etc/vault/notes.txt && ln -s ../../etc/vault/notes.txt VENDOR/odm/etc/debug.prop && printf 'import /odm/etc/debug.prop\n' >> VENDOR/odm/etc/build.prop"
real_case effective-later-partition 'production target-files lacks ro.secure=1' \
  "printf 'ro.secure = 0 \n' >> VENDOR/odm/etc/build.prop"
real_case force-debuggable-alone 'contains debug/ADB artifacts' \
  ": > BOOT/RAMDISK/force_debuggable"
real_case adb-debug-prop-safe-values 'contains debug/ADB artifacts' \
  "printf 'ro.debuggable=0\n' > VENDOR_BOOT/RAMDISK/adb_debug.prop"
real_case userdebug-sepolicy 'contains debug/ADB artifacts' \
  ": > BOOT/RAMDISK/first_stage_ramdisk/userdebug_plat_sepolicy.cil"
real_case init-import-writable 'imports an init file from outside the image' \
  "printf 'import /data/vault/late.rc\n' >> VENDOR/etc/init/hw/init.bluejay.rc"
real_case init-import-directory 'start adbd or set up its endpoint outside ro.debuggable=1' \
  "mkdir -p VENDOR/etc/vault/init && printf 'import /vendor/etc/vault/init\n' >> VENDOR/etc/init/hw/init.bluejay.rc && printf 'on boot\n    exec_start adbd\n' > VENDOR/etc/vault/init/late.conf"
real_case init-quoted-continuation 'start adbd or set up its endpoint outside ro.debuggable=1' \
  "printf '%s\n' 'on boot' '    \"start\" ad\\' '  bd' >> VENDOR/etc/init/hw/init.bluejay.rc"
real_case init-runtime-property 'start adbd or set up its endpoint outside ro.debuggable=1' \
  "printf '%s\n' 'on boot' '    start \${ro.boot.vault_svc}' >> VENDOR/etc/init/hw/init.bluejay.rc"
real_case init-mutable-property 'start adbd or set up its endpoint outside ro.debuggable=1' \
  "printf '%s\n' 'on boot' '    setprop sys.usb.config \${vendor.vault.usb:-none}' >> VENDOR/etc/init/hw/init.bluejay.rc"
real_case init-exec-adbd 'start adbd or set up its endpoint outside ro.debuggable=1' \
  "printf '%s\n' 'on boot' '    exec_background - root -- /system/bin/adbd' >> VENDOR/etc/init/hw/init.bluejay.rc"
real_case adbd-not-disabled 'adbd service is not disabled' \
  "sed -i.x '/^    disabled\$/d' SYSTEM/etc/init/hw/init.usb.rc && rm SYSTEM/etc/init/hw/init.usb.rc.x"
real_case debuggable-wildcard-trigger 'start adbd or set up its endpoint outside ro.debuggable=1' \
  "printf '%s\n' 'on property:ro.debuggable=*' '    mkdir /dev/usb-ffs/adb 0770 shell shell' >> VENDOR/etc/init/hw/init.bluejay.rc"
}
echo "Realistic target-files positives and init-model negatives passed."

release_script="${ROOT}/scripts/sign-release.sh"
# These are literal source snippets; the variables must not expand in the test.
# shellcheck disable=SC2016
for required_release_evidence in \
    'public_key_dir="${OUTPUT_DIR}/public-keys"' \
    'public_key_inventory="${OUTPUT_DIR}/PUBLIC-KEY-INVENTORY.txt"' \
    '"${KEY_DIR}/avb_pkmd.bin"' \
    '"${KEY_DIR}/apex.avbpubkey"' \
    'cd "${OUTPUT_DIR}"' \
    '"${OUTPUT_DIR}" "${SOURCE}/external/avb/avbtool.py"' \
    "printf 'public_key_inventory_sha256=%s\\n'" \
    '"${SCRIPT_DIR}/verify-release-source.sh" "${PROJECT}"' \
    '"${SCRIPT_DIR}/verify-release-overrides.sh" "${INPUT_TARGET_FILES}" "${PROJECT}"' \
    '"${SCRIPT_DIR}/verify-rollback-index.sh" "${candidate_rollback_index}"' \
    '[[ "${rollback_index}" == "${candidate_rollback_index}" ]]'; do
  grep -Fq -- "${required_release_evidence}" "${release_script}" || {
    echo "release bundle omits public verification evidence: ${required_release_evidence}" >&2
    exit 1
  }
done
public_export_block="$(sed -n '/^public_key_sources=(/,/^)/p' "${release_script}")"
if grep -Eq '(\.pk8|/avb\.pem|/apex\.pem)' <<<"${public_export_block}"; then
  echo "release bundle public export includes private key material" >&2
  exit 1
fi

keyset_script="${ROOT}/scripts/generate-release-keyset.sh"
# These are literal source snippets; variables must not expand in the test.
# shellcheck disable=SC2016
for required_keyset_invariant in \
    'mountpoint -q "${KEY_DIR}"' \
    'for name in releasekey platform shared media networkstack sdk_sandbox bluetooth nfc module phonevault-app' \
    'run_make_key "${name}"' \
    'trap '\''rm -rf \${tmpdir}; echo; exit 1'\'' EXIT INT QUIT' \
    'openssl asn1parse -inform DER' \
    'openssl x509 -in "${KEY_DIR}/${name}.x509.pem" -noout' \
    'cd "${KEY_DIR}"' \
    'sha256sum "${public_files[@]}"' \
    'chmod 0600 "${KEY_DIR}"/*.pk8 "${KEY_DIR}/avb.pem" "${KEY_DIR}/apex.pem"'; do
  grep -Fq -- "${required_keyset_invariant}" "${keyset_script}" || {
    echo "release keyset generator lacks invariant: ${required_keyset_invariant}" >&2
    exit 1
  }
done

echo "Production target-files and public release-bundle gates passed."
