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

# DEBUG-38: adb as the default USB function, in any installed property file.
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

# DEBUG-47: a pre-authorised adb host key.
printf 'QAAAA fixture-host-key\n' > "${fixture}/BOOT/RAMDISK/adb_keys"
expect_production_failure negative-adb-keys 'contains debug/ADB artifacts'
rm "${fixture}/BOOT/RAMDISK/adb_keys"

# DEBUG-41: the early-adb init script, exactly as it was installed.
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
    '"${PROJECT}/vault-os/dev-ladder/check-overrides.sh" release "${INPUT_TARGET_FILES}"' \
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
