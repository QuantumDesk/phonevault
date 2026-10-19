# Bluejay release target (Pixel 6a): BETA images

The first **release-style** images for the Pixel 6a: a `user` build of the
[dev-ladder-bluejay](../dev-ladder-bluejay/README.md) hardening, with no debugging access and no
development key. Not a production release: AVB and the signer app are signed with BETA-TEST keys
generated on the build host, the platform is still signed with Lineage's test keys, and the phone
stays unlocked (see "Not yet" below).

## Layout

```
release-bluejay/
  BETA/                one beta configuration; same file names and meaning as a ladder rung dir
    BASE               "rung RUNG" (dev-ladder-bluejay/rung-RUNG) or "beta NAME" (another beta)
    common.mk          ┐ replace the base's file of the same name
    BoardConfigVault.mk│ (common.mk, BoardConfigVault.mk, Android.bp, config.xml and the four
    config.xml         ┘  upstream diffs are allowed)
    expect-build.txt   APPENDED to the base's expectations (check-build.sh syntax)
  resolve-beta.sh BETA OUTDIR          BASE chain -> one flat, rung-shaped directory (+ RESOLVED.txt)
  gen-beta-keys.sh [KEY_DIR]           BETA-TEST AVB + app keys on the build host (once)
  sign-beta-apk.sh UNSIGNED OUT        signer app release build -> v2-signed with the beta app key
  sync-beta.sh BETA TREE APK [KDIST]   resolved beta -> Lineage 24.0 tree (no adb key, recovery patch)
  build-beta.sh BETA TREE DEST         user build, gates, images, super.img, flash script, manifest
```

Why a separate directory rather than editing `vendor/phonevault/` in place: `vendor/phonevault/`
and `device/phonevault/` are the release intent shared by both phones, and today their
`common.mk`, `BoardConfigVault.mk` and `Android.bp` are the **crosshatch** release (crosshatch
paths, crosshatch overrides, the crosshatch AVB key path, the crosshatch kernel fragment). The
6a's proven state is a ladder rung, so a beta is expressed as "that rung, minus its development
deviations": the rung's Android.bp (overrides), overlay and upstream diffs are reused byte for
byte through `BASE`, and only `common.mk`/`BoardConfigVault.mk` are beta-owned. The sync installs
them over the same tree paths a rung uses (`vendor/phonevault/config/common.mk`, …), so the
product (`device/phonevault/bluejay/vault_bluejay.mk`, unchanged) is the same product the ladder
boots. Folding the bluejay release back into `vendor/phonevault/` (per-device config files) is the
follow-up once a beta has booted.

| beta | BASE | what it is |
|---|---|---|
| `beta1` | rung b4d-1 | **the first beta**: b4d-1 as a user build (below) |
| `beta1-novoice` | beta beta1 | opt-in experiment: beta1 + `config_voice_capable`, `config_sms_capable`, `config_enable_emergency_call_while_sim_locked` = false (the release overlay verbatim). Not built yet |
| `beta2` | rung b4d-1 | **beta1 + the USB enumeration fix** ([below](#beta2-usb-enumeration-without-adb)): beta1's files (version/channel `beta2`) + `config_usbChargingFunctionsAccessory=true` (frameworks-base-a17 0006). beta1 booted to SET PIN but never appeared on the Mac's USB |

## What beta1 carries

From the ladder (all passed on the 6a; details in [dev-ladder-bluejay](../dev-ladder-bluejay/README.md)):

| rung | carried in beta1 | where |
|---|---|---|
| b0/b1 | product, overlay (`config_fixedFunctionDeviceOwner`, no doze/AOD, power menu power/restart only), preferred HOME, no launcher, no Lineage Trust, initial package state, built `boot.img`, bootloader/baseband pins; frameworks/base A17 **0003** (fixed-function device owner, factory-boot wake-up), **0004** (resource export), **0005** (no keyguard clock/date) | `device/phonevault/bluejay`, `vendor/phonevault` (rsync), rung-b4d-1 `config.xml`/`Android.bp`, `patches/frameworks-base-a17` |
| b2 | 56 unused GKI/vendor modules out, `usbcore.authorized_default=0` | beta1 `BoardConfigVault.mk` (same list) |
| b3 | USB: only AOA function instances (+ `ffs.adb` only when `ro.debuggable=1`, i.e. never here), port pinned sink/UFP, role/OTG nodes root-only, no USB host feature, `ro.vendor.phonevault.offline=true` | rung-b4d-1 vendor + gs101 diffs, beta1 `common.mk` |
| b4a | Wi-Fi/BT/NFC/eSE/GNSS/modem drivers + their services, VINTF entries and features | `BoardConfigVault.mk`, rung-b4d-1 diffs + `Android.bp`, `phonevault-no-radios.xml` |
| b4b/b4c | app strip slices A+B (79 modules), ModuleMetadata kept | rung-b4d-1 `Android.bp` |
| b4d-1 | rild + vendor radio daemons, radio HAL VINTF entries, OEM-RIL apps, euiccpixel | rung-b4d-1 `Android.bp` + diffs |

New in beta1 (not on any rung):

- **`user` build**: `lunch vault_bluejay-cp2a-user`, `WITH_ADB_INSECURE` unset → `ro.debuggable=0`,
  `ro.secure=1`, Lineage's `ro.adb.secure=1`; `persist.sys.usb.config=none` (/product).
- **No adb at all**: no `PRODUCT_ADB_KEYS`, no adb key file anywhere (only AOSP rootdir's
  `/adb_keys -> /product/etc/security/adb_keys` links in the two ramdisks, which every build
  installs and which point at nothing here; the production gate checks they are inert),
  `PV_DEV_ADB_KEY` neither needed nor read (sync-beta.sh unsets it and deletes the dev rungs'
  `debug_adbkey.pub` from the tree), no adbd start outside `ro.debuggable=1` / framework
  USB-function triggers (production gate), no `ffs.adb` endpoint (b3 rc, debuggable-only).
- **Recovery hardening** (`patches/bootable-recovery/0001`, applied to the A17 `bootable/recovery`
  by sync-beta.sh; recovery lives in vendor_boot on gs101): no "Install anyway?" for unverified,
  downgrade or SPL-downgrade packages, no "Enable ADB", no system mount/format, recovery adbd
  never started (explicit "Apply from ADB" sideload stays and must verify).
- **Kernel command line**: gs101's `earlycon=exynos4210,0x10A00000 console=ttySAC0,115200
  androidboot.console=ttySAC0 printk.devkmsg=on` filtered out (also from bootconfig);
  `usbcore.authorized_default=0` kept. pstore/ramoops is unaffected.
- **AVB with the BETA key** on vbmeta and the three chained partitions (boot, vbmeta_system,
  vbmeta_vendor), flags 0, and the project rollback index (`release-version.mk`, 2026101300) on all
  four instead of the security-patch timestamp. The dev key is refused by the board file, by the
  source gate and by build-beta.sh (its public-key sha1 is compared).
- **Signer app RELEASE build** (`gradle :app:assembleRelease`: `VAULT_DEV_BUILD=false`, no
  DevTools/screen dump, `DISALLOW_INSTALL_APPS`/`DISALLOW_DEBUGGING_FEATURES` lockdown, StrongBox
  required, minified), signed with the BETA app key, verified by `verify-signer-apk.sh` (release
  variant marker, permission/manifest allowlist, one v2 signer = the beta cert) at sign, sync and
  build time. The dev rungs ran the `appliance` (dev) build: **beta1 is the first 6a image with the
  release app.**

Deliberately **not** in beta1: `config_voice_capable=false` (and the SMS/emergency booleans). b4d,
the first image that carried them, did not boot; b4d-1 (without them) boots. They hide the keyguard
"Emergency" button (kiosk escape), so they are the next experiment: `beta1-novoice`, built and
flashed only after beta1 boots. Until then the lock screen can show "Emergency calls only" /
an Emergency button, as on b4c/b4d-1.

## Keys (build host only)

`gen-beta-keys.sh` → `/home/aipg/.phonevault-keys/beta/` (directory 0700, private keys 0600, owner
aipg; never printed, never committed, never copied off the host):

| file | what |
|---|---|
| `phonevault_bluejay_avb_BETA_rsa4096.pem` | AVB key (private) |
| `avb_pkmd_bluejay_BETA.bin` | its public blob (`avbtool extract_public_key`; the future `avb_custom_key`) |
| `phonevault-app-BETA.pk8` / `.x509.pem` | signer-app key (private PKCS#8) / certificate |
| `BETA-TEST-KEYS.txt` | label + public digests |

Public identities of the keys generated 2026-10-18 on the build host:

- AVB public key blob: sha1 `7d4a65ae6268cf470c69157cfa8b14d29bb94fd4`,
  sha256 `234b8f9bd98cac321ddda1a035cb4e8cfade4f96c63d0c081b6c9cdec4ea80f0`
- app certificate (DER) sha256 `934c4f78f34daebc9f6733af217ff78bdb864fba20e408a1ad3ff5e00a7c032f`
  (subject `CN=Phone Vault signer app BETA-TEST, OU=BETA-TEST signing key - replace before release`)

These are **BETA-TEST** keys: to be replaced by beta keys generated offline
(`scripts/generate-release-keyset.sh`, offline machine) before any phone is relocked to a beta
key or a beta goes to anyone outside the project. They are separate from the AVB dev key
(`~/.phonevault-keys/avb`, sha1 `af09b166…`), which the beta never uses. The tree reaches the AVB
key only through the symlink `vendor/phonevault/keys/avb_bluejay_beta.pem` (sync-beta.sh removes
the dev key's link at the same time). A new key = a new identity: re-flashing a beta signed by a
different app key needs a wipe (the flash script always wipes).

## Build (build host, as the tree owner)

```sh
# app (any machine with JDK 17+, SDK 35, Gradle 8.10.2): unsigned release build
gradle :app:assembleRelease          # app/build/outputs/apk/release/app-release-unsigned.apk
# build host, once: keys
release-bluejay/gen-beta-keys.sh     # ~/.phonevault-keys/beta
# build host: sign, sync, build (under the shared build lock)
release-bluejay/sign-beta-apk.sh app-release-unsigned.apk /build/pv-beta1/PhoneVault-beta1.apk
LINEAGE_TREE=/build/lineage-24 release-bluejay/sync-beta.sh beta1 /build/lineage-24 /build/pv-beta1/PhoneVault-beta1.apk
release-bluejay/build-beta.sh beta1 /build/lineage-24 /build/out-beta1
```

**Tree state.** sync-beta.sh resets exactly what a rung sync resets (the four upstream device/vendor
repos to upstream + the resolved diffs, `vendor/phonevault` and `device/phonevault/bluejay` from the
repo, the A17 frameworks/base patches present) and in addition restores `bootable/recovery` to
upstream and applies the recovery patch. build-beta.sh then runs `m installclean` (the out dir
switches userdebug → user; the build would also do it on its own because
`previous_build_config.mk` changes). The kernel prebuilts are not touched (same Kleaf dist as
b4d-1). To go back to a dev rung: `sync-rung.sh RUNG …` (with `PV_DEV_ADB_KEY` and
`PV_AVB_KEY_DIR`, as before; it re-creates the dev key link) and, for byte-identical dev
recovery, `git -C $TREE/bootable/recovery checkout -- .`; the next rung build installcleans back
to userdebug by itself.

## Gates

build-beta.sh fails the build unless all of these pass on the produced target files / images:

| gate | checks |
|---|---|
| `scripts/verify-production-target-files.sh TF` | `build_type=user`; effective (init load order) `ro.debuggable=0`, `ro.secure=1`, `ro.adb.secure=1` and no file contradicting them; `persist.sys.usb.config` exactly `none` everywhere; no adb USB default, no adb debug properties; no `adb_keys` (bar the inert rootdir link to an absent verified path), `debug_adbkey`, `force_debuggable`, `adb_debug.prop` or ramdisk `userdebug_plat_sepolicy.cil`; every installed init file (+ imports) starts adbd / sets up its endpoint only under `ro.debuggable=1` or framework USB-function triggers (recovery's own init.rc exempt) |
| `scripts/verify-release-source.sh ROOT --bluejay-beta beta1` | release rules on `vendor/phonevault` + `device/phonevault`, and on the resolved beta: no adb keys/insecure adb/dev props/debug rc/markers, `persist.sys.usb.config=none`, AVB key = the beta link (no dev/test key named), project rollback index, console/earlycon/printk.devkmsg filtered, `usbcore.authorized_default=0`, recovery patch applied by the sync; voice-capable reported as a warning |
| `scripts/verify-release-overrides.sh TF ROOT beta-config/Android.bp` | every override of the beta's (= b4d-1's) list absent from the image |
| `dev-ladder-bluejay/check-build.sh beta-config …` | b2..b4d-1 artifact checks (removed modules not packaged, load lists/modules.dep consistent, cmdline, overrides incl. vendor binaries/VINTF/permissions, b4d-1's `expect-build.txt`) + beta1's expectations (user props, no adb_keys, no debug ramdisk, recovery in vendor_boot, app on /product) |
| build-beta.sh own checks | kernel cmdline (boot + vendor_boot + bootconfig) free of the four console/kmsg options and carrying `usbcore.authorized_default=0`; vbmeta/boot/vbmeta_system/vbmeta_vendor signed by the beta key (pkmd sha1, ≠ dev key), vbmeta flags 0, rollback index = `release-version.mk`; the APK in the image passes `verify-signer-apk.sh` against the beta cert; recovery patch reverse-applies in the tree |

**Not yet gated for bluejay** (crosshatch-only today):

- `verify-appliance-target-files.sh`: the appliance artifact policy (`policy/forbidden-*.regex`:
  telephony, Wi-Fi, media, APEX payloads, kernel config) is crosshatch-shaped and would fail on
  every b4d-1 keep (telephony framework, Wi-Fi stack and features, the camera/TPU/sensor HALs);
  the 6a has no Kconfig fragment (GKI). The bluejay equivalent today is check-build.sh with
  b4d-1's expectations. A bluejay policy file set is needed once the 6a strips telephony/Wi-Fi.
- `sign-release.sh` / `install-overlay.sh`: container-only and crosshatch-only (crosshatch
  device/kernel patches, `SYSTEM/app/PhoneVault` instead of `PRODUCT/app`, no
  `--avb_vbmeta_vendor_key` for gs101's chained vbmeta_vendor, crosshatch `avb.pem` path). So
  beta1 is **not** re-signed with owned platform/APEX keys: `ro.build.tags=test-keys`, platform /
  shared / media / networkstack APKs and APEX payloads carry Lineage's public test keys. Owned
  platform keys + signed OTA are the release step (G2).
- `verify-rollback-index.sh` / release manifest signing (no signed previous release yet; beta1 is
  not a production release).
- frameworks/base 0001 (ambiguous recovery signatures) and 0002 (no APEX install on user builds)
  are not rebased to Android 17.

## beta1 build (2026-10-18)

Built on the build host into `/build/out-beta1` (tree `/build/lineage-24`; full user rebuild
3 h 29 min after the userdebug rungs, then a no-installclean re-run for the adb_keys gate fix).
All gates above passed: production gate, release source (`--bluejay-beta beta1`, with the
voice-capable warning), overrides (111 absent, 58 APKs remain), check-build (70 modules removed,
444 `.ko` remain, load lists/modules.dep consistent, 117 expectations), cmdline, AVB, app.

| | |
|---|---|
| build | `user`, `ro.build.id=CP2A.260605.016`, `ro.build.tags=test-keys`, incremental/date `1792369100`, SPL 2026-10-01, Phone Vault 0.1.0-beta1 (`ro.system.build.fingerprint` is Lineage's stock-Pixel fingerprint string, not ours) |
| ramdisk props | `ro.debuggable=0`, `ro.secure=1`, `ro.adb.secure=1`, `persist.sys.usb.config=none` |
| vendor_boot cmdline | `fips140.load_sequential=1 exynos_mfc.load_sequential=1 exynos_drm.load_sequential=1 pcie-exynos-core.load_sequential=1 g2d.load_sequential=1 disable_dma32=on dyndbg="func alloc_contig_dump_pages +p" cma_sysfs.experimental=Y rcupdate.rcu_expedited=1 rcu_nocbs=all rcutree.enable_rcu_lazy swiotlb=noforce cgroup.memory=nokmem rodata=on at24.write_timeout=100 log_buf_len=1024K android_arch_task_struct_size=512 usbcore.authorized_default=0` (bootconfig: `androidboot.load_modules_parallel=true androidboot.boot_devices=14700000.ufs`) |
| AVB | vbmeta, boot, vbmeta_system, vbmeta_vendor: BETA key (pkmd sha1 `7d4a65ae…fd4`), flags 0, rollback index 2026101300 |
| app | `dev.phonevault.signer` 0.3.0 release, cert `934c4f78…032f`, APK sha256 `6b5073e912ccb22d564a3ff8491901c6c6e14eb81e63baa54d49726c38383b71` |

Image hashes (sha256; all in `SHA256SUMS` and `manifest.json`):

```
ca395e38703a26b6d96ad793bf39574b7251b425d5a3ca234fb0e07a74a12c75  images/boot.img
e1230167a575fb8d9d6e5ea607ab9d4799c585b911267d19cf70bb0035858ac9  images/vendor_boot.img
8d5687a541e9b88453b89c9e42d537fd784444ffc40feb099de2c4f062849287  images/dtbo.img
4a5a0bb47984d05cc77fdd868b14fdfc8aab158bfe4a356980503765fcc07e9b  images/pvmfw.img
9f24824b37e53d638f21644bb5250efaf1ef922262ddf15c69e663a8a9ded27a  images/vbmeta.img
5e5baf5e4c67d12fdb2157688380514bf8c7e6bfdc550eee8d1dfec21fdb6d44  images/vbmeta_system.img
9311d31b49fd86972e027f1c8af0b8e77f6300d8d8e0f942e34fecee326c3e56  images/vbmeta_vendor.img
bc553fe503208ebf39999d6737c53b7668cc10d18b731be84e5725422e24d560  super.img
654e604b46980ab4753e6e016dd08870871a44a1a5e63632fdccaea470c2a451  images/android-info.txt
72cd2a860f168be500262f276614f9aa25776f10f519eca105f29567f0f76a75  flash-beta1-mac.sh
83f873f97c061be1db94aaa8b4436352830ff389f2f3783a8f95de0e73f52816  manifest.json
9f56f22066e348d6a0398ed2dbaf2d94336d135dfe6894669de41ed3b30e50a2  vault_bluejay-target_files-beta1.zip
45cfad7626dca37d4070bb0c5e00aa481545a60001be780a6b30475f5da0bf86  vault_bluejay-img-beta1.zip
```

**On hardware (2026-10-19):** boots to Phone Vault's SET PIN, but the Mac's USB tree shows no
device at all (no adb, as intended, but also nothing under `system_profiler SPUSBDataType`):
risk 2 below, confirmed. Fixed in [beta2](#beta2-usb-enumeration-without-adb).

## Flash (from the Mac, bootloader only, human-approved)

Same method as the rungs (fastbootd writes fail on macOS): `flash-beta1-mac.sh` is
dev-ladder-bluejay/flash-mac.sh. It checks SHA256SUMS and the phone (bluejay, bootloader
`bluejay-17.0-15199431`, baseband `g5123b-145971-260414-B-15201439`, unlocked, not fastbootd),
then flashes slot a (boot vendor_boot dtbo pvmfw vbmeta vbmeta_system vbmeta_vendor + sparse
super), erases metadata, wipes userdata, sets slot a active and reboots. Firmware, bootloader,
radio and `avb_custom_key` are never written; the phone stays unlocked (orange state).

```sh
mkdir -p ~/pv-bluejay && cd ~/pv-bluejay
rsync -av --exclude 'vault_bluejay-*.zip' root@<build-host>:/build/out-beta1/ out-beta1/
cd out-beta1
shasum -a 256 -c SHA256SUMS            # optional; the script checks the flashed files itself
# phone: power off, hold Volume-Down + Power -> bootloader, USB to the Mac
./flash-beta1-mac.sh --check           # read-only pre-flight
./flash-beta1-mac.sh                   # type FLASH
```

`manifest.json` lists the same steps (partition, file, size, sha256) plus build id, fingerprint,
AVB and app key identities, for a future web installer.

**Rollback:** reflash b4d-1 (`cd ~/pv-bluejay/out-b4d-1 && ./flash-b4d-1-mac.sh`); the bootloader is
never written, so it is always reachable (Volume-Down + Power).

## First boot: what can go wrong, and how to see it without adb

A user build has no adb, so a boot loop cannot be logged the way the rungs were. beta1 differs
from the booting b4d-1 in exactly seven things: `user` variant, no adb, the console/kmsg cmdline
options, the beta AVB key, the rollback index, the hardened recovery, the release app. Plan:

1. **Before flashing**, nothing to do on the phone: every artifact gate above has passed.
2. **Pass criteria without adb**: hands-off first boot to SET PIN; owner "Phone Vault" on the lock
   screen after a reboot; Settings is unreachable; recovery (bootloader → Recovery mode) shows no
   "Enable ADB" / "Install anyway"; `adb devices` on the Mac shows nothing at any time; the Mac sees
   the phone and the companion pairs over USB (see risk 2).
3. **If it boot-loops** (slot a exhausts its retries, the bootloader stops in fastboot or falls back):
   reflash b4d-1 to get a working phone back, then build the **debuggable twin**: beta1's exact
   configuration as `userdebug` + `WITH_ADB_INSECURE` + the builder's adb key (i.e. b4d-1 plus the
   beta deltas one at a time: cmdline, AVB key + rollback index, recovery, release app). The twin
   boots with adb from early boot, so `adb logcat -b all`, `adb shell cat /sys/fs/pstore/*` (root)
   show the failure; if the twin boots, the cause is user-only (the `user` sepolicy build, the
   release app's lockdown, `ro.debuggable=0` paths), and a bisect between twin and beta1 finds it.
   The previous boot's kernel log stays in pstore across a warm reboot, so the first boot of the
   twin after the failed beta1 boot can still read beta1's last console (`/sys/fs/pstore/console-ramoops*`)
   if no cold power-off happened in between.
4. **Partial failure** (boots, but something misbehaves): the release app shows its own state; the
   bootloader screen and `fastboot getvar all` give slot/retry/boot-reason; the dev twin reproduces
   anything that is not user-only.

**Risks, most likely first:**

1. **Release app on Android 17**: never run on the 6a before (the rungs ran the dev `appliance`
   build). It applies the full lockdown (`DISALLOW_DEBUGGING_FEATURES`, `DISALLOW_INSTALL_APPS`,
   …) and requires StrongBox (Titan M2: present). A crash in the release-only paths would show as
   the kiosk never appearing (FallbackHome) rather than a boot loop.
2. **USB enumeration without adb**: on a user build with adb off, `UsbDeviceManager`'s charging
   functions are **MTP** (`getChargingFunctions()`: ADB if adb is enabled, else MTP). b3 removed
   every MTP instance (`mtp.gs0`, `ffs.mtp`), so the prebuilt gadget HAL cannot link MTP; when the
   failing request is the charging request the framework does not retry
   (`setCurrentUsbFunctionsCb`: "Setting default functions" only for non-charging requests). The
   rungs never hit this because adb was always on. Likely symptom: the phone charges but the Mac
   sees no USB device, so the companion cannot start AOA. Not a boot risk. Cheap pre-test on a
   b4d-1 phone: turn USB debugging off (`adb shell settings put global adb_enabled 0`), then check
   `system_profiler SPUSBDataType` and the companion; restore by reflashing. Fix candidates: a
   frameworks/base change making the appliance's charging function ACCESSORY (or NONE with the
   userspace-AOA control endpoint), or an inert kernel MTP instance; each needs its own rung.
3. **`user` build differences**: user sepolicy (no `userdebug_or_eng` rules), no
   `ro.debuggable`-gated services; Lineage ships userdebug for bluejay, so the user variant of the
   gs101 tree is less exercised.
4. **Kernel command line**: low; the console options only affect the UART and kmsg rate limiting.
5. **AVB**: low; the phone is unlocked (orange), and the same layout as b1–b4d-1 with another key.

## beta2: USB enumeration without adb

**Root cause** (beta1 on hardware; read from the A17 sources and the prebuilt HAL):

1. `frameworks/base/services/usb/java/com/android/server/usb/UsbDeviceManager.java`: with no
   function selected the framework composes the "charging" functions, `getChargingFunctions()` =
   ADB if adb is enabled, **else MTP**. beta1 is `user` with `persist.sys.usb.config=none`, so
   adb is off and the boot-time request is MTP. In `UsbHandlerHal.setCurrentUsbFunctionsCb` a
   failed request is retried with the defaults only when it was *not* the charging request
   (`else if (!mChargingFunctions) … MSG_SET_CHARGING_FUNCTIONS`): a failed charging request is
   final, the gadget stays unbound, and nothing enumerates, not even as a charging-only device.
2. The b3 gadget rc (`init.gs101.usb.rc`, rung-b4d-1 `vendor-google-bluejay.diff`) creates only
   `accessory.gs2`, `ffs.aoa`, `ffs.ctrl` (+ `ffs.adb` when debuggable). The prebuilt
   `android.hardware.usb.gadget-service.gs101` links MTP as `ffs.mtp`, which does not exist, so
   the MTP request fails. The rungs never saw this because adb (then the charging function) was on.
3. Userspace AOA (A17's `ffs.ctrl` control function, served by `aoad` from `system/usb/aoa/daemon`)
   is off on this build and would not help. The framework needs both the aconfig flag
   `android.hardware.usb.flags.enable_aoa_userspace_implementation` (not set in the cp2a release
   config) and `ro.usb.userspace.aoa.enabled`, which `usb_accessory_utils`
   (`hardware/google/pixel/usb/UsbAccessoryUtils.cpp`) sets from `enable_uaoa_all_pixels_except_p8`
   (also unset): hence the dev logs' "Device enabled userspace AOA: false". Even with it on, the
   charging composition would be MTP|CTRL (MTP still missing), and the prebuilt HAL masks CTRL
   out and then rejects a CTRL-only request as "Combination not supported" (disassembly of its
   VID/PID switch: after `functions & ~CTRL`, only ADB, ACCESSORY, MTP, PTP, MIDI, RNDIS, audio
   source, UVC, NCM and their adb combinations have a PID; NONE pulls the gadget down). With this
   HAL the **only** adb-free composition that exposes no data function is ACCESSORY
   (`accessory.gs2`, 18d1:2d00).

**Fix:** `patches/frameworks-base-a17/0006` adds the framework resource
`config_usbChargingFunctionsAccessory` (default false = upstream behaviour); beta2's overlay sets it
true. With adb off, `getChargingFunctions()` returns ACCESSORY instead of MTP. Effect:

- idle (cable in, nothing from the host yet): the phone enumerates as **18d1:2d00** with one
  interface, the accessory's vendor-specific ff/ff/00 with two bulk endpoints. Nothing on the
  phone reads them: `mCurrentFunctions` stays NONE, no accessory is attached, no app sees anything.
- the host sends the AOA handshake (GET_PROTOCOL, the six strings, START) on EP0 of that device;
  the kernel accessory driver (kernel AOA, as on b3) raises `ACCESSORY=START`, the framework
  reads the strings and makes ACCESSORY the current function; the gadget HAL always tears the
  gadget down and re-composes (no same-function shortcut in its `setCurrentUsbFunctions`), so the
  phone re-enumerates as 18d1:2d00 and the accessory is attached with the host's strings
  (`USB_ACCESSORY_ATTACHED` → the app's AccessoryTransport).
- after the session (unplug, or the accessory closed) the framework restores the charging
  composition: the accessory again, without strings.

**Why nothing else can be exposed:** the gadget can only link function instances that exist in
configfs, and the b3 rc creates no other instance (configfs `functions/` and the gadget root stay
root-owned; the HAL runs as system). The patch only changes which existing function the framework
requests; adb stays off (`ro.debuggable=0` → no `ffs.adb` instance at all;
`persist.sys.usb.config=none`). Gates: rung b3/b4d-1 expectations (none of `mtp.gs0 ptp.gs1
audio_source rndis midi acm. dm.gs7 uts.gs8 ncm.gs9 etr_miu uvc.0 ffs.mtp ffs.ptp`, root-owned
configfs), beta1's (no adb endpoint outside the debuggable trigger, user props) and beta2's own:
an **allowlist** of instances (`accessory.gs2 ffs.aoa ffs.ctrl ffs.adb`), init never links a
function into a configuration and never writes `UDC`. build-beta.sh checks that every
frameworks-base-a17 patch is applied in the tree and that the compiled product RRO carries
`config_usbChargingFunctionsAccessory=true` (and framework-res its false default). The production
gate is unchanged (no adb anywhere).

**Host side:** `companion/src-tauri/src/aoa.rs` used to skip the handshake whenever it saw a
2d00/2d01 device ("already switched"). An idle beta2 phone *is* 2d00 without strings, so the
companion now remembers the accessory it switched (bus/address; forgotten when no accessory is on
the bus) and handshakes an accessory it does not know; if that accessory keeps its address for
4 s after START it is taken as already switched (a session that predates the companion).
`tools/aoa_client.py` (one-shot) always handshakes, with the same 4 s fallback.

### beta2 build (2026-10-19)

Built on the build host into `/build/out-beta2` exactly as beta1 (`sync-beta.sh beta2` with
beta1's signed release APK, byte-identical: same app; `build-beta.sh beta2` with installclean;
1 h 05 min), then a no-installclean gate re-run after a build-beta.sh fix (the new RRO check
SIGPIPE'd `aapt` under pipefail; the artifacts were already right). All gates passed: production,
release source (`--bluejay-beta beta2`, voice-capable warnings as beta1), overrides (111 absent,
58 APKs), check-build (70 modules removed, 444 `.ko`, 123 expectations incl. beta2's USB
allowlist), cmdline, AVB (beta key `7d4a65ae…fd4`, flags 0, rollback index 2026101300), app
(cert `934c4f78…032f`, APK `6b5073e9…3b71`), USB (`config_usbChargingFunctionsAccessory`: false
in framework-res, true in the product RRO; services.jar carries the 0006 code).
`user`, `CP2A.260605.016`, `test-keys`, incremental/date `1792426224`, SPL 2026-10-01,
Phone Vault 0.1.0-beta2.

```
5be3d4b02b8e79838fe2d9913b97b26f5736fb1b8888eee6482ab2484e07f7aa  images/boot.img
030d6b7fd27bfd15632b593059345a345703b6f8d2f9670cba0415a9c3542b5e  images/vendor_boot.img
8d5687a541e9b88453b89c9e42d537fd784444ffc40feb099de2c4f062849287  images/dtbo.img
4a5a0bb47984d05cc77fdd868b14fdfc8aab158bfe4a356980503765fcc07e9b  images/pvmfw.img
cac0ebde96ff5a80414c1f6ee447b0099d06270161d435937922111c46045c16  images/vbmeta.img
6adcb66dc432d3727d0fdd885cf6767c129141dba4df2d2f5bbda53c65bdb673  images/vbmeta_system.img
94d818fa529c4dcbcc77fa3ef129a3c6b47367bc9bf283cb7464af9c36e47639  images/vbmeta_vendor.img
86a204263d9970fa594385f7aca41854c6c6970e32961a4776d4c390ebd1baf6  super.img
654e604b46980ab4753e6e016dd08870871a44a1a5e63632fdccaea470c2a451  images/android-info.txt
72cd2a860f168be500262f276614f9aa25776f10f519eca105f29567f0f76a75  flash-beta2-mac.sh
5aba4539bf9e8d887b3bc61e8f1e0e3efd27df81ac36918a0b111043ee0c8d48  manifest.json
65054fff18572fb935710481b56a90e40c957e60e55b6d87e85fcc4053e005da  vault_bluejay-target_files-beta2.zip
210130a5202b22d9af5cfb2b1541c7a8d65813bcd94ad1bc04fa542628f47787  vault_bluejay-img-beta2.zip
```

Not flashed yet. Flash and rollback as beta1 (`rsync … /build/out-beta2/ out-beta2/`,
`./flash-beta2-mac.sh --check`, `./flash-beta2-mac.sh`).

### Verify on hardware without adb

1. Flash as beta1 (`flash-beta2-mac.sh`), first boot to SET PIN, set the PIN.
2. USB-C cable to the Mac: `system_profiler SPUSBDataType` shows a **Google device**
   (Vendor ID `0x18d1`, the phone's product string and serial) with **Product ID `0x2d00`**, and
   nothing else from the phone: no MTP/PTP volume (Image Capture sees nothing), no
   network/serial/MIDI/audio device. `ioreg -p IOUSB -l -w0` shows one interface for it, class
   255/255/0. `adb devices` lists nothing.
3. Start the companion: it detects the phone and pairs. During the handshake the phone leaves the
   bus for about a second and comes back, still **0x2d00** = accessory without adb (0x2d01 =
   accessory + adb must never appear on beta2). The app shows the connection; signing works.
4. Unplug/replug: 0x2d00 again within seconds; the companion pairs again.
5. Fail signs: no Google device at all (fix not active: is it really beta2?), a second interface,
   or any PID other than 0x2d00: stop and report.

**Risks:** (1) untested on hardware, and without adb a misbehaviour cannot be logged; rollback =
reflash b4d-1, where `adb shell settings put global adb_enabled 0` reproduces beta1's no-device
state but not the fix (0006 is in the tree for every rung, inert unless the resource is set).
(2) Older companion builds skip the handshake on a 2d00 device and time out: use the companion
from this commit. (3) The gs101 gadget HAL may cap charge current while the accessory function is
composed (its `usb_limit_accessory_*` paths); a Mac port supplies less anyway. (4) A host that
opens the idle accessory's bulk endpoints without the handshake talks to nothing; the endpoint
exists only as the AOA transport itself. (5) Rebuilding the framework changes framework-res
(new public-internal resource): if the build misbehaves, compare with beta1's target files.
