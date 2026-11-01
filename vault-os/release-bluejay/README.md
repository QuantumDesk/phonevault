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
| `beta3` | rung b4d-1 | **beta2 + the current signer app** ([below](#beta3-beta2--the-stale-session-app)): beta2's files (version/channel `beta3`); the app now reopens a still-attached accessory after a lock and on start, so a returning host finds a live session without a replug |
| `beta4` | rung b4d-1 | **beta3 + the 6a-fix app** ([below](#beta4-beta3--the-6a-fix-app)): beta3's files (version/channel `beta4`), app 0.3.1 (code 4) with the held request on the credential locked page and the PIN-cancel wedge fix; AVB rollback index raised to 2026103000 |
| `beta5` | rung b4d-1 | **beta4 + the beta5 app** ([below](#beta5-beta4--the-beta5-app)): beta4's files (version/channel `beta5`), app 0.3.2 (code 5): the system PIN prompt says a request is waiting, brightness, restart, timeouts, lock after screen off, guessable-PIN refusal, reconnect after the host gives up; AVB rollback index raised to 2026110100 |

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
key or a beta goes to anyone outside the project.

> **Conscious exception (public beta, 2026-11):** the public beta, **0.1.0-beta4**
> ([GitHub release](https://github.com/QuantumDesk/phonevault/releases/tag/v0.1.0-beta4)), ships
> to outside testers signed with these **BETA-TEST** keys. That breaks the rule above on purpose:
> the offline key ceremony (`scripts/generate-release-keyset.sh`) has not happened yet, and the
> beta is offered for small amounts only, with the bootloader **unlocked** and never relocked to
> these keys, and the genuine check accepts a beta phone only in Developer mode and never better
> than Development. The rule still holds for relocking: no phone is relocked to a BETA-TEST key.
> The exception ends with the key ceremony; the first image signed with offline-generated keys
> needs a re-install (wipe) and a restore from the recovery phrase.

They are separate from the AVB dev key
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
- after an unplug the framework restores the charging composition: the accessory again, without
  strings. Closing the accessory on the phone (the vault locks) changes nothing on the bus: the
  phone stays the attached accessory, and a later handshake does **not** re-enumerate it
  (UsbDeviceManager skips an unchanged function set), see the stale-session note below.

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
2d00/2d01 device ("already switched"). An idle beta2 phone *is* 2d00 without strings. The
companion and `tools/aoa_client.py` now **probe** an existing accessory: a zero-length bulk OUT
packet completes only while the phone's app has a read queued (f_accessory drops a ZLP unseen), so
a live session is used at once, without a handshake. One nobody reads (an idle beta2 phone, or a
**stale session**: the vault locked or the app restarted while the cable stayed in) gets the
handshake; an idle phone re-enumerates by itself (its functions change), a stale one does not, so
the host then resets the USB port while START is pending, which makes the framework attach the
accessory afresh (`USB_ACCESSORY_ATTACHED`, a new app session). If nothing reads even then, the
companion says to unplug and replug. Since the same fix the app also reopens the still-attached
accessory after every lock (and on start), so with a current app the probe simply succeeds.
**beta2's app predates that**: on beta2 only the host recovery (START + port reset) applies.

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
5. Stale session (no replug): after a request, let the vault lock (or press power), unlock, ask
   again from the companion. Expected: answered within ~10 s (the companion's log line "attaching
   it afresh" with beta2's app; none with an app that reopens the accessory). Then quit and
   restart the companion and ask again: answered at once. Also check the zero-length probe on
   macOS: a live session must be used without that log line. Never an endless wait: a failure
   says "unplug and replug".
6. Fail signs: no Google device at all (fix not active: is it really beta2?), a second interface,
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

## beta3: beta2 + the stale-session app

**What changed vs beta2:** only the signer app and the beta's name. `release-bluejay/beta3` is
beta2's directory (same `BASE` rung b4d-1, same `config.xml` with
`config_usbChargingFunctionsAccessory=true`, same board file, same expectations) with
`PHONEVAULT_VERSION := 0.1.0-beta3`, `ro.phonevault.channel=beta3` and the beta name in comments
and error texts. The image is otherwise built from the same tree state (kernel prebuilts, upstream
diffs, frameworks-base-a17 0003..0006, recovery hardening) as beta2.

The app is a fresh `gradle :app:assembleRelease` of main at the merge of the USB stale-session
recovery (`354afa3`, merged in `f07009f`), signed with the beta app key by `sign-beta-apk.sh`
exactly as beta1's: after a lock, on start and after unlock it reopens the still-attached
accessory (only the filtered Phone Vault host, only with the permission the attach granted, only
while `USB_STATE` reports the accessory function configured), and closes the session on
`USB_ACCESSORY_DETACHED`. With beta2's app a host that came back after a lock found nothing
reading and had to fall back to START + port reset (or a replug); with beta3's the companion's
zero-length probe finds a live session at once. The release-only paths are unchanged
(`versionName` is still 0.3.0, `versionCode` 3: the version was not bumped for this fix; the
classes.dex differs from beta1/beta2's and carries the reopen path, the manifest is
byte-identical).

### beta3 build (2026-10-30)

Built on the build host into `/build/out-beta3` as beta2 (`/build/pv-ladder/build-beta3.sh`:
`sign-beta-apk.sh`, `sync-beta.sh beta3`, `build-beta.sh beta3` with installclean, as aipg under
`/root/pv-build.lock`; 32 min, the out dir was last built as beta2). The app was built as root with
the host's Gradle 8.10.2, `/root/android-sdk` (platform 35, build-tools 35.0.0) and the tree's
JDK 21 from a `git archive` of the beta3 commit (unsigned APK sha256 `0ff4f7c1…dcc9`).

All gates passed: production, release source (`--bluejay-beta beta3`, voice/SMS-capable warnings
as beta1/beta2), overrides (111 absent, 58 APKs), check-build (70 modules removed, 444 `.ko`,
load lists/modules.dep consistent, 123 expectations incl. beta2's USB allowlist and the `beta3`
channel), patch provenance (2 pinned GrapheneOS imports, 61 project patches; run on the repo copy
the build used), cmdline, AVB (beta key `7d4a65ae…fd4`, flags 0, rollback index 2026101300 =
beta2's: not a production release, `release-version.mk` unchanged), app (cert `934c4f78…032f`,
release variant, APK `43c6eced…27e7`), USB (`config_usbChargingFunctionsAccessory` true in the
product RRO).
`user`, `CP2A.260605.016`, `test-keys`, incremental/date `1793371783`, SPL 2026-10-01,
Phone Vault 0.1.0-beta3; app `dev.phonevault.signer` 0.3.0 (code 3) release, APK sha256
`43c6ecedf5938b3ac5facf7f933144ca6a08fe4b1cacf23fe54021b0458727e7`.

```
5c30df4be82329452e6d3026c23b6b2928c68f027dd1e6f6a55b2a8029f8287a  images/boot.img
fc770312ecd50405f3fc47601c759193063750c1edbf53450104d036a5149315  images/vendor_boot.img
8d5687a541e9b88453b89c9e42d537fd784444ffc40feb099de2c4f062849287  images/dtbo.img
4a5a0bb47984d05cc77fdd868b14fdfc8aab158bfe4a356980503765fcc07e9b  images/pvmfw.img
92dc227abc400954ec7f5ed8d95c95dd54280e4a30d07b89780dd8c2c1de86c1  images/vbmeta.img
6d904e4f2ee954e21a26c5058de5f5d4de9ce2e2e52d3002a8c3d32325b5eb78  images/vbmeta_system.img
3e01e6eec861bb1508f8e954e6c009d9d9d4fe412a19ba5c9ad130ffe2e023b4  images/vbmeta_vendor.img
9143a6c69e652bce2f0f73446e9b4190b02705963eb3dc1c6a4a384e25f08b10  super.img
654e604b46980ab4753e6e016dd08870871a44a1a5e63632fdccaea470c2a451  images/android-info.txt
72cd2a860f168be500262f276614f9aa25776f10f519eca105f29567f0f76a75  flash-beta3-mac.sh
967036e65bb5627eeb63386f2fa335d434de89bcb65c59fc1e47a3725bba9e2d  manifest.json
793005daf9a1c16fd5a06f5ba3afac0c2af0fbcfe584ed6b8441bc8e9fccc3c2  vault_bluejay-target_files-beta3.zip
d2c1df35cdd4f422efacbed8370aea5880c6b26692da8d8fbe29d4a46a049e85  vault_bluejay-img-beta3.zip
```

Not flashed yet. Flash and rollback as beta1 (`rsync … /build/out-beta3/ out-beta3/`,
`./flash-beta3-mac.sh --check`, `./flash-beta3-mac.sh`). The app key is unchanged, but the flash
script always wipes anyway.

### Verify on hardware without adb

1. Flash (`flash-beta3-mac.sh`), first boot to SET PIN, set the PIN.
2. Enumeration, as beta2: `system_profiler SPUSBDataType` shows the Google device `0x18d1` /
   **`0x2d00`**, one interface (`ioreg -p IOUSB -l -w0`: class 255/255/0), no MTP/PTP volume, no
   network/serial/MIDI/audio device; `adb devices` lists nothing.
3. Start the companion (from main): it detects the phone and pairs; during the first handshake
   the phone leaves the bus for about a second and returns as **0x2d00** (0x2d01 must never
   appear). Signing works.
4. Unplug/replug: 0x2d00 again within seconds; the companion pairs again.
5. Reconnect checks (beta2's step 5; **the beta3 difference**), no replug anywhere:
   - after a request, let the vault lock (or press power), unlock, ask again from the companion:
     answered **at once**, and the companion log has **no** "attaching it afresh" line (beta2
     needed START + port reset here; beta3's app has already reopened the accessory, so the
     zero-length probe finds a live session);
   - ask while the vault is still locked: the request is held behind the PIN gate and never
     answered while locked; unlock, then ask again if the companion gave up: answered at once;
   - quit and restart the companion, ask again: answered at once (the probe uses the live session;
     no handshake, no re-enumeration, `system_profiler` still shows 0x2d00);
   - repeat the lock/unlock cycle several times (power button and timeout lock) with requests in
     between: each answered without a replug. If one ever needs the fallback, the companion
     logs "attaching it afresh" and answers within ~10 s (beta2's path, still present); never an
     endless wait, a failure says "unplug and replug".
6. Fail signs: no Google device at all, a second interface, any PID other than 0x2d00, a request
   that hangs after a lock/unlock cycle (the reopen path not working: compare with beta2's
   behaviour, where the companion's fallback should still recover it): stop and report.

**Risks:** (1) the reopen path is new on a user build and on hardware without adb: if it
misbehaves (e.g. it holds `/dev/usb_accessory` open at a moment the framework wants to START), the
symptom is a host that needs the port-reset fallback or a replug, not a boot problem; beta2 is
the comparison image. (2) The app's version was not bumped (0.3.0 / code 3, same as beta1/beta2):
`manifest.json`'s `apk_sha256` and the image's `ro.phonevault.version` tell the builds apart, not
the app version. (3) Same as beta2 otherwise: platform on Lineage test keys, BETA-TEST AVB/app
keys, unlocked bootloader, voice/SMS-capable left at default (keyguard Emergency button).

## beta4: beta3 + the 6a-fix app

**What changed vs beta3:** the signer app, the beta's name and the AVB rollback index.
`release-bluejay/beta4` is beta3's directory (same `BASE` rung b4d-1, same `config.xml`, board
file and expectations) with `PHONEVAULT_VERSION := 0.1.0-beta4`, `ro.phonevault.channel=beta4` and
the beta name in comments and error texts. The image is otherwise built from the same tree state
(kernel prebuilts, upstream diffs, frameworks-base-a17 0003..0006, recovery hardening) as beta3.

- **App 0.3.1 (versionCode 4)**, a fresh `gradle :app:assembleRelease` of main at the merge of the
  Pixel 6a fixes (`304cf55`, app change `e0e2ac2`) plus the version bump, signed with the beta app
  key by `sign-beta-apk.sh` as before (same cert; builds are now also told apart by version):
  - a request held while the credential **locked page** is up is shown there ("INCOMING REQUEST"
    card; before, only the in-app PIN screen showed it) and is **kept across a relock** while
    still locked (beta3 dropped it on screen-off and the host waited for its timeout); a lock
    from unlocked with a request not yet dispatched answers it with an error ("The phone locked
    before this request was reviewed. Nothing was signed.") as the session's last frame;
  - a **dismissed PIN prompt** (Back/error/timeout) on a sensitive action releases the flow, so
    the next sensitive action asks again (beta3: every later sensitive action did nothing until
    the next lock); a PIN prompt that outlived its session unlocks the current locked page.
- **USB re-attach race**: host-side only (`ee89e50`, companion `aoa.rs` and `tools/aoa_client.py`:
  wait 7 s for the phone's own re-attach after START, settle 1.2 s before opening, retry a
  vanished open once). Nothing in the image changes for it; use the companion from main.
- **AVB rollback index 2026103000** (`release-version.mk`, was 2026101300 for beta1..beta3), on
  vbmeta and the three chained partitions. Still only enforced once a phone is relocked to the
  beta key; an unlocked phone can go back to beta3 by reflashing.

### beta4 build (2026-10-30)

Built on the build host into `/build/out-beta4` as beta3 (`/build/pv-ladder/build-beta4.sh`:
`sign-beta-apk.sh`, `sync-beta.sh beta4`, `build-beta.sh beta4` with installclean, as aipg under
`/root/pv-build.lock`; 32 min). The app was built as root in `/root/pv-beta4-app` with the host's
Gradle 8.10.2, `/root/android-sdk` and the tree's JDK 21 from a `git archive` of the beta4 config
commit (unsigned APK sha256 `0003d0d2…b1f2`); the repo copy the build used is
`/build/pv-beta4/repo`.

All gates passed: production, release source (`--bluejay-beta beta4`, voice/SMS-capable warnings
as before), overrides (111 absent, 58 APKs), check-build (70 modules removed, 444 `.ko`, load
lists/modules.dep consistent, 123 expectations incl. the `beta4` channel), patch provenance
(2 pinned GrapheneOS imports, 61 project patches; on the repo copy), cmdline, AVB (beta key
`7d4a65ae…fd4`, flags 0, rollback index **2026103000**), app (cert `934c4f78…032f`, release
variant, 0.3.1), USB (`config_usbChargingFunctionsAccessory` true in the product RRO). The image's
APK is `dev.phonevault.signer` versionCode 4 / versionName 0.3.1 and its dex carries the new
locked-refusal text (absent from beta3's).
`user`, `CP2A.260605.016`, `test-keys`, incremental/date `1793408946`, SPL 2026-10-01,
Phone Vault 0.1.0-beta4; APK sha256
`7f07d5c060b8346caec31d4624551af4c0043deb93e0140e29cf11a36bec03fd`.

```
08ce393f63825de6f5939f688e102773e7ac925e0786fc5dc22cf9243a13ac17  images/boot.img
21571bc956a6f8a61ee121fad292b47328c28ffb8b85362288416632ee773e94  images/vendor_boot.img
8d5687a541e9b88453b89c9e42d537fd784444ffc40feb099de2c4f062849287  images/dtbo.img
4a5a0bb47984d05cc77fdd868b14fdfc8aab158bfe4a356980503765fcc07e9b  images/pvmfw.img
bccce089283a89c4fd81da574db5b8e43981e725f4a03a73feb75f83467d2cd7  images/vbmeta.img
58dcfe4a979b42e91ee0006fa0989cc6489b5281c83e2daaa449eae55d5bd442  images/vbmeta_system.img
f7b3805a8b538434364cb6a56fb0b076706ec18d501c7e5c171ecb5086997ddd  images/vbmeta_vendor.img
0cfda121bc35a4872a9f5f46f578d794bf9850151f7d79644c8e3844ac8585e3  super.img
654e604b46980ab4753e6e016dd08870871a44a1a5e63632fdccaea470c2a451  images/android-info.txt
72cd2a860f168be500262f276614f9aa25776f10f519eca105f29567f0f76a75  flash-beta4-mac.sh
e26f04427d7fde99235136c285f2f0482e751894e326f3bd9880ead4afb990be  manifest.json
b799b157b844bd9358c5812cbb11760d4577b8d11264669cf93e098de61e132b  vault_bluejay-target_files-beta4.zip
72fbf3842c52b2921111db301b1136fda87dbb77c7cb7ad057d5f5c7c91a24e0  vault_bluejay-img-beta4.zip
```

Copied to the Mac (`~/pv-bluejay/out-beta4/`, without the two zips): `shasum -a 256 -c` on
`SHA256SUMS` minus the zip lines, 37/37 OK. For the public beta release
([v0.1.0-beta4](https://github.com/QuantumDesk/phonevault/releases/tag/v0.1.0-beta4), with the
BETA-TEST keys as the exception noted under Keys): `super.img` split in two parts below GitHub's
2 GiB limit, the seven slot images and `android-info.txt` in a zip, the build's own `SHA256SUMS`
(sha256 `26fa3625b8350f204aeb76004f8d6e546500683da979ec4c491c502156eeeec4`) and `manifest.json`,
`flash-beta4-mac.sh`, and `install-beta4-mac.sh` (joins, unzips, verifies against `SHA256SUMS`,
then runs the flash script's `--check` and the flash). The source of `install-beta4-mac.sh` is
kept at [`release/beta/install-beta4-mac.sh`](../../release/beta/install-beta4-mac.sh). Not flashed yet. Flash and rollback as beta1
(`./flash-beta4-mac.sh --check`, `./flash-beta4-mac.sh`; the flash script always wipes).

### Verify on hardware without adb

1. Flash (`flash-beta4-mac.sh`), first boot to SET PIN, set the PIN.
2. Enumeration and pairing, as beta3 steps 2-4: `0x18d1`/**`0x2d00`**, one interface (class
   255/255/0), no MTP/PTP/network/serial device, `adb devices` empty; the companion (from main)
   pairs, 0x2d01 never appears; unplug/replug pairs again.
3. Reconnect checks, as beta3 step 5 (lock/unlock, companion restart, repeated cycles; each
   answered without a replug). With the companion from main a fallback START is followed by the
   phone's own re-attach and **no** second drop (an older companion could reset the port just as
   the phone came back and fail on a vanished device).
4. **Held request on the locked page (beta4):** lock the vault, send a request from the
   companion: the locked page shows an **INCOMING REQUEST** card at once. Press power (screen off)
   and wake again while still locked: the card is still there and the companion is still
   waiting. Enter the PIN: the request is reviewed and answered.
5. **Lock before review (beta4):** unlock, send a request and lock immediately (before it is
   reviewed): the companion gets "The phone locked before this request was reviewed. Nothing
   was signed." promptly, not a timeout.
6. **PIN-cancel wedge (beta4):** with USB unplugged, Security → Show recovery phrase, dismiss the
   PIN prompt with Back; tap it again: a fresh PIN prompt appears (twice); then enter the PIN:
   the phrase screen opens. Other sensitive actions (☰ → Wallet, "Continue · verify PIN") still
   prompt after a dismissal.
7. Fail signs: as beta3 step 6, plus a held request that disappears on a screen-off while locked,
   or a sensitive action that does nothing after a dismissed prompt: stop and report.

**Risks:** (1) the locked-page rebuild and the kept gate session are new on a user build; if they
misbehave the symptom is a request not shown or not answered on the lock screen, not a boot
problem; beta3 is the comparison image. (2) The rollback index rose: harmless while unlocked,
but a phone ever relocked on beta4 can no longer take beta1..beta3. (3) Same as beta3 otherwise:
platform on Lineage test keys, BETA-TEST AVB/app keys, unlocked bootloader, voice/SMS-capable left
at default (keyguard Emergency button).

## beta5: beta4 + the beta5 app

**What changed vs beta4:** the signer app, the beta's name and the AVB rollback index.
`release-bluejay/beta5` is beta4's directory (same `BASE` rung b4d-1, same `config.xml`, board
file and expectations) with `PHONEVAULT_VERSION := 0.1.0-beta5`, `ro.phonevault.channel=beta5` and
the beta name in comments and error texts. The image is otherwise built from the same tree state
(kernel prebuilts, upstream diffs, frameworks-base-a17 0003..0006, recovery hardening) as beta4.

- **App 0.3.2 (versionCode 5)**, a fresh `gradle :app:assembleRelease` of main at `7f73b3f`
  (app changes `80b3b88`, `cd489e5`) plus the version bump, signed with the beta app key by
  `sign-beta-apk.sh` as before (same cert):
  - **the system PIN prompt says a request is waiting**: on the credential locked page the
    system PIN prompt covers the "INCOMING REQUEST" card, so its text now comes from the held
    request: title "Incoming request", "From your Mac" (or "From <site>, via your Mac" for a
    validated message-signature origin), "<Kind>. Unlock to review it. Nothing is signed until
    you approve it." (kind only: never an amount, address or message content). An open prompt is
    shown again with the new text when a request arrives, is replaced or is dropped;
  - **brightness**: ☰ → Display & auto-lock has a 1..100 % slider and Automatic (as device owner
    through the system setting; saved and re-applied on start);
  - **restart**: ☰ → Power → Restart (confirmed; device owner only; never while a request is held
    or under review) locks first, then reboots;
  - **timeouts**: screen timeout default 2 min (a saved choice is kept); screen timeout and idle
    lock choices 30 s, 1, 2, 5, 10 min;
  - **lock after screen off**: Immediately (default), 30 s or 1 min. The grace applies only when
    the display really went off while unlocked with no sensitive screen up; a wake past it locks
    before drawing; a sensitive action after a grace wake always asks for the PIN; a shutdown or
    reboot locks;
  - **guessable PINs refused** at SET PIN ("That PIN is one of the first a thief would try. Choose
    six digits that aren't a pattern."): one digit six times, straight runs (also across 9→0),
    repeated 2- or 3-digit groups, three doubled digits, the common-PIN list. Unlock never applies
    the check (an existing PIN keeps working);
  - **reconnect after the host gives up** (the 6a beta4 wedge): after a bus reset or disconnect
    f_accessory leaves the open descriptor unable to write, and beta4 never reopened it, so later
    hosts got no answer until a replug. A zero-length write probe now detects the stale
    descriptor (when a request is read and when `USB_STATE` reports configured again), what was
    held for the gone host is dropped with "Your Mac stopped waiting… Nothing was signed", and
    the still-attached accessory is reopened without a replug (bounded).
- **AVB rollback index 2026110100** (`release-version.mk`, was 2026103000 for beta4), on vbmeta
  and the three chained partitions. Still only enforced once a phone is relocked to the beta key.

### beta5 build (2026-11-01)

Built on the build host into `/build/out-beta5` as beta4 (`/build/pv-ladder/build-beta5.sh`:
`sign-beta-apk.sh`, `sync-beta.sh beta5`, `build-beta.sh beta5` with installclean, as aipg under
`/root/pv-build.lock`; 32 min). The app was built as root in `/root/pv-beta5-relapp` with the
host's Gradle 8.10.2, `/root/android-sdk` and the tree's JDK 21 from an archive of the beta5
config commit (unsigned APK sha256 `06bc3bd9…99cd6`); the repo copy the build used is
`/build/pv-beta5/repo`. The tree state before the sync was the same as beta4's.

All gates passed: production, release source (`--bluejay-beta beta5`, voice/SMS-capable warnings
as before), overrides (111 absent, 58 APKs), check-build (70 modules removed, 444 `.ko`, load
lists/modules.dep consistent, 123 expectations incl. the `beta5` channel), patch provenance
(2 pinned GrapheneOS imports, 61 project patches; on the repo copy), cmdline, AVB (beta key
`7d4a65ae…fd4`, flags 0, rollback index **2026110100**), app (cert `934c4f78…032f`, release
variant, 0.3.2), recovery patch, USB (`config_usbChargingFunctionsAccessory` true in the product
RRO). The image's APK (`PRODUCT/app/PhoneVault`) is `dev.phonevault.signer` versionCode 5 /
versionName 0.3.2 and its dex carries "That PIN is one of the first a thief would try" and "Your
Mac stopped waiting" (both absent from beta4's).
`user`, `CP2A.260605.016`, `test-keys`, incremental/date `1793575899`, SPL 2026-10-01,
Phone Vault 0.1.0-beta5; APK sha256
`95fb54a02289ef06ef5095e15b41b540c0b86a8208e7237cdb30167d5d750cb7`.

```
77b15a8da219c1e507b6b5f0d6470ba170654debcde762d2a36d108cafe32ab9  images/boot.img
7b59d66db6253fd2f5d370ae538db220315532c031217a8e175387c80562380b  images/vendor_boot.img
8d5687a541e9b88453b89c9e42d537fd784444ffc40feb099de2c4f062849287  images/dtbo.img
4a5a0bb47984d05cc77fdd868b14fdfc8aab158bfe4a356980503765fcc07e9b  images/pvmfw.img
1cc1ccb27aaa1c93acb36a101625a41bd8b6c114f678b7b1293d1f85857bb9d4  images/vbmeta.img
880adc9763905e440ee7b37a24c6badfda4b5f913fdda620c4fefd66319940ce  images/vbmeta_system.img
462d9c33c07f6508b6782d983f4679d6515e23f50c0a413854aba2c72cb81174  images/vbmeta_vendor.img
4240e89d53e42ecc73512d5525821aac8fbaacb530e69d2d829f72d56c635293  super.img
654e604b46980ab4753e6e016dd08870871a44a1a5e63632fdccaea470c2a451  images/android-info.txt
72cd2a860f168be500262f276614f9aa25776f10f519eca105f29567f0f76a75  flash-beta5-mac.sh
6e2d1ee4abd168072c368026f0f45c059b40fd6e32698c7313673a247be1980f  manifest.json
0475b0da5d7ab215599b6b637a97ff4c47a947c1b43500332327ff2c7a64188d  vault_bluejay-target_files-beta5.zip
3e6ae3fe0d27803acb18eb0417101bdd62bd27a3565d686ced3700dcfa946f12  vault_bluejay-img-beta5.zip
```

Copied to the Mac (`~/pv-bluejay/out-beta5/`, without the two zips): `shasum -a 256 -c` on
`SHA256SUMS` minus the zip lines, 37/37 OK. Not flashed yet. Flash and rollback as beta1
(`./flash-beta5-mac.sh --check`, `./flash-beta5-mac.sh`; the flash script always wipes).

For automated testing on a dev rung, the **appliance** (dev) APK from the same commit
(`gradle :app:assembleAppliance`, versionName `0.3.2-dev-appliance`, code 5, manifest variant
`dev-appliance`, signed with the build host's Android debug key `d8eab12d…4b53`, the same cert as
the dev rungs' baked app) is at `~/pv-bluejay/out-beta5/app-appliance.apk`, sha256
`43069ec76d38b5aad65aa5a8b7c341c1e551f11cfc4d8b426e4ed576942faae2`. It is not part of the image.

### Verify on hardware without adb

1. Flash (`flash-beta5-mac.sh`), first boot to SET PIN.
2. **Guessable PIN (beta5):** at SET PIN try `123456`, `000000`, `121212`, `112233`: each is
   refused with "That PIN is one of the first a thief would try…"; a non-pattern six-digit PIN is
   accepted, and unlock with it works.
3. Enumeration, pairing and reconnects as beta4 steps 2-3 (`0x18d1`/**`0x2d00`**, one interface,
   no MTP/network/serial device, `adb devices` empty; lock/unlock, companion restart, repeated
   cycles answered without a replug).
4. **PIN prompt says a request is waiting (beta5):** lock the vault, send a request from the
   companion: the system PIN prompt reads "Incoming request" / "From your Mac" / "<Kind>. Unlock
   to review it…" (no amount, no address). Without a request it is the plain unlock prompt.
   Enter the PIN: the request is reviewed and answered. Beta4 steps 4-6 (held request across a
   screen-off, lock before review, PIN-cancel wedge) still hold.
5. **Reconnect after the host gives up (beta5):** lock the vault, send a request, and let the
   companion time out (or quit it) while the request is held. Unlock: the phone says "Your Mac
   stopped waiting… Nothing was signed". Ask again from a fresh companion: answered, **no
   replug** (beta4 needed one here). Also unplug/replug mid-session, then ask: answered.
6. **Brightness (beta5):** ☰ → Display & auto-lock: move the slider, the screen follows;
   Automatic follows ambient light. After a restart (step 8) the choice is kept.
7. **Timeouts and lock after screen off (beta5):** the screen timeout defaults to 2 min; pick
   30 s and check the screen turns off after 30 s idle. With "Lock after screen off" =
   Immediately, every power-button wake asks for the PIN. Set 30 s: screen off, wake within ~10 s:
   still unlocked, but Security → Show recovery phrase asks for the PIN; screen off, wake after
   more than 30 s: the PIN is asked before anything is drawn. Screen off with the phrase or a PIN
   screen up: locked at once.
8. **Restart (beta5):** ☰ → Power → Restart → "Restart now": the vault locks, the phone reboots
   and comes up asking for the PIN. With a request held or under review, Restart is refused
   ("Not while a request from your Mac is waiting or under review…").
9. Fail signs: as beta4 step 7, plus a guessable PIN accepted, a request that still needs a
   replug after the host gave up, a grace wake that opens a sensitive screen without the PIN, or a
   Restart that does not lock first: stop and report.

**Risks:** (1) brightness, screen timeout and restart use device-owner system settings and
`DevicePolicyManager#reboot` for the first time on a user build; a failure shows "Setting not
saved" or "The phone did not restart", not a boot problem. (2) The stale-descriptor probe and
reopen are new on hardware without adb; if they misbehave the symptom is a request not answered
after a host gave up (beta4's behaviour, cured by a replug); beta4 is the comparison image. (3) The
rollback index rose: harmless while unlocked, but a phone ever relocked on beta5 can no longer
take beta1..beta4. (4) Same as beta4 otherwise: platform on Lineage test keys, BETA-TEST AVB/app
keys, unlocked bootloader, voice/SMS-capable left at default (keyguard Emergency button).
