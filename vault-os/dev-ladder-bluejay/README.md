# Bluejay ladder (Pixel 6a, LineageOS 24.0 / Android 17)

The Pixel 6a counterpart of `dev-ladder/` (crosshatch). The plan, the partition layout, the
rung list and the firmware rules are in `docs/port-bluejay.md`; this directory holds what each
rung actually builds. Nothing here is shared with the crosshatch tree: the scripts default to
`/build/lineage-24` (the real path; `/root/lineage-24` is a symlink) and the Kleaf workspace
`/build/gs-6.1-kernel`, and never touch `/root/lineage-src`.

```
dev-ladder-bluejay/
  sync-rung.sh   RUNG [TREE] [APK] [KERNEL_DIST]   product + rung overrides + A17 framework patches + kernel dist → tree
  build-rung.sh  RUNG [TREE] [OUT]                 target-files → firmware-free fastboot zip + loose images + SHA256SUMS
                                                   (b1+: AVB/launcher checks, sparse super.img, flash-RUNG-mac.sh)
  flash-mac.sh                                     bootloader-only slot-a flash from macOS (installed as flash-RUNG-mac.sh)
  rung-b0/       files that still override release intent at b0
  rung-b1/       … at b1 (AVB dev key, no launcher, sysconfig)
```

A rung directory has the same meaning as on crosshatch: it holds only the files that still
override release intent (`common.mk`, `BoardConfigVault.mk`, `Android.bp`, `config.xml`,
`debug_adbkey.pub`, optional `device-google-bluejay.diff`). `sync-rung.sh`:

1. rsyncs `device/phonevault/bluejay` and `vendor/phonevault` (no `keys/`, no APK; `keys/` in the
   tree is neither overwritten nor deleted, see "AVB dev key" below);
2. copies the rung overrides over their targets;
3. restores `device/google/bluejay` to upstream, applies the rung's device diff if any, and
   appends `include vendor/phonevault/config/BoardConfigVault.mk` to `bluejay/BoardConfig.mk`;
4. applies `patches/frameworks-base-a17/*.patch` (Android 17 rebases; the Android 15 series in
   `patches/frameworks-base/` does not apply to this tree);
5. copies the Kleaf dist (`out/bluejay/dist`: `boot.img`, `dtbo.img`, `dtb.img`, `*.ko`, …)
   into `device/google/bluejay-kernels/6.1`, but never the four tracked list files
   (`modules.load`, `vendor_dlkm.modules.load`, `vendor_dlkm.modules.blocklist`,
   `init.insmod.bluejay.cfg`): those are the module-stripping lever of b3+; it reports when the
   dist disagrees with them;
6. bakes the signer APK as `vendor/phonevault/prebuilt/PhoneVault.apk`.

Kernel: `cd /build/gs-6.1-kernel && ./build_bluejay.sh` (as aipg). Lineage 24.0's kernel
manifest pins the GKI `android14-6.1-2025-12_r30` as a downloaded prebuilt, so only the Pixel
vendor modules are compiled: about 6 min on the build box.

Build: as aipg, `build-rung.sh b0` → lunch `vault_bluejay-cp2a-userdebug`, `WITH_ADB_INSECURE=true`
(without it Lineage turns userdebug into `ro.adb.secure=1` + `ro.debuggable=0`),
`m target-files-package`, `img_from_target_files`, then the zip is rebuilt **without** the nine
firmware images (`abl bl1 bl2 bl31 gsa ldfw pbl tzsw modem`) and checked to hold exactly
`android-info.txt` + boot dtbo pvmfw vendor_boot vbmeta vbmeta_system vbmeta_vendor system
system_ext product vendor vendor_dlkm (+ `super_empty.img` / `fastboot-info.txt` if present),
with `android-info.txt` = `vendor/phonevault/config/board-info-bluejay.txt`
(`require board=bluejay`, `version-bootloader=bluejay-17.0-15199431`,
`version-baseband=g5123b-145971-260414-B-15201439`). Output in `/build/out-<rung>/`.

Flashing: from the owner's Mac, **from the bootloader only** (fastbootd writes fail on macOS, see
"b0 on the phone"). From b1 the out directory carries everything for that path: `images/` (slot
partitions + `android-info.txt`), a sparse `super.img` (slot a populated, built by
`build/make/tools/releasetools/build_super_image.py` from the target files) and
`flash-<rung>-mac.sh`, which checks SHA256SUMS and the phone (product, bootloader, upper-case-B
baseband, unlocked, not fastbootd), then `fastboot --slot=a flash` boot vendor_boot dtbo pvmfw
vbmeta vbmeta_system vbmeta_vendor, `fastboot flash super super.img`, `erase metadata`, `-w`,
`--set-active=a`, `reboot`. `--check` runs the checks only. Bootloader, radio and
`avb_custom_key` are never written.

AVB dev key (b1+): RSA-4096, **development only, not the release key**, generated on the build
box as aipg: private key `/home/aipg/.phonevault-keys/avb/phonevault_bluejay_avb_DEV_rsa4096.pem`
(0400, dir 0700, never committed, never copied off the box), public blob
`/home/aipg/.phonevault-keys/avb/avb_pkmd_bluejay_DEV.bin` (`avbtool extract_public_key`;
sha256 `068a9865f04cc9b91f6838b537c14f32e4fa6e32682cbcfbfd6c9782ab71ae8c`, sha1
`af09b166ade90fb31a184e9ab6c59819cd33fc8a` = what `avbtool info_image` prints). The tree reaches it
through the symlink `vendor/phonevault/keys/avb_bluejay_dev.pem`; the rung's
`BoardConfigVault.mk` stops the build if it is missing. The release key for b8/b9 is a separate
key that never lives on the build box.

## Rung log

| Rung | Change | Status | Notes |
|---|---|---|---|
| b0 | Lineage 24.0 bluejay (CP2A.260705.006 blobs, GKI 6.1 + Kleaf vendor modules) + `vault_bluejay` product: signer app as an ordinary system app on **/product** (`privileged: false`, `product_specific: true`: gs101 enforces generic_system's artifact path requirement, so nothing product-specific may go to /system; props and `preferred-apps` moved to /product for the same reason), frameworks/base 0003 + 0004 rebased to Android 17 (`patches/frameworks-base-a17/`), Phone Vault overlay ahead of Lineage's (wallpaper, `config_fixedFunctionDeviceOwner`, no doze/AOD, airplane mode default on; becomes the auto-generated product RRO), preferred HOME, `LineageSetupWizard` overridden, userdebug (`ro.debuggable=1`, `ro.adb.secure=0`) with pre-authorised build-box and owner-Mac keys, `board-info-bluejay.txt` bootloader/baseband pins. `boot.img` is built (kernel `Image.lz4` + generic ramdisk) instead of the kernel-only Kleaf prebuilt, see `BoardConfigVault.mk`. **AVB is the Lineage gs101 default: vbmeta signed with the public AOSP `testkey_rsa4096`, boot/vbmeta_system/vbmeta_vendor chained with the public `testkey_rsa2048`, vbmeta `--flags 3`** (verification off), rollback indexes 1790812800 (2026-10-01) — unlocked dev phone only; b1 re-keys. Not ported yet: 0001/0002 (GrapheneOS imports), 0005 (keyguard clock), the boot animation, appliance/device patches. | **built 2026-10-11, not flashed.** Full build 6 h 58 min (kernel 6 min). `/build/out-b0/`: `vault_bluejay-img-b0.zip` sha256 `90ac0b78…`, app `c5def7d6…`, `boot.img` `c0c0fa6b…`; zip holds exactly android-info + boot dtbo pvmfw vendor_boot vbmeta vbmeta_system vbmeta_vendor system system_ext product vendor vendor_dlkm super_empty (firmware, `system_other`, `userdata` dropped) | Boot test per `docs/port-bluejay.md` §5 b0 row (owner `fixed-function-system-image`, `mLockTaskModeState=LOCKED`, SET PIN on genuine first boot, inventory, `attesttest.sh`) |
| b1 | b0 + **factory-boot wake-up**: frameworks/base 0003 unstops the configured owner before `setActiveAdmin` and re-sends `DEVICE_ADMIN_ENABLED` once user 0 is unlocked (b0's enable broadcast was never sent: user 0 is locked at `PHASE_ACTIVITY_MANAGER_READY`, the receiver is not direct-boot aware, and the package was scanned stopped), plus `/product/etc/sysconfig/phonevault-initial-package-state.xml` (`stopped=false`); **no launcher** (`Launcher3QuickStep`, `Launcher3Overlay` overridden); **own AVB dev key** on vbmeta + boot + vbmeta_system + vbmeta_vendor (RSA-4096, key sha1 `af09b166…`, pkmd sha256 `068a9865…`), vbmeta **flags 0** (verification on), rollback indexes 1790812800 as before, not relocked; frameworks/base **0005** rebased (no keyguard clock/smartspace/date; SystemUI overlay synced again); **no Lineage Trust** (bluejay overlay drops `TrustInterfaceService` from `config_externalLineageServices`, sysconfig `unavailable-feature org.lineageos.trust`). Same kernel and app (`c5def7d6…`) as b0. | **built 2026-10-11, not flashed.** Incremental build 46 min (13:01–13:47). `/build/out-b1/`: `super.img` (sparse, slot a populated) `a3f09f7d…`, `vbmeta.img` `62c12610…`, `boot.img` `13cee4a5…`, `vendor_boot.img` `90998a7e…`, image zip `50dc5f8d…`, `flash-b1-mac.sh` `d26bab20…`; checks in build-rung.sh passed (all four AVB signatures = dev key, flags 0, no launcher in target files, both sysconfigs present); RROs verified with aapt2 (`config_phonevaultHideKeyguardClock` true, `config_externalLineageServices` 7 entries without Trust) | On the phone: `./flash-b1-mac.sh --check`, then `./flash-b1-mac.sh`. Must land on SET PIN with **no** manual step; see the b1 checklist below |

- 2026-10-11: android-info.txt required baseband `…-260414-b-…` but the phone reports `…-260414-B-…` (fastboot compares exactly; it would have refused the flash). Fixed in board-info and build-rung.sh; the b0 zip on the Mac was patched in place (android-info.txt only): sha256 `bd26a0f13f9800a4889e84cac1d6054c3708e6e5027b708c6f9848aeac970aec`. Pre-flight on the phone (read-only) matched board, bootloader, baseband and slot b.

## b0 on the phone (2026-10-11)

- Flashing: `fastboot update` from the Mac failed at the switch to userspace fastboot (fastbootd
  enumerates on macOS but every write fails "Write to device failed (No such file or directory)",
  also through a hub). The interrupted update had already flashed slot b's boot partitions and
  reset super (slot a's dynamic partitions gone). Worked around entirely from the bootloader:
  `build_super_image.py` on the target files → sparse `super.img` (489e7429…, slot a populated),
  then `fastboot --slot=a flash` boot / vendor_boot / dtbo / pvmfw / vbmeta / vbmeta_system /
  vbmeta_vendor, `fastboot flash super super.img`, `erase metadata`, `-w`, `--set-active=a`.
  Bootloader and radio never written. **Use this bootloader-only path from macOS.**
- Booted in ~50 s: `24.0-20261011-UNOFFICIAL-bluejay`, slot `_a`, verified boot orange (unlocked).
  Device owner = `dev.phonevault.signer`, provisioning context `fixed-function-system-image`
  (the Android 17 port of patch 0003 works).
- Gap: the app was never started after provisioning (no VaultProvision log, keyguard + a HOME
  chooser with Trebuchet). `am start` → kiosk LOCKED at SET PIN. Same class of first-boot gap as
  crosshatch before the USER_STARTED fallback; on 17 the fallback did not fire. Fix in b1.
- Also seen: "Discover Trust" notification, "belongs to your organization" (org name not yet
  applied because provisioning never ran), clock/date on the keyguard (patch 0005 not ported yet).
- First run from the Mac (harness needs Homebrew bash ≥4; macOS bash 3.2 lacks `mapfile`): PIN →
  credential installed on the Titan M2, wallet created with **no** extra PIN prompt (the keystore
  readiness check works), 3-word spot check, Home, kiosk LOCKED. Attestation: factory-provisioned
  StrongBox chain, verdict development (see device-attestation.md).

## b1 checklist (on the phone)

1. Mac, phone in the bootloader: `./flash-b1-mac.sh --check` (hashes, product, bootloader,
   upper-case-B baseband, unlocked, not fastbootd), then `./flash-b1-mac.sh` (type FLASH).
2. **Factory-boot test: touch nothing.** The phone must reach Phone Vault's SET PIN by itself:
   no keyguard swipe, no HOME chooser, no `am start`. `adb logcat -d | grep VaultProvision` shows
   `appliance provisioned on admin enable`; `adb logcat -d -b system | grep -i fixed-function`
   shows no wtf/warning.
3. `dumpsys device_policy`: owner `dev.phonevault.signer/.VaultDeviceAdminReceiver`, provisioning
   context `fixed-function-system-image`, organization name `Phone Vault`;
   `dumpsys activity activities | grep mLockTaskModeState` = LOCKED;
   `cmd package query-activities -a android.intent.action.MAIN -c android.intent.category.HOME`
   lists PhoneVault and Settings' FallbackHome only; `pm list packages | grep -i launcher3` empty;
   `dumpsys package dev.phonevault.signer | grep stopped` = false.
4. No "Discover Trust" notification (`dumpsys notification | grep -i trust` empty;
   `service list | grep lineagetrust` empty; `pm list features | grep lineageos.trust` empty).
5. Reboot after setting the PIN: the boot keyguard/bouncer shows **no clock, no date**; the
   disclosure line says the device belongs to **Phone Vault**.
6. AVB: `getprop ro.boot.verifiedbootstate` = orange (unlocked), `ro.boot.veritymode` =
   enforcing, `ro.boot.vbmeta.digest` non-empty, `ro.boot.vbmeta.avb_version` set; no dm-verity
   errors in `dmesg`. (Unlocked: a mis-signed image would still boot orange, so this is safe.)
7. First run as in b0 (PIN, wallet, Titan M2 keystore, kiosk LOCKED), `attesttest.sh` (verdict
   stays development: unlocked, dev key not pinned), crash-loop count 0.

