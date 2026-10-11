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
  rung-b0/       files that still override release intent at b0
```

A rung directory has the same meaning as on crosshatch: it holds only the files that still
override release intent (`common.mk`, `BoardConfigVault.mk`, `Android.bp`, `config.xml`,
`debug_adbkey.pub`, optional `device-google-bluejay.diff`). `sync-rung.sh`:

1. rsyncs `device/phonevault/bluejay` and `vendor/phonevault` (no `keys/`, no APK; the SystemUI
   overlay is left out until frameworks/base 0005 is rebased to Android 17);
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

Flashing: from the owner's Mac, per `docs/port-bluejay.md` §8 (`fastboot update` of the image
zip, current slot only, firmware untouched).

## Rung log

| Rung | Change | Status | Notes |
|---|---|---|---|
| b0 | Lineage 24.0 bluejay (CP2A.260705.006 blobs, GKI 6.1 + Kleaf vendor modules) + `vault_bluejay` product: signer app as an ordinary system app on **/product** (`privileged: false`, `product_specific: true`: gs101 enforces generic_system's artifact path requirement, so nothing product-specific may go to /system; props and `preferred-apps` moved to /product for the same reason), frameworks/base 0003 + 0004 rebased to Android 17 (`patches/frameworks-base-a17/`), Phone Vault overlay ahead of Lineage's (wallpaper, `config_fixedFunctionDeviceOwner`, no doze/AOD, airplane mode default on; becomes the auto-generated product RRO), preferred HOME, `LineageSetupWizard` overridden, userdebug (`ro.debuggable=1`, `ro.adb.secure=0`) with pre-authorised build-box and owner-Mac keys, `board-info-bluejay.txt` bootloader/baseband pins. `boot.img` is built (kernel `Image.lz4` + generic ramdisk) instead of the kernel-only Kleaf prebuilt, see `BoardConfigVault.mk`. **AVB is the Lineage gs101 default: vbmeta signed with the public AOSP `testkey_rsa4096`, boot/vbmeta_system/vbmeta_vendor chained with the public `testkey_rsa2048`, vbmeta `--flags 3`** (verification off), rollback indexes 1790812800 (2026-10-01) — unlocked dev phone only; b1 re-keys. Not ported yet: 0001/0002 (GrapheneOS imports), 0005 (keyguard clock), the boot animation, appliance/device patches. | **built 2026-10-11, not flashed.** Full build 6 h 58 min (kernel 6 min). `/build/out-b0/`: `vault_bluejay-img-b0.zip` sha256 `90ac0b78…`, app `c5def7d6…`, `boot.img` `c0c0fa6b…`; zip holds exactly android-info + boot dtbo pvmfw vendor_boot vbmeta vbmeta_system vbmeta_vendor system system_ext product vendor vendor_dlkm super_empty (firmware, `system_other`, `userdata` dropped) | Boot test per `docs/port-bluejay.md` §5 b0 row (owner `fixed-function-system-image`, `mLockTaskModeState=LOCKED`, SET PIN on genuine first boot, inventory, `attesttest.sh`) |

- 2026-10-11: android-info.txt required baseband `…-260414-b-…` but the phone reports `…-260414-B-…` (fastboot compares exactly; it would have refused the flash). Fixed in board-info and build-rung.sh; the b0 zip on the Mac was patched in place (android-info.txt only): sha256 `bd26a0f13f9800a4889e84cac1d6054c3708e6e5027b708c6f9848aeac970aec`. Pre-flight on the phone (read-only) matched board, bootloader, baseband and slot b.
