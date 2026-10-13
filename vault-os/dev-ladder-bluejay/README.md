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
  check-build.sh RUNG TF OUT [TREE]                b2+ artifact gate on the build box (run by build-rung.sh)
  check-rung.sh  RUNG [--no-usb]                   on-phone pass criteria over adb, from the Mac (cumulative)
  rung-b0/       files that still override release intent at b0
  rung-b1/       … at b1 (AVB dev key, no launcher, sysconfig)
  rung-b2/       … b2 (kernel slice 1: unused GKI/vendor modules out, usbcore.authorized_default=0)
  rung-b3/       … b3 (USB: AOA/adb-only gadget, sink/UFP-only port, no host feature)
  rung-b4a/      … b4a (radios: Wi-Fi/BT/NFC/eSE/GNSS/modem drivers + their services + features)
  rung-b4b/      … b4b (app strip slice A = crosshatch 4a)
  rung-b4c/      … b4c (app strip slice B = crosshatch 4b, ModuleMetadata kept)
```

A rung directory has the same meaning as on crosshatch: it holds only the files that still
override release intent (`common.mk`, `BoardConfigVault.mk`, `Android.bp`, `config.xml`,
`debug_adbkey.pub`), plus optional diffs against four upstream trees
(`device-google-bluejay.diff`, `device-google-gs101.diff`, `vendor-google-bluejay.diff`,
`device-google-bluejay-kernels.diff`) and, from b2, `expect-build.txt` (check-build.sh). `sync-rung.sh`:

1. rsyncs `device/phonevault/bluejay` and `vendor/phonevault` (no `keys/`, no APK; `keys/` in the
   tree is neither overwritten nor deleted, see "AVB dev key" below);
2. copies the rung overrides over their targets;
3. restores `device/google/bluejay`, `device/google/gs101`, `vendor/google/bluejay` and
   `device/google/bluejay-kernels` to upstream (tracked files only: the Kleaf dist and the LFS
   blobs stay), applies the rung's diff for each if any, and appends
   `include vendor/phonevault/config/BoardConfigVault.mk` to `bluejay/BoardConfig.mk`;
4. applies `patches/frameworks-base-a17/*.patch` (Android 17 rebases; the Android 15 series in
   `patches/frameworks-base/` does not apply to this tree);
5. copies the Kleaf dist (`out/bluejay/dist`: `boot.img`, `dtbo.img`, `dtb.img`, `*.ko`, …)
   into `device/google/bluejay-kernels/6.1`, but never the four tracked list files
   (`modules.load`, `vendor_dlkm.modules.load`, `vendor_dlkm.modules.blocklist`,
   `init.insmod.bluejay.cfg`): rungs change them only through `device-google-bluejay-kernels.diff`
   (b4a+); it reports when the dist disagrees with them;
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
| b2 | b1 + **kernel hardening slice 1** (crosshatch 2d-a/2d-d intent within GKI): 56 GKI/vendor modules nothing in userspace uses are left out of vendor_dlkm and the load lists (Linux BT host stack, mac80211, Linux NFC, 802.15.4/6LoWPAN, CAN, PPP/PPTP/L2TP, TIPC, VLAN, WWAN, USB-host class drivers: USB ethernet, USB serial, CDC-ACM); `usbcore.authorized_default=0` on the vendor_boot cmdline | **built 2026-10-13, not flashed** (40 min). `/build/out-b2/`: `super.img` `415d82c0…`, `boot.img` `b87e18fa…`, `vendor_boot.img` `a0972aef…`, `vbmeta.img` `ed4b05b4…`, image zip `4d810e82…`, `flash-b2-mac.sh` `d26bab20…`; check-build: 56 modules absent, modules.dep consistent, cmdline present, 18 expectations OK; AVB 4× dev key, flags 0 | [b2](#b2-kernel-slice-1) |
| b3 | b2 + **USB lock-down** (crosshatch 2d-d + rung 3 intent, adapted to the prebuilt gs101 USB HALs): gadget function instances only `accessory.gs2` + userspace-AOA `ffs.aoa`/`ffs.ctrl` (+ `ffs.adb` only while `ro.debuggable=1`); configfs `functions/` and the gadget root stay root-owned; Type-C port pinned **sink/UFP** at boot and boot_completed, role/mode nodes and the DWC3 OTG id root-only; no charger-mode MIDI gadget, no usbuwb mode; `android.hardware.usb.host` not declared; `ro.vendor.phonevault.offline=true` | **built 2026-10-13, not flashed** (40 min). `/build/out-b3/`: `super.img` `4d85a899…`, `boot.img` `4f19efaf…`, `vendor_boot.img` `19bc22f1…`, `vbmeta.img` `8b37abfd…`, image zip `ad747f3b…`; check-build: 33 expectations OK (instances, sink pin, ueventd modes, no usb.host, Titan/Trusty rc present) | [b3](#b3-usb) |
| b4a | b3 + **radios off** (crosshatch 2d-a/2d-b/2d-c2/4b-feature intent): Wi-Fi (bcmdhd4389, cfg80211, rfkill), Bluetooth (nitrous), NFC + eSE (st21nfc, st54spi, st33spi), GNSS (bcm47765, bbd_pps_gpio), modem interface (cpif stack) out of the kernel image **together with** their services (BT HAL, NFC HAL, gto eSE HAL, GNSS HAL + gpsd/lhd/scd, cbd/rfsd/dmd/shared_modem_platform), VINTF entries and features (BT, NFC, OMAPI, GPS). Telephony framework, rild and the radio HAL stay (telephony rung, as on crosshatch); the modem firmware stays on its partitions, never booted | **built 2026-10-13, not flashed** (second build, 80 min; the first failed check-build: BT feature from handheld_core_hardware.xml, stale ramdisk `.ko`, both fixed). `/build/out-b4a/`: `super.img` `8abfc4e5…`, `boot.img` `7e402142…`, `vendor_boot.img` `d2ab8cc6…`, `vbmeta.img` `850173ce…`, image zip `476609aa…`; check-build: 70 modules absent (444 `.ko` left), 20 overrides absent, 62 expectations OK; `check_target_files_vintf` rc 0 (also on b4c) | [b4a](#b4a-radios) |
| b4b | b4a + **app strip slice A** (= crosshatch 4a, adapted): 32 user-facing modules (camera/gallery/music/browser/clock/calendar/calculator/recorder/PDF/Canvas, AudioFX, Updater, pickers, dreams, EasterEgg, HTMLViewer, Tag, DeviceAsWebcam, …) | **built 2026-10-13, not flashed** (16 min). `/build/out-b4b/`: `super.img` `f9227b4f…`, `boot.img` `3badaab3…`, `vendor_boot.img` `bc090820…`, `vbmeta.img` `e6249699…`, image zip `8bc8b818…`; check-build: 52 overrides absent, 109 APKs remain | [b4b](#b4b--b4c-app-strip) |
| b4c | b4b + **app strip slice B** (= crosshatch 4b, adapted): 47 on-demand system modules (telephony UI/role apps, backup, print, WebView + feature, MTP, Lineage parts/profiles, CDM/credential/DSU/cert/PAC/VPN/captive-portal/SE/BT-MIDI satellites, providers, Pixel blobs). **ModuleMetadata kept** (4b boot loop), Settings, LatinIME, GoogleParts (eUICC disabler on gs101) kept | **built 2026-10-13, not flashed** (14 min). `/build/out-b4c/`: `super.img` `93782a2e…`, `boot.img` `124d6528…`, `vendor_boot.img` `f78f06d4…`, `vbmeta.img` `4162c12e…`, image zip `6b2d5f3c…`; check-build: 99 overrides absent, 63 APKs remain (`apks-rung-b4c.txt`) | [b4b](#b4b--b4c-app-strip) |

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


## b1 on the phone (2026-10-11)

- Slot a carried an older bootloader/radio (16.4-14097577 / 251030) — Pixel firmware is per-slot and b0 ran on slot a. Wrote Google's CP2A.260705.006 bootloader + radio to slot a from the factory zip (sha256 03992adc…cb33 verified against Google's page) with exactly the two flash-all.sh steps; slot a now 17.0-15199431 / 260414-B-15201439.
- `flash-b1-mac.sh` (bootloader-only) pre-flight passed, flashed. **Hands-off factory boot PASSED**: no input at all → kiosk LOCKED at SET PIN; `VaultProvision: appliance provisioned on admin enable (attempt 1)`; organizationName=Phone Vault; HOME = Phone Vault only (no launcher3/trebuchet); no Trust notification; `ro.boot.veritymode=enforcing`, vbmeta digest present (our dev AVB key), orange (unlocked).
- First run from the Mac passes (PIN on the Titan M2, wallet, spot check, Home). Reboot: boot lock screen shows **no clock / no date / no notifications**, our padlock wallpaper, and the device-owner lock-screen text **"Phone Vault · enter your PIN to unlock"** (Android 17 renders `setDeviceOwnerLockScreenInfo`; Android 15 on crosshatch did not). One PIN → storage unlocked → vault, kiosk LOCKED, no second prompt.

## Hardening rungs b2–b4c (crosshatch 2d-a … 4b parity)

Prepared and built 2026-10-13 from the b1 tree, one cumulative rung each, so a failed flash
bisects to one change set. All are **userdebug dev rungs with adb kept** (release adb-off is
the `vendor/phonevault` user-build work, not these rungs). Same signer app as b0/b1
(`c5def7d6…`, from `/build/pv-b1/PhoneVault.apk`) so only the OS changes between rungs. The
rung numbers differ from the plan in `docs/port-bluejay.md` §5 (b2 VINTF, b3 radios, b4 modem,
b5 camera, b6 USB, b7 apps): this ladder did kernel → USB → radios+modem → apps first; the
appliance VINTF manifest and the camera/TPU/sensor slice are still open (b5+).

| crosshatch | what | bluejay | how on gs101 / Lineage 24.0 |
|---|---|---|---|
| 2d-a | connectivity kernel drivers | b2 (unused stacks) + b4a (drivers with users) | GKI: leave modules out of vendor_dlkm (no Kconfig) |
| 2d-b | modem kernel | b4a | s5300 `cpif` stack out; `google_modemctl` kept (AoC audio + BCL depend on it) |
| 2d-c / c2 / c3 | camera/media/DSP + crash-loopers | **not yet** | AoC must stay (audio, sensors); TPU driver binds the thermal HAL's `tpu_cooling`; LWIS/codecs need their HAL blobs removed with them (later rung) |
| 2d-d | USB gadget functions in Kconfig | b3 | GKI built-ins: enforced by not creating function instances |
| 3 | gadget HAL allowlist + port HAL host refusal | b3 | gs101 USB HALs are **prebuilt blobs**: enforced in `init.gs101.usb.rc` + `ueventd.rc` (instances, sink-only port, root-only role nodes) + `usbcore.authorized_default=0` (b2) |
| 4a | app strip slice A | b4b | `Android.bp` overrides |
| 4b | app strip slice B + BT/NFC features | b4a (features) + b4c (apps) | ModuleMetadata kept |

### What the GKI kernel allows (b2, b4a)

Lineage 24.0 builds no kernel from source for bluejay: the Kleaf workspace downloads the
Google-built GKI `android14-6.1-2025-12_r30` image and compiles only the Pixel vendor modules
(`build_bluejay.sh`). So:

- **Achievable without touching any kernel source: module removal.** Every unprotected GKI
  module (Bluetooth, cfg80211/mac80211, NFC, CAN, PPP, L2TP, TIPC, 802.15.4, USB-net/serial/ACM
  …) and every vendor module is a `.ko` on vendor_dlkm (the 6a has no system_dlkm) or in the
  vendor_boot ramdisk. `BoardConfigVault.mk` filters `PHONEVAULT_KMODS_REMOVED` out of
  `BOARD_VENDOR_KERNEL_MODULES{,_LOAD}` and `BOARD_VENDOR_RAMDISK_KERNEL_MODULES{,_LOAD}` (the
  gs101 board file installs `*.ko` wholesale); a missing name stops the build;
  `check-build.sh` proves no removed `.ko` is packaged and every `modules.dep` still resolves.
  The tracked load lists change only through `device-google-bluejay-kernels.diff` (b4a drops
  `bcmdhd4389` from `init.insmod.bluejay.cfg` and the blocklist).
- **Achievable via the kernel command line:** GKI built-in parameters such as
  `usbcore.authorized_default=0` (b2), in vendor_boot, covered by vbmeta.
- **Achievable only with a Kleaf rebuild (not done):** a defconfig fragment for
  `private/devices/google/bluejay` changes *vendor* modules only, which removal already covers.
- **Not achievable while staying GKI:** anything built into the GKI image: all USB gadget
  functions (mass storage, FunctionFS, MIDI, HID, UVC, UAC2, NCM/ECM/EEM, ACM, accessory),
  usb-storage/uas, uvcvideo, snd-usb-audio, xhci, tcpm/typec, the generic net stack. Turning
  those off means building a non-GKI kernel (losing Google's signed GKI updates); the rungs
  enforce the intent in userspace instead (b3) and refuse device authorisation (b2).

### b2: kernel slice 1

**Changes** (`rung-b2/BoardConfigVault.mk` only; the rest = b1): 56 modules out (Linux BT host
stack `bluetooth hci_uart btbcm btqca btsdio rfcomm hidp`; `mac80211 libarc4`; `nfc`;
802.15.4/6LoWPAN; CAN; PPP/PPTP/L2TP + `slhc`; TIPC + its `diag`; `8021q`; `wwan`; USB-host
class `usbnet mii asix ax88179_178a cdc_ether cdc_eem cdc_ncm aqc111 r8152 r8153_ecm rtl8150
cdc-acm usbserial ftdi_sio`). Nothing in userspace uses any of them (Android's Bluetooth reaches
the controller through the vendor HAL over a tty; bcmdhd is FullMAC cfg80211; the ST NFC HAL
uses its char device), so no service loses a device in this rung. `usbcore.authorized_default=0`:
should the phone ever be a USB host, a plugged device is never configured, so no built-in class
driver binds. Gadget mode is unaffected.

**Pass criteria** (`./check-rung.sh b2`, then the app suites):
`cat /sys/module/usbcore/parameters/authorized_default` = 0; none of the 56 in `/proc/modules`
or `/vendor_dlkm/lib/modules`; `bcmdhd4389`, `cpif`, `aoc_core` still loaded (radios go in b4a);
hands-off factory boot to SET PIN, owner + kiosk LOCKED, verity enforcing; no service in
`[restarting]`; companion pairs and signs over USB (`tools/dev-device/firstrun.sh`,
`usbsigntest.sh`, `tokensigntest.sh`, `msgsigntest.sh`, `credentialtest.sh`).

**Risk:** low: only modules with no consumer go. A wrong closure would show as a build failure
(make `$(error)` / check-build.sh), not on the phone. **Rollback:** reflash b1.

### b3: USB

**Changes:** `vendor-google-bluejay.diff` edits two Google blobs' config, `init.gs101.usb.rc`
and `ueventd.rc`; `device-google-gs101.diff` drops `android.hardware.usb.host.xml`; `common.mk`
sets `ro.vendor.phonevault.offline=true`.

- Gadget function instances: only `accessory.gs2` (kernel AOA), `ffs.aoa` + `ffs.ctrl`
  (Android 17's userspace AOA: `usb_accessory_utils` sets `ro.usb.userspace.aoa.enabled`, the
  gadget HAL then serves AOA through `/dev/usb-ffs/{aoa,ctrl}`: both AOA paths are kept because
  the Mac companion's accessory transport is the one thing USB must do), and `ffs.adb` only
  `on early-boot && property:ro.debuggable=1`. Gone: `mtp.gs0 ptp.gs1 ffs.mtp ffs.ptp
  audio_source.gs3 rndis.gs4 midi.gs5 acm.gs6 dm.gs7 uts.gs8 ncm.gs9 etr_miu.gs11 acm.uwb0 uvc.0`
  and their mounts/props. The gadget HAL can only symlink existing instances into the config,
  so any other composition fails and the framework falls back to the default (adb). Stock chowns
  `/config/usb_gadget/` and `functions/` to system; b3 leaves both root-owned, so the HAL
  (uid system) cannot create an instance or a second gadget.
- Type-C: `write /sys/class/typec/port0/port_type sink` on boot and again on
  `sys.boot_completed=1` (tcpm then presents Rd only: charges, is a USB device to the Mac, never
  sources VBUS or hosts, refuses DR/PR swaps: the crosshatch rung-3 mechanism). `port_type`,
  `power_role`, `data_role` and the DWC3 `dwc3_exynos_otg_id` node (writing 0 forces host mode)
  become `0644 root root` in `ueventd.rc` (stock: `0664 root system`) and are chowned again in
  the rc, so the USB HAL can no longer switch the port back. DWC3 stays dual-role in the kernel
  (crosshatch 2d-d lesson: a gadget-only DWC3 never enumerated).
- Off-mode charging presents no gadget (stock: a MIDI function); the SDP enumeration-timeout
  write stays. The `usbuwb` boot-mode gadget trigger is gone (the 6a has no UWB).

**Why not the crosshatch HAL patches:** on Lineage 24.0 the gs101 USB HALs
(`android.hardware.usb-service.gs101`, `android.hardware.usb.gadget-service.gs101`) are prebuilt
binaries from the CP2A factory image, not source, so release device patches 0002/0003 cannot
be applied. The policy is enforced one layer below them instead (the configfs instances they
can link, the sysfs nodes they can write). `ro.vendor.phonevault.offline` is set for parity but
nothing reads it here. Follow-up: a source-built gs101 USB HAL (AOSP `device/google/gs101/usb`,
the `hardware/google/pixel/usb` library is already in the tree) carrying the allowlist itself,
plus a sepolicy rule that only init and the HAL may write `configfs`.

**Pass criteria** (`./check-rung.sh b3`; the USB probe re-enumerates USB three times, use
`--no-usb` to skip it):
- `pm list features`: no `android.hardware.usb.host`, `android.hardware.usb.accessory` present;
- `svc usb setFunctions mtp|rndis|midi` each leave `sys.usb.state` without that function (the
  gadget HAL fails to link it; the framework restores adb within a few seconds);
- `/sys/class/typec/port0/port_type` reads `dual source [sink]` and is root-only (if the shell
  can read it; else `dumpsys usb` shows the port as UFP/sink);
- if readable, `/config/usb_gadget/g1/functions` holds only `accessory.gs2 ffs.aoa ffs.ctrl ffs.adb`;
- on the Mac, `ioreg` shows only vendor-specific interfaces (class 255) for the phone: adb
  (ff/42/01) and, while the companion holds it, AOA (ff/ff/00); `system_profiler SPUSBDataType`
  lists "Pixel 6a Vault" only (no MTP/PTP volume, no network/serial/MIDI/audio device);
- **companion pairs over USB** and signs (`usbsigntest.sh`, `tokensigntest.sh`,
  `msgsigntest.sh`), charging from the Mac works;
- manual: a USB-C OTG adapter + USB stick on the phone stays unpowered (no VBUS from the
  phone), nothing appears in `ls /sys/bus/usb/devices`.

**Risks:** (1) the companion's AOA handshake needs a function the rc no longer creates →
symptom: adb works, companion never connects; diagnose with `adb logcat -s UsbDeviceManager
UsbGadget usb_accessory_utils` and `getprop | grep -i usb`; (2) the port stays sink on a
Mac whose port insists on being a sink too (not a Mac behaviour; Macs source) → no data; (3) the
blob HAL logs EACCES on role writes (expected). Boot itself does not depend on any of this.
**Rollback:** reflash b2 (USB to the Mac in the bootloader is independent of all of it).

### b4a: radios

**Changes** (cumulative on b3):

| radio | kernel (`BoardConfigVault.mk`) | services out (`Android.bp` overrides, rc via vendor diff) | VINTF / features |
|---|---|---|---|
| Wi-Fi | `bcmdhd4389 cfg80211 rfkill` (+ `bcmdhd4389` out of `init.insmod.bluejay.cfg` and the blocklist) | none: Wi-Fi HAL, wpa_supplicant, hostapd stay and find no `wlan0` (as crosshatch 2d-a) | features kept (as crosshatch) |
| Bluetooth | `nitrous` | `android.hardware.bluetooth-service.bcmbtlinux` + its rc | gs101 manifest: bluetooth, finder, lmp_event, ranging, `vendor.google.bluetooth_ext` out; `android.hardware.bluetooth{,_le}` features out → no BluetoothManagerService |
| NFC / eSE | `st21nfc st54spi st33spi` | `android.hardware.nfc-service.st` (rc + fragment ship with it), `android.hardware.secure_element@1.2-service-gto` | bluejay manifest: `ISecureElement/eSE1` out; NFC (`nfc`, hce, hcef, uicc, ese, mifare) and OMAPI features out → NfcService never created |
| GNSS | `bcm47765 bbd_pps_gpio` | `gpsd lhd scd android.hardware.gnss@2.1-service-brcm` + `init.gps.rc` | gnss fragment out; `android.hardware.location.gps` out |
| modem | `cpif shm_ipc cpif_page exynos_dit boot_device_spi` | `cbd` (boots the CP), `rfsd`, `dmd`, `shared_modem_platform` + their rc | `dmd.xml`, `shared_modem_platform.xml` fragments out |

Features: the feature XMLs are not installed, **and** `common.mk` installs
`/product/etc/sysconfig/phonevault-no-radios.xml` (`device/phonevault/bluejay/sysconfig/`), which
withdraws the Bluetooth, NFC, OMAPI and GPS features with `<unavailable-feature>`: the first b4a
build showed that frameworks/native `handheld_core_hardware.xml` itself declares
`android.hardware.bluetooth` (check-build.sh caught it). The same build also showed that the
vendor_boot dlkm-fragment staging dirs are never pruned, so modules dropped from the ramdisk list
(`cpif`, `st54spi`, …) were still packaged in vendor_boot, unlisted; `build-rung.sh` now deletes
those staging dirs before every build.

Kept (telephony rung, as crosshatch kept them): `rild_exynos` + the radio HAL manifest,
`radioext`, `bipchmgr`, the UICC SE HAL (SIM1/SIM2), TeleService/Telecom and the carrier blobs,
`google_modemctl` and `cp_thermal_zone`. **Baseband firmware remains** on `modem_a`/`modem_b`
(firmware is never written); with no `cpif`/`cbd` it is never loaded into the CP. Never touched:
citadeld, Weaver, KeyMint (citadel + Trusty), AuthSecret, OemLock, Gatekeeper (check-build.sh
asserts their rc files).

**Pass criteria** (`./check-rung.sh b4a`): no BT/NFC/OMAPI/GPS features; no `wlan*`/`rmnet*`
netdevs, no `/sys/class/bluetooth`, no `/dev/umts_*`; `init.svc.{cpboot-daemon,RFS-daemon,
DM-daemon,gpsd,lhd,scd,gnss_service,bcmbtlinux}` undefined; no `bluetooth_manager`/`nfc` system
service; Titan/Trusty services running; plus all of b2/b3, the app suites, and an idle hour on
battery (expect less drain than b3). Expected WARN: `ril-daemon` may show `[restarting]` (rild
with no modem behind it; it goes in the telephony rung), Wi-Fi HAL errors in logcat.

**Risks:** (1) a HAL still declared but never registering would make a client block at boot:
mitigated by removing each service's VINTF entry in the same rung (check-build.sh greps the
assembled manifest); (2) the thermal HAL aborts when a configured sensor/cooling device is
missing: `thermal_info_config.json` has no Wi-Fi/modem/GNSS sensor (`gnss_tcxo_therm` is a PMIC
NTC), checked; the EdgeTPU (`tpu_cooling`) is deliberately kept; (3) `rild` crash-looping on the
missing modem (noise and battery, not boot). **Rollback:** reflash b3.

### b4b / b4c: app strip

`Android.bp` overrides (main.mk drops an overridden module before expanding `required`;
`out/soong/Android-vault_bluejay.mk` shows no installed module requiring any of these, and
check-build.sh proves each absent from the target files). `build-rung.sh` scrubs stale app dirs
first (crosshatch 4a JNI-symlink leftovers).

**b4b (slice A, 32):** `Aperture ApertureLensLauncher ApertureOverlayBluejay` (camera app,
its lens launcher and bluejay RRO), `AudioFX`, `Camelot` (PDF), `Canvas`
(org.lineageos.canvas), `DeskClock`, `Etar`, `ExactCalculator`, `Glimpse`, `Jelly`,
`Recorder`, `Twelve`, `Updater` (Lineage OTA client; the appliance updates only by image),
`AvatarPicker`, `Backgrounds`, `BasicDreams`, `EasterEgg`, `HTMLViewer`,
`LiveWallpapersPicker`, `PhotoTable`, `SoundPicker`, `ThemePicker`, `ThemesStub`,
`AccessibilityMenu`, `CameraExtensionsProxy`, `DeviceAsWebcam` (UVC: no instance since b3),
`DeviceDiagnostics`, `DownloadProviderUi`, `EmergencyInfo`, `SettingsIntelligence`, `Tag`.
Reasons as crosshatch 4a ([../dev-ladder/README.md](../dev-ladder/README.md#removed-in-4a-40-modules)).

**b4c (slice B, 47):** telephony UI/role apps `CallLogBackup CarrierDefaultApp
CellBroadcastLegacyApp Contacts Dialer SimAppDialog Stk messaging`; backup `BackupRestoreConfirmation
LocalContactsBackup LocalTransport Seedvault SharedStorageBackup WallpaperBackup`; print
`BuiltInPrintService PrintRecommendationService PrintSpooler`; `webview` +
`android.software.webview.prebuilt.xml`; `MtpService StorageManager LineageParts Profiles
QuickAccessWallet BluetoothMidiService CaptivePortalLogin CertInstaller CompanionDeviceManager
CredentialManager DynamicSystemInstallationService PacProcessor ProxyHandler SecureElement
StatementService VpnDialogs`; providers `BookmarkProvider CalendarProvider E2eeContactKeysProvider
PartnerBookmarksProvider`; Pixel blobs `NowPlayingPrebuilt DeviceIntelligenceNetworkPrebuiltAstrea
DevicePersonalizationAiAiPrebuiltPixel2021 HardwareInfo HotwordEnrollmentOKGoogleFUSIONPro
HotwordEnrollmentXGoogleFUSIONPro PixelCameraServices PersistentBackgroundCameraServices`.
Reasons as crosshatch 4b ([../dev-ladder/README.md](../dev-ladder/README.md#removed-in-4b-57-modules-on-top-of-4a)).

**Kept, unlike or beyond crosshatch:** `ModuleMetadata` (4b's system_server boot loop),
`GoogleParts` (on gs101 it is only the boot-time eUICC disabler, not Active Edge), `Settings`,
`LatinIME` (step-up PIN prompt IME), `PackageInstaller`, `PermissionController`, `ExtShared`,
`FusedLocation`, `Shell`, `ManagedProvisioning`, the telephony stack, `NetworkStack`, media
providers, `ANGLE`, `HbmSVManager` (display), `ConnectivityThermalPowerManager`, `Iwlan`,
`EyeDropper`, `PrivateSpace`, `ContactsPicker`, all APEXes.

**Pass criteria** (`./check-rung.sh b4b` / `b4c`): none of the packages installed;
ModuleMetadata, Settings, LatinIME, SystemUI, PackageInstaller, Shell, Phone Vault present; HOME =
Phone Vault; hands-off factory boot to SET PIN; crash buffer empty; the full app suite incl.
`credentialtest.sh` (reboot) and the manual soft-keyboard check in the step-up PIN prompt
(crosshatch 4a check 4).

**Risks:** b4c is the one most likely to boot-loop (crosshatch 4b did, on ModuleMetadata):
Android 17 might have grown a boot-time dependency on `CompanionDeviceManager`,
`CredentialManager` or WebView. Symptom: stuck boot animation / system_server restarts; capture
`adb logcat -b crash -b system` during the loop (adb is up early on userdebug), then
**rollback:** reflash b4b. If `handheld_core_hardware.xml` still declares
`android.software.webview`, WebViewUpdateService starts with no provider and logs it (not
fatal).

### Flashing a rung from the Mac (human-approved; the phone in the bootloader)

```sh
# 1. fetch the out dir (images/, super.img, SHA256SUMS, flash script; ~4.5 GB without the zips)
mkdir -p ~/pv-bluejay && cd ~/pv-bluejay
rsync -av --exclude 'vault_bluejay-*.zip' root@192.168.20.98:/build/out-b2/ out-b2/
cd out-b2
# 2. read-only pre-flight + hash check (product, bootloader 17.0-15199431, baseband …-B-…, unlocked, not fastbootd)
./flash-b2-mac.sh --check
# 3. flash slot a (boot vendor_boot dtbo pvmfw vbmeta vbmeta_system vbmeta_vendor + super), erase
#    metadata, -w, set slot a active, reboot. Type FLASH. Bootloader/radio/avb_custom_key untouched.
./flash-b2-mac.sh
# 4. after the hands-off first boot (SET PIN without input), from the repo:
vault-os/dev-ladder-bluejay/check-rung.sh b2
PV_THROWAWAY_DEVICE=1 tools/dev-device/firstrun.sh   # then usbsign/tokensign/msgsign/credential
```

Same for every rung (`out-b3`/`flash-b3-mac.sh`, …). Every flash wipes userdata+metadata
(genuine factory boot each time). **Rollback for any rung:** there is no fallback slot (slot b
has had no system partitions since b0's interrupted `fastboot update`), but the bootloader is
never written and always reachable (power off, hold Volume-Down + Power): run the previous good
rung's `flash-<rung>-mac.sh` (or b1's) from its out dir. If slot a fails repeatedly the
bootloader may switch to slot b and stop in fastboot mode: that is fine, the flash script
re-checks the (identical, stock 17.0-15199431) bootloader of the current slot and sets slot a
active again. Last resort: Google's CP2A factory image (`docs/port-bluejay.md` §8).
