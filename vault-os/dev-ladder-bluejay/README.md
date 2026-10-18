# Bluejay ladder (Pixel 6a, LineageOS 24.0 / Android 17)

The Pixel 6a counterpart of [`dev-ladder/`](../dev-ladder/README.md) (crosshatch). The plan,
the partition layout, the firmware rules and the reasoning are in
[`docs/port-bluejay.md`](../docs/port-bluejay.md); this directory holds what each rung actually
builds. Nothing here is shared with the crosshatch tree.

Paths are placeholders: `$LINEAGE_TREE` is a LineageOS 24.0 tree with the bluejay repos
(`vault-os/manifest/bluejay/local_manifests-bluejay.xml`), `$KERNEL_TREE` the Kleaf workspace
(`LineageOS/android_kernel_google_gs-6.1_manifest`, branch `lineage-24.0`), `$OUT_DIR` the rung
output directory, `<build-host>` the Linux machine that builds. The scripts take these as
arguments or environment variables; read each script's header for the exact names.

```
dev-ladder-bluejay/
  sync-rung.sh   RUNG [TREE] [APK] [KERNEL_DIST]   product + rung overrides + A17 framework patches + kernel dist → tree
  build-rung.sh  RUNG [TREE] [OUT]                 target-files → firmware-free fastboot zip + loose images + SHA256SUMS
                                                   (b1+: AVB/launcher checks, sparse super.img, flash-RUNG-mac.sh)
  flash-mac.sh                                     bootloader-only slot-a flash from macOS (installed as flash-RUNG-mac.sh)
  check-build.sh RUNG TF OUT [TREE]                b2+ artifact gate on the build host (run by build-rung.sh)
  check-rung.sh  RUNG [--no-usb]                   on-phone pass criteria over adb, from the Mac (cumulative)
  rung-b0/       files that still override release intent at b0
  rung-b1/       … at b1 (AVB dev key, no launcher, sysconfig)
  rung-b2/       … b2 (kernel slice 1: unused GKI/vendor modules out, usbcore.authorized_default=0)
  rung-b3/       … b3 (USB: AOA/adb-only gadget, sink/UFP-only port, no host feature)
  rung-b4a/      … b4a (radios: Wi-Fi/BT/NFC/eSE/GNSS/modem drivers + their services + features)
  rung-b4b/      … b4b (app strip slice A = crosshatch 4a)
  rung-b4c/      … b4c (app strip slice B = crosshatch 4b, ModuleMetadata kept)
  rung-b4d-1/    … b4d-1 (b4d's radio-daemon half only: rild + vendor radio daemons, radio HAL entries, OEM-RIL apps, euiccpixel)
  rung-b4d/      … b4d (telephony + Wi-Fi software: rild, radio HALs, phone process, carrier/IMS/eUICC apps, Wi-Fi HAL)
```

A rung directory has the same meaning as on crosshatch: it holds only the files that still
override release intent (`common.mk`, `BoardConfigVault.mk`, `Android.bp`, `config.xml`), plus
optional diffs against four upstream trees (`device-google-bluejay.diff`,
`device-google-gs101.diff`, `vendor-google-bluejay.diff`, `device-google-bluejay-kernels.diff`)
and, from b2, `expect-build.txt` (check-build.sh). `sync-rung.sh`:

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

**Development adb key.** Rungs are `userdebug` with adb pre-authorised for the builder. No adb
key is committed: the sync reads your public adb key from the path in `PV_DEV_ADB_KEY` (for
example `~/.android/adbkey.pub` on the Mac that will talk to the phone) and installs it only in
the build tree.

Kernel: `cd $KERNEL_TREE && ./build_bluejay.sh` as the tree owner. Lineage 24.0's kernel
manifest pins the GKI `android14-6.1-2025-12_r30` as a downloaded prebuilt, so only the Pixel
vendor modules are compiled (minutes, not hours).

Build: as the tree owner, `build-rung.sh RUNG $LINEAGE_TREE $OUT_DIR` → lunch
`vault_bluejay-cp2a-userdebug`, `WITH_ADB_INSECURE=true` (without it Lineage turns userdebug into
`ro.adb.secure=1` + `ro.debuggable=0`), `m target-files-package`, `img_from_target_files`, then
the zip is rebuilt **without** the nine firmware images (`abl bl1 bl2 bl31 gsa ldfw pbl tzsw
modem`) and checked to hold exactly `android-info.txt` + boot dtbo pvmfw vendor_boot vbmeta
vbmeta_system vbmeta_vendor system system_ext product vendor vendor_dlkm (+ `super_empty.img` /
`fastboot-info.txt` if present), with `android-info.txt` =
`vendor/phonevault/config/board-info-bluejay.txt` (`require board=bluejay`,
`version-bootloader=bluejay-17.0-15199431`, `version-baseband=g5123b-145971-260414-B-15201439`;
fastboot compares the baseband string exactly, including the upper-case `B`). A first full build
takes several hours; an incremental rung build tens of minutes.

Flashing: from a Mac, **from the bootloader only**. Userspace fastboot (fastbootd) enumerates on
macOS but every write fails ("Write to device failed"), so `fastboot update` cannot be used; an
interrupted `fastboot update` can leave `super` reset. From b1 the out directory carries
everything for the bootloader-only path: `images/` (slot partitions + `android-info.txt`), a
sparse `super.img` (slot a populated, built by `build/make/tools/releasetools/build_super_image.py`
from the target files) and `flash-<rung>-mac.sh`, which checks SHA256SUMS and the phone (product,
bootloader, upper-case-B baseband, unlocked, not fastbootd), then `fastboot --slot=a flash` boot
vendor_boot dtbo pvmfw vbmeta vbmeta_system vbmeta_vendor, `fastboot flash super super.img`,
`erase metadata`, `-w`, `--set-active=a`, `reboot`. `--check` runs the checks only. Bootloader,
radio and `avb_custom_key` are never written. Pixel firmware is per slot: before flashing slot
a, make sure it carries the same CP2A bootloader and radio as the phone's current slot (write
Google's CP2A.260705.006 bootloader + radio to it with exactly the two `flash-all.sh` steps if
not).

AVB dev key (b1+): RSA-4096, **development only, not the release key**, generated on the build
host and kept outside the repository (private key mode 0400 in a 0700 directory, never
committed, never copied off the host). Public blob (`avbtool extract_public_key`) sha256
`068a9865f04cc9b91f6838b537c14f32e4fa6e32682cbcfbfd6c9782ab71ae8c`, sha1
`af09b166ade90fb31a184e9ab6c59819cd33fc8a` (what `avbtool info_image` prints). The tree reaches
it through the symlink `vendor/phonevault/keys/avb_bluejay_dev.pem`; the rung's
`BoardConfigVault.mk` stops the build if it is missing. A builder without this key generates
their own and gets their own digests. The release key for b8/b9 is a separate key that never
lives on a build host.

## Rung log

| Rung | Change | Result on hardware | Pass criteria |
|---|---|---|---|
| b0 | Lineage 24.0 bluejay (CP2A.260705.006 blobs, GKI 6.1 + Kleaf vendor modules) + `vault_bluejay` product: signer app as an ordinary system app on **/product** (`privileged: false`, `product_specific: true`: gs101 enforces generic_system's artifact path requirement, so nothing product-specific may go to /system; props and `preferred-apps` moved to /product for the same reason), frameworks/base 0003 + 0004 rebased to Android 17 (`patches/frameworks-base-a17/`), Phone Vault overlay ahead of Lineage's (wallpaper, `config_fixedFunctionDeviceOwner`, no doze/AOD, airplane mode default on; becomes the auto-generated product RRO), preferred HOME, `LineageSetupWizard` overridden, userdebug (`ro.debuggable=1`, `ro.adb.secure=0`) with the builder's pre-authorised adb key, `board-info-bluejay.txt` bootloader/baseband pins. `boot.img` is built (kernel `Image.lz4` + generic ramdisk) instead of the kernel-only Kleaf prebuilt, see `BoardConfigVault.mk`. **AVB is the Lineage gs101 default: vbmeta signed with the public AOSP `testkey_rsa4096`, boot/vbmeta_system/vbmeta_vendor chained with the public `testkey_rsa2048`, vbmeta `--flags 3`** (verification off), rollback indexes 1790812800 — unlocked dev phone only; b1 re-keys | boots; device owner `dev.phonevault.signer` with provisioning context `fixed-function-system-image` (the Android 17 port of patch 0003 works). Gap: the app was never started after provisioning (keyguard + a HOME chooser); fixed in b1. First run (PIN on the Titan M2, wallet, spot check, kiosk LOCKED) and attestation (factory-provisioned StrongBox chain, verdict development) pass | `docs/port-bluejay.md` §5 b0 row |
| b1 | b0 + **factory-boot wake-up**: frameworks/base 0003 unstops the configured owner before `setActiveAdmin` and re-sends `DEVICE_ADMIN_ENABLED` once user 0 is unlocked (b0's enable broadcast was never sent: user 0 is locked at `PHASE_ACTIVITY_MANAGER_READY`, the receiver is not direct-boot aware, and the package was scanned stopped), plus `/product/etc/sysconfig/phonevault-initial-package-state.xml` (`stopped=false`); **no launcher** (`Launcher3QuickStep`, `Launcher3Overlay` overridden); **own AVB dev key** on vbmeta + boot + vbmeta_system + vbmeta_vendor, vbmeta **flags 0** (verification on), rollback indexes as before, not relocked; frameworks/base **0005** rebased (no keyguard clock/smartspace/date); **no Lineage Trust** (bluejay overlay drops `TrustInterfaceService` from `config_externalLineageServices`, sysconfig `unavailable-feature org.lineageos.trust`). Same kernel and app as b0 | **passed**: hands-off factory boot to SET PIN (`VaultProvision: appliance provisioned on admin enable`), organization name Phone Vault, HOME = Phone Vault only, no Trust notification, `ro.boot.veritymode=enforcing`, vbmeta digest from our dev key, orange (unlocked). After a reboot the boot lock screen shows no clock, date or notifications, the padlock wallpaper and the device-owner text "Phone Vault · enter your PIN to unlock" (Android 17 renders `setDeviceOwnerLockScreenInfo`; Android 15 on crosshatch did not); one PIN unlocks storage and the vault | [b1 checklist](#b1-checklist) |
| b2 | b1 + **kernel hardening slice 1** (crosshatch 2d-a/2d-d intent within GKI): 56 GKI/vendor modules nothing in userspace uses are left out of vendor_dlkm and the load lists (Linux BT host stack, mac80211, Linux NFC, 802.15.4/6LoWPAN, CAN, PPP/PPTP/L2TP, TIPC, VLAN, WWAN, USB-host class drivers: USB ethernet, USB serial, CDC-ACM); `usbcore.authorized_default=0` on the vendor_boot cmdline | **passed**: `check-rung.sh b2` 0 FAIL (56 modules absent, `usbcore.authorized_default=0`, kiosk + device owner, verity) | [b2](#b2-kernel-slice-1) |
| b3 | b2 + **USB lock-down** (crosshatch 2d-d + rung 3 intent, adapted to the prebuilt gs101 USB HALs): gadget function instances only `accessory.gs2` + userspace-AOA `ffs.aoa`/`ffs.ctrl` (+ `ffs.adb` only while `ro.debuggable=1`); configfs `functions/` and the gadget root stay root-owned; Type-C port pinned **sink/UFP** at boot and boot_completed, role/mode nodes and the DWC3 OTG id root-only; no charger-mode MIDI gadget, no usbuwb mode; `android.hardware.usb.host` not declared; `ro.vendor.phonevault.offline=true` | **passed**: 0 FAIL; MTP/RNDIS/MIDI refused, port UFP, the Mac sees one vendor-specific interface, the companion's AOA handshake reaches the phone | [b3](#b3-usb) |
| b4a | b3 + **radios off** (crosshatch 2d-a/2d-b/2d-c2/4b-feature intent): Wi-Fi (bcmdhd4389, cfg80211, rfkill), Bluetooth (nitrous), NFC + eSE (st21nfc, st54spi, st33spi), GNSS (bcm47765, bbd_pps_gpio), modem interface (cpif stack) out of the kernel image **together with** their services (BT HAL, NFC HAL, gto eSE HAL, GNSS HAL + gpsd/lhd/scd, cbd/rfsd/dmd/shared_modem_platform), VINTF entries and features (BT, NFC, OMAPI, GPS). Telephony framework, rild and the radio HAL stay (telephony rung, as on crosshatch); the modem firmware stays on its partitions, never booted | **passed**: 0 FAIL; no wlan/rmnet/bluetooth/umts, radio services undefined, Titan M2 gatekeeperd running. Found: `pktrouter` (wfc-pkt-router) crash-loops with the modem gone; removed in b4c | [b4a](#b4a-radios) |
| b4b | b4a + **app strip slice A** (= crosshatch 4a, adapted): 32 user-facing modules (camera/gallery/music/browser/clock/calendar/calculator/recorder/PDF/Canvas, AudioFX, Updater, pickers, dreams, EasterEgg, HTMLViewer, Tag, DeviceAsWebcam, …) | **passed**: 0 FAIL | [b4b / b4c](#b4b--b4c-app-strip) |
| b4c | b4b + **app strip slice B** (= crosshatch 4b, adapted): 47 on-demand system modules (telephony UI/role apps, backup, print, WebView + feature, MTP, Lineage parts/profiles, CDM/credential/DSU/cert/PAC/VPN/captive-portal/SE/BT-MIDI satellites, providers, Pixel blobs) and `pktrouter`. **ModuleMetadata kept** (crosshatch 4b boot loop), Settings, LatinIME, GoogleParts (eUICC disabler on gs101) kept | **passed**: 0 FAIL, 167 packages, only crash `euiccpixel` ×2 at boot. `firstrun.sh`, `usbsigntest.sh`, `msgsigntest.sh`, `credentialtest.sh` pass. The lock screen still says "Emergency calls only" on this dev rung: the release overlay's `config_voice_capable=false` is not in the ladder; check it on the release build | [b4b / b4c](#b4b--b4c-app-strip) |
| b4d-1 | b4c + **b4d's radio-daemon half only** (bisecting b4d): `rild_exynos` (`ril-daemon`), the radio-ext/BIP/UICC-SE/init.radio/modem-logging daemons and their rc, the radio HAL VINTF entries (IRadio/ISap slot1+2, IRadioConfig, SIM1/SIM2, Samsung radioExternal), the RIL-side persistent apps `OemRilService`, `OemRilHookService`, `grilservice`, and `com.google.euiccpixel` (+ its permissions package). **Kept:** TeleService, Telecom, TelephonyProvider, CarrierConfig, the IMS/carrier apps, EuiccGoogle, GoogleParts, the whole Wi-Fi stack, every b4c feature, and b4c's framework overlay (no `config_voice_capable=false`, which b4d also added) | not flashed yet | [b4d-1](#b4d-1-radio-daemons-only) |
| b4d | b4c + **telephony and Wi-Fi software out** (the drivers went in b4a): `rild_exynos`, the radio-ext/BIP/UICC-SE/init.radio/modem-logging daemons and their rc, the radio HAL VINTF entries (IRadio/ISap slot1+2, IRadioConfig, SIM1/SIM2, Samsung radioExternal), TeleService, TelephonyProvider, CarrierConfig, MmsService, ONS, Iwlan, the Samsung/Google RIL, IMS, carrier, OMA-DM and Verizon apps, the eUICC apps + update APEX + GoogleParts, the Pixel Wi-Fi HAL APEX, wpa_supplicant, hostapd, wificond; every `android.hardware.telephony*`/`wifi*`/`sip` feature withdrawn; the release overlay's `config_voice_capable`/`config_sms_capable=false` now in the ladder. **Telecom kept** (system_server on A17) | **does not boot**: Android 17 requests `reboot` a few seconds into system_server start-up, right after UsbDeviceManager init; restored to b4c. Bisected with b4d-1 | [b4d](#b4d-telephony-and-wi-fi-software) |

Not yet done on the 6a: the appliance VINTF manifest, the camera/TPU/sensor slice, the user build (b8) and the relock (b9); see `docs/port-bluejay.md` §5.

## b1 checklist

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
7. First run (PIN, wallet, Titan M2 keystore, kiosk LOCKED), `attesttest.sh` (verdict stays
   development: unlocked, dev key not pinned), crash-loop count 0.

The on-phone tests run from the Mac need Homebrew bash ≥ 4 (macOS bash 3.2 lacks `mapfile`).

## Hardening rungs b2–b4d (crosshatch 2d-a … 4b parity, then b4d ahead of the crosshatch ladder)

One cumulative rung each on top of b1, so a failed flash bisects to one change set. All are
**userdebug dev rungs with adb kept** (release adb-off is the `vendor/phonevault` user-build
work, not these rungs). The same signer APK is baked into every rung so only the OS changes
between rungs. The rung numbers differ from the plan in `docs/port-bluejay.md` §5 (b2 VINTF, b3 radios, b4 modem,
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
| release-only on crosshatch | telephony/radio/IMS stack, Wi-Fi HAL | b4d | `Android.bp` overrides + rc/VINTF/feature removal; Telecom kept (A17 mainline, in system_server) |

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
Reasons as crosshatch 4a ([hardening-ladder.md](../docs/hardening-ladder.md#removed-in-4a-40-modules)).

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
Reasons as crosshatch 4b ([hardening-ladder.md](../docs/hardening-ladder.md#removed-in-4b-57-modules-on-top-of-4a)).

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

### b4d: telephony and Wi-Fi software

> **b4d status (2026-10-17): does not boot on the 6a.** Flashed twice; slot a exhausts its retries.
> Android 17 requests a plain `reboot` a few seconds into system_server start-up, right after
> UsbDeviceManager initialises (where adb drops, so the trigger is not in the captured logs; the
> pstore console needs root, which the ladder never uses). The phone was restored to b4c.
> Next: split b4d into [b4d-1](#b4d-1-radio-daemons-only) (rild, radio daemons and radio HAL
> entries, eSIM app only; keep TeleService, Telecom, TelephonyProvider, CarrierConfig and the Wi-Fi
> HAL) and b4d-2 (Wi-Fi HAL) to find which removal Android 17 needs. Separately, the leftover `/system/bin/wificond` is a
> dangling compat symlink (no service starts it); check-build should treat it as absent.


b4a removed the modem and Wi-Fi drivers but kept rild, the telephony framework and the Wi-Fi HAL
(crosshatch kept them for a telephony rung). On the b4c phone that leftover loops forever:
`ril-daemon` restarts every ~5 s ("RIL RESET by RilApplication Init Fail"), hwservicemanager asks
init for `IOemSlsiRadioExternal/rilExternal` and `IRadio/slot1`, `com.android.phone` ANRs "failed
to complete startup" in a loop next to the OEM-RIL / RIL-hook persistent apps,
`vendor.wifi_hal_legacy` (`vendor.google.wifi_ext-service-vendor`) fails with "Failed to start
legacy HAL: TIMED_OUT" / "Unknown iface name: wlan0", and `com.google.euiccpixel` crashes at boot.
`adb reboot` also drops USB without the phone ever rebooting (no new boot reason). The suspected
cause is shutdown waiting on that wedged stack (`ShutdownThread` shuts the radios down through
the phone process before rebooting). b4d removes the stack so that nothing can loop.

**Changes** (cumulative on b4c; `BoardConfigVault.mk` and the kernel lists are unchanged):

| what | removed | how |
|---|---|---|
| RIL + vendor radio daemons | `rild_exynos` (`ril-daemon`), `vendor.google.radioext@1.0-service` (+ `manifest_radioext.xml`), `bipchmgr` (SIM toolkit BIP), `android.hardware.secure_element@1.2-uicc-service` (SIM1/SIM2), `init.radio` (`init-radio-sh`), `modem_logging_control` | `Android.bp` overrides; `vendor-google-bluejay.diff` drops their rc copies (`rild_exynos.rc`, `vendor.google.radioext@1.0-service.rc`, `bipchmgr.rc`, `android.hardware.secure_element@1.2-uicc-service.rc`, `init.vendor_telephony.rc`, `init.modem_logging_control.rc`) |
| radio HAL VINTF | `android.hardware.radio` (`@1.2::ISap/slot1,2`, `@1.6::IRadio/slot1,2`), `android.hardware.radio.config` (`@1.1::IRadioConfig/default`), `android.hardware.secure_element` `ISecureElement/SIM1,SIM2`, `vendor.samsung_slsi.telephony.hardware.radioExternal` (`@1.1::IOemSlsiRadioExternal/rilExternal`) | `device-google-gs101.diff` (`vintf/manifest.xml`); `vendor.google.radioext` goes with its fragment module |
| AOSP telephony apps | `TeleService` (com.android.phone), `TelephonyProvider`, `CarrierConfig`, `MmsService`, `ONS`, `Iwlan` | overrides |
| Samsung/Google telephony blobs | `OemRilService`, `OemRilHookService`, `grilservice`, `ShannonIms`, `ShannonRcs`, `ShannonQualifiedNetworksService`, `CarrierSettings`, `CarrierSetup`, `CarrierWifi`, `WfcActivation`, `ImsServiceEntitlement`, `TetheringEntitlement`, `AppDirectedSMSService`, `VZWAPNLib`, `MyVerizonServices`, `ConnMO`, `DCMO`, `DiagMon`, `DMService` (+ its four JNI-lib modules), `OemDmTrigger`, `ConnectivityThermalPowerManager` | overrides |
| eUICC | `EuiccGoogle`, `EuiccGoogleOverlay`, `EuiccSupportPixel` (+ its three `DKA_RC7_*` copies), `EuiccSupportPixelPermissions`, `com.google.pixel.euicc.update` (vendor APEX), `GoogleParts` (on gs101 its only job is re-enabling the two eUICC packages at boot) | overrides; the vendor diff drops the `EuiccSupportPixel/` copies |
| Wi-Fi | `com.google.pixel.wifi.ext` (vendor APEX: `vendor.wifi_hal_legacy` = IWifi v4 + IWifiExt, with its rc and VINTF fragment inside), `wpa_supplicant` + `wpa_supplicant.conf`, `hostapd` (their rc and VINTF fragments ship with the modules), `wificond` | overrides |
| features | `android.hardware.telephony` and every sub-feature (gsm, ims, ims.singlereg, carrierlock, euicc, calling, data, messaging, radio.access, subscription, …), `android.software.sip(.voip)`, `com.verizon.hardware.telephony.*`, `android.hardware.wifi` (+ direct, aware, passpoint, rtt) | the feature files are no longer installed (gs101 diff: Wi-Fi, euicc, carrierlock; vendor diff: gsm, ims, ims.singlereg, features-verizon), **and** `/product/etc/sysconfig/phonevault-no-telephony-wifi.xml` withdraws them all (it also covers Lineage's `sip.voip`) |
| overlay | `config_voice_capable=false`, `config_sms_capable=false`, `config_enable_emergency_call_while_sim_locked=false` | the release `vendor/phonevault/overlay` already had them; the build host's repo copy predated them, so b4d is the first ladder image that carries them |

**Kept, and why:**

- **Telecom.** On Android 17 Telecom is a mainline module: the `com.android.telephonycore` APEX
  puts `framework-telephony` and `framework-telecom` on the boot classpath and `service-telecom`
  in system_server; `TelecomShim` (com.android.server.telecom) is the package it runs as.
  SystemServer starts `TelecomLoaderService` on any device with a microphone (not only with
  telephony), and removing the APEX would break the boot classpath. `android.software.telecom`
  stays declared (`handheld_core_hardware.xml`), as on a Wi-Fi-only tablet. It does not bring the
  keyguard "Emergency" button back: SystemUI shows that only with `android.hardware.telephony`.
- The `com.android.wifi` APEX: `framework-wifi` is on the boot classpath. Without
  `android.hardware.wifi`, SystemServer starts no WifiService, WifiScanningService, RttService,
  WifiAwareService or WifiP2pService.
- `com.android.cellbroadcast` (APEXes are a later rung) and `BlockedNumberProvider` (Telecom and
  SystemUI query it).
- Inert leftovers: the static RROs aimed at removed packages, the carrier data files, the vendor
  RIL libraries (no client left), and the privapp/sysconfig XMLs of removed packages (ignored for
  absent packages).
- `google_modemctl` and `cp_thermal_zone` (b4a), and everything else from b4c: USB lock-down,
  kernel module removal, app strip, Titan M2/Trusty, the signer app, adb.

**Why system_server should tolerate this** (Android 17 `frameworks/base`):

- `MmsServiceBroker` is started only with `FEATURE_TELEPHONY`.
- `TelephonyRegistry` lives in system_server. Without `FEATURE_TELEPHONY_CALLING` /
  `_MESSAGING` it skips the emergency-number query, which is the one that needs the phone process.
- `PermissionPolicyService` and `AppRestrictionController` register their carrier-privilege
  callbacks with TelephonyRegistry, not with the phone process.
- `SystemEmergencyHelper` catches the `IllegalStateException` from `isEmergencyNumber`.
- Nothing in `services/` calls `waitForService` on `phone`, `isub` or a Wi-Fi service.

Android TV images also ship without TeleService, and Lineage's own Wi-Fi-only tablet config uses
the same `config_voice_capable`/`config_sms_capable=false` overlay.

**Pass criteria** (`./check-rung.sh b4d`, cumulative):

- No `android.hardware.telephony*`, `android.hardware.wifi*`, `android.software.sip*` or Verizon
  feature.
- `init.svc.` undefined for `ril-daemon vendor.google.radioext@1.0 BIP-Channel-Manager
  secure_element_uicc_hal_service init-radio-sh modem_logging_start vendor.wifi_hal_legacy
  wpa_supplicant hostapd wificond`.
- No `phone isub carrier_config imms wifi wifiscanner wifip2p wifiaware rttmanager` system service.
- The 32 telephony/eUICC packages absent; `com.android.server.telecom` present.
- **No init service in `[restarting]`** (a FAIL from b4d on, a WARN before).
- No log line naming IRadio, radioExternal or IWifi; no phone, eUICC or OEM-RIL process in the
  crash buffer or in ActivityManager.
- Everything from b1–b4c (owner, kiosk LOCKED, Titan/Trusty running, USB lock-down) and the app
  suites (`firstrun.sh`, `usbsigntest.sh`, `tokensigntest.sh`, `msgsigntest.sh`,
  `credentialtest.sh`).

Then the **reboot test**, by hand (check-rung.sh never reboots):

1. Note `adb shell cat /proc/sys/kernel/random/boot_id`.
2. Run `adb reboot` and wait.
3. Pass: adb comes back by itself within about 2 minutes with a **different** `boot_id`, the
   phone shows the boot lock screen, and `adb shell getprop sys.boot.reason.last` reads `reboot`
   (or `reboot,…`).
4. Repeat once from the power menu (Restart).

**Risks:**

1. **Boot loop** (moderate; lower than b4c): something on Android 17 still depends on the phone
   process or on IWifi. Symptom: the boot animation runs for minutes, or system_server / SystemUI
   keep restarting. adb is up early on userdebug, so capture:
   - `adb logcat -b all -d > b4d-boot.txt`
   - `adb logcat -b crash -d`
   - `adb shell dumpsys activity processes`

   Look for `FATAL EXCEPTION`, and for `UnsupportedOperationException` / `IllegalStateException`
   from `TelephonyManager`, `SubscriptionManager` or `WifiManager`. **Rollback:** reflash b4c
   (below).
2. **SystemUI or Settings crash** on a missing Wi-Fi/telephony manager (QS internet tile, status
   bar mobile icons): capture the same logs. The kiosk (Phone Vault as HOME) needs neither.
3. **`adb reboot` still hangs**: then telephony was not the cause. Force a restart (hold Power for
   about 10 s), then capture `adb logcat -b all -d` around "ShutdownThread" / "init: Reboot",
   `adb shell getprop sys.boot.reason.last`, and an `adb bugreport` (it includes the previous
   boot's pstore console log).
4. **`wificond` noise**: zygote's rc says `onrestart restart wificond`. With the service gone, init
   logs one error per zygote restart (noise only).

**Rollback:** reflash b4c from the Mac: `cd ~/pv-bluejay/out-b4c2 && ./flash-b4c-mac.sh --check`,
then `echo FLASH | ./flash-b4c-mac.sh`. That is the b4c image the phone runs now.

### b4d-1: radio daemons only

The first half of the b4d bisect. b4d removed telephony and Wi-Fi together and does not boot
(status note above). b4c boots but loops: `ril-daemon` restarts every ~5 s, hwservicemanager keeps
asking init for `IOemSlsiRadioExternal/rilExternal` and `IRadio/slot1`, the OEM-RIL / RIL-hook
persistent apps restart, `com.android.phone` ANRs "failed to complete startup", the Wi-Fi ext HAL
times out on the missing `wlan0`, `com.google.euiccpixel` crashes at boot, and `adb reboot` drops
USB without the phone ever rebooting. b4d-1 is the smallest change that removes the looping radio
daemon and every declaration that makes something ask for it, and nothing else. If `adb reboot`
works on b4d-1, the wedged RIL stack was the shutdown blocker. If b4d-1 boots where b4d did not,
the boot failure is in what b4d-1 keeps (TeleService and the other telephony apps, or the Wi-Fi
HAL, which b4d-2 tests).

**Changes vs b4c** (`rung-b4d-1/` is a copy of `rung-b4c/` plus only these parts of b4d;
`BoardConfigVault.mk`, `common.mk` and the kernel lists are unchanged apart from comments;
`config.xml` keeps the framework overlay at b4c's, see below):

| what | removed | how |
|---|---|---|
| RIL + vendor radio daemons | `rild_exynos` (`ril-daemon`), `vendor.google.radioext@1.0-service` (+ `manifest_radioext.xml`), `bipchmgr` (SIM toolkit BIP), `android.hardware.secure_element@1.2-uicc-service` (SIM1/SIM2; its client `com.android.se` went in b4c), `init.radio` (`init-radio-sh`), `modem_logging_control` | `Android.bp` overrides; `vendor-google-bluejay.diff` drops their rc copies (`rild_exynos.rc`, `vendor.google.radioext@1.0-service.rc`, `bipchmgr.rc`, `android.hardware.secure_element@1.2-uicc-service.rc`, `init.vendor_telephony.rc`, `init.modem_logging_control.rc`) |
| radio HAL VINTF | `android.hardware.radio` (`@1.2::ISap/slot1,2`, `@1.6::IRadio/slot1,2`), `android.hardware.radio.config` (`@1.1::IRadioConfig/default`), `android.hardware.secure_element` `ISecureElement/SIM1,SIM2`, `vendor.samsung_slsi.telephony.hardware.radioExternal` (`@1.1::IOemSlsiRadioExternal/rilExternal`) | `device-google-gs101.diff` (`vintf/manifest.xml`, same hunk as b4d); `vendor.google.radioext` goes with its fragment module |
| RIL-side persistent apps | `OemRilService` (com.samsung.slsi.telephony.oemril, the radioExternal client), `OemRilHookService` (…oem.oemrilhookservice), `grilservice` (the radioext client) | overrides. These are the "oemril/mrilhook restarting" processes; with their HALs gone they could only loop |
| eSIM | `EuiccSupportPixel` (com.google.euiccpixel, the boot crash) + `EuiccSupportPixelPermissions` | overrides; the vendor diff drops the three `DKA_RC7_*` copies in its priv-app dir |

**Kept, unlike b4d:** TeleService (`com.android.phone`), Telecom (telephonycore APEX + TelecomShim),
TelephonyProvider, CarrierConfig, MmsService, ONS, Iwlan, the Shannon IMS/RCS/QNS apps, the
carrier, OMA-DM and Verizon apps, `EuiccGoogle` + its overlay, the eUICC update APEX,
`GoogleParts`, `ConnectivityThermalPowerManager`, the Wi-Fi HAL APEX, `wpa_supplicant`, `hostapd`,
`wificond`, and **every feature b4c declares** (`android.hardware.telephony*`, `wifi*`, `sip`; no
`phonevault-no-telephony-wifi.xml`, no overlay change). TeleService and Telecom stay because
crosshatch 4b needed them ([hardening-ladder.md](../docs/hardening-ladder.md)). Features are left
alone so that the only variable is the radio daemon. With the radio HAL no longer declared, the
phone process's RIL gets "not declared" back at once instead of waiting on a declared HAL that
never registers, which should end its "failed to complete startup" loop. If it does not, the
telephony features are the next lever (on a later rung, not in b4d-1). The `/system/bin/wificond`
compat-symlink note from b4d does not apply: `wificond` is kept, so the link has its target.

**A third b4d variable, held back in b4d-1: the overlay.** b4c (`out-b4c2`) was built before the
release overlay's `config_voice_capable`, `config_sms_capable` and
`config_enable_emergency_call_while_sim_locked=false` reached the build host's repo copy; b4d was
the first ladder image that carried them (a dump of the two product framework-res RROs differs in
exactly these three booleans). `config_voice_capable=false` changes how Telecom, TeleService and
PhoneWindowManager behave at boot, so it is as much a b4d suspect as the removals. b4d-1 therefore
carries `rung-b4d-1/config.xml`: the release `config.xml` without those three entries, so the
framework overlay is the b4c one. They get their own step after b4d-1/b4d-2.

**Pass criteria** (`./check-rung.sh b4d-1`, cumulative over b1–b4c):

- `init.svc.` undefined for `ril-daemon vendor.google.radioext@1.0 BIP-Channel-Manager
  secure_element_uicc_hal_service init-radio-sh modem_logging_start`.
- **No init service in `[restarting]`** (a FAIL from b4d-1 on). If the only one left is
  `vendor.wifi_hal_legacy`, that points at b4d-2, not at a b4d-1 regression.
- No hwservicemanager "lazy HAL" / `ctl.interface_start` request for IRadio, IRadioConfig, ISap,
  radioExternal, radioext or ISecureElement/SIM in `logcat -b all`.
- `com.google.euiccpixel(.permissions)`, `…oemril`, `…oemrilhookservice` and `…grilservice` not
  installed, and none of them in the crash buffer.
- Kept: `com.android.phone`, `com.android.server.telecom`, `com.android.providers.telephony`,
  `com.android.carrierconfig` installed; `android.hardware.telephony` and `android.hardware.wifi`
  still declared; the `phone`/`isub`/`telecom`/`wifi` system services are reported (WARN if absent).
- No `ANR in com.android.phone` / "failed to complete startup" and no phone crash in the log.
- Everything from b1–b4c and the app suites (`firstrun.sh`, `usbsigntest.sh`, `tokensigntest.sh`,
  `msgsigntest.sh`, `credentialtest.sh`).

Then the **reboot test**, by hand, exactly as for b4d (check-rung.sh never reboots): note
`adb shell cat /proc/sys/kernel/random/boot_id`, run `adb reboot`, and expect adb back by itself
within about 2 minutes with a different `boot_id`, the boot lock screen, and
`getprop sys.boot.reason.last` = `reboot` (or `reboot,…`). Repeat once from the power menu.

**check-build expectations** (`rung-b4d-1/expect-build.txt`): the b4c set minus its "rild/radio
HAL stays" lines, plus: every daemon binary and rc above and `manifest_radioext.xml` absent; no
`android.hardware.radio`/`radio.config`/radioExternal/radioext `<name>` and no
IRadio/ISap/IRadioConfig/IOemSlsiRadioExternal/`ISecureElement/SIM` in the device manifest; no
`service ril-daemon` in `init.gs101.rc`; the OEM-RIL/gril/euiccpixel APKs and the DKA files
absent; TeleService, TelephonyProvider, CarrierConfig, TelecomShim, telephonycore, EuiccGoogle,
GoogleParts, both Wi-Fi APEXes, wpa_supplicant, hostapd, wificond and the telephony/Wi-Fi feature
files present; `phonevault-no-telephony-wifi.xml` absent.

**Risks:**

1. **Boot loop** (low; b4d-1 removes only what b4c already showed to be dead). If b4d-1 does not
   boot either, the cause is in the radio half (most likely the phone process reacting to an
   undeclared IRadio). Capture `adb logcat -b all -d` and `adb logcat -b crash -d` as for b4d,
   then reflash b4c.
2. **`com.android.phone` still loops** (ANR or crash on the missing radio HAL): b4d-1 then FAILs
   on the phone checks but still answers the reboot question. The next rung withdraws the
   telephony features (or TeleService) with the phone process.
3. **`adb reboot` still hangs**: then the RIL stack was not the shutdown blocker. Force a restart
   (hold Power for about 10 s) and capture as in b4d risk 3. The Wi-Fi HAL (b4d-2) is next.
4. **`EuiccGoogle` without `euiccpixel`**: the LPA may log errors when TeleService's
   EuiccController binds it (no SIM, no eUICC firmware path). Crash-buffer entries for
   `com.google.android.euicc` show up as the cumulative "crash buffer" WARN.

**Rollback:** reflash b4c from the Mac: `cd ~/pv-bluejay/out-b4c2 && ./flash-b4c-mac.sh --check`,
then `echo FLASH | ./flash-b4c-mac.sh`.

**Flash (human-approved, phone in the bootloader):**

```sh
mkdir -p ~/pv-bluejay && cd ~/pv-bluejay
rsync -av --exclude 'vault_bluejay-*.zip' <build-host>:/build/out-b4d-1/ out-b4d-1/
cd out-b4d-1 && ./flash-b4d-1-mac.sh --check && ./flash-b4d-1-mac.sh    # type FLASH
# hands-off first boot to SET PIN, then from the repo:
vault-os/dev-ladder-bluejay/check-rung.sh b4d-1     # then the app suites and the reboot test
```

### Flashing a rung from the Mac (human-approved; the phone in the bootloader)

```sh
# 1. fetch the out dir (images/, super.img, SHA256SUMS, flash script; ~4.5 GB without the zips)
mkdir -p ~/pv-bluejay && cd ~/pv-bluejay
rsync -av --exclude 'vault_bluejay-*.zip' <build-host>:$OUT_DIR/ out-b2/
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
(genuine factory boot each time). **Rollback for any rung:** do not count on the other slot
(after an interrupted `fastboot update` it may hold no system partitions), but the bootloader is
never written and always reachable (power off, hold Volume-Down + Power): run the previous good
rung's `flash-<rung>-mac.sh` (or b1's) from its out dir. If slot a fails repeatedly the
bootloader may switch to slot b and stop in fastboot mode: that is fine, the flash script
re-checks the (identical, stock 17.0-15199431) bootloader of the current slot and sets slot a
active again. Last resort: Google's CP2A factory image (`docs/port-bluejay.md` §8).
