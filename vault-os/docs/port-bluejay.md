# Port to the Pixel 6a (bluejay, Google Tensor gs101, Titan M2)

Status 2026-10-10: sources synced (moved to `/build`, its own SSD), kernel and rung **b0**
built (see `dev-ladder-bluejay/README.md`), nothing flashed. Build findings are in §10. This is the plan for milestone **G3** (`path-to-release.md`: "Port to a current Pixel
with Titan M2"). The Pixel 3 XL (crosshatch, Lineage 22.2) stays the dev target for the
ladder already in `dev-ladder/`; this document is the ladder for the 6a.

## 1. Verdict

**Build bluejay on LineageOS 24.0 (Android 17), in a separate tree. Do not use the 22.2 tree,
and do not use Lineage 23.2.** Only 24.0 matches the firmware already on the owner's phone, so
it is the only branch where neither the bootloader nor the radio changes version.

The phone, read over fastboot by the lead (read-only): `product=bluejay`, locked,
`get_unlock_ability=1`, `version-bootloader=bluejay-17.0-15199431`, current slot `b`.

| Branch | Blobs / firmware it is built from | Bootloader that firmware carries | Fit for this phone |
|---|---|---|---|
| lineage-22.2 (Android 15) | BP1A.250505.005 (May 2025); bluejay branch frozen since 2025-05-08 | Android 15 | **No.** Either run Android 15 vendor/kernel on Android 17 firmware (Lineage requires matching firmware), or downgrade the bootloader and radio. No vendor/kernel security fixes after May 2025, so it fails the point of G3 ("still-patched"). Its AVB rollback indexes (SPL 2025-05) are also older than the phone's stored ones, which matters once we relock (section 7). |
| lineage-23.2 (Android 16, official, weekly) | BP4A.251205.006 (Dec 2025) | `bluejay-16.4-14097577` | **No (not as-is).** The wiki requires Android 16 firmware. The OTA ships 16.4 bootloader + radio images, so installing it writes an older bootloader. |
| **lineage-24.0** (Android 17, in development, not yet on the wiki or the build roster) | **CP2A.260705.006** (Jul 2026); device, gs101, kernel-config and blob repos all updated 2026-06/08 | **`bluejay-17.0-15199431`** | **Yes.** Exactly the bootloader the phone has. Radio `g5123b-145971-260414-B-15201439` is the same in CP2A.260605.012 and .260705.006. |

**What bootloader 17.0 means.** I read the factory-image zip directories with HTTP range
requests, so nothing was downloaded:

| Factory build | Android | Bootloader | Radio |
|---|---|---|---|
| BP2A.250705.008 | 16 (Jul 2025) | bluejay-16.2-13291547 | g5123b-145971-250328-b-13284995 |
| BP4A.251205.006 | 16 (Dec 2025) | bluejay-16.4-14097577 | g5123b-145971-251030-b-14356419 |
| CP1A.260405.005 | 16 (Apr 2026) | bluejay-16.4-14548185 | g5123b-145971-260109-b-14688209 |
| **CP2A.260605.012 / CP2A.260705.006** | **17 (Jun/Jul 2026)** | **bluejay-17.0-15199431** | **g5123b-145971-260414-B-15201439** |
| CP3A.260905.009 / CP3A.261005.002.A1 | 17 (Sep/Oct 2026) | bluejay-17.0-15681480 | g5123b-145971-260721-b-15910359 |

So the phone runs the June or July 2026 Android 17 release and has not taken the September
update. We don't know which of the two OS builds it is (both carry the same bootloader). That
doesn't matter, because we replace the OS.

**Anti-rollback (Google factory-images page, "Special instructions…").** Pixel 6/6 Pro/6a
received bootloader anti-rollback increments with Android 13 (2022) and with **May 2025
(BP1A.250505.005)**: "After flashing the May 2025 update on these devices you won't be able to
flash and boot older Android 15 builds." The page lists no later increment for the Pixel 6
family. The May 2026 increment applies only to the Pixel 10 family. As a result:

- **Never flash** any bluejay bootloader or factory image older than BP1A.250505.005. That
  includes every Android 12–14 image and Android 15 builds before May 2025.
- A 16.x bootloader is probably still accepted (same anti-rollback epoch as May 2025). Nobody
  needs to test that, because 24.0 doesn't downgrade.
- After any firmware change, both A/B slots need a bootable bootloader. Google's fallback-slot
  warning describes the failure: the inactive slot holds an old bootloader, a failed boot
  falls back to it, and the device becomes unbootable. Our plan never writes firmware, so the
  inactive slot `a` keeps whatever stock put there. Section 8 says how to check that before
  anything is written.

**Can we install without touching the bootloader or radio?** Yes, on 24.0. The OS
partitions are the only ones we write, from the Mac with `fastboot update` and an image zip
from which the nine firmware images have been removed (section 8). A Lineage OTA zip
(`ships_fw: true`) would also rewrite `abl bl1 bl2 bl31 gsa ldfw pbl tzsw modem`. On 24.0
those are byte-identical in version to what the phone runs, but we strip them anyway and add
a `require version-bootloader=` gate so a mismatch fails closed.

### Partitions on bluejay (from the CP2A.260705.006 factory image and gs101 `BoardConfig-common.mk`)

- **Firmware (bootloader-mode fastboot, never written by us):** `abl bl1 bl2 bl31 gsa ldfw
  pbl tzsw` (the "bootloader" image) and `modem` (the "radio" image). Titan M2 firmware
  (`d3m2.ec.bin`, `evt.ec.bin`, `proto11.ec.bin` in the factory zip) is not a partition. The
  OS-side updater delivers it to the chip.
- **Boot chain (bootloader-mode fastboot):** `boot` (GKI kernel + generic ramdisk, header
  v4, 64 MiB), `vendor_boot` (vendor ramdisk with first-stage modules and the Lineage
  recovery: `recovery_partition_name: vendor_boot`), `dtbo` (16 MiB), `pvmfw` (1 MiB,
  protected-VM firmware, chained into `vbmeta_system`), `vbmeta`, `vbmeta_system`,
  `vbmeta_vendor`.
- **Dynamic partitions in `super` (userspace fastbootd):** `system system_ext product vendor
  vendor_dlkm`. `vendor_dlkm` holds the vendor *and* GKI kernel modules ("Pixel 6/6pro
  doesn't have a system_dlkm partition"), unstripped.
- **None of these exist:** `init_boot` (only devices that launched with Android 13+; the 6a
  launched with 12, and the generic ramdisk stays in `boot`), `vendor_kernel_boot`,
  `system_dlkm`, `recovery`. The factory image's `image-bluejay-*.zip` contains exactly:
  boot, dtbo, pvmfw, vendor_boot, vbmeta, vbmeta_system, vbmeta_vendor, system,
  system_ext, product, vendor, vendor_dlkm, system_other, super_empty, plus the firmware
  images.
- **Data:** `userdata`, `metadata` (FBE + metadata encryption).

### Sources opened

- LineageOS wiki device data, `_data/devices/bluejay.yml` (the HTML wiki returns 403 to
  fetchers, so I read the YAML it renders from): `current_branch: 23.2`, `versions: [20, 21,
  22.1, 22.2, 23.0, 23.2]`, `before_install: {instructions: needs_specific_android_fw,
  ships_fw: true, version: '16'}`, `before_recovery_install: boot_stack [boot, dtbo]`,
  `recovery_partition_name: vendor_boot`, `custom_unlock_cmd: fastboot flashing unlock`,
  kernel `android_kernel_google_gs-6.1_manifest` 6.1.
  <https://github.com/LineageOS/lineage_wiki/blob/main/_data/devices/bluejay.yml>
- Wiki commits that set the firmware requirement: 14→15 (`9d55c1dc95`, 2025-01-01);
  temporarily "15 (BP1A.250405.007)" then reverted (`30ac8a0370`/`936d0d2ad0`, May 2025);
  15→16 when promoted to 23.0 (`538c85e0c0`, 2025-11-03).
- Wiki install text (`_includes/templates/device_specific/before_install_needs_specific_android_fw.md`):
  "Your device needs a specific firmware version before proceeding. If your device is
  currently using a newer or older version than the required version, please up- or
  downgrade…". Install flow: `recovery_install_fastboot_nexus.md`,
  `before_recovery_install_boot_stack.md`.
- Official build roster `LineageOS/hudson/lineage-build-targets`: `bluejay userdebug
  lineage-23.2 W` (24.0 is not on it).
- `LineageOS/android_device_google_bluejay`: branches up to `lineage-24.0`. 22.2 head
  `df9bb3cb` "Update fingerprint/build description from BP1A.250505.005" (2025-05-07). 24.0
  head `8b796969` (2026-08-21) after "bluejay: Update to CP2A.260705.006" (2026-07-09).
- `TheMuppets/proprietary_vendor_google_bluejay`: `radio/` = `abl bl1 bl2 bl31 gsa ldfw
  modem pbl tzsw` and `BoardConfigVendor.mk` adds all nine to `AB_OTA_PARTITIONS`. Firmware
  per branch: 22.2 BP1A.250505.005, 23.2 BP4A.251205.006, 24.0 CP2A.260705.006.
- Google factory images: <https://developers.google.com/android/images> (bluejay table;
  anti-rollback sections for May 2025 and May 2026; `flash-all.sh` of CP2A.260705.006, which
  flashes `bootloader-bluejay-bluejay-17.0-15199431.img` and
  `radio-bluejay-g5123b-145971-260414-B-15201439.img`, then `fastboot -w update image-….zip`).
  Bootloader and radio versions come from the zip central directories (table above).
- `LineageOS/android_device_google_gs101` `BoardConfig-common.mk` / `BoardConfigLineage.mk`
  (22.2 and 24.0): partition list, AVB chaining and rollback-index locations, module packaging.
- `LineageOS/android_kernel_google_gs-6.1_manifest` (lineage-24.0): GKI `android14-6.1-2025-12_r30`
  + `private/google-modules` + `private/devices` (`build_bluejay.sh` → `tools/build_dist.sh
  bluejay`; `google/bluejay/{bluejay_defconfig, vendor_dlkm.blocklist.bluejay,
  vendor_ramdisk.modules.bluejay}`).
- GrapheneOS CLI install guide <https://grapheneos.org/install/cli>: unlock/lock confirmation
  on the device wipes data; 6a OEM unlocking needs stock ≥ June 2022; after relock the OEM
  unlocking toggle should be turned off. It also proves that custom-key relocking works on
  this hardware.

## 2. Sources on the build host

**Separate tree, because the branch differs.** Lineage 24.0 and 22.2 share no tree. Adding
bluejay to `/root/lineage-src` would mean 22.2 device repos against Android 17 blobs, which
won't work. The crosshatch tree is not touched (no `dev-ladder-sync`, no `build-rung`, no
edits to its device/vendor/kernel repos). The only thing borrowed is its `repo` launcher.

| Path | What | Owner |
|---|---|---|
| `/root/lineage-24` | LineageOS 24.0, `repo init --git-lfs --depth=1 --no-clone-bundle -g default,-darwin,-notdefault`, plus `.repo/local_manifests/bluejay.xml` = `vault-os/manifest/bluejay/local_manifests-bluejay.xml` (device/google/bluejay, device/google/gs101, device/google/bluejay-kernels, TheMuppets vendor/google/bluejay) | aipg |
| `/root/gs-6.1-kernel` | Kleaf kernel workspace, `LineageOS/android_kernel_google_gs-6.1_manifest` `lineage-24.0` | aipg |
| `/root/sync-bluejay.sh` | = `vault-os/manifest/bluejay/sync-bluejay.sh` (resumable) | root |
| `/root/bluejay-sync.log` | sync log | root |

Started 2026-10-10 18:34 EDT with
`nohup su aipg -s /bin/bash -c 'bash /root/sync-bluejay.sh' > /root/bluejay-sync.log 2>&1 &`.
Re-running the same command resumes the sync.

**Disk.** Before the sync: 464 GB, 232 GB free. The crosshatch tree is 118 GB of sources
(28 GB `.repo`, 57 GB prebuilts) plus 109 GB `out/`. Expect the 24.0 tree at about 120–130 GB
and the kernel workspace at about 10–15 GB, which leaves **about 90 GB free after the sync**.
That is not enough for a bluejay `out/` (100–150 GB for Android 17). Before the first bluejay
build, one of these has to happen:

1. **Preferred:** add a disk and build with `OUT_DIR=/mnt/<disk>/out-bluejay`.
2. Delete `/root/lineage-src/out` at a crosshatch checkpoint. The next crosshatch rung is
   then a full rebuild, about 3 h.

The root filesystem is already btrfs `compress=zstd:3`, so compression won't help further.

**Kernel.** Lineage 24.0 does not ship kernel prebuilts. `device/google/bluejay-kernels/6.1`
holds only `modules.load`, `vendor_dlkm.modules.load`, `vendor_dlkm.modules.blocklist`,
`init.insmod.bluejay.cfg`, and a `.gitignore` for `boot.img`, `dtbo.img`, `dtb.img`, `*.ko`,
`vendor_dlkm.img`, …. Without those files, gs101's `BOARD_PREBUILT_BOOTIMAGE` is empty. Steps:

```sh
cd /root/gs-6.1-kernel && ./build_bluejay.sh                 # Kleaf; output in out/bluejay/dist (verify path)
cp out/bluejay/dist/{boot.img,dtbo.img,dtb.img,*.ko,…} /root/lineage-24/device/google/bluejay-kernels/6.1/
```

Never overwrite the four tracked list files with the dist copies without a diff: they are
our stripping lever (section 4). Estimates on 24 cores / 94 GB: kernel 30–60 min, first full
Android 17 build 3–4 h, incremental rung builds 20–60 min.

## 3. Product layout for bluejay

- `device/phonevault/bluejay/{AndroidProducts.mk, vault_bluejay.mk}`, mirroring
  `vault_crosshatch.mk`:
  - `PRODUCT_PACKAGE_OVERLAYS += vendor/phonevault/overlay` **before** the first inherit.
    This is the 2d-c3 lesson: otherwise `vendor/lineage/overlay/common` wins.
  - Then `inherit-product device/google/bluejay/lineage_bluejay.mk` and
    `vendor/google/bluejay/bluejay-vendor.mk` (lineage_bluejay.mk already inherits it, so
    check for duplication).
  - `vendor/phonevault/config/common.mk` last.
  - `PRODUCT_DEVICE := bluejay`, `PRODUCT_NAME := vault_bluejay`,
    `PRODUCT_MODEL := Pixel 6a Vault`, `TARGET_SCREEN_HEIGHT/WIDTH := 2400/1080`.
  - Lunch: `vault_bluejay-<release>-userdebug`, using the release config of the 24.0 tree
    (crosshatch uses `bp1a`; read `build/release` in the 24.0 tree for the Android 17 name).
- `vendor/phonevault` is shared. Device-specific pieces get per-device files:
  - `board-info.txt` → `board-info-bluejay.txt` (`require board=bluejay`,
    `require version-bootloader=bluejay-17.0-15199431`,
    `require version-baseband=g5123b-145971-260414-B-15201439`), so that `fastboot update`
    refuses a phone on other firmware.
  - The VINTF manifest and matrices are regenerated for gs101 HAL names.
  - `BoardConfigVault.mk` keeps device-neutral lines only. Kernel fragments move to the
    module lists (section 4).
- The dev-ladder scripts are crosshatch-specific (msm-4.9 paths, `vault_crosshatch` lunch,
  `out/target/product/crosshatch`). Bluejay gets `dev-ladder-bluejay/` with its own
  `sync`/`build` scripts that take the tree as an argument and default to `/root/lineage-24`.
  Nothing shared may default to the crosshatch tree.

## 4. How each crosshatch rung maps to gs101 / GKI

The patch series under `patches/` targets Android 15 and the crosshatch trees. Every patch
must be **rebased to Android 17**: patches against `frameworks/base` and AOSP projects are
re-applied, and `device-crosshatch`/`kernel-crosshatch` patches are rewritten for gs101.

| Crosshatch rung / patch | What it did | On bluejay (gs101, GKI 6.1) |
|---|---|---|
| 0 / 1 / 1b | owner provisioning, kiosk, HOME, setup wizard stripped | frameworks/base **0003 + 0004 are device-independent**. Rebase to A17 `DevicePolicyManagerService`; the same overlay resource `config_fixedFunctionDeviceOwner` = `dev.phonevault.signer/.VaultDeviceAdminReceiver`. `Android.bp` strips `LineageSetupWizard` (check the 24.0 package name). `preferred-apps/phonevault-home.xml` unchanged. Lineage 24.0's gs101 can build "minimal GMS" (`6503b583`); make sure no GMS is in our product. |
| 2a / 2b | our AVB key, `--flags 3` removed | gs101 chains `boot` (rollback location 2), `vbmeta_system` (1, includes `pvmfw`), `vbmeta_vendor` (3), all signed with **`external/avb/test/data/testkey_rsa2048.pem`**, and `BoardConfigLineage.mk` appends `--flags 3`. Our `BoardConfigVault.mk` must re-key **every** chained partition, not just vbmeta: a chained partition signed with the public AOSP test key can be re-signed by anyone. Set `BOARD_AVB_{BOOT,VBMETA_SYSTEM,VBMETA_VENDOR}_KEY_PATH`/`_ALGORITHM` and keep the `--flags 3` filter. Rollback indexes: section 7. |
| 2c | appliance VINTF manifest | regenerate from the running b0 image (`lshal`, `/vendor/etc/vintf`). HAL names differ (AIDL everywhere on gs101). |
| 2d-a (Wi-Fi/BT/NFC/…) | Kconfig fragment | **GKI: the vendor drivers are modules on `vendor_dlkm`/`vendor_boot`.** Stripping = remove them from `vendor_dlkm.modules.load` / `modules.load` (vendor_boot) **and** list them in `vendor_dlkm.modules.blocklist`, **and** don't install the `.ko` (filter `BOARD_VENDOR_KERNEL_MODULES`). Kernel rebuild only if we also drop them from `private/devices/google/bluejay/bluejay_defconfig` (vendor fragment; optional, later). **Never edit the GKI `gki_defconfig`**: that breaks the KMI that every vendor module is built against. Wi-Fi: Broadcom BCM4389 (`bcmdhd4389`). BT: Broadcom via the Pixel "nitrous" power/LPM driver + `android.hardware.bluetooth` AIDL HAL. NFC: ST (`android.hardware.nfc-service.st` in gs101 `common.mk`, ST21NFC/ST54 secure element). Names to confirm with `lsmod` on b0. |
| 2d-b (modem) | Qualcomm PIL/GLINK | **Exynos modem (g5123b):** `cpif` (modem interface) + `cbd` (boots the modem) + Samsung/Exynos RIL (`rild`, `libsitril`), IMS/IWLAN, eSIM (`EuiccGoogle`), modem logging (`modem_svc`, `dmd`). Stripping the `cbd`/`cpif` modules leaves the modem unpowered. The `modem` partition stays untouched. |
| 2d-c (camera/media/DSP/sensors) | Kconfig + patch 0002 | Camera: LWIS drivers + Google camera HAL (vendor blob provider). TPU: `edgetpu` (gs101 "abrolhos") + NN HAL. Sensors and CHRE run on the **AoC (always-on compute)**. **Keep `aoc.ko`**: on gs101 audio also routes through AoC. Remove the sensors HAL, CHRE daemon and camera provider instead. Fingerprint (Goodix optical, `ro.vendor.fingerprint.ta.name=g7.app`) and touch (ST FTS on spi11) stay: the credential mode uses `USE_BIOMETRIC`. No equivalent of crosshatch patch 0002 is expected. |
| 2d-c2 / 2d-c3 | crash-looping vendor services | Same rule: when a driver goes, its vendor service, rc and VINTF entry go in the **same** rung. 2d-c showed that a crash loop otherwise follows. frameworks/base **0005** (keyguard clock) is device-independent; rebase it. The `migrate_clocks_to_blueprint` flag state must be re-checked on Android 17. Ambient display / doze overlay values: re-check against the gs101 overlays. |
| 2d-d (USB functions) | Kconfig: AOA + FunctionFS only | **On GKI the configfs functions (mass storage, MTP/PTP, MIDI, HID, …) are built into the GKI image.** They can't be removed without leaving GKI. Enforce in userspace: the gs101 USB init/HAL only composes `accessory` (+ `ffs.adb` until the user build), plus a sepolicy rule that only init and the USB HAL may write `/config/usb_gadget`. **Lesson from 2d-d: never turn off dual-role.** gs101 DWC3 runs through the Exynos glue + the MAX77759 TCPC and role switch. The host role is refused in the USB HAL (`hardware/google/pixel/usb`), never in the kernel. |
| 3 | USB gadget rc, `persist.sys.usb.config=none` | Same intent. gs101 USB rc lives in `device/google/gs101/conf/init.gs101.usb.rc` (verify name) and the Pixel USB HAL. |
| 4… | `Android.bp` overrides, APEX strips | Rebase appliance patches 0001–0022 to Android 17. Expect conflicts in connectivity/wifi/media APEX layouts. |
| UWB | n/a | **The Pixel 6a has no UWB** (wiki peripherals list; UWB is on the 6 Pro / raven). gs101's `uwb/` directory exists for raven: make sure nothing from it is installed. |
| final | `user` build, no adb, release keys | same |

**Keep all of the Titan M2 and Trusty stack. Never strip it:**

- `citadeld`
- `android.hardware.security.keymint-service.citadel` (StrongBox)
- Weaver (the Titan M2 HAL used for the PIN/credential)
- AuthSecret (`…authsecret…citadel`)
- **OemLock** (`…oemlock…citadel`: the OEM-unlocking state lives in the Titan M2)
- the Titan M2 firmware updater (`init_citadel` / `citadel_updater` with `/vendor/firmware/citadel/*.ec.bin`)
- Trusty TEE: `android.hardware.security.keymint-service.trusty`, `android.hardware.gatekeeper-service.trusty`, `storageproxyd`, trusty confirmationui
- the GSA firmware interfaces

FBE and metadata encryption depend on Trusty KeyMint. Confirm exact service names with
`lshal`/`service list` on b0. Then write them into an allowlist test that fails the build
if any of them disappears.

## 5. Ordered rungs for bluejay

Each rung is boot-tested on the 6a with the same per-rung checklist as `dev-ladder/README.md`.
Owner + kiosk, `pintest`/`lifecycletest`, `usbsigntest`, `tokensign`, `msgsign`,
`credentialtest` all have to pass, and the crash-loop count (`logcat -b events | grep -c
am_crash` + `init: Service … exited` repeats) has to be 0, before the next rung.

| Rung | Change | Boot test (in addition to the checklist) |
|---|---|---|
| **b0** | Lineage 24.0 bluejay + `vault_bluejay` product: app prebuilt, frameworks/base 0003+0004 rebased (as built: 0001/0002/0005 deferred to a later rung so b0 only has to prove boot + owner provisioning), overlays, HOME preferred-apps, setup wizard stripped, userdebug with the pre-authorised dev adb key (like crosshatch rung 0/1b). AVB still Lineage default. | Genuine first boot on wiped data lands on SET PIN, owner = `fixed-function-system-image`, `mLockTaskModeState=LOCKED`. Record the **inventory** for later rungs: `lsmod`, `lshal`, `service list`, `getprop`, `ls /vendor/etc/init`, `cat /proc/cmdline`, `/sys/class/typec`, `ls /config/usb_gadget/g1/functions`. **Run `attesttest.sh`** and record whether the StrongBox chain is factory or RKP (section 6). |
| b1 | Our AVB **dev** key (RSA-4096, `/home/aipg/.phonevault-keys/avb/`, pkmd sha256 `068a9865…`) on vbmeta + all chained partitions (boot, vbmeta_system, vbmeta_vendor), `--flags 3` removed (verification on), rollback indexes unchanged (≥ stock), `board-info-bluejay.txt` pins (b0). Plus the b0 gaps: factory-boot wake-up (frameworks/base 0003 unstops the owner and re-sends DEVICE_ADMIN_ENABLED after the system user unlocks; sysconfig `initial-package-state stopped=false`), no launcher (`Launcher3QuickStep`, `Launcher3Overlay` overridden), 0005 rebased (no keyguard clock/date), no Lineage Trust (overlay drops `TrustInterfaceService`, sysconfig withdraws `org.lineageos.trust`). Not relocked. | Factory boot after `-w` lands on SET PIN with **no** manual step (`VaultProvision: appliance provisioned on admin enable`), no HOME chooser, no "Discover Trust", keyguard disclosure names "Phone Vault" and shows no clock/date. `ro.boot.veritymode=enforcing`, `ro.boot.vbmeta.digest` non-empty, `avbtool info_image` of each image shows key sha1 `af09b166…`. |
| b2 | Appliance VINTF manifest for gs101 | No VINTF/`isBuildConsistent` popup, no HAL registration refusals. |
| b3 | Wi-Fi, Bluetooth, NFC + secure element, GNSS: modules out of load lists + blocklist, their HALs/daemons/rc/VINTF out | No `wlan0`, no `/sys/class/bluetooth`, no NFC HAL, `dumpsys location` shows no GNSS HAL; no crash loops. |
| b4 | Modem: `cpif`/`cbd`/RIL/IMS/eSIM out | No `rmnet*`/`umts_*` netdevs, `cbd` absent, modem not powered (no `/dev/umts_*`). Battery drain over 12 h idle (expect better than b3). |
| b5 | Camera (LWIS + provider), TPU/NN, sensors HAL + CHRE (keep AoC) | `dumpsys media.camera` → 0 cameras, `dumpsys sensorservice` → no sensors. Display, touch, fingerprint, audio (none needed) and haptics OK. |
| b6 | USB: compose only `accessory` (+ `ffs.adb` until b8), sepolicy guard on configfs, dual-role kept, host role refused in the USB HAL | From the Mac/host: only AOA (+adb) enumerates. An OTG device plugged into the phone is not enumerated. Charging works. |
| b7… | `Android.bp`/APEX strips, appliance patches 0001–0022 rebased, in slices like crosshatch rung 4 | Artifact policy gates (`vault-os/tests`) adapted to bluejay paths. |
| b8 | `user` build, release keys, release-signed app, no adb | `adb` unreachable. Full signing suite over AOA only. |
| **b9** | **Relock:** `avb_custom_key` + `fastboot flashing lock` | Boot shows the yellow "different OS" screen with our key's ID. Attestation → **GENUINE**. A vbmeta signed with another key is refused (red/eio). The OEM unlocking toggle is turned off afterwards. |

## 6. Attestation on the 6a (Titan M2) and what our verifier expects

The verifier (`docs/device-attestation.md`, `companion/src-tauri/src/attest/`) requires all of
the following for GENUINE:

- a chain ending at a pinned Google root: the RSA-4096 root key, or the EC P-384 "Key
  Attestation CA1" root used since 2026-02-01;
- `attestationSecurityLevel = StrongBox`;
- `deviceLocked = true`, state Verified or SelfSigned, and `verifiedBootKey` equal to a pinned
  Phone Vault AVB key;
- the release app signer;
- a fresh challenge;
- `osPatchLevel` ≥ the minimum.

Bluejay-specific points:

- **Factory keys or RKP.** The Pixel 6 family is the first with Remote Key Provisioning. The
  TEE KeyMint (Trusty) is RKP-provisioned. A secondary source (droidwin, "Keybox might no
  longer work from February 2026") says the **Titan M2 StrongBox on the Pixel 6 series has
  no native RKP and still uses factory-provisioned keys** under the older Google root.
  **Unverified.** b0's `attesttest.sh` settles it:
  - RKP chains have short-lived leaves and "Droid CA2/CA3"-style intermediates.
  - Factory chains look like the Pixel 3 ones in the verifier's test set.
- **If StrongBox is factory-provisioned**, attestation works offline exactly as on crosshatch.
  Nothing changes in the verifier except pinning the bluejay AVB key.
- **The TEE path becomes unavailable.** The image has no network and strips the
  RemoteKeyProvisioning module (`rkpd`), so the RKP pool can never fill and TEE attestation
  would fail with `OUT_OF_KEYS`. That is acceptable: StrongBox is required for GENUINE, and
  the TEE fallback only ever produced DEVELOPMENT.
- **If StrongBox turns out to be RKP-provisioned as well**, an offline appliance can't
  attest. Two options:
  - (a) Companion-relayed provisioning: the phone produces the RKP CSR via
    `IRemotelyProvisionedComponent`, the companion posts it to Google's RKP service over its
    own network, and returns the certificates over AOA. That needs a patched `rkpd` or our
    own client. It is a new feature and needs a security review.
  - (b) Accept that bluejay can't be GENUINE. That defeats G2/G3.
- **AVB key.** Use a separate release AVB key per device model, and add its SHA-256 to
  `attestation-policy.json` `avbKeySha256` (a list). SelfSigned (yellow) is expected: the
  verifier accepts it only with a pinned key.
- **Patch levels.** 24.0 tracks current Android security bulletins (`android-security-17.0.0_r1`
  forks, 2026-09). `vendorPatchLevel`/`bootPatchLevel` come from CP2A (2026-07) until
  Lineage moves to CP3A, which again means a firmware change (bootloader 17.0-15681480).
  Once the phone is ours, firmware updates are a deliberate step: flash Google's newer
  bootloader+radio to **both** slots, per the anti-rollback guidance.

## 7. Verified boot, rollback indexes, relock

- **Dev key (b1–b8).** Rungs b1+ sign vbmeta, boot, vbmeta_system and vbmeta_vendor with one
  RSA-4096 **development** key that only exists on the build box
  (`/home/aipg/.phonevault-keys/avb/`, see `dev-ladder-bluejay/README.md`). Its public blob
  (`avb_pkmd_bluejay_DEV.bin`) has sha256 `068a9865f04cc9b91f6838b537c14f32e4fa6e32682cbcfbfd6c9782ab71ae8c`
  (avbtool sha1 `af09b166ade90fb31a184e9ab6c59819cd33fc8a`). It could be flashed as
  `avb_custom_key` for a relock test on a lab phone, but the shipped relock (b9) uses the
  separate release key. Verification is on (vbmeta flags 0) while the phone stays unlocked: an
  unlocked bootloader still boots a mis-signed image (orange), so a signing mistake shows up
  as a verification error instead of bricking anything.

- Custom-key relocking on Tensor is supported: GrapheneOS ships on the 6a exactly this way.
  Steps: `avbtool extract_public_key --key <release avb key> --output avb_pkmd.bin`; in
  bootloader fastboot, unlocked: `fastboot erase avb_custom_key`,
  `fastboot flash avb_custom_key avb_pkmd.bin`, `fastboot flashing lock` (on-screen confirm,
  wipes data).
- **Rollback indexes.** gs101 sets `BOARD_AVB_{BOOT,VBMETA_SYSTEM,VBMETA_VENDOR}_ROLLBACK_INDEX
  := $(PLATFORM_SECURITY_PATCH_TIMESTAMP)` (locations 2/1/3). While the phone was locked on
  stock CP2A, the bootloader stored indexes for those locations at roughly the CP2A patch
  timestamp. Once relocked, our images must carry indexes **≥** those stored values or they
  won't boot. We are assuming the stored values survive unlocking; that has not been tested.
  24.0 (security patch ≥ 2026-07) satisfies this automatically. A 22.2 image (2025-05) would
  not. Each rung's `avbtool info_image` output therefore records the rollback indexes, and
  b1 adds a policy test: index ≥ the stock CP2A value.
- `ro.vendor.build.svn` (96 in the 24.0 vendor props) is Google's vendor security version.
  Leave it exactly as the device tree sets it.
- **The relocked phone's OEM-unlocking toggle must be off**, so that a thief can't unlock and
  reflash without the PIN. On a kiosk image the Settings toggle isn't reachable, which keeps
  it in whatever state it was in at relock. b9 therefore has to turn it off before the lock,
  using Developer options in the dev image, or `cmd oem-lock` / the OemLock HAL from adb
  while still userdebug. Do this in b8/b9 and verify with `fastboot flashing
  get_unlock_ability` → 0.

## 8. Flashing from the Mac

Tools: `brew install --cask android-platform-tools`. `fastboot --version` must be ≥ 33.0.1
(Google's `flash-all.sh` refuses older). The build host can't enumerate the 6a (its USB-2
controllers), so images are built there and copied to the Mac
(`scp root@192.168.20.98:…/vault_bluejay-img-<rung>.zip .`).

**Images we produce per rung (on the build host):**

```sh
# after `m target-files-package` (and `m otapackage` for later OTA rungs):
out/host/linux-x86/bin/img_from_target_files <TF.zip> vault_bluejay-img-<rung>.zip
# strip firmware unconditionally (no-op if absent), then show what is left
zip -d vault_bluejay-img-<rung>.zip abl.img bl1.img bl2.img bl31.img gsa.img ldfw.img pbl.img tzsw.img modem.img || true
unzip -l vault_bluejay-img-<rung>.zip
```

The listing must show exactly `android-info.txt` and
`boot dtbo pvmfw vendor_boot vbmeta vbmeta_system vbmeta_vendor system system_ext product
vendor vendor_dlkm` (`.img`), plus `super_empty.img` if present. Nothing else.
(`dev-ladder-bluejay/build-rung.sh` does all of this and fails otherwise. As built, b0's raw
`img_from_target_files` output also held `system_other.img` — `fastboot update` writes that to
the *other* slot, our stock fallback — `userdata.img`, `unsparse_super_empty.img` and a
`fastboot-info.txt` listing them; all four are dropped.)
`android-info.txt` = our `board-info-bluejay.txt`
(`require board=bluejay`, `require version-bootloader=bluejay-17.0-15199431`,
`require version-baseband=g5123b-145971-260414-B-15201439`), so fastboot refuses a
mismatched phone before writing anything.

### Rung b0: first install (lead runs the commands, owner confirms on the phone)

0. **Prepare (Mac, before touching the phone).**
   - Download the rollback image `bluejay-cp2a.260705.006-factory-03992adc.zip` from the
     Google factory-images page (sha256
     `03992adc723742de3fa12c6a40fb19ecbcd7f388a9eaacf93e27af466a79cb33`) and verify it.
   - Any **newer** official bluejay factory image is also a valid rollback. Never use one
     older than BP1A.250505.005.
   - Have `vault_bluejay-img-b0.zip` and its sha256 from the build host.

1. **Owner, in stock Android.** Back up anything wanted: unlocking wipes the phone.
   Settings → About phone → tap **Build number** seven times → Settings → System →
   Developer options → **OEM unlocking** ON. The lead's reading
   `get_unlock_ability=1` says it is already on. Confirm it is still on. If greyed out, the
   phone needs to have been online once / not carrier-locked. Removing the Google account is
   optional; with OEM unlocking on, the unlock wipe does not trigger FRP.

2. **Owner: bootloader mode.** Power off, then hold **Volume Down + Power** until the
   fastboot screen appears. Connect USB-C to the Mac.

3. **Lead: read-only preflight (Mac).** Every value must match. If one doesn't, stop.

   ```sh
   fastboot devices
   fastboot getvar product              # bluejay
   fastboot getvar version-bootloader   # bluejay-17.0-15199431
   fastboot getvar version-baseband     # g5123b-145971-260414-B-15201439
   fastboot getvar current-slot         # b
   fastboot getvar unlocked             # no
   fastboot flashing get_unlock_ability # 1
   ```

   Slot `a` will stay stock and become the fallback. Its bootloader version can't be read
   without switching slots, and we never switch slots before b0 has booted.

4. **Lead: unlock.**

   ```sh
   fastboot flashing unlock
   ```

   **Owner:** the phone asks whether to unlock. Use **Volume** to select "Unlock the
   bootloader" and **Power** to confirm. The phone erases user data and returns to fastboot
   mode (orange "unlocked" state). Then the lead runs:

   ```sh
   fastboot getvar unlocked   # yes
   ```

5. **Lead: flash the OS partitions (bootloader and radio untouched).**

   ```sh
   fastboot snapshot-update cancel                         # clear any pending Virtual A/B merge from the last stock OTA
   fastboot -w update vault_bluejay-img-b0.zip             # checks android-info, flashes boot/dtbo/pvmfw/vendor_boot/vbmeta*,
                                                           # reboots into fastbootd for system/system_ext/product/vendor/vendor_dlkm,
                                                           # wipes userdata (+metadata) and reboots
   ```

   `fastboot update` writes only the current slot (`b`). If it complains about
   `version-bootloader` or `version-baseband`, the `require` lines did their job: stop.

6. **First boot.** The phone shows the orange "Your device is corrupt/unlocked… loading a
   different operating system" warning (about 5 s, normal for an unlocked bootloader), then
   the Lineage/Phone Vault boot animation. The first boot after a wipe takes several minutes.
   The expected result is the Phone Vault SET PIN screen with no setup wizard. The owner sets
   a **throwaway** PIN/wallet for testing.

7. **Lead: checklist** (adb from the Mac, dev key pre-authorised): owner, kiosk, HOME,
   inventory, `attesttest.sh` (reports DEVELOPMENT: unlocked), signing suites.

**Rollback to stock** (either slot broken, or the decision to abort): bootloader mode, then in
the factory zip directory run `./flash-all.sh`. It flashes **the same** 17.0-15199431 bootloader
and radio, then `fastboot -w update image-bluejay-cp2a.260705.006.zip`. Afterwards, optionally,
`fastboot flashing lock` (on-screen confirm, wipes). If `avb_custom_key` was ever flashed, run
`fastboot erase avb_custom_key` first.

### Later rungs

- **Fresh first boot (provisioning tests):** same as b0 step 5 with the new image zip
  (`fastboot snapshot-update cancel` + `fastboot -w update vault_bluejay-img-bN.zip`).
- **Keep data (OTA):** build the OTA with firmware excluded from `AB_OTA_PARTITIONS`
  (filter the nine names in `vault_bluejay.mk`/`BoardConfigVault.mk`), then
  `adb reboot sideload` (or Lineage recovery → Apply update → Apply from ADB) and
  `adb sideload vault_bluejay-ota-bN.zip`. The recovery is in `vendor_boot` and trusts the
  OTA key of the same build, so there is no "install anyway" tap if both use our release key.
  OTA rungs install to the **other** slot: before the first OTA rung, make both slots ours
  (`fastboot --slot=all` variant of the image flash, or one OTA immediately after b0). That
  way a failed boot never falls back to the stock slot with wiped data mid-test.
- **Relock (b9):**

  ```sh
  fastboot erase avb_custom_key
  fastboot flash avb_custom_key avb_pkmd_bluejay.bin
  fastboot flashing lock          # owner: Volume to "Lock the bootloader", Power to confirm; wipes data
  ```

  First boot shows the yellow "different OS" notice with our key's ID. The owner compares it
  with the ID published for our key.

## 9. Open items

1. Before the first build: disk for `out/` (section 2).
2. b0 decides the attestation question (section 6). Do it before investing in b3+.
3. The Lineage 24.0 bluejay branch is not yet official. Pin SHAs
   (`generate-pinned-manifest`) as soon as b0 boots, and watch for the CP3A rebase, which
   changes firmware.
4. Kernel dist path and file list from `build_dist.sh`: confirm on the first kernel build.
5. Exact gs101 module and service names (Wi-Fi/BT/NFC/modem/LWIS/edgetpu/AoC): take them
   from the b0 inventory, not from this document.
6. Rebasing frameworks/base 0001–0005 and appliance 0001–0022 to Android 17 is the bulk of
   the work. Do 0003/0004 first (b0 depends on them). 0003/0004 are done:
   `patches/frameworks-base-a17/`.

## 10. Findings from the first build (b0, 2026-10-10/11)

- **Paths.** The tree is at `/build/lineage-24` (own SSD, ~290 GB free before the build;
  `/root/lineage-24` is a symlink, build from the real path) and the kernel workspace at
  `/build/gs-6.1-kernel`, both owned by aipg. That settles open item 1.
- **Kernel (open item 4).** `./build_bluejay.sh` takes about 6 min: the manifest pins GKI
  `android14-6.1-2025-12_r30` as a downloaded prebuilt and only the Pixel vendor modules are
  compiled. Dist path: `out/bluejay/dist` (boot.img, dtbo.img, dtb.img, 318 `.ko`, the four
  module lists, which match the tracked copies in `bluejay-kernels/6.1`).
- **The Kleaf `boot.img` is kernel-only (ramdisk size 0).** gs101 uses it as
  `BOARD_PREBUILT_BOOTIMAGE`, but the 6a has no `init_boot`, so the generic ramdisk with
  first-stage init must be in `boot`. As-is, the image would have panicked with no `/init`. b0's
  `BoardConfigVault.mk` builds `boot.img` instead, from `Image.lz4` (byte-identical to the
  prebuilt's kernel) and the generic ramdisk, and `build-rung.sh` refuses a `boot.img` whose
  ramdisk lacks `init`.
- **git-lfs.** `repo init --git-lfs` fetched the LFS objects but left pointer files: all of
  `vendor/google/bluejay` (blobs, APEXes, radio images, whose SHA1 check then fails kati) and
  the webview APKs. `git lfs install --local && git lfs pull` per project fixed it, and
  `sync-bluejay.sh` now does that.
- **Host tool.** Android 17's `main.mk` shells out to `zip`; it was missing on the build box
  and has been installed (`pacman -S zip`).
- **Artifact path requirement.** gs101 enforces `generic_system.mk`'s artifact path
  requirement, so a device product may install nothing into `/system`. That covers the
  signer app, `PRODUCT_SYSTEM_PROPERTIES` and `etc/preferred-apps`. b0 puts the app on
  `/product` (`product_specific: true`; still `FLAG_SYSTEM`, not privileged), and puts the
  `ro.phonevault.*` props and the HOME preference on `/product`. Android 17's PackageManager
  reads `etc/preferred-apps` from every partition. The release `vendor/phonevault` files still
  target `/system` (crosshatch) and need the same split for bluejay.
- **Overlays** become the auto-generated RRO
  `product/overlay/framework-res__vault_bluejay__auto_generated_rro_product.apk`, which carries
  `config_fixedFunctionDeviceOwner`. Base `framework-res` keeps the empty default.
- **Lineage adb.** Without `WITH_ADB_INSECURE`, Lineage's `common.mk` sets `ro.adb.secure=1`
  **and** `PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG` (`ro.debuggable=0`) on userdebug.
  `build-rung.sh` exports it, and b0 has `ro.debuggable=1`, `ro.adb.secure=0`.
- **`img_from_target_files` output** also holds `system_other.img`, `userdata.img`,
  `unsparse_super_empty.img` and a `fastboot-info.txt`. `build-rung.sh` drops them (§8).
- **AVB as built (b0).** vbmeta is signed with the public AOSP `testkey_rsa4096` (sha1
  `2597c218…`) and has flags 3. boot (location 2), vbmeta_system (1) and vbmeta_vendor (3) are
  signed with the public `testkey_rsa2048` (sha1 `cdbb7717…`). All rollback indexes are
  1790812800 (2026-10-01, the tree's security patch level), which is ≥ the stock CP2A values.
- **Build time.** First full build: 6 h 58 min on 24 cores (233k ninja steps). An incremental
  rebuild after a board-config change takes about 15 min.

## 11. Findings preparing b1 (2026-10-11)

- **Why the app never started on b0's factory boot** (read in the 24.0 tree, not guessed):
  - `provisionConfiguredFixedFunctionOwner` runs at `PHASE_ACTIVITY_MANAGER_READY`.
    `setActiveAdmin` then calls `sendAdminCommandLocked(…DEVICE_ADMIN_ENABLED…)`, which first
    asks PackageManager for the admin receiver in user 0. User 0 is still **locked** at that
    point (it unlocks later in boot even without a credential), so only direct-boot-aware
    components resolve. `VaultDeviceAdminReceiver` is not direct-boot aware: the query is
    empty and DPMS sends nothing at all. `ACTION_USER_STARTED` → `sendDeviceOwnerUserCommand`
    goes through the same method while the user is still locked: same result. Android 17 did
    not change the admin broadcasts or their flags (no `FLAG_INCLUDE_STOPPED_PACKAGES`, as
    before).
  - Independently, `config_stopSystemPackagesByDefault` is `true` (since Android 14):
    `InstallPackageHelper` scans a system package seen for the first time as **stopped** when
    it has a launcher activity (ours does) and it is not listed in an
    `<initial-package-state stopped="false">` sysconfig. `BroadcastController` adds
    `FLAG_EXCLUDE_STOPPED_PACKAGES` to every broadcast by default, so even a resolvable admin
    broadcast would have been dropped until something launched the app.
  - On crosshatch the HOME preference launched the activity, which provisions itself, so the
    gap stayed hidden. On b0 the HOME preference did not hold and Trebuchet produced a chooser.
- **Fix (b1).** 0003 now (a) unstops the configured owner, after all its checks have passed and
  before `setActiveAdmin` (what a first launch would do), and (b) remembers that this boot
  provisioned the owner and re-sends `DEVICE_ADMIN_ENABLED` to the device owner from DPMS'
  existing `ACTION_USER_UNLOCKED` handler for user 0. The app's receiver
  (`onEnabled` → `ApplianceProvisioning.apply` → `showVault`) is unchanged and needs no new
  permission. The product also ships
  `/product/etc/sysconfig/phonevault-initial-package-state.xml`, so the package is never
  scanned stopped. The launcher is overridden, so HOME has one real candidate.
- **0005 on Android 17.** `migrate_clocks_to_blueprint` is gone (the View blueprint is the only
  View path) and `scene_container` is DISABLED/READ_ONLY in cp2a, so
  `DefaultKeyguardBlueprint` is what renders. The slice section now inflates its own date view;
  it must still be added because the notification stack and AOD promoted-notification sections
  anchor to its `smart_space_barrier_bottom`, so it is added GONE and never bound.
- **"Discover Trust"** comes from lineage-sdk `TrustInterfaceService.onBootPhase(BOOT_COMPLETED)`
  while `LineageSettings.System.TRUST_INTERFACE_HINTED` is 0; LineageSettingsProvider has no
  default resource for that key. The bluejay overlay drops the service from
  `config_externalLineageServices` (lineage-sdk resources are static-RRO targets in the zygote:
  `OverlayConfig` maps `org.lineageos.platform-res.apk`), and a product sysconfig marks
  `org.lineageos.trust` unavailable so `TrustInterface` does not throw in LineageParts.
- **Org name.** `ApplianceProvisioning.apply` already calls
  `setOrganizationName(admin, "Phone Vault")` before anything else that can fail after the
  device-owner check; b0 showed "your organization" only because it never ran.

