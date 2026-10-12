# Re-hardening ladder (chunk 4)

(Crosshatch / Lineage 22.2 only. The Pixel 6a ladder — rungs b0… on Lineage 24.0 — lives in
`dev-ladder-bluejay/`.)

`vault-os/vendor/phonevault/`, `device/phonevault/` and `patches/` describe the **release
intent**. The development phone, however, boots an image whose tree deliberately deviates from
that intent: the multi-week boot failures were debugged by peeling hardening off until the
image booted (the DEBUG-40/44/47/48 markers), and the working state was never written down as
files — only as a tree on the build box.

This directory makes each step of putting the hardening back an explicit, reviewable,
boot-tested **rung**:

```
dev-ladder/
  rung-0/   the exact deviations that produced the known-good boot of 2026-09-02
  rung-1/   rung-0 minus one deviation (owner provisioning restored)
  rung-N/   …
```

A rung directory contains **only the files that still override release intent** at that rung,
plus `device-google-crosshatch.diff` for the two upstream device-tree edits. Climbing a rung
means deleting a file from the next rung directory, syncing, building, sideloading, and running
the boot-test checklist. When the last rung directory is empty, the tree *is* the release intent.

`scripts/dev-ladder-sync.sh RUNG /path/to/lineage` does the sync:

1. `rsync` the release `vendor/phonevault/` and `device/phonevault/` into the tree
   (keeping the tree's `keys/` — never versioned);
2. copy the rung's override files over their targets;
3. restore `device/google/crosshatch` (and the extract-utils makefiles of `vendor/google/crosshatch`)
   to upstream, then apply the rung's `device-google-crosshatch.diff` (and
   `vendor-google-crosshatch.diff`, from rung 2d-c2) — each rung carries exactly its own edits;
4. bake the current **dev-appliance** APK as `prebuilt/PhoneVault.apk` (rungs are dev images:
   `verify-signer-apk.sh` correctly refuses this variant, so the release path —
   `install-overlay.sh` with a release-signed APK — is not used here);
5. append the `BoardConfigVault.mk` include to the Lineage board file if missing.

Build with `dev-ladder/build-rung.sh` (userdebug, `WITH_ADB_INSECURE` while a rung still
carries the adb deviation), then flash with the sideload flow in `NOTES.md`.

## Rung log

| Rung | Deviation removed | Boot-tested | Notes |
|---|---|---|---|
| 0 | — (known-good baseline) | ✅ 2026-09-02 | overrides disabled (DEBUG48), AVB/VINTF/kernel fragment disabled (DEBUG44), minimal `common.mk` with insecure adb + pre-authorised key (DEBUG-47), owner string emptied (DEBUG-40), wifi-keystore HAL `optional`, branding boot animation |
| 1 | `config.xml` — `config_fixedFunctionDeviceOwner` restored | ⚠️ partial 2026-09-04 | OS provisioned the owner on a wiped /data (`mProvisioningContext=fixed-function-system-image`, `device_provisioned=1`) but HOME resolved to `org.lineageos.setupwizard` (priority 9) behind the keyguard: the app had never run, so its HOME preference did not exist |
| 1b | app provisions itself from `DeviceAdminReceiver.onEnabled` (`ApplianceProvisioning`: lock-task packages, persistent HOME, keyguard off, setup wizards hidden); `Android.bp` strips `LineageSetupWizard` | ✅ 2026-09-04 | genuine first boot (userdata+metadata erased) landed on SET PIN with zero adb: owner `fixed-function-system-image`, HOME=PhoneVault, `mLockTaskModeState=LOCKED`, keyguard off, 0 setupwizard packages. OTA `f0a836b4…` |
| 2a | `BoardConfigVault.mk` partially: `WITH_AVB`, our AVB key/algorithm for vbmeta + vbmeta_system, `board-info.txt` | ✅ boot 2026-09-05 | vbmeta in the OTA signed with our key (sha1 `75cadb14…`, SHA256_RSA4096, flags 3); this tree folds boot/dtbo/system/system_ext/product/vendor into the single vbmeta (no chained `vbmeta_system`). Booted (both slots): owner, provisioned, HOME, kiosk LOCKED, PIN gate, no popup. After a /data wipe restored adb: PIN-lifecycle (pintest 4/4, regentest 3/3, lifecycletest 6/6) ✓; AOA getAddress round-trip + host receive ✓ (host `address` rc=0, screen shows CONNECTED/WAITING). Full on-device sign-approval round-trip: transport proven, automation flaky (adb-server vs libusb), finish manually |
| 2b | `--flags 3` removed → verity and hashtree enforcement on | ✅ boot 2026-09-05 | OTA `385ece79` (rebuilt clean: wizard stripped, app 0.3.0 `7c803ca`). On device: `ro.boot.veritymode=enforcing`, `ro.boot.vbmeta.digest=7f16f2fb…` (bootloader processed our signed vbmeta; empty under 2a's flags 3), owner+kiosk survived the OTA, 0.3.0 UI up. Bootloader still unlocked → refuse-to-boot proof waits for relock (chunk 5). |
| 2c | appliance VINTF manifest + matrices | ✅ boot 2026-09-05 | device manifest loaded (28 HALs), our appliance manifest packaged; 0 VINTF/isBuildConsistent popup hits, owner+kiosk+verity intact, no app crash. OTA `469a1372`. |
| 2d-a | kernel fragment slice A: connectivity (BT/NFC/WLAN/CNSS/IPA/RMNET) `phonevault-a.config`; plus `etc/preferred-apps/phonevault-home.xml` (first-boot HOME chooser race seen on phone 2 at rung 2c, 2026-09-13; the Soong `overrides` route did not remove Trebuchet) | ✅ 2026-09-16 (phone 2) | OTA `7c57e435…`. The 2026-09-13 "did not boot" verdict was WRONG: the phone had simply left the USB port; on 09-16 it was found running slot B with 2.5 days of uptime. Verified: no bluetooth/nfc/wlan/cnss/ipa/rmnet modules, no `/sys/class/bluetooth`, no `wlan0`, verity enforcing, owner + kiosk LOCKED, backupcheck / usbsigntest / lifecycletest (reboot) all pass. Leftover `/dev/subsys_ipa_fws`, `ramdump_ipa_fws`, `rmnet_ctrl` nodes come from the PIL/subsystem-restart framework, not the removed drivers. |
| ~~2d-a1 / a2 / a23~~ | bisect of slice A | not needed | built 2026-09-13/14 while 2d-a was wrongly believed to hang; directories removed |
| 2d-b | slice B: modem/GLINK (`MODEMSMEM`, `MSM_PIL_MSS_QDSP6V5`, `MSM_GLINK_*`) `phonevault-b.config` (dir `rung-2d-b`, on top of 2d-a) | ✅ 2026-09-16 (phone 2) | OTA `353ae19b…` sideloaded 09-16 (the host saw `adb: failed to read command` right after the tap — that is the install proceeding on-device, not a failure). Booted slot A, verity enforcing, kiosk LOCKED, no `pil_mss` module (core `glink` transport remains, expected), usbsigntest + lifecycletest (reboot) pass with the ☰-menu app `9093e49c…`+. |
| 2d-c | slice C: camera / media / video codecs / DVB / sensor hub / touchscreen heatmap / compute-DSP `phonevault-c.config` + `CONFIG_PHONEVAULT_APPLIANCE=y` + kernel patch 0002 (carried in the rung dir; `dev-ladder-sync.sh` applies `rung-*/kernel-*.patch` to the kernel tree) | **PASSED 2026-09-27** on phone 2 (OTA f7624d38…): 0 cameras, no sensors, no DSP nodes, display fine; credential, USB tx and message signing pass. Found: vendor services for removed hardware crash-loop (cdsprpcd/adsprpcd/sscrpcd every 100 ms, gnss, NN HALs, easelmanagerd, ppd, cnss-daemon, sensors HAL) — flood logcat, cost battery; cleanup queued | a camera/media-only sub-slice without the patch fails to LINK (`sde_hw_rot` needs the V4L2 rotator, `heatmap.c` needs `video_unregister_device`) — so slice C goes in whole, with its patch |
| 2d-c2 | 2d-c + services for hardware the image no longer has are not installed: `vendor-google-crosshatch.diff` drops the rc + binary of `vendor.sensors` (sscrpcd), `vendor.sensors.qti`, `vendor.sensors-hal-2-0`, `neuralnetworks_hal_service(_paintbox)`, `easelmanagerd` and the `adsprpcd`/`cdsprpcd`/`cnss-daemon`/`mm-pp-dpps` binaries; the device diff removes the `adsprpcd`, `cdsprpcd`, `cnss-daemon`, `ppd` service blocks (and ppd's hwcomposer triggers) from `init.hardware.rc` and the GNSS HAL service/impl from `device.mk`. No VINTF change: none of these HALs is in the appliance manifest (that is why the HIDL ones crash-looped: hwservicemanager refused to register them). `dev-ladder-sync.sh` now resets device + vendor makefiles to upstream before applying a rung's diffs | built 2026-09-27 (OTA `43dd7c89…`), ready to flash | kept: audio HAL, camera provider, contexthub/CHRE, loc_launcher/lowi/xtra (not crash-looping; later slices) · **PASSED 2026-09-28** on phone 2: targeted loops gone, Titan M services up; usbsign, tokensign (5/5), msgsign, credential pass. Still looping: nfc_hal, chre, camera-provider (→ 2d-c3) |
| 2d-c3 | 2d-c2 + lock-screen cleanup and three more crash-loopers. (1) frameworks-base patch 0005 (`config_phonevaultHideKeyguardClock`, default false; overlay sets it true in `overlay/frameworks/base/packages/SystemUI`): the default keyguard blueprint leaves out the clock and smartspace sections and the date slice is detached, so no time/date on the keyguard or AOD; lock icon, bouncer, owner disclosure and charging line unchanged (blueprint path: `migrate_clocks_to_blueprint` is ENABLED/READ_ONLY in bp1a). `dev-ladder-sync.sh` now applies every `patches/frameworks-base/*.patch` (0001-0004 are already commits in the tree). (2) No ambient display: overlay restores the AOSP doze defaults (empty `config_dozeComponent`, AOD unavailable, no pickup pulse). (3) Wallpaper: the Phone Vault overlay lost to `vendor/lineage/overlay/common` (earlier `PRODUCT_PACKAGE_OVERLAYS` entries win and common.mk is inherited last), which on the build box holds a hand-copied copy of the OLD padlock, so 2d-c/2d-c2 shipped the old image; the overlay is now added in `vault_crosshatch.mk` before any inherit (policy gate enforces it), and the wallpaper is a small centered padlock. (4) Device diff also drops `android.hardware.nfc@1.2-service`, `android.hardware.camera.provider@2.4-service_64` and `chre_daemon_msm` (all optional in the FCM, none in the appliance manifest). | built 2026-09-28 (OTA `3182bbd3…`, app `5d781e25…`), ready to flash | rungs before 2d-c3 still list the overlay in their own common.mk: rebuilding one with the new `vault_crosshatch.mk` would list the directory twice — drop that line first · **PASSED 2026-09-28** on phone 2 (OTA 3182bbd3…): boot lock screen has no clock/date, new centred padlock wallpaper, no crash loops (68 service exits over a full test run incl. reboot, all one-shot); usbsign, tokensign 5/5, msgsign 6/6, credential pass |
| 2d-d | 2d-c3 + slice D `phonevault-d.config`: USB gadget functions — only adb (FunctionFS) and Android Open Accessory remain; no mass storage/MTP/PTP/MIDI/HID/CCID/audio/cdev/diag/QDSS/GSI. DWC3 stays dual-role | **first attempt FAILED 2026-09-28** (OTA e6d32269…, also DUAL_ROLE/HOST off): booted, but USB never enumerated (host: error -71 from the running kernel; bootloader on the same port fine) — rolled back to slot b (2d-c3) with `fastboot --set-active`. Retry without the DWC3 role lines | the release defconfig patch 0001 also turns DUAL_ROLE/HOST off: fix it before release (keep dual-role; refuse host role in the USB HAL) · **retry PASSED 2026-10-10** on phone 2 (OTA 8ebda5bd…): USB enumerates, `svc usb setFunctions mtp` leaves `sys.usb.config=adb` (function gone); usbsign, tokensign 5/5, msgsign 6/6, credential pass |
| 3 | 2d-d + USB lock-down at the OS level (DWC3 stays dual-role in the kernel, per 2d-d). Device diff: (1) release device patch 0002 in the gadget HAL — `setCurrentUsbFunctions` rejects (CONFIGURATION_NOT_SUPPORTED, current gadget kept) anything but none / accessory / adb / accessory+adb, adb only with `ro.debuggable=1`; plus `getVendorFunctions()` returns nothing, so `vendor.usb.config` / `persist.vendor.usb.usbradio.config` / usbradio boot mode can no longer append diag/serial/rmnet outside that allowlist. (2) Release patch 0003 in the port HAL — `switchRole` refuses source power role, host data role and DFP/DRP mode; plus a failed mode switch falls back to `sink` instead of `dual`, and port status reports UFP-only with no role/mode changes. (3) `init.sdm845.usb.rc`: port pinned with `write /sys/class/typec/port0/port_type sink` on boot and again on boot_completed (tcpm then presents Rd only: charges, is a USB device, never sources VBUS or hosts, rejects DR/PR_SWAP; same write stock off-mode charging does); only `accessory.gs2` is created unconditionally, `ffs.adb` only `on early-boot && property:ro.debuggable=1`; audio_source/MIDI/MTP/PTP/diag/cser/gsi/QDSS instances, the mtp/ptp FunctionFS mounts, `sys.usb.mtp.device_type`, the RNDIS class id and the charger-mode MIDI gadget are gone. (4) The dwc3 `id` node (writing 0 forces host mode) is no longer chowned to system. (5) `android.hardware.usb.host` feature not declared. `common.mk` adds `ro.vendor.phonevault.offline=true` (vendor property; only these two HALs read it in this tree) and keeps `persist.sys.usb.config=adb` — the user build (rung 5) sets `none`, AOA links accessory on attach | built 2026-10-10, not flashed (OTA `03227ed6…`, app `c5def7d6…`) | release patch 0001 replaces this rc wholesale with `init.phonevault.usb.rc`; the rung edits the stock rc instead (smaller step from the 2d-d boot). Recovery keeps the stock DRP port (sideload only) · **PASSED 2026-10-10** on phone 2 (OTA 03227ed6…): `svc usb setFunctions` mtp / rndis / midi each refused by the gadget HAL ("Phone Vault rejected USB gadget functions: 0x5 / 0x21 / 0x9"), `sys.usb.config` stays `adb`; charging on USB; usbsign, tokensign 5/5, msgsign 6/6, credential (reboot) pass; 71 service exits over the run (one-shots). Not yet shown: an OTG device left unpowered (needs a physical test), port-role readout (`/sys/class/typec` is root-only) |
| 4a | rung 3 + the app strip, slice A: `Android.bp` overrides 40 more modules, user-facing apps that nothing in system_server or SystemUI binds at boot — the Trebuchet launcher (with `Launcher3QuickStep`, the AOSP module whose Trebuchet definition `required`s it, its overlay and the six icon-pack launcher overlays), camera/gallery/music/browser/clock/calendar/calculator/recorder/PDF apps, AudioFX, Updater, wallpaper/theme/avatar/sound pickers, dreams, EasterEgg, HTMLViewer, Tag, DeviceDiagnostics, DeviceAsWebcam, CameraExtensionsProxy, AccessibilityMenu, EmergencyInfo, SettingsIntelligence, DownloadProviderUi. Board, kernel, device/vendor diffs, `common.mk` = rung 3. Full list, mechanism and reasons: [Rung 4](#rung-4-app-strip) | **prepared, not built** | before flashing: `check-overrides.sh 4a` on the target-files must print OK (the 2026-09-13 Trebuchet override silently did nothing). HOME after the launcher goes: PhoneVault (priority 0) is the only HOME besides Settings' direct-boot `FallbackHome` (priority -1000) · **built 2026-10-11** (OTA 0fc70803…, 74 MB smaller than rung 3). `check-overrides.sh 4a`: every 4a module gone EXCEPT `Gallery2` (product) and `DeviceAsWebcam` (system priv-app) — **cause found 2026-10-11 (4b prep): the overrides worked** — neither APK (nor odex) was in the image; what survived were their dangling JNI-lib symlinks from an August build (`PRODUCT/app/Gallery2/lib/arm64/libjni_*.so → /product/lib64/…`, `SYSTEM/priv-app/DeviceAsWebcam/lib/arm64/libjni_deviceAsWebcam.so`), which soong_ui's stale-install cleaner cannot delete (see [Rung 4](#rung-4-app-strip), "Stale staging leftovers"). On the phone that is an APK-less dir PackageManager skips. No `build/make` change needed; `build-rung.sh` now scrubs such dirs before building. Not flashed yet · **PASSED 2026-10-11** on phone 2: checked removed apps absent, HOME = Phone Vault, kiosk LOCKED; usbsign, tokensign 5/5, msgsign 6/6, credential pass; 71 service exits. Crash log: 489 FATALs, all `org.protonaosp.elmyra` (sensor-less gesture service, removed in 4b) |
| 4b | 4a + slice B: 57 system-side modules bound only on demand (Active Edge `ElmyraService` + `GoogleParts`, telephony UI/role apps, backup, print, WebView + its feature, DocumentsUI/StorageManager/MtpService, LineageParts/Profiles/QuickAccessWallet, CDM/credential/DSU/cert/app-link/PAC/VPN/captive-portal/SE/BT-MIDI satellites, four unused providers, the non-radio Pixel blobs). Device diff additionally drops the Bluetooth, NFC (+ per-SKU ODM NFC/eSE/OMAPI, FeliCa) and OMAPI-UICC feature declarations: SystemServer then skips BluetoothManagerService and the APEX NFC app never creates NfcService (the `com.android.nfc` ANRs) | **built 2026-10-11**, not flashed (OTA `/home/aipg/rung-4b-ota.zip`, 812 MB, sha256 `419dbff59190cb23e10dc18c93cc782f06986bfb9dbfa3ef4436539864cd8246`; app `c5def7d6…`); `check-overrides.sh 4b`: **OK** — 98 active overrides, none packaged, 65 APKs remain (the build-time scrub removed the stale `Gallery2` / `DeviceAsWebcam` dirs and, before soong_ui could strand its JNI symlink, `PrintSpooler`'s) | build only after 4a passes. Kept for later rungs: the telephony core + radio glue, NetworkStack, the media providers, ManagedProvisioning, the APEXes (see [Rung 4](#rung-4-app-strip)) · **first flash FAILED 2026-10-11**: boot loop — system_server `IllegalStateException: Call to getInstalledModules before metadata loaded` (ModuleMetadata was removed); log captured over adb during the loop, rolled back to slot a (4a) with `fastboot --set-active`. Rebuilt keeping ModuleMetadata. Also seen: `com.android.nfc` / `com.android.bluetooth` remain installed (APEX-bundled; features withdrawn instead) · **rebuild PASSED 2026-10-11** on phone 2 (OTA 9ee2c7c2…): boots, 160 packages (4a: 221), HOME = Phone Vault, kiosk LOCKED, crash log empty (Elmyra gone), usbsign / tokensign 5/5 / msgsign 6/6 pass; credentialtest passed on rerun (first run hit one "Backup unavailable" after a successful PIN check — seed-key window race; app now re-prompts once instead) · **root-caused 2026-10-11, app-side, not a 4b removal**: keystore2 admits the seed key's `Cipher.init` until ~31 s after it *received* the PIN token (whole seconds), the Titan M refuses the update after 30.000 s from the token's *issue* time; a controlled sweep fails every decrypt at +29.7…+30.8 s on **both** 4a and 4b (4/4 each), and the harness's "inside the window" reveal lands right there (4a +29.3 s ×2 pass, 4b +30.0/+30.2 s fail). The re-prompt never worked (re-entered `beginSensitive`, stuck on "Opening secure backup"). Also a cold-start race made the vault prompt again after the boot PIN on 4b (2/2). App fix: no edge probing after our own PIN check, full-operation probe, same-flow retry, one boot gate per session ([pin-credential-design.md](../docs/pin-credential-design.md)); then on 4b: credentialtest 3/3 in a row incl. reboot, usbsign pass. No rung change |
| 4c… | `Android.bp` overrides in further slices (telephony/radio + system_server gating → media → APEXes → vendor prune; ManagedProvisioning needs a wiped first boot of its own) | planned | chunk-4 item 4 |
| final | `common.mk` release version, no `debug_adbkey.pub`, `user` variant | planned | chunk-4 item 5 |

## Per-rung checklist (all must pass before the next rung)

1. `vault-os/tests/*.sh` policy gates on the repo.
2. Build → OTA → sideload (recovery signature tap until the OTA key is trusted) → boot.
3. Owner + kiosk: `dumpsys device_policy` shows the owner, `mLockTaskModeState=LOCKED`,
   `settings get global device_provisioned` = 1, no setup wizard.
4. PIN lifecycle (`tools/dev-device/pintest.sh` on a throwaway wallet), identity persists
   across a reboot, USB signing round-trip with `tools/aoa_client.py`.
5. Rollback image at hand: `/root/rollback/known-good-2026-09-02.zip` (sha256 `0de27021…`).

## Rung 4: app strip

Prepared 2026-10-10 from the rung-3 build output on the build box (`out/target/product/crosshatch`
target-files, 152 APKs) and its sources; nothing was built. `rung-4a/` and `rung-4b/` are full
rung directories (copies of rung 3 plus the changes below), synced and built like any rung:
`dev-ladder-sync.sh 4a …`, `build-rung.sh 4a`, then **`check-overrides.sh 4a`** before sideloading.

### Removal mechanism, and why

Soong `overrides` on the PhoneVault module (`rung-4*/Android.bp`), extended slice by slice. That is
the release intent's mechanism (the commented DEBUG48 list), it already removes LineageSetupWizard
since rung 1b, and it is the only product-level tool that works on this build system:

- **`PRODUCT_PACKAGES -=` / `filter-out` cannot work.** `inherit-product` does not include the
  parent; it appends an `@inherit:<file>` placeholder to every product list
  (`build/make/core/product.mk`), and `node_fns.mk` expands the placeholders only after all nodes
  are imported. In the leaf, `PRODUCT_PACKAGES` holds placeholders, not Lineage's entries; after
  expansion the variable is `.KATI_READONLY`. (`-=` is not even a GNU Make operator.) There is no
  `PRODUCT_PACKAGES_REMOVE`-style variable in this tree (`_product_list_vars` checked).
- **Lineage's opt-out knobs set in `common.mk` are dead.** `_import-node` includes a makefile and
  then its inherited children in *sorted path order*, depth first. `vault_crosshatch.mk`'s children
  sort as `device/google/crosshatch/lineage_crosshatch.mk` (which pulls in all of
  `vendor/lineage/config`) → `vendor/google/…` → `vendor/phonevault/config/common.mk`, so
  `TARGET_EXCLUDES_AUDIOFX`, `PRODUCT_NO_CAMERA`, `PRODUCT_NO_DYNAMIC_SYSTEM_UPDATE` and
  `TARGET_DISABLE_LINEAGE_SDK` are assigned after Lineage/AOSP already tested them: AudioFX,
  Aperture, DynamicSystemInstallationService and the Lineage SDK are all in the rung-3 image. Such
  knobs only work when set in the leaf `vault_crosshatch.mk` (included before every child). Rung 4
  does not rely on them; the release `common.mk` lines need that fix (follow-up), and
  `TARGET_DISABLE_LINEAGE_SDK` must NOT simply be made effective: Lineage's SystemUI/Settings use
  the SDK and LineageSettingsProvider.
- **Editing `vendor/lineage/config/*.mk` / `build/make/target/product/*.mk` via a rung diff** would
  also work, but scatters the removal over three upstream trees (two of them not ladder-managed
  today) and loses the single reviewable list.
- **Why `overrides` failed for Trebuchet on 2026-09-13, and the trap it shows.**
  `product-installed-modules` (main.mk) drops every overridden name before expanding `required`, so
  an override beats any inherited `PRODUCT_PACKAGES` entry. But
  `add-all-target-to-target-required-modules-deps` separately makes an installed module's files
  depend on the files of everything it `required`s, so a module that something *installed*
  requires gets staged into the partition anyway. A scan of every Soong module's
  `LOCAL_REQUIRED_MODULES` (`out/soong/Android-vault_crosshatch.mk`) against the 4a/4b list found
  three such edges: `Launcher3QuickStep → TrebuchetQuickStep` (AOSP lists Launcher3QuickStep in
  `handheld_system_ext.mk`; Lineage's Trebuchet `Android.bp` defines it with
  `required: ["TrebuchetQuickStep"]`), `Aperture → ApertureLensLauncher` and
  `Seedvault → LocalContactsBackup`. Both ends of each are overridden. (On paper Trebuchet's own
  override of Launcher3QuickStep should already have cut the first edge, so the 09-13 result is not
  fully explained from sources; whatever the cause, `check-overrides.sh` now proves the result on
  the target-files instead of assuming it.) No Android.mk module in the device/vendor/Lineage trees
  `required`s a removed module.

- **Stale staging leftovers (the 4a "survivors").** An app with embedded JNI libs is installed with
  `lib/<abi>/*.so` symlinks pointing at absolute *device* paths (`/product/lib64/…`). When the app
  stops being installed, soong_ui's `cleanOldFiles` (`build/soong/ui/build/cleanbuild.go`) removes
  every path that left `.installable_files`, but tests each with `os.Stat`, which follows the
  symlink, finds no such host path and silently skips it. The APK and odex go; the dangling
  symlinks stay in `out/target/product/crosshatch/`, and target-files and the partition images copy
  that staging tree wholesale. In 4a that was `Gallery2` and `DeviceAsWebcam` (the only 4a apps
  with JNI libs); in 4b it would have been `PrintSpooler`. Neither a `build/make` diff nor anything
  else at the product level can fix it — the module is already not installed. `build-rung.sh`
  therefore deletes, before building, every staged `app|priv-app/<name>/` dir that has no APK and
  every one named in the rung's active `overrides` (if an overridden module really is still
  installed, ninja re-creates it and `check-overrides.sh` fails as it should). `check-overrides.sh`
  marks a hit without an APK as a "stale staging leftover".

### HOME without Trebuchet

HOME candidates left after 4a (manifests read from the rung-3 APKs): PhoneVault `MainActivity`
(MAIN/HOME/DEFAULT, priority 0), Settings `FallbackHome` (priority -1000, direct-boot aware: it
covers the window before the credential unlocks CE storage after a reboot and finishes itself on
unlock), and ManagedProvisioning `PostEncryptionActivity` (`enabled=false`). The resolver picks the
higher-priority match without a chooser, so PhoneVault is HOME even before
`etc/preferred-apps/phonevault-home.xml` or the owner's persistent preference apply; both stay in
place. On the already-provisioned phone the device-owner persistent preferred HOME takes precedence
over everything. Settings therefore stays (FallbackHome, confirm-credential and device-admin UIs).

### Removed in 4a (40 modules)

| Module | Package | Where (rung 3) | Why it is safe to remove |
|---|---|---|---|
| `TrebuchetQuickStep` | `com.android.launcher3` | system_ext/priv-app | launcher; PhoneVault is HOME (preferred-apps + owner persistent preference). SystemUI recents binding to the launcher just fails (lock task has no recents) |
| `Launcher3QuickStep` | — | not packaged today | not installed today (Trebuchet overrides it), but its Trebuchet definition `required`s TrebuchetQuickStep, so it is overridden too |
| `TrebuchetOverlay` | `com.android.launcher3.overlay` | product/overlay | RRO for the launcher |
| `IconPack{Circular,Filled,Kai,Rounded,Sam,Victor}LauncherOverlay` | (overlays) | product/overlay | RROs for the launcher (6 modules) |
| `Aperture` | `org.lineageos.aperture` | product/app | camera app; no camera since 2d-c |
| `ApertureLensLauncher` | `com.google.android.apps.googlecamera.fishfood` | product/app | required by Aperture |
| `AudioFX` | `org.lineageos.audiofx` | system_ext/priv-app | audio effects UI; the `TARGET_EXCLUDES_AUDIOFX` knob in common.mk is evaluated too late to work |
| `Camelot` | `org.lineageos.camelot` | product/app | PDF viewer |
| `DeskClock` | `com.android.deskclock` | product/app | clock/alarms app |
| `Etar` | `org.lineageos.etar` | product/app | calendar app |
| `ExactCalculator` | `com.android.calculator2` | product/app | calculator |
| `Gallery2` | `com.android.gallery3d` | product/app | gallery |
| `Glimpse` | `org.lineageos.glimpse` | product/app | gallery |
| `Jelly` | `org.lineageos.jelly` | product/app | browser (default browser role is simply left empty) |
| `Recorder` | `org.lineageos.recorder` | product/app | sound recorder |
| `Twelve` | `org.lineageos.twelve` | product/app | music player |
| `Updater` | `org.lineageos.updater` | system_ext/priv-app | Lineage OTA client; the appliance updates only by signed sideload |
| `AvatarPicker` | `com.android.avatarpicker` | system/priv-app | user-avatar picker |
| `Backgrounds` | `org.lineageos.backgrounds` | product/app | wallpaper picker |
| `BasicDreams` | `com.android.dreams.basic` | system/app | default dream component; if the screensaver ever triggers, DreamManagerService fails the bind and lets the screen sleep (on-phone check 6) |
| `EasterEgg` | `com.android.egg` | system/app | easter egg |
| `HTMLViewer` | `com.android.htmlviewer` | system/app | opens legal HTML from Settings |
| `LiveWallpapersPicker` | `com.android.wallpaper.livepicker` | system/priv-app | live-wallpaper picker |
| `PhotoTable` | `com.android.dreams.phototable` | product/app | dream |
| `SoundPicker` | `com.android.soundpicker` | system/priv-app | ringtone picker |
| `ThemePicker` | `com.android.wallpaper` | system_ext/priv-app | wallpaper/style picker (SystemUI keeps its own ImageWallpaper) |
| `ThemesStub` | `com.android.customization.themes` | product/app | theme stub for ThemePicker |
| `AccessibilityMenu` | `com.android.systemui.accessibility.accessibilitymenu` | system_ext/app | accessibility service, never enabled |
| `CameraExtensionsProxy` | `com.android.cameraextensions` | system/app | bound only by CameraExtensionCharacteristics; cameraserver disabled |
| `DeviceAsWebcam` | `com.android.DeviceAsWebcam` | system/priv-app | UVC webcam service; started by UsbService only for the UVC function, which the gadget HAL rejects |
| `DeviceDiagnostics` | `com.android.devicediagnostics` | system/priv-app | diagnostics UI |
| `DownloadProviderUi` | `com.android.providers.downloads.ui` | system/priv-app | downloads UI (DownloadProvider stays) |
| `EmergencyInfo` | `com.android.emergency` | system_ext/priv-app | emergency-info UI linked from Settings/dialer |
| `SettingsIntelligence` | `com.android.settings.intelligence` | product/priv-app | Settings search/suggestions; Settings is not reachable in the kiosk |
| `Tag` | `com.android.apps.tag` | system/priv-app | NFC tag viewer; no NFC |

### Removed in 4b (57 modules, on top of 4a)

| Module | Package | Where (rung 3) | Why it is safe to remove |
|---|---|---|---|
| `ElmyraService` | `org.protonaosp.elmyra` | system_ext/priv-app | Active Edge; persistent, directBootAware, crash-loops without the squeeze sensors (slice C) |
| `GoogleParts` | `org.lineageos.settings` | system_ext/priv-app | Active Edge / device "Advanced settings"; persistent system-uid app, nothing else uses it |
| `CallLogBackup` | `com.android.calllogbackup` | system/priv-app | call-log backup agent |
| `CarrierDefaultApp` | `com.android.carrierdefaultapp` | system/app | carrier captive-portal / signal UI, only on carrier signals |
| `CellBroadcastLegacyApp` | `com.android.cellbroadcastreceiver` | system/priv-app | legacy CB settings provider; the cellbroadcast APEX tolerates its absence (migration is try/catch) |
| `Contacts` | `com.android.contacts` | product/priv-app | contacts UI |
| `Dialer` | `com.android.dialer` | product/priv-app | dialer UI / dialer role holder; no calls (no modem since 2d-b) |
| `SimAppDialog` | `com.android.simappdialog` | system/app | SIM setup dialog, only with a SIM |
| `Stk` | `com.android.stk` | system/app | SIM toolkit, only with a SIM |
| `messaging` | `com.android.messaging` | product/app | SMS UI / SMS role holder; no radio |
| `BackupRestoreConfirmation` | `com.android.backupconfirm` | system/priv-app | adb backup confirmation UI; backup service is off under a device owner |
| `LocalContactsBackup` | `org.calyxos.backup.contacts` | product/app | required by Seedvault |
| `LocalTransport` | `com.android.localtransport` | system/priv-app | test backup transport |
| `Seedvault` | `com.stevesoltys.seedvault` | system_ext/priv-app | Lineage backup transport (a vault must never export data) |
| `SharedStorageBackup` | `com.android.sharedstoragebackup` | system/priv-app | backup agent for shared storage |
| `WallpaperBackup` | `com.android.wallpaperbackup` | system/app | backup agent for the wallpaper |
| `BuiltInPrintService` | `com.android.bips` | system/priv-app | print plugin |
| `PrintRecommendationService` | `com.android.printservice.recommendation` | system/app | print plugin recommender |
| `PrintSpooler` | `com.android.printspooler` | system/app | print spooler; PrintManagerService binds it lazily and logs a bind failure at most |
| `webview` | `com.android.webview` | product/app | WebView provider; nothing on the appliance renders web content |
| `android.software.webview.prebuilt.xml` | (feature file) | system/etc/permissions/android.software.webview.xml | the `android.software.webview` feature: without it SystemServer does not start WebViewUpdateService |
| `DocumentsUI` | `com.android.documentsui` | system/priv-app | SAF file picker / Files |
| `DocumentsUIOverlay` | `com.android.documentsui.overlay` | product/overlay | Lineage RRO for DocumentsUI |
| `MtpService` | `com.android.mtp` | system/priv-app | MTP documents provider; MTP refused by the gadget HAL since rung 3 |
| `StorageManager` | `com.android.storagemanager` | system_ext/priv-app | storage clean-up UI / automatic storage manager |
| `LineageParts` | `org.lineageos.lineageparts` | system_ext/priv-app | Lineage settings UI (Trust, stats, profiles UI); the SDK services and LineageSettingsProvider stay |
| `Profiles` | `org.lineageos.profiles` | system_ext/app | Lineage profiles UI |
| `QuickAccessWallet` | `com.android.systemui.plugin.globalactions.wallet` | system_ext/priv-app | SystemUI wallet plugin; plugin absence is the default case |
| `BluetoothMidiService` | `com.android.bluetoothmidiservice` | system/app | BT MIDI; Bluetooth feature dropped in this rung |
| `CaptivePortalLogin` | `com.android.captiveportallogin` | system/app | launched by NetworkStack on a captive portal; no network |
| `CertInstaller` | `com.android.certinstaller` | system/app | user CA/cert install UI |
| `CompanionDeviceManager` | `com.android.companiondevicemanager` | system/app | CDM pairing UI |
| `CredentialManager` | `com.android.credentialmanager` | system/priv-app | Credential Manager selector UI |
| `DynamicSystemInstallationService` | `com.android.dynsystem` | system/priv-app | DSU (GSI) installer; `PRODUCT_NO_DYNAMIC_SYSTEM_UPDATE` in common.mk is evaluated too late to work |
| ~~`ModuleMetadata`~~ **KEPT** | `com.android.modulemetadata` | product/app | REQUIRED: without it `ModuleInfoProvider` never loads metadata and `AppRestrictionController.onSystemReady` → `getInstalledModules` throws "Call to getInstalledModules before metadata loaded": system_server crash loop (4b first build, phone 2, 2026-10-11) |
| `PacProcessor` | `com.android.pacprocessor` | system/app | PAC proxy resolver, bound only when a PAC URL is set |
| `ProxyHandler` | `com.android.proxyhandler` | system/priv-app | PAC proxy handler, same |
| `SecureElement` | `com.android.se` | system/app | OMAPI service; OMAPI feature dropped in this rung, SE HAL is the -disabled stub |
| `StatementService` | `com.android.statementservice` | system/priv-app | app-link verification agent; DomainVerificationService runs without one |
| `VpnDialogs` | `com.android.vpndialogs` | system/priv-app | VPN consent UI |
| `BookmarkProvider` | `com.android.bookmarkprovider` | system/app | browser bookmarks provider |
| `CalendarProvider` | `com.android.providers.calendar` | system/priv-app | calendar provider (Etar gone in 4a) |
| `E2eeContactKeysProvider` | `com.android.providers.contactkeys` | system/priv-app | contact-keys provider |
| `PartnerBookmarksProvider` | `com.android.providers.partnerbookmarks` | system/app | partner bookmarks provider |
| `AmbientSensePrebuilt` | `com.google.intelligence.sense` | product/priv-app | Now Playing (ambient music) |
| `DeviceIntelligenceNetworkPrebuilt` | `com.google.android.as.oss` | product/priv-app | Private Compute Services (network) |
| `DevicePersonalizationPrebuiltPixel3` | `com.google.android.as` | product/priv-app | Pixel AiAi: the device overlay names it for system intelligence roles and content-suggestion/app-prediction/caption services; those services treat a missing package as "no service" |
| `HardwareInfo` | `com.google.android.hardwareinfo` | product/priv-app | hardware-info provider for Settings |
| `HotwordEnrollmentOKGoogleWCD9340` | `com.android.hotwordenrollment.okgoogle` | product/priv-app | hotword enrollment (no assistant, no mic use) |
| `HotwordEnrollmentXGoogleWCD9340` | `com.android.hotwordenrollment.xgoogle` | product/priv-app | hotword enrollment |
| `MobileFeliCaClient` | `com.felicanetworks.mfc` | product/app | FeliCa (Japan NFC payments); no NFC |
| `MobileFeliCaMenuMainApp` | `com.felicanetworks.mfm.main` | product/app | FeliCa |
| `MobileFeliCaSettingApp` | `com.felicanetworks.mfs` | product/app | FeliCa |
| `MobileFeliCaWebPlugin` | `com.felicanetworks.mfw.a.main` | product/app | FeliCa |
| `MobileFeliCaWebPluginBoot` | `com.felicanetworks.mfw.a.boot` | product/app | FeliCa |
| `PixelCameraServicesCrosshatch` | `com.google.android.apps.camera.services` | product/app | camera extension service; no camera |
| `com.qualcomm.qti.services.secureui` | `com.qualcomm.qti.services.secureui` | system_ext/app | Qualcomm TEE secure-UI app; unused (the vault PIN is Gatekeeper/Weaver on Titan M) |

Device diff (4b): `device.mk` no longer copies `android.hardware.bluetooth.xml`,
`android.hardware.bluetooth_le.xml`, `android.hardware.nfc{,.hce,.hcef}.xml`, `com.nxp.mifare.xml`,
`android.hardware.se.omapi.uicc.xml`, the per-SKU ODM `nfc.uicc` / `nfc.ese` / `se.omapi.ese`
files, or the FeliCa `com.google.hardware.pixel.japan.xml`. Without `android.hardware.bluetooth`
SystemServer logs "No Bluetooth Service" and never starts BluetoothManagerService (so the
`com.android.bluetooth` app in the btservices APEX is never started); without any NFC feature
`android.hardware.nfc.any` is gone and `NfcApplication` returns before creating NfcService — that
is the fix for the `com.android.nfc` ANRs, because the NFC app itself lives in the
`com.android.nfcservices` APEX and cannot be overridden like an APK. The APEXes stay until the APEX
rung (their framework jars are on the boot classpath; removing them is a classpath change). The rest
of the rung-3 device diff is unchanged (diff regenerated from upstream `device.mk`, preimage
`651cd6c` matches rung 3's).

### Kept, and why

| Module (package) | Why it stays |
|---|---|
| PhoneVault (`dev.phonevault.signer`) | the appliance |
| SystemUI (`com.android.systemui`) | keyguard, boot PIN bouncer (own NumPad, no IME), BiometricPrompt credential UI, status bar |
| LatinIME (`com.android.inputmethod.latin`) | **the only IME, and it is needed**: the boot keyguard has its own PIN pad, but the vault's step-up prompt (BiometricPrompt, DEVICE_CREDENTIAL) is SystemUI's `auth_credential_password_pin_content_view` — an `ImeAwareEditText` that calls `scheduleShowSoftInput()`; AOSP ships no `pin_pad` there. The harness keys the PIN with `input text`, which bypasses the IME, so the tests would not notice its removal |
| UserDictionaryProvider | LatinIME's dictionary provider |
| SettingsProvider, Settings | settings storage; `FallbackHome`, confirm-credential and device-admin screens |
| PackageInstaller | PackageManagerService throws "There must be exactly one installer/uninstaller" at boot without it |
| PermissionController (APEX), ExtShared (`android.ext.shared`) | PMS requires a permission controller and the `android.ext.shared` system shared library at boot |
| FusedLocation | LocationManagerService throws "Unable to find a direct boot aware fused location provider" (DEBUG-39 put it back for this reason) |
| Shell | dev adb (`com.android.shell`); revisit for the user build |
| IntentResolver, KeyChain, InputDevices | framework chooser/resolver, keystore/cert plumbing used by DPM, keyboard-layout receiver |
| LineageSettingsProvider, SimpleDeviceConfig, SimpleSettingsConfig | Lineage framework and SystemUI read LineageSettings; boot-time DeviceConfig/settings defaults |
| TimeService (`com.qualcomm.timeservice`) | persists the user/RTC time offset via time_daemon; without it the clock resets on reboot |
| TeleService, Telecom, TelephonyProvider, CarrierConfig, ContactsProvider, BlockedNumberProvider, MmsService, ONS, ImsServiceEntitlement, ims, qcrilmsgtunnel, QtiTelephonyService, uceShimService, PresencePolling, RcsService, uimremoteclient/server, grilservice, RilConfigService, CneApp, IWlanService and the carrier blobs (CarrierServices, CarrierSettings, CarrierWifi, CarrierSetup, ConnMO, DCMO, DMService, DiagMon, EuiccGoogle, EuiccSupportPixel(+Permissions), OemDmTrigger, SprintDM, SprintHM, TetheringEntitlement, USCCDM, WfcActivation, AppDirectedSMSService, MyVerizonServices, OBDM_Permissions, obdm_stub, VZWAPNLib) | telephony rung: TeleService is persistent and binds several of these at boot while the telephony/IMS/eUICC features are still declared; they go together with the system_server gating and the vendor-mk removal of their permission XMLs (release appliance patch 0003) |
| NetworkStack (and the connectivity / wifi / tethering APEXes) | network rung (ConnectivityService needs a network stack module) |
| MediaProviderLegacy, DownloadProvider, ExternalStorageProvider | media rung (shared `android.media` uid, MediaProvider APEX, StorageManagerService) |
| ManagedProvisioning | DevicePolicyManagerService plumbing; the fixed-function owner patch bypasses it, but removal needs its own wiped-first-boot test (4c) |
| com.android.nfc / com.android.bluetooth (inside APEXes) | APEX rung; made dormant in 4b by the feature removal |

### On-phone checks

Before flashing either rung: `check-overrides.sh RUNG` on the build box prints OK.

**4a** (after the per-rung checklist above: owner, kiosk LOCKED, provisioned, PIN suites):

1. `adb shell pm list packages | sort` — none of the 4a packages; `cmd package resolve-activity
   --brief -c android.intent.category.HOME -a android.intent.action.MAIN` → `dev.phonevault.signer/.MainActivity`.
2. **First boot on wiped userdata+metadata** (the case the launcher chooser hit): lands on SET PIN
   with no chooser and no "Select a home app" dialog, owner `fixed-function-system-image`,
   `mLockTaskModeState=LOCKED`.
3. Reboot with a credential set: boot keyguard shows the PIN pad, `FallbackHome` covers the locked
   window, after the PIN Home is PhoneVault (credentialtest reboot step).
4. **Manual, not covered by the harness**: open "Show recovery phrase" (or any step-up prompt) and
   check the soft keyboard appears in the system PIN prompt (`dumpsys input_method | grep
   mInputShown` = true while it is up). LatinIME stays, this guards against an IME regression.
5. `logcat -b crash` empty over the run; `dumpsys activity service OverviewProxyService` may show
   the recents connection failing (no launcher) — expected, must not loop at high frequency.
6. Screen timeout while on USB power: screen goes off normally (no dream bound, no "Unable to bind
   dream" loop).
7. usbsign, tokensign 5/5, msgsign 6/6, credential (reboot), lifecycletest pass.

**4b**, additionally:

1. `pm list packages` — none of the 4b packages; `pm list features` has no `android.hardware.nfc*`,
   `android.hardware.bluetooth*`, `android.hardware.se.omapi.*`, `android.software.webview`,
   `com.google.hardware.pixel.japan`.
2. No `com.android.nfc` ANR / no `NfcService` init in logcat; `dumpsys nfc` reports no service or a
   dormant app; `org.protonaosp.elmyra` absent and no crash loop; `service list | grep -c
   bluetooth_manager` = 0 and `logcat | grep 'No Bluetooth Service'`.
3. `service list | grep -c webviewupdate` = 0, and nothing crashes on its absence (SystemUI,
   Settings, PhoneVault stay up across the full suite).
4. `dumpsys print` / `dumpsys backup` do not crash system_server (print spooler bind failure at
   unlock is logged at most once).
5. Service-exit count over the full run stays in the rung-3 range (≈70, one-shots only); battery
   drain over an idle hour is no worse than rung 3.
6. Same app suites as 4a, plus a wiped first boot.
7. The 4a leftovers are gone: `adb shell ls -d /product/app/Gallery2 /system/priv-app/DeviceAsWebcam
   /system/app/PrintSpooler` → all "No such file or directory" (no APK-less app dirs left).

Follow-ups noticed while preparing:

- Lineage's "Discover Trust" lock-screen notification is posted by the SDK's
  `TrustInterfaceService` (system_server) until `LineageSettings.System.TRUST_INTERFACE_HINTED` is
  1; removing LineageParts only removes the activity it links to. Set that default in the vault
  overlay (LineageSettingsProvider) in a later rung.
- `config_recentsComponentName` still names Trebuchet's RecentsActivity; overlay it empty when the
  overlay is next touched, so SystemUI stops retrying the recents binding.
- Release `vault_crosshatch.mk`/`common.mk`: move `PRODUCT_NO_CAMERA`, `TARGET_EXCLUDES_AUDIOFX`,
  `PRODUCT_NO_DYNAMIC_SYSTEM_UPDATE` into the leaf (see above); keep `overrides` as the removal list.
