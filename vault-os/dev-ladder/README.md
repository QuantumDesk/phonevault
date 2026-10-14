# Re-hardening ladder (Pixel 3 XL / crosshatch)

(Crosshatch / LineageOS 22.2 only. The Pixel 6a ladder, rungs b0… on LineageOS 24.0, lives in
[`../dev-ladder-bluejay/`](../dev-ladder-bluejay/README.md).)

`vault-os/vendor/phonevault/`, `device/phonevault/` and `patches/` describe the **release
intent**. The first images that booted on the development phone did so only after much of that
hardening had been peeled off (the `DEBUG-40/44/47/48` markers in rung 0). This ladder puts the
hardening back one explicit, reviewable, boot-tested **rung** at a time:

```
dev-ladder/
  rung-0/   the deviations of the first known-good development boot
  rung-1/   rung-0 minus one deviation (owner provisioning restored)
  rung-N/   …
```

A rung directory contains **only the files that still override release intent** at that rung,
plus `device-google-crosshatch.diff` (and, from rung 2d-c2, `vendor-google-crosshatch.diff`)
for upstream device-tree edits, and kernel config fragments / patches where the rung needs them.
Climbing a rung means removing a deviation, syncing, building, flashing and running the
per-rung checklist. When the last rung directory is empty, the tree *is* the release intent.
The release configuration already folds in everything proven through rung 4b
([release-config.md](../docs/release-config.md)).

## Using the ladder

Paths below are placeholders: `$LINEAGE_TREE` is your LineageOS 22.2 tree with the crosshatch
device, vendor and kernel repos, `$OUT_DIR` where the rung OTA goes.

`scripts/dev-ladder-sync.sh RUNG $LINEAGE_TREE [APK]` syncs a rung into the tree:

1. `rsync` the release `vendor/phonevault/` and `device/phonevault/` into the tree (keeping the
   tree's `keys/`, which are never versioned);
2. copy the rung's override files over their targets;
3. restore `device/google/crosshatch` (and the extract-utils makefiles of
   `vendor/google/crosshatch`) to upstream, then apply the rung's diffs, so each rung carries
   exactly its own edits; apply `rung-*/kernel-*.patch` to the kernel tree and every
   `patches/frameworks-base/*.patch` not already in the tree;
4. bake the **dev-appliance** APK as `prebuilt/PhoneVault.apk` (rungs are development images:
   `verify-signer-apk.sh` correctly refuses this variant, so the release path, `install-overlay.sh`
   with a release-signed APK, is not used here);
5. append the `BoardConfigVault.mk` include to the Lineage board file if missing.

**Development adb key.** Rung images are `userdebug` with adb pre-authorised for the builder. No
adb key is committed: the sync reads your public adb key from the path in `PV_DEV_ADB_KEY`
(for example `~/.android/adbkey.pub`) and installs it only in the build tree. The release
configuration carries no adb key, and the release-source gate refuses one.

Build with `dev-ladder/build-rung.sh RUNG` as the tree owner (never root; `PV_TREE` names the
tree, `PV_OUT_DIR` the output directory, i.e. `$LINEAGE_TREE` and `$OUT_DIR`): a `userdebug`
build with `WITH_ADB_INSECURE` while the rung still carries the adb deviation, producing
`rung-RUNG-ota.zip`. From rung 4a, run `dev-ladder/check-overrides.sh RUNG TARGET_FILES` on the
target-files before flashing; it must print OK.

Flash with `dev-ladder/flash-rung.sh RUNG [--wipe]` (`PV_OTA` = the OTA, `PV_SERIAL` = the
phone's serial). It sideloads the OTA; until the OTA key is trusted, the recovery shows
"Signature verification failed — install anyway?" and someone must confirm on the phone.
`--wipe` erases userdata and metadata afterwards so the next boot is a genuine first boot; it
destroys the on-device wallet and requires `PV_THROWAWAY_DEVICE=1`. The script refuses to run
while any other device is attached. `dev-ladder/wipe-data.sh` erases userdata and metadata on
its own, under the same rules.

## Rung log

| Rung | Deviation removed / change | Result on hardware | Notes |
|---|---|---|---|
| 0 | — (known-good baseline) | boots | overrides disabled (DEBUG48), AVB/VINTF/kernel fragment disabled (DEBUG44), minimal `common.mk` with insecure adb + pre-authorised key (DEBUG-47), owner string emptied (DEBUG-40), wifi-keystore HAL `optional`, branding boot animation |
| 1 | `config.xml`: `config_fixedFunctionDeviceOwner` restored | partial | the OS provisioned the owner on wiped /data (`fixed-function-system-image`, `device_provisioned=1`), but HOME resolved to the Lineage setup wizard behind the keyguard: the app had never run, so its HOME preference did not exist. Fixed in 1b |
| 1b | the app provisions itself from `DeviceAdminReceiver.onEnabled` (`ApplianceProvisioning`: lock-task packages, persistent HOME, keyguard off, setup wizards hidden); `Android.bp` strips `LineageSetupWizard` | passed | genuine first boot (userdata + metadata erased) lands on SET PIN with no adb interaction: owner `fixed-function-system-image`, HOME = Phone Vault, `mLockTaskModeState=LOCKED`, keyguard off, no setup-wizard packages |
| 2a | `BoardConfigVault.mk` partially: `WITH_AVB`, our AVB key/algorithm for vbmeta, `board-info.txt` | passed | vbmeta signed with our key (SHA256_RSA4096, flags 3); this tree folds boot/dtbo/system/system_ext/product/vendor into the single vbmeta (no chained `vbmeta_system`). Owner, provisioning, HOME, kiosk, PIN lifecycle and AOA `getAddress` pass |
| 2b | `--flags 3` removed: verity and hashtree enforcement on | passed | `ro.boot.veritymode=enforcing`, `ro.boot.vbmeta.digest` set; owner and kiosk survive the OTA. The bootloader is still unlocked, so the refuse-to-boot proof waits for the relock |
| 2c | appliance VINTF manifest + matrices | passed | device manifest loads, no VINTF / `isBuildConsistent` popup, owner, kiosk and verity intact |
| 2d-a | kernel fragment slice A: connectivity (BT/NFC/WLAN/CNSS/IPA/RMNET) `phonevault-a.config`; `etc/preferred-apps/phonevault-home.xml` against a first-boot HOME-chooser race | passed | no bluetooth/nfc/wlan/cnss/ipa/rmnet modules, no `/sys/class/bluetooth`, no `wlan0`; backup check, USB signing and lifecycle (reboot) pass. Leftover `/dev/subsys_ipa_fws`, `ramdump_ipa_fws`, `rmnet_ctrl` nodes come from the PIL/subsystem-restart framework, not the removed drivers. (Directory `rung-2d`.) |
| 2d-b | slice B: modem/GLINK (`MODEMSMEM`, `MSM_PIL_MSS_QDSP6V5`, `MSM_GLINK_*`) `phonevault-b.config` | passed | no `pil_mss` module (core `glink` transport remains, expected); USB signing and lifecycle (reboot) pass. Note: `adb: failed to read command` right after the recovery confirmation is the install proceeding on the phone, not a failure |
| 2d-c | slice C: camera / media / video codecs / DVB / sensor hub / touchscreen heatmap / compute DSP `phonevault-c.config` + `CONFIG_PHONEVAULT_APPLIANCE=y` + kernel patch 0002 (carried in the rung directory) | passed | 0 cameras, no sensors, no DSP nodes, display fine; credential, USB transaction and message signing pass. Vendor services for the removed hardware then crash-loop (addressed in 2d-c2/2d-c3). A camera/media-only sub-slice without the patch fails to link (`sde_hw_rot` needs the V4L2 rotator, `heatmap.c` needs `video_unregister_device`), so slice C goes in whole, with its patch |
| 2d-c2 | services for hardware the image no longer has are not installed: `vendor-google-crosshatch.diff` drops the rc + binary of `vendor.sensors` (sscrpcd), `vendor.sensors.qti`, `vendor.sensors-hal-2-0`, `neuralnetworks_hal_service(_paintbox)`, `easelmanagerd` and the `adsprpcd`/`cdsprpcd`/`cnss-daemon`/`mm-pp-dpps` binaries; the device diff removes the `adsprpcd`, `cdsprpcd`, `cnss-daemon`, `ppd` service blocks (and ppd's hwcomposer triggers) from `init.hardware.rc` and the GNSS HAL from `device.mk`. No VINTF change: none of these HALs is in the appliance manifest (which is why the HIDL ones crash-looped) | passed | targeted loops gone, Titan M services up; USB, token and message signing and credential pass. Kept for later slices: audio HAL, camera provider, contexthub/CHRE, loc_launcher/lowi/xtra |
| 2d-c3 | 2d-c2 + lock-screen cleanup and three more crash-loopers: (1) frameworks-base patch 0005 (`config_phonevaultHideKeyguardClock`; the overlay sets it true): no clock, smartspace or date on the keyguard or AOD; lock icon, bouncer, owner disclosure and charging line unchanged. (2) No ambient display (AOSP doze defaults). (3) The Phone Vault overlay is added in `vault_crosshatch.mk` before any inherit, because earlier `PRODUCT_PACKAGE_OVERLAYS` entries win over `vendor/lineage/overlay/common` (policy gate enforces it); new centred padlock wallpaper. (4) The device diff also drops `android.hardware.nfc@1.2-service`, `android.hardware.camera.provider@2.4-service_64` and `chre_daemon_msm` | passed | no clock/date on the boot lock screen, new wallpaper, no crash loops (only one-shot service exits over a full run including reboot); USB, token and message signing and credential pass. Rungs before 2d-c3 list the overlay in their own `common.mk`: drop that line before rebuilding one with the new `vault_crosshatch.mk` |
| 2d-d | 2d-c3 + slice D `phonevault-d.config`: USB gadget functions — only adb (FunctionFS) and Android Open Accessory remain; no mass storage/MTP/PTP/MIDI/HID/CCID/audio/cdev/diag/QDSS/GSI. **DWC3 stays dual-role** | passed (second attempt) | a first build that also turned DWC3 `DUAL_ROLE`/`HOST` off booted but never enumerated on USB (host saw error -71) and was rolled back to the previous slot. Without the DWC3 role lines: USB enumerates, `svc usb setFunctions mtp` leaves `sys.usb.config=adb`; signing suites and credential pass. The release defconfig was fixed accordingly |
| 3 | 2d-d + USB lock-down at the OS level (DWC3 dual-role in the kernel). Device diff: (1) gadget HAL (release device patch 0002): `setCurrentUsbFunctions` rejects (`CONFIGURATION_NOT_SUPPORTED`, current gadget kept) anything but none / accessory / adb / accessory+adb, adb only with `ro.debuggable=1`; `getVendorFunctions()` returns nothing, so `vendor.usb.config` / `persist.vendor.usb.usbradio.config` / usbradio boot mode cannot append diag/serial/rmnet. (2) Port HAL (release patch 0003): `switchRole` refuses source power role, host data role and DFP/DRP mode; a failed mode switch falls back to `sink`; status reports UFP-only. (3) `init.sdm845.usb.rc`: port pinned with `write /sys/class/typec/port0/port_type sink` on boot and on boot_completed (charges, is a USB device, never sources VBUS or hosts, rejects DR/PR swaps); only `accessory.gs2` is created unconditionally, `ffs.adb` only on `ro.debuggable=1`; audio_source/MIDI/MTP/PTP/diag/cser/gsi/QDSS instances, the mtp/ptp FunctionFS mounts and the charger-mode MIDI gadget are gone. (4) The dwc3 `id` node (writing 0 forces host mode) stays root-owned. (5) `android.hardware.usb.host` not declared. `common.mk` adds `ro.vendor.phonevault.offline=true` and keeps `persist.sys.usb.config=adb` (the user build sets `none`) | passed | `svc usb setFunctions` mtp / rndis / midi each refused by the gadget HAL ("Phone Vault rejected USB gadget functions"), `sys.usb.config` stays `adb`; charging works; signing suites and credential (reboot) pass. Release patch 0001 replaces this rc wholesale with `init.phonevault.usb.rc`; the rung edits the stock rc (smaller step). Recovery keeps the stock DRP port (sideload only). Not yet shown: an OTG device left unpowered (physical test), port-role readout (`/sys/class/typec` is root-only) |
| 4a | rung 3 + app strip slice A: `Android.bp` overrides 40 more modules, user-facing apps that nothing in system_server or SystemUI binds at boot (launcher, camera/gallery/music/browser/clock/calendar/calculator/recorder/PDF apps, AudioFX, Updater, pickers, dreams, …). Full list, mechanism and reasons: [Rung 4](#rung-4-app-strip) | passed | removed apps absent, HOME = Phone Vault, kiosk LOCKED; signing suites and credential pass. `check-overrides.sh 4a` first reported `Gallery2` and `DeviceAsWebcam`: not installed apps but dangling JNI-lib symlinks left in the staging tree (see "Stale staging leftovers"); `build-rung.sh` now scrubs them. Remaining crashes: `org.protonaosp.elmyra` (sensor-less gesture service, removed in 4b) |
| 4b | 4a + slice B: 57 system-side modules bound only on demand (Active Edge `ElmyraService` + `GoogleParts`, telephony UI/role apps, backup, print, WebView + its feature, DocumentsUI/StorageManager/MtpService, LineageParts/Profiles/QuickAccessWallet, CDM/credential/DSU/cert/app-link/PAC/VPN/captive-portal/SE/BT-MIDI satellites, four unused providers, the non-radio Pixel blobs). The device diff also drops the Bluetooth, NFC (+ per-SKU ODM NFC/eSE/OMAPI, FeliCa) and OMAPI-UICC feature declarations, so SystemServer skips BluetoothManagerService and the NFC APEX app never creates NfcService | passed (second build) | the first build boot-looped: system_server `IllegalStateException: Call to getInstalledModules before metadata loaded` because `ModuleMetadata` was removed; rolled back to the previous slot and rebuilt keeping it. Rebuilt: 160 packages (4a: 221), HOME = Phone Vault, kiosk LOCKED, crash log empty, signing suites and credential (reboot) pass. `com.android.nfc` / `com.android.bluetooth` stay installed inside their APEXes and are made dormant by the feature removal |
| 4c… | `Android.bp` overrides in further slices (telephony/radio + system_server gating → media → APEXes → vendor prune; ManagedProvisioning needs a wiped first boot of its own) | planned | |
| final | `common.mk` release version, no adb key, `user` variant | planned | the release configuration already folds in 2d-d (kernel, DWC3 dual-role), rung 3 (USB HAL/init as device patches 0027–0029) and 4a/4b (overrides, kept modules), with release adb off and gated ([release-config.md](../docs/release-config.md)). Not built or booted as a release yet |

## Per-rung checklist (all must pass before the next rung)

1. `vault-os/tests/*.sh` policy gates on the repository.
2. Build → OTA → sideload (confirm the recovery signature prompt until the OTA key is trusted)
   → boot. From rung 4a, `check-overrides.sh RUNG` on the target-files prints OK first.
3. Owner + kiosk: `dumpsys device_policy` shows the owner, `mLockTaskModeState=LOCKED`,
   `settings get global device_provisioned` = 1, no setup wizard.
4. On a throwaway wallet (`tools/dev-device/`): `firstrun.sh` on a wiped phone, `credentialtest.sh`
   (PIN lifecycle including reboot), `lifecycletest.sh`, `usbsigntest.sh`, `tokensigntest.sh`,
   `msgsigntest.sh`; identity persists across a reboot.
5. No crash-looping services (`logcat -b crash`, repeated `init: Service … exited`).
6. A known-good rollback image at hand (the previous rung's OTA, or the inactive A/B slot with
   `fastboot --set-active`).

## Rung 4: app strip

Prepared from the rung-3 build output (`out/target/product/crosshatch` target-files, 152 APKs)
and its sources. `rung-4a/` and `rung-4b/` are full
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
- **Why an earlier `overrides` attempt did not remove Trebuchet, and the trap it shows.**
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
  override of Launcher3QuickStep should already have cut the first edge, so that result is not
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
| ~~`ModuleMetadata`~~ **KEPT** | `com.android.modulemetadata` | product/app | REQUIRED: without it `ModuleInfoProvider` never loads metadata and `AppRestrictionController.onSystemReady` → `getInstalledModules` throws "Call to getInstalledModules before metadata loaded": system_server crash loop (4b first build) |
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

Before flashing either rung: `check-overrides.sh RUNG` on the target-files prints OK.

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
