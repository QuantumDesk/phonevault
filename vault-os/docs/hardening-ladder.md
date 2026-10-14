# Crosshatch hardening ladder (archived rungs 0–4a)

The first Phone Vault images that booted on the Pixel 3 XL (`crosshatch`, LineageOS 22.2) did so
only after much of the release hardening had been peeled off. The crosshatch dev ladder put it
back one boot-tested **rung** at a time: each rung directory under `vault-os/dev-ladder/` held
only the files that still overrode release intent at that step (product/board makefiles,
`Android.bp` overrides, kernel config fragments and patches, upstream device/vendor tree diffs),
and each rung had to pass the per-rung checklist on development phone 2 before the next one.

Every rung passed. Its final state is folded into the release configuration
([release-config.md](release-config.md)), so rungs 0 to 4a were removed from the tree. They are
preserved in git under the annotated tag **`crosshatch-ladder-archive`**. Rung 4b, the last
rung and the live development baseline, stays in [`../dev-ladder/rung-4b/`](../dev-ladder/rung-4b/)
with the ladder scripts ([`../dev-ladder/README.md`](../dev-ladder/README.md)). The Pixel 6a
ladder ([`../dev-ladder-bluejay/`](../dev-ladder-bluejay/README.md)) is separate and active.

## Rungs

Each rung is its predecessor plus the change listed. Directory names are `rung-<name>`, except
2d-a, whose directory is `rung-2d`.

| Rung | Change (deviation removed) | Proven on hardware | Failures and lessons | In the release config |
|---|---|---|---|---|
| 0 | Known-good baseline: overrides disabled (`DEBUG48`), AVB, VINTF and the kernel fragment disabled (`DEBUG44`), minimal `common.mk` with insecure adb and a pre-authorised key (`DEBUG-47`), owner string emptied (`DEBUG-40`), wifi-keystore HAL `optional` | boots | The full release hardening at once did not boot; the ladder exists to reintroduce it in reviewable steps | Every `DEBUG-*` deviation is gone from the release files ([release-config.md §1](release-config.md#1-development-deviations-removed-from-the-release-config)); the release-source gate rejects them |
| 1 | `config.xml`: `config_fixedFunctionDeviceOwner` restored | partial | The OS provisioned the owner on wiped /data, but HOME resolved to the Lineage setup wizard: the app had never run, so its HOME preference did not exist | `vendor/phonevault/overlay` config + `patches/frameworks-base/0003`, `0004` |
| 1b | The app provisions itself from `DeviceAdminReceiver.onEnabled` (lock-task packages, persistent HOME, keyguard off, setup wizards hidden); `Android.bp` overrides `LineageSetupWizard` | passed | Genuine first boot (userdata + metadata erased) lands on SET PIN with no adb interaction, owner `fixed-function-system-image`, kiosk LOCKED | App `ApplianceProvisioning`; `LineageSetupWizard` in the release `overrides` |
| 2a | `BoardConfigVault.mk`: `WITH_AVB`, our AVB key/algorithm, `board-info.txt` | passed | vbmeta signed with our key (SHA256_RSA4096, still `--flags 3`). This tree folds every partition into a single vbmeta. Rungs 2a/2b were first branched from rung 1 and lost the 1b setup-wizard override: each rung must be a full copy of its predecessor. `persist.log.tag=V` rolled the boot log and was dropped | Release `BoardConfigVault.mk` (AVB key, algorithm, rollback index, board-info) |
| 2b | `--flags 3` removed: verity and hashtree enforcement on | passed | `ro.boot.veritymode=enforcing`; owner and kiosk survive the OTA. Refuse-to-boot on tampering needs a relocked bootloader (not yet shown) | Release `BoardConfigVault.mk` filters out `--flags 3` |
| 2c | Appliance VINTF manifest + compatibility matrices | passed | Manifest loads, no VINTF / `isBuildConsistent` popup | `vendor/phonevault/vintf/` via the release `BoardConfigVault.mk` |
| 2d-a | Kernel fragment slice A: BT/NFC/WLAN/CNSS/IPA/RMNET (`phonevault-a.config`); `etc/preferred-apps/phonevault-home.xml` against a first-boot HOME-chooser race | passed | No connectivity modules, no `wlan0`. An apparent no-boot was the phone off USB (the boot watch now reports USB presence). Single-driver bisect slices do not compile (WLAN needs IPA). Leftover `/dev/subsys_ipa_fws` and similar nodes come from the PIL framework, not the removed drivers | `patches/kernel-crosshatch/0001` (slices A-D); `phonevault-home.xml` installed by the release `common.mk` |
| 2d-b | Slice B: modem/GLINK (`MODEMSMEM`, `MSM_PIL_MSS_QDSP6V5`, `MSM_GLINK_*`) | passed | No `pil_mss`; core `glink` transport remains (expected). `adb: failed to read command` right after the recovery prompt is the install proceeding, not a failure | `patches/kernel-crosshatch/0001` |
| 2d-c | Slice C: camera/media/video/DVB/sensor hub/touch heatmap/compute DSP + `CONFIG_PHONEVAULT_APPLIANCE=y` + kernel patch 0002 | passed | 0 cameras, no sensors, no DSP nodes, display fine. A camera/media-only sub-slice without patch 0002 fails to link (`sde_hw_rot` needs the V4L2 rotator, `heatmap.c` needs `video_unregister_device`), so slice C goes in whole. Vendor services for the removed hardware crash-looped | `patches/kernel-crosshatch/0001`, `0002` |
| 2d-c2 | Services for hardware the image no longer has are not installed: vendor diff drops sensors, neuralnetworks, `easelmanagerd`, `adsprpcd`/`cdsprpcd`/`cnss-daemon`/`mm-pp-dpps`; device diff drops their init blocks and the GNSS HAL | passed | The HIDL services crash-looped because they are absent from the appliance manifest; removing them, not declaring them, is the fix | `patches/appliance/0007`, `0012`, device patches `0005`, `0018`, release `overrides` |
| 2d-c3 | Keyguard clock/date/smartspace hidden (`frameworks-base/0005`), no ambient display, Phone Vault overlay listed before every inherit; NFC HAL, camera provider and CHRE daemon not installed | passed | Overlays set in `common.mk` lost to `vendor/lineage/overlay/common` (the wallpaper change never reached the image): the earliest `PRODUCT_PACKAGE_OVERLAYS` entry wins, so the overlay goes in `vault_crosshatch.mk` before any inherit (policy gate enforces it) | `patches/frameworks-base/0005`, overlay `config.xml`, `device/phonevault/crosshatch/vault_crosshatch.mk`, device patch `0022`, release `overrides` |
| 2d-d | Slice D: USB gadget functions, only adb (FunctionFS) and Android Open Accessory remain | passed (second build) | A first build that also turned DWC3 `DUAL_ROLE`/`HOST` off booted but never enumerated on USB (host error -71) and was rolled back to the other slot. DWC3 stays dual-role; host/source roles are refused in user space instead | `patches/kernel-crosshatch/0001`; the appliance gate requires `CONFIG_USB_DWC3_DUAL_ROLE=y` and `policy/forbidden-kernel-config.regex` forbids `CONFIG_USB_DWC3_HOST` |
| 3 | USB lock-down in user space: gadget HAL allowlist {none, accessory, adb, accessory+adb} (adb only with `ro.debuggable=1`), no vendor diag/serial/rmnet functions; port HAL refuses source/host/DFP/DRP, a failed switch falls back to `sink`, status UFP-only; port pinned `sink` in init; dwc3 `id` node root-only; no `android.hardware.usb.host` | passed | `svc usb setFunctions` mtp/rndis/midi each refused, `sys.usb.config` stays `adb`, charging works. Recovery keeps the stock DRP port (sideload only). Not shown: an OTG device left unpowered (physical test) | Device patches `0002`, `0003`, `0027`–`0029`; `init.phonevault.usb.rc`; `ro.vendor.phonevault.offline=true` in the release `common.mk` |
| 4a | App strip slice A: `overrides` 40 user-facing modules nothing in system_server or SystemUI binds at boot ([list](#removed-in-4a-40-modules)) | passed | `check-overrides.sh` first reported `Gallery2` and `DeviceAsWebcam`: not installed apps but dangling JNI-lib symlinks in the staging tree; `build-rung.sh` now scrubs them ([details](../dev-ladder/README.md#stale-staging-leftovers)) | Release `Android.bp` "Rung 4a" section |
| 4b | Still in the tree ([`rung-4b/`](../dev-ladder/rung-4b/)): slice B, 57 on-demand system modules ([list](#removed-in-4b-57-modules-on-top-of-4a)); Bluetooth/NFC/OMAPI/FeliCa feature declarations dropped | passed (second build) | Removing `ModuleMetadata` crash-looped system_server (`getInstalledModules before metadata loaded`); rolled back and kept | Release `Android.bp` "Rung 4b" section; device patch `0001`; `ModuleMetadata` on the never-override list |

The release configuration adds what no rung has boot-tested yet: 174 further overrides (telephony,
network stack, media providers, ManagedProvisioning, APEXes, HAL services, native tools), the
`user` variant with adb off, and the hardened recovery. See
[release-config.md §2](release-config.md#2-release-build--rung-4b-hardening--user-build--adb-off).
`vault-os/tests/test_forbidden_policy_coverage.py` enforces that every rung-4b override is also
in the release list and that the modules the ladder proved required are never overridden or
forbidden.

## App-strip module lists

Paths are where each module was installed in the rung-3 image. Mechanism, the modules kept and
why: [`../dev-ladder/README.md`](../dev-ladder/README.md#app-strip-mechanism).

### Removed in 4a (40 modules)

| Module | Package | Where (rung 3) | Why it is safe to remove |
|---|---|---|---|
| `TrebuchetQuickStep` | `com.android.launcher3` | system_ext/priv-app | launcher; PhoneVault is HOME (preferred-apps + owner persistent preference). SystemUI recents binding to the launcher just fails (lock task has no recents) |
| `Launcher3QuickStep` | — | not packaged | not installed (Trebuchet overrides it), but its Trebuchet definition `required`s TrebuchetQuickStep, so it is overridden too |
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
| `BasicDreams` | `com.android.dreams.basic` | system/app | default dream component; if the screensaver ever triggers, DreamManagerService fails the bind and lets the screen sleep |
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

## Looking at an archived rung

The tag points at the last commit that still has every rung directory and the full rung log.

```sh
git show crosshatch-ladder-archive                                    # tag message: what is archived
git ls-tree -r --name-only crosshatch-ladder-archive vault-os/dev-ladder/rung-2d-d/
git show crosshatch-ladder-archive:vault-os/dev-ladder/rung-2d-d/BoardConfigVault.mk
git show crosshatch-ladder-archive:vault-os/dev-ladder/README.md      # the full rung log
git diff crosshatch-ladder-archive:vault-os/dev-ladder/rung-4a crosshatch-ladder-archive:vault-os/dev-ladder/rung-4b
```

To rebuild an archived rung, restore its directory next to `rung-4b` and use the ladder scripts
as usual:

```sh
git restore --source=crosshatch-ladder-archive -- vault-os/dev-ladder/rung-3
vault-os/scripts/dev-ladder-sync.sh 3 "$LINEAGE_TREE" app-appliance.apk
```

A rung directory is self-contained (the sync script reads only that directory plus the release
overlay), but rungs before 2d-c3 list the overlay in their own `common.mk`: drop that line before
rebuilding one with the current `vault_crosshatch.mk`. Every rung's `common.mk` needs
`PV_DEV_ADB_KEY` (see [`../dev-ladder/README.md`](../dev-ladder/README.md)).
