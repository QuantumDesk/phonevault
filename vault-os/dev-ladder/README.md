# Crosshatch development ladder (Pixel 3 XL)

(Crosshatch / LineageOS 22.2 only. The Pixel 6a ladder, rungs b0… on LineageOS 24.0, lives in
[`../dev-ladder-bluejay/`](../dev-ladder-bluejay/README.md).)

`vault-os/vendor/phonevault/`, `device/phonevault/` and `patches/` describe the **release
intent**. This ladder put the release hardening back onto a booting development image one
boot-tested rung at a time; every rung passed and its result is folded into the release
configuration ([release-config.md](../docs/release-config.md)). Rungs 0 to 4a are archived under
the git tag `crosshatch-ladder-archive`; what each one changed, proved and taught is in
[hardening-ladder.md](../docs/hardening-ladder.md).

What remains here:

```
dev-ladder/
  rung-4b/             the development baseline (development phone 2 runs it)
  build-rung.sh        build a rung: target-files → OTA zip (build host, as the tree owner)
  check-overrides.sh   prove the rung's Android.bp overrides are absent from the target-files
  flash-rung.sh        sideload a rung OTA to the phone and verify the boot
  wipe-data.sh         erase userdata + metadata (throwaway phones only)
  device-guard.sh      sourced by flash-rung.sh / wipe-data.sh: one pinned device, throwaway guard
```

## rung-4b

A rung directory contains **only the files that still override release intent**, plus
`device-google-crosshatch.diff` / `vendor-google-crosshatch.diff` for upstream device-tree edits
and the kernel config fragments / patches it needs. `rung-4b/` is self-contained: the sync reads
nothing but this directory and the release overlay. Against the release configuration it is:

- **`common.mk`**: a minimal `userdebug` product (PhoneVault only) with adb as the default USB
  function, insecure adb and the builder's pre-authorised adb key; `ro.vendor.phonevault.offline`
  as in the release.
- **`BoardConfigVault.mk`**: AVB with our key, verity on, appliance VINTF, board-info; the kernel
  fragment as four slices `phonevault-{a,b,c,d}.config` (the release has the same symbols as one
  `phonevault.config`, `patches/kernel-crosshatch/0001`) plus `kernel-0002-…patch`.
- **`Android.bp`**: `overrides` = `LineageSetupWizard` + app strip slices A (40 modules) and B
  (57 modules, `ModuleMetadata` kept); the release-only overrides stay disabled.
- **`device-google-crosshatch.diff`**: the USB lock-down (gadget function allowlist, port
  sink/UFP-only, no host role), services for removed hardware not installed, and no Bluetooth /
  NFC / OMAPI / FeliCa feature declarations. **`vendor-google-crosshatch.diff`**: vendor services
  for the removed hardware not installed. The release carries these as device/appliance patches.

The next steps (telephony/radio with system_server gating → media → APEXes → vendor prune, then
a `user` build without adb) are the release-only part of the release config; none has been
boot-tested yet ([release-config.md](../docs/release-config.md#ahead-of-the-ladder-not-yet-boot-tested)).

## Using the ladder

Paths below are placeholders: `$LINEAGE_TREE` is your LineageOS 22.2 tree with the crosshatch
device, vendor and kernel repos, `$OUT_DIR` where the rung OTA goes.

`scripts/dev-ladder-sync.sh 4b $LINEAGE_TREE [APK]` syncs the rung into the tree:

1. `rsync` the release `vendor/phonevault/` and `device/phonevault/` into the tree (keeping the
   tree's `keys/`, which are never versioned);
2. copy the rung's override files over their targets;
3. restore `device/google/crosshatch` (and the extract-utils makefiles of
   `vendor/google/crosshatch`) and the kernel tree to upstream, then apply the rung's diffs and
   `kernel-*.patch`, so the tree carries exactly this rung's edits; apply every
   `patches/frameworks-base/*.patch` not already in the tree;
4. bake the **dev-appliance** APK as `prebuilt/PhoneVault.apk` (rungs are development images:
   `verify-signer-apk.sh` correctly refuses this variant, so the release path, `install-overlay.sh`
   with a release-signed APK, is not used here);
5. append the `BoardConfigVault.mk` include to the Lineage board file if missing.

**Development adb key.** Rung images are `userdebug` with adb pre-authorised for the builder. No
adb key is committed: the sync reads your public adb key from the path in `PV_DEV_ADB_KEY`
(for example `~/.android/adbkey.pub`) and installs it only in the build tree. The release
configuration carries no adb key, and the release-source gate refuses one.

Build with `dev-ladder/build-rung.sh 4b` as the tree owner (never root; `LINEAGE_TREE` names the
tree, `PV_OUT_DIR` the output directory): a `userdebug` build with `WITH_ADB_INSECURE`, producing
`rung-4b-ota.zip`. Then run `dev-ladder/check-overrides.sh 4b [TARGET_FILES]` on the build host;
it must print OK before the OTA goes anywhere near the phone. (`check-overrides.sh release
TARGET_FILES` runs the release overrides gate, `scripts/verify-release-overrides.sh`.)

Flash with `dev-ladder/flash-rung.sh 4b [--wipe]` (`PV_OTA` = the OTA, `PV_SERIAL` = the
phone's serial). It sideloads the OTA; until the OTA key is trusted, the recovery shows
"Signature verification failed — install anyway?" and someone must confirm on the phone.
`--wipe` erases userdata and metadata afterwards so the next boot is a genuine first boot; it
destroys the on-device wallet and requires `PV_THROWAWAY_DEVICE=1`. The script refuses to run
while any other device is attached. `dev-ladder/wipe-data.sh` erases userdata and metadata on
its own, under the same rules.

To build an archived rung, restore its directory from the tag first
([hardening-ladder.md](../docs/hardening-ladder.md#looking-at-an-archived-rung)).

## Checklist (every build of a rung)

1. `vault-os/tests/*.sh` policy gates on the repository.
2. Build → `check-overrides.sh` OK → OTA → sideload (confirm the recovery signature prompt until
   the OTA key is trusted) → boot.
3. Owner + kiosk: `dumpsys device_policy` shows the owner, `mLockTaskModeState=LOCKED`,
   `settings get global device_provisioned` = 1, no setup wizard.
4. On a throwaway wallet (`tools/dev-device/`): `firstrun.sh` on a wiped phone, `credentialtest.sh`
   (PIN lifecycle including reboot), `lifecycletest.sh`, `usbsigntest.sh`, `tokensigntest.sh`,
   `msgsigntest.sh`; identity persists across a reboot.
5. No crash-looping services (`logcat -b crash`, repeated `init: Service … exited`).
6. A known-good rollback image at hand (the previous OTA, or the inactive A/B slot with
   `fastboot --set-active`).

Rung-4b specific checks:

1. `pm list packages` has none of the removed packages; `cmd package resolve-activity --brief -c
   android.intent.category.HOME -a android.intent.action.MAIN` → `dev.phonevault.signer/.MainActivity`.
   `pm list features` has no `android.hardware.nfc*`, `android.hardware.bluetooth*`,
   `android.hardware.se.omapi.*`, `android.software.webview`, `com.google.hardware.pixel.japan`.
2. **First boot on wiped userdata+metadata** lands on SET PIN with no "Select a home app" chooser,
   owner `fixed-function-system-image`, `mLockTaskModeState=LOCKED`.
3. Reboot with a credential set: the boot keyguard shows the PIN pad, `FallbackHome` covers the
   locked window, after the PIN Home is PhoneVault.
4. **Manual, not covered by the harness**: open "Show recovery phrase" (or any step-up prompt) and
   check the soft keyboard appears in the system PIN prompt (`dumpsys input_method | grep
   mInputShown` = true). The harness keys the PIN with `input text`, which bypasses the IME.
5. No `com.android.nfc` ANR / `NfcService` init; `service list` has no `bluetooth_manager` and no
   `webviewupdate`, and nothing crashes on their absence; `dumpsys print` / `dumpsys backup` do
   not crash system_server. `OverviewProxyService` may log the recents connection failing (no
   launcher), but must not loop at high frequency.
6. Screen timeout on USB power: the screen goes off normally (no dream bound).
7. No APK-less app dirs: `adb shell ls -d /product/app/Gallery2 /system/priv-app/DeviceAsWebcam
   /system/app/PrintSpooler` → all "No such file or directory".

## App strip mechanism

Soong `overrides` on the PhoneVault module (`rung-4b/Android.bp`, and the release
`vendor/phonevault/prebuilt/Android.bp`). It is the only product-level removal tool that works on
this build system:

- **`PRODUCT_PACKAGES -=` / `filter-out` cannot work.** `inherit-product` appends an
  `@inherit:<file>` placeholder to every product list (`build/make/core/product.mk`), and
  `node_fns.mk` expands the placeholders only after all nodes are imported; after expansion the
  variable is `.KATI_READONLY`. There is no `PRODUCT_PACKAGES_REMOVE`-style variable.
- **Lineage's opt-out knobs set in `common.mk` are dead.** `_import-node` includes a makefile and
  then its inherited children in sorted path order, depth first, so `vendor/phonevault/config/common.mk`
  is evaluated after `vendor/lineage/config`: `TARGET_EXCLUDES_AUDIOFX`, `PRODUCT_NO_CAMERA`,
  `PRODUCT_NO_DYNAMIC_SYSTEM_UPDATE` and `TARGET_DISABLE_LINEAGE_SDK` are assigned after they were
  tested. Such knobs only work in the leaf `vault_crosshatch.mk`. `TARGET_DISABLE_LINEAGE_SDK`
  must NOT be made effective: Lineage's SystemUI/Settings use the SDK and LineageSettingsProvider.
- **`required` defeats an override.** `product-installed-modules` (main.mk) drops every
  overridden name before expanding `required`, so an override beats any inherited
  `PRODUCT_PACKAGES` entry. But an installed module's files depend on the files of everything it
  `required`s, so a module that something *installed* requires is staged anyway. The three such
  edges (`Launcher3QuickStep → TrebuchetQuickStep`, `Aperture → ApertureLensLauncher`,
  `Seedvault → LocalContactsBackup`) have both ends overridden, and `check-overrides.sh` proves
  the result on the target-files instead of assuming it.

### Stale staging leftovers

An app with embedded JNI libs is installed with `lib/<abi>/*.so` symlinks pointing at absolute
*device* paths (`/product/lib64/…`). When the app stops being installed, soong_ui's
`cleanOldFiles` (`build/soong/ui/build/cleanbuild.go`) tests each old path with `os.Stat`, which
follows the symlink, finds no such host path and skips it. The APK and odex go; the dangling
symlinks stay in `out/target/product/crosshatch/`, and target-files and the partition images copy
that staging tree wholesale (rung 4a: `Gallery2`, `DeviceAsWebcam`). `build-rung.sh` therefore
deletes, before building, every staged `app|priv-app/<name>/` dir that has no APK and every one
named in the rung's active `overrides` (if an overridden module really is still installed, ninja
re-creates it and `check-overrides.sh` fails as it should). `check-overrides.sh` marks a hit
without an APK as a "stale staging leftover".

### Kept, and why

The removed modules and the reason each is safe to remove:
[hardening-ladder.md](../docs/hardening-ladder.md#app-strip-module-lists).

| Module (package) | Why it stays |
|---|---|
| PhoneVault (`dev.phonevault.signer`) | the appliance |
| SystemUI (`com.android.systemui`) | keyguard, boot PIN bouncer (own NumPad, no IME), BiometricPrompt credential UI, status bar |
| LatinIME (`com.android.inputmethod.latin`) | **the only IME, and it is needed**: the boot keyguard has its own PIN pad, but the vault's step-up prompt (BiometricPrompt, DEVICE_CREDENTIAL) is SystemUI's `auth_credential_password_pin_content_view`, an `ImeAwareEditText` that calls `scheduleShowSoftInput()` |
| UserDictionaryProvider | LatinIME's dictionary provider |
| SettingsProvider, Settings | settings storage; `FallbackHome` (priority -1000, direct-boot aware: covers the window before the credential unlocks CE storage), confirm-credential and device-admin screens |
| PackageInstaller | PackageManagerService throws "There must be exactly one installer/uninstaller" at boot without it |
| PermissionController (APEX), ExtShared (`android.ext.shared`) | PMS requires a permission controller and the `android.ext.shared` system shared library at boot |
| FusedLocation | LocationManagerService throws "Unable to find a direct boot aware fused location provider" |
| ModuleMetadata | without it system_server crash-loops ("Call to getInstalledModules before metadata loaded") |
| Shell | dev adb (`com.android.shell`); revisit for the user build |
| IntentResolver, KeyChain, InputDevices | framework chooser/resolver, keystore/cert plumbing used by DPM, keyboard-layout receiver |
| LineageSettingsProvider, SimpleDeviceConfig, SimpleSettingsConfig | Lineage framework and SystemUI read LineageSettings; boot-time DeviceConfig/settings defaults |
| TimeService (`com.qualcomm.timeservice`) | persists the user/RTC time offset via time_daemon; without it the clock resets on reboot |
| TeleService, Telecom, TelephonyProvider, CarrierConfig, ContactsProvider, BlockedNumberProvider, MmsService, ONS, ImsServiceEntitlement, ims, qcrilmsgtunnel, QtiTelephonyService, uceShimService, PresencePolling, RcsService, uimremoteclient/server, grilservice, RilConfigService, CneApp, IWlanService and the carrier blobs | telephony step: TeleService is persistent and binds several of these at boot while the telephony/IMS/eUICC features are still declared; they go together with the system_server gating and the vendor-mk removal of their permission XMLs (release appliance patch 0003) |
| NetworkStack (and the connectivity / wifi / tethering APEXes) | network step (ConnectivityService needs a network stack module) |
| MediaProviderLegacy, DownloadProvider, ExternalStorageProvider | media step (shared `android.media` uid, MediaProvider APEX, StorageManagerService) |
| ManagedProvisioning | DevicePolicyManagerService plumbing; the fixed-function owner patch bypasses it, but removal needs its own wiped-first-boot test |
| com.android.nfc / com.android.bluetooth (inside APEXes) | APEX step (their framework jars are on the boot classpath); dormant because the features are not declared |

HOME without a launcher: the resolver picks PhoneVault `MainActivity` (priority 0) over Settings
`FallbackHome` (-1000) without a chooser, even before `etc/preferred-apps/phonevault-home.xml` or
the owner's persistent preferred HOME apply; both stay in place.

### Follow-ups

- Lineage's "Discover Trust" lock-screen notification is posted by the SDK's
  `TrustInterfaceService` until `LineageSettings.System.TRUST_INTERFACE_HINTED` is 1; set that
  default in the vault overlay (LineageSettingsProvider).
- `config_recentsComponentName` still names Trebuchet's RecentsActivity; overlay it empty so
  SystemUI stops retrying the recents binding.
- Release `vault_crosshatch.mk`/`common.mk`: move `PRODUCT_NO_CAMERA`, `TARGET_EXCLUDES_AUDIOFX`,
  `PRODUCT_NO_DYNAMIC_SYSTEM_UPDATE` into the leaf; keep `overrides` as the removal list.
