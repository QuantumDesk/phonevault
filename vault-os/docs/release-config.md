# Release configuration and release gates

`vault-os/vendor/phonevault/`, `vault-os/device/phonevault/` and `vault-os/patches/` are the
**release intent**. This note records how the release configuration was brought in line with
what the development ladder (`dev-ladder/README.md`) proved on a phone, which development
deviations from the early boot debugging were removed, what a release build consists of, which
gates enforce it, and what still needs a phone.

## 1. Development deviations removed from the release config

| Was | Now |
|---|---|
| `common.mk`: `persist.sys.usb.config=adb   # DEBUG-38: temporary` | `persist.sys.usb.config=none` |
| `common.mk` installed `prebuilt/zzz-debug-earlyadb.rc` (DEBUG-41): configfs gadget + `ffs.adb` + `start adbd` in `post-fs`, on **every** build type | file and install line deleted |
| `common.mk`: commented DEBUG-39 `PRODUCT_SYSTEM_SERVER_APPS -=` block | deleted (FusedLocation is required; `-=` never worked, see rung 4) |
| `common.mk`: `TARGET_DISABLE_LINEAGE_SDK := true` | deleted: it was inert (evaluated after Lineage's config) and must not be made effective — Lineage's SystemUI/Settings use the SDK and LineageSettingsProvider |
| tracked `common.mk.rel-bak`, `common.mk.b38-bak` | deleted |

The dev-ladder rung directories (`dev-ladder/rung-*`, `dev-ladder-bluejay/rung-*`) still carry adb
for their userdebug images; they override the release files only inside the build tree
(`dev-ladder-sync.sh`), never in the repository's release config, and the release-source gate
below rejects any of it reappearing there.

## 2. Release build = rung 4b hardening + user build + adb off

| Area | Proven by | Release config |
|---|---|---|
| Kernel fragment | rung 2d-d (slices A-D), passed on hardware | `patches/kernel-crosshatch/0001` is symbol-for-symbol slices A-D. DWC3 stays **dual-role** (gadget-only never enumerated); `policy/forbidden-kernel-config.regex` now forbids only `CONFIG_USB_DWC3_HOST`, and the appliance gate requires `CONFIG_USB_DWC3_DUAL_ROLE=y` |
| USB HALs / init | rung 3, passed on hardware | device patches 0002/0003 (already release) + new 0027 (no vendor diag/serial/rmnet functions), 0028 (failed mode switch falls back to `sink`; port reported UFP-only, no role/mode changes), 0029 (dwc3 `id` node root-only); `init.phonevault.usb.rc` re-pins `port_type sink` on `sys.boot_completed=1`. The appliance gate rejects any init file that chowns/chmods `a600000.ssusb/id` |
| App strip | rungs 4a + 4b, passed on hardware | every rung-4b override is in the release `Android.bp` (test-enforced). Section comments kept |
| Kept modules | rung 4 "Kept, and why"; 4b boot loop | **Settings** (FallbackHome, confirm-credential, device-admin UI), **PackageInstaller** (PMS needs exactly one installer), **LatinIME** (only IME; the step-up PIN prompt needs it), **FusedLocation** (LocationManagerService), **ModuleMetadata** (system_server boot loop). Removed from the release overrides and from `policy/forbidden-target-files.regex`; `tests/test_forbidden_policy_coverage.py` fails if any of them (or SystemUI, SettingsProvider, PermissionController) is overridden or forbidden again |
| Variant / adb | — | `user` lunch target, `persist.sys.usb.config=none`, no adb keys, no early-adb rc; recovery hardened (section 4) |

### Ahead of the ladder (not yet boot-tested)

The release `Android.bp` keeps 174 overrides that no rung has boot-tested yet, under the comment
"Release-only: ahead of the boot-tested ladder": the telephony/radio/IMS stack (TeleService,
Telecom, TelephonyProvider, CarrierConfig, …), NetworkStack/Tethering, DownloadProvider,
ExternalStorageProvider, **ManagedProvisioning**, the modular APEXes, HAL services and native
tools. They are coupled to the release appliance/device patch series (system_server gating,
feature withdrawal), which the ladder has not run as a whole either. They stay because removing
them would ship less hardening, and the artifact policy keeps forbidding them (ManagedProvisioning
included: rung 4 only kept it pending its own wiped-first-boot test). The ladder's next rungs
(4c… telephony → media → APEXes → vendor prune) must boot-test them; **a release image must not
ship until a release build has booted and passed the per-rung checklist.**

## 3. Release gates

Run by `sign-release.sh` before anything is signed (new usage:
`sign-release.sh INPUT /release-keys OUTPUT (PREVIOUS_RELEASE_DIR | --first-release)`):

1. `scripts/verify-release-source.sh` (also run by `install-overlay.sh` before a tree is
   prepared): in `vendor/phonevault/**` and `device/phonevault/**` no `DEBUG-`/`DEBUGnn` marker,
   no `*.bak`/`*-bak`/`*.orig`/`zzz-debug*`/adb-key files, no `persist.sys.usb.config` other than
   `none`, no adb in any USB config property, no `ro.adb.secure=0`, `ro.debuggable=1`,
   `persist.adb.notify`, `PRODUCT_ADB_KEYS`, `WITH_ADB_INSECURE`, no debug init script install, no
   `start adbd` and no `ffs.adb`/`usb-ffs/adb` setup outside a `ro.debuggable=1` trigger in any
   release `.rc`; plus the rollback-index file, the voice/SMS overlay and the recovery patch
   wiring. Property rules also apply to every `*.prop` in the release directories and to each
   file named by `TARGET_*_PROP` / `PRODUCT_*_PROPERTIES` (parsed as init does; a referenced
   file outside the release directories, or an `import` in one, fails). Any install destination
   or module filename `adb_keys` fails whatever the source file is called. `.rc` files (and any
   file installed under `etc/init/`) are read with init's tokenizer: continuations joined,
   `on`/`service`/`import` at any indentation, `enable`/`exec_start` like `start`, a
   property-expanded service name or USB-config value counts as adb, and imports from writable
   or unresolved paths fail.
2. `scripts/verify-production-target-files.sh` (new release ADB policy on the target-files): any
   `(persist.)sys|vendor.usb.config` containing adb, a `persist.sys.usb.config` that is not
   exactly `none`, `ro.force.debuggable=1`, `service.adb.root=1`, `ro.adb.secure.recovery=0`,
   `persist.adb.notify=0`, any `adb_keys`, `zzz-debug` or `debug_adbkey` path, and — across every
   installed init file — `start/restart adbd` outside a `ro.debuggable=1` trigger or a trigger
   made only of framework USB-function properties (`sys.usb.config/configfs/ffs.ready`, which the
   gadget HAL refuses for adb on user builds), `ffs.adb`/`usb-ffs/adb`/`functionfs adb` setup
   outside `ro.debuggable=1`, `setprop … usb.config …adb`, and any adbd service outside
   `init.usb.rc`. Only the recovery ramdisk's own `init.rc` (it prepares the FunctionFS endpoint
   for `adb sideload`; `BOOT`, `RECOVERY` or, with recovery in vendor_boot, `VENDOR_BOOT`) is
   exempt, and only when it really is the recovery init.
   Property files are read the way init reads them (`property_service.cpp`): whitespace around
   `=` stripped, `#` comments, `import <path> [filter]` followed into the image (an import that
   resolves outside the image fails), and the effective value computed in init's load order
   (ramdisk `prop.default`, second-stage ramdisk `build.prop`, system, system_ext, system_dlkm,
   vendor, vendor_dlkm, odm_dlkm, odm, product, debug-ramdisk `adb_debug.prop`; a later file
   wins, `ro.*` included). The effective `ro.debuggable`/`ro.secure`/`ro.adb.secure` must be
   0/1/1, `persist.sys.usb.config` exactly `none`, and no property file anywhere may set them to
   anything else. Debug-ramdisk artifacts (`force_debuggable`, `adb_debug.prop`, and
   `userdebug_plat_sepolicy.cil` in a ramdisk) fail. Init files are tokenized like init
   (continuations, quotes, `on`/`service`/`import` at any indentation), `import`s are followed
   anywhere in the image (writable locations fail), `enable`/`exec_start`/`exec … adbd` count
   like `start`, an adbd service must be `disabled`, and a property-expanded service name or USB
   function must resolve to a build-time `ro.*` constant (not `ro.boot.*`/`ro.hardware`, which
   the bootloader sets first) that is not adbd/adb. `tests/test-production-gate.sh` keeps a
   bluejay/crosshatch-shaped user layout with the stock idioms as a positive.
3. `scripts/verify-appliance-target-files.sh` (DWC3 dual-role required, host-only forbidden, dwc3
   `id` node root-only).
4. `dev-ladder/check-overrides.sh release TARGET_FILES`: no release override is packaged.
5. `scripts/verify-rollback-index.sh` (section 5).

Tests: `tests/test-release-gate-gaps.sh` (adversarial negatives from a security audit),
`tests/test-production-gate.sh` (ADB negatives incl. the exact DEBUG-41 script),
`tests/test-release-gates.sh` (source gate incl. the exact DEBUG-38 line, rollback gate,
release overrides gate), `tests/test-appliance-gate.sh` (DWC3 / id node),
`tests/test_forbidden_policy_coverage.py` (overrides ⇔ policy, ladder-required modules).

## 4. Recovery

`patches/bootable-recovery/0001-…` — on `ro.debuggable=0` builds no "Install anyway?" for
unverified, downgrade or SPL-downgrade packages, no "Enable ADB" (and no system mount/format)
items, and recovery adbd is never started; the explicit "Apply from ADB" sideload stays (the
package must still verify against the release OTA certificate). Userdebug ladder images keep the
install-anyway prompt they rely on. Applied by `install-overlay.sh`. Verified: `git apply
--check` clean on both `$LINEAGE_TREE/bootable/recovery` trees (Lineage 22.2, and Lineage 24.0
with offsets only), and `m recovery` compiled on the crosshatch tree.

## 5. AVB rollback index

`vendor/phonevault/config/release-version.mk` owns `PHONEVAULT_AVB_ROLLBACK_INDEX` (format
`YYYYMMDDNN`, first value `2026101300`, above the inherited security-patch timestamp
`1785542400` so no phone that booted a timestamp-indexed image is locked out).
`BoardConfigVault.mk` sets `BOARD_AVB_ROLLBACK_INDEX` (and the vbmeta_system index) from it.
`sign-release.sh` refuses an image whose vbmeta index differs from that file, and refuses an
index that is not strictly greater than the `vbmeta_rollback_index` of the previous signed
`RELEASE-MANIFEST.txt` (whose Ed25519 signature is verified with the release-metadata key
first). `--first-release` is the explicit exception for the first production release.
**Bump the index for every release.**

## 6. Emergency-call kiosk escape

The keyguard/bouncer "Emergency" button opens the emergency dialer outside the lock-task kiosk.
SystemUI (`EmergencyButton.updateEmergencyCallButton`, bp1a) shows it only when
`android.hardware.telephony` is declared — the release device patches withdraw that feature and
the appliance gate forbids every `android.hardware.telephony*` declaration. The overlay now also
sets `config_voice_capable=false`, `config_sms_capable=false` and
`config_enable_emergency_call_while_sim_locked=false`, so the rest of the platform agrees the
device cannot place calls (the power menu was already limited to power off / restart).
Note the dev-ladder rungs up to 4b still declare telephony features, so the button can still
appear on those images.

## Still needs a phone

- Boot a full **release** (user) build and run the per-rung checklist (owner, kiosk LOCKED,
  PIN suites, USB signing) — the release-only overrides and the release patch series have not
  been booted together.
- Recovery on the user build: an unsigned / wrong-key OTA is refused with no "Install anyway?",
  no "Enable ADB" item, `adb devices` shows nothing in recovery until "Apply from ADB".
- **Physical kiosk-escape test**: lock screen and bouncer show no "Emergency" button; the power
  menu offers only power off / restart; long-press/emergency gestures (e.g. power ×5 emergency
  SOS) do nothing.
- `config_voice_capable=false` side effects (Telecom/SystemUI) on a booted image.
- USB: an OTG device stays unpowered and is not enumerated; `svc usb setFunctions adb` is refused
  on the user build; the port reports UFP-only.
- Rollback: on a relocked phone, the release with index N boots, an image with a lower index is
  refused by the bootloader.
