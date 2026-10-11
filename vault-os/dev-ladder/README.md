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
| 3 | 2d-d + USB lock-down at the OS level (DWC3 stays dual-role in the kernel, per 2d-d). Device diff: (1) release device patch 0002 in the gadget HAL — `setCurrentUsbFunctions` rejects (CONFIGURATION_NOT_SUPPORTED, current gadget kept) anything but none / accessory / adb / accessory+adb, adb only with `ro.debuggable=1`; plus `getVendorFunctions()` returns nothing, so `vendor.usb.config` / `persist.vendor.usb.usbradio.config` / usbradio boot mode can no longer append diag/serial/rmnet outside that allowlist. (2) Release patch 0003 in the port HAL — `switchRole` refuses source power role, host data role and DFP/DRP mode; plus a failed mode switch falls back to `sink` instead of `dual`, and port status reports UFP-only with no role/mode changes. (3) `init.sdm845.usb.rc`: port pinned with `write /sys/class/typec/port0/port_type sink` on boot and again on boot_completed (tcpm then presents Rd only: charges, is a USB device, never sources VBUS or hosts, rejects DR/PR_SWAP; same write stock off-mode charging does); only `accessory.gs2` is created unconditionally, `ffs.adb` only `on early-boot && property:ro.debuggable=1`; audio_source/MIDI/MTP/PTP/diag/cser/gsi/QDSS instances, the mtp/ptp FunctionFS mounts, `sys.usb.mtp.device_type`, the RNDIS class id and the charger-mode MIDI gadget are gone. (4) The dwc3 `id` node (writing 0 forces host mode) is no longer chowned to system. (5) `android.hardware.usb.host` feature not declared. `common.mk` adds `ro.vendor.phonevault.offline=true` (vendor property; only these two HALs read it in this tree) and keeps `persist.sys.usb.config=adb` — the user build (rung 5) sets `none`, AOA links accessory on attach | built 2026-10-10, not flashed (OTA `03227ed6…`, app `c5def7d6…`) | release patch 0001 replaces this rc wholesale with `init.phonevault.usb.rc`; the rung edits the stock rc instead (smaller step from the 2d-d boot). Recovery keeps the stock DRP port (sideload only) |
| 4… | `Android.bp` overrides in slices (apps → media/camera → telephony/radio + system_server gating → APEXes → vendor prune) | planned | chunk-4 item 4 |
| final | `common.mk` release version, no `debug_adbkey.pub`, `user` variant | planned | chunk-4 item 5 |

## Per-rung checklist (all must pass before the next rung)

1. `vault-os/tests/*.sh` policy gates on the repo.
2. Build → OTA → sideload (recovery signature tap until the OTA key is trusted) → boot.
3. Owner + kiosk: `dumpsys device_policy` shows the owner, `mLockTaskModeState=LOCKED`,
   `settings get global device_provisioned` = 1, no setup wizard.
4. PIN lifecycle (`tools/dev-device/pintest.sh` on a throwaway wallet), identity persists
   across a reboot, USB signing round-trip with `tools/aoa_client.py`.
5. Rollback image at hand: `/root/rollback/known-good-2026-09-02.zip` (sha256 `0de27021…`).
