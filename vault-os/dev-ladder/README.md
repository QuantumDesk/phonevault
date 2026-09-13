# Re-hardening ladder (chunk 4)

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
3. apply the rung's device-tree diff if it is not already applied;
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
| 2d-a | kernel fragment slice A: connectivity (BT/NFC/WLAN/CNSS/IPA/RMNET) `phonevault-a.config`; plus `etc/preferred-apps/phonevault-home.xml` (first-boot HOME chooser race seen on phone 2 at rung 2c, 2026-09-13; the Soong `overrides` route did not remove Trebuchet) | rebuilt 2026-09-13 | the full fragment was the August boot-blocker, so it returns in four slices; `dev-ladder-sync.sh` installs `rung-*/ *.config` into the kernel tree |
| 2d-b | slice B: modem/GLINK (`MODEMSMEM`, `MSM_PIL_MSS_QDSP6V5`, `MSM_GLINK_*`) | planned | |
| 2d-c | slice C: camera/media/sensors/DSP | planned | needs kernel patch 0002 (display rotator without diagnostic sensors) |
| 2d-d | slice D: USB gadget functions (mass storage, MTP/PTP, MIDI, HID, diag, …) | planned | keep `USB_DWC3_GADGET=y`; pairs with rung 3 |
| 3 | USB gadget rc (`init.phonevault.usb.rc`, no adb function on user), `persist.sys.usb.config=none`, peripheral-only | planned | chunk-4 item 3 |
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
