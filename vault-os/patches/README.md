# Selective upstream hardening

Vault OS does not fork GrapheneOS wholesale. Each imported change must have a
specific appliance threat, a compatible Android baseline, preserved authorship,
and a test or inspection gate.

## Accepted for Android 15 QPR2 evaluation

| Patch | Upstream | Rationale |
|---|---|---|
| Reject ambiguous recovery signatures | GrapheneOS [`4a3b6b70826c2a6efdbba28c87c9a88f52a33850`](https://github.com/GrapheneOS/platform_frameworks_base/commit/4a3b6b70826c2a6efdbba28c87c9a88f52a33850) | Fail closed when a PKCS#7 recovery signature contains multiple certificates or signer records. |
| Disable runtime APEX installation on user builds | GrapheneOS [`b471ebaaac9a190e3c61b51e5671573d2af5f45d`](https://github.com/GrapheneOS/platform_frameworks_base/commit/b471ebaaac9a190e3c61b51e5671573d2af5f45d) | A fixed-function appliance does not need live APEX installation; removing it narrows privileged update attack surface. |

Both commits are from GrapheneOS `platform_frameworks_base`, branch
`15-qpr2`, and retain their original author, message, and Apache-2.0 project
licensing in the mail patches.

## Phone Vault platform patch

`0003-provision-configured-appliance-owner.patch` and its internal-resource
export follow-up `0004-export-fixed-function-owner-resource.patch` are Phone
Vault changes, not GrapheneOS imports. Bootloader relocking wipes `/data`, so a
device owner set by ADB before relocking would be lost. The patches add an
empty-by-default framework resource that a fixed-function product can overlay
with a device-admin component and expose that resource to the device-policy
service through `com.android.internal.R`. On first boot only, before setup and
only when no owner exists, the service activates that component and records it
as device owner. After successful owner creation it marks the system user setup
complete and the owner-managed appliance provisioned, replacing the normally
required Managed Provisioning/Setup Wizard completion step. Before granting authority it verifies that the configured
package is installed as a non-privileged system app. The Vault overlay selects
`dev.phonevault.signer/.VaultDeviceAdminReceiver`; ordinary products retain
upstream behavior.

`patches/frameworks-base-a17/` holds the Android 17 (LineageOS 24.0, Pixel 6a / bluejay)
rebases of 0003 and 0004. Same call site (`PHASE_ACTIVITY_MANAGER_READY`, after the
policy-engine migration), same checks in the same order; Android 17 moved `Owners` behind
`DeviceAdmins`, so the owner queries read `mDeviceAdmins.hasDeviceOwner()`,
`getDeviceOwnerComponent()` and `hasProfileOwner()`, and the `Slogf.wtf` calls use its
format-string overloads. `verify-owner-provisioning-policy.sh` checks both series for the same
fail-closed invariants. 0001, 0002 and 0005 are not rebased yet (bluejay rung b0 does not carry
them).

`0005-systemui-optionally-hide-keyguard-clock.patch` adds the SystemUI resource
`config_phonevaultHideKeyguardClock` (default false). When the product overlays it
to true, the default keyguard blueprint omits the clock and smartspace sections and
the legacy date slice is detached, so the once-per-boot credential keyguard shows
no time or date (keyguard and AOD share that view tree); lock icon, bouncer and the
indication area are unchanged. It covers the blueprint path only, which is the
compiled path while `com.android.systemui.migrate_clocks_to_blueprint` is
ENABLED/READ_ONLY (bp1a).

The patches under `patches/appliance/`, `patches/device-crosshatch/`, and
`patches/kernel-crosshatch/` are also Phone Vault changes. They remove
appliance-inapplicable SystemServer startup paths, hardware declarations,
radio startup triggers, and unsafe USB gadget functions. Appliance patch 0013
gates the `netd` init action on the immutable offline property and removes stale
zygote restart hooks; the corresponding
native daemons and network administration tools are excluded from the product
and rejected by the artifact policy. Appliance patch 0014 retains Android's
required connectivity boot/system-server classpath fragments but strips the
same APEX of its network daemons, daemon init files, BPF programs, and resource
application. The release verifier opens that APEX filesystem and audits its
embedded paths instead of trusting the outer target-files listing. Patches
0015 and 0018 disable otherwise unconditional modular consumer services and the
system text-classifier under the immutable appliance property, while the
PhoneVault module overrides exclude the complete advertising, SDK sandbox,
AppSearch, device-lock, external text service, health, personalization,
scheduling, UWB, virtualization, neural-network, software-codec,
remote-provisioning, and DNS-resolver modules. Their boot/system-server jar
declarations in `default_art_config.mk` are intentionally left in place: Soong
analyzes every source `bootclasspath_fragment`/`systemserverclasspath_fragment`
regardless of installation and rejects a missing `PRODUCT_APEX_BOOT_JARS` /
`PRODUCT_APEX_SYSTEM_SERVER_JARS` entry, whereas runtime class paths derive
only from installed APEX protos. Exclusion is verified on the artifact, not the
classpath configuration. A dexpreopt-enabled production build must still
resolve `dex_preopt_check` for the declared-but-uninstalled system-server jars. SystemUI links the Bluetooth and Wi-Fi framework APIs, so
patch 0016 retains those classpath jars while stripping their applications,
JNI libraries, radio executable, certificates/configuration, and other runtime
payload. The connectivity and Wi-Fi service jars compile against the resource-only
`ServiceConnectivityResources` and `ServiceWifiResources` APKs (Soong rejects
an APEX module that depends on a system-partition module), so patches 0014 and
0016 keep exactly those two code-free APKs and the APEX payload policies exempt
them by exact `priv-app/<name>@<build-id>/` path; the tethering application,
Cronet native runtime, and every other application remain forbidden (patch
0021 marks Cronet's test-only twin non-installable so the two identically
named libraries do not collide once neither is packaged in an APEX). Patch
0017 similarly retains Android/SystemUI media API jars while
removing MediaProvider, Photo Picker, PDF/media JNI, extractor plugins,
transcoding service, CLI, init policy, and compatibility resources. Patch 0019
removes the incident-reporting, heap-profiling, Perfetto/traced, and
kernel-log diagnostic executables plus Android's default persistent-tracing
property; the device audit rejects those processes and the modular consumer
services disabled by patch 0015. Patch 0020 removes the `netcat`/`nc` applet
from the device toybox multiplexer (`CFG_NETCAT`, source, and symlinks) because
package overrides cannot remove a toybox symlink. Crosshatch device patch 0023
drops the NXP NFC controller configuration copies that survive package
subtraction.

Appliance patch 0022 removes the camera-daemon cgroup setup from AOSP's
`init.rc` and the `android.system.wifi.keystore` declaration from the framework
VINTF manifest. Crosshatch device patches 0024–0026 trim the stock
`product.prop`/A2DP property overrides to display and input tuning, drop the
per-SKU secure-element ODM manifests, and stop installing the modem
diagnostic, RFS, and logging init files that earlier patches had already
stopped importing.

The first full appliance image showed that a small set of HAL *client
interface* stubs cannot be removed by product policy: `libandroid_servers`
(system_server JNI) links the GNSS and ContextHub stubs, `libsensorservice`
links the sensors stubs, `libandroid_runtime` (zygote) links the
`camera.device@3.2` stub, `qseecomd` (the TEE daemon behind keymaster and FBE)
has `libdrmfs` as a NEEDED dependency, and the vendor display post-processing
daemon links the sensorservice client. Those exact paths are enumerated in
`policy/permitted-interface-libraries.txt` and are matched literally by the
target-files gate; HAL servers, init policy, feature declarations, VINTF
entries, kernel drivers, and any other interface library remain forbidden.
Removing the GNSS/ContextHub JNI and evaluating `mm-pp-dpps` are recorded
follow-ups once the image boots. Later
Crosshatch patches also remove modem
RFS, diagnostic, SLPI sensor, wireless, radio/location/NFC, ramdump, factory,
Bluetooth-audio, sound-trigger, and hardware-media initialization that remains
after package subtraction. The final Crosshatch appliance patches also remove
unused CDSP/SLPI payloads and firmware plus explicitly installed proprietary
camera, location, sensor-hub, neural-compute, DRM, Bluetooth-codec, diagnostic,
and wireless-charging libraries. Device-side follow-ups remove the matching
namespaces, properties, feature/config copies, calibration inputs, subsystem
restart targets, and dead init policy rather than relying only on package
overrides. They must not be represented as GrapheneOS work.

The Qualcomm legacy WLAN Soong namespace remains visible solely because Soong
validates the root `hostapd` definition even when Phone Vault excludes that
module. Namespace visibility is not installation: Wi-Fi packages, firmware,
permissions, VINTF declarations, init policy, and final artifacts remain
release-blocking.

The Crosshatch kernel patch adds a fragment merged after the stock
`b1c1_defconfig`. It disables Wi-Fi, Bluetooth, NFC, the Qualcomm modem
firmware loader, cellular RMNET/IPA, GLINK test/userspace packet endpoints,
camera, sensor-hub, and unused compute-DSP drivers, and removes every configfs
USB function except Android Open Accessory and FunctionFS (the latter is
retained only for gated userdebug ADB). It is symbol-for-symbol the union of the
boot-tested dev-ladder slices A-D (rung 2d-d). DWC3 stays dual-role: a
gadget-only kernel booted but never enumerated on USB (rung 2d-d first attempt,
2026-09-28); the host-only mode is forbidden, and host/source roles are refused
in user space instead (device patches 0002, 0003, 0027-0029 and the sink pin in
`init.phonevault.usb.rc`). The target-files gate evaluates
`META/kernel_configs.txt`, so a future upstream config change cannot silently
re-enable these drivers.

Device patches 0027-0029 fold the dev-ladder rung-3 USB lock-down (boot-tested
2026-10-10) into the release series: the gadget HAL appends no Qualcomm vendor
functions (diag/serial/rmnet via `vendor.usb.config` or the usbradio boot mode),
a failed port mode switch falls back to `sink` instead of dual-role and the port
status reports UFP-only with no role or mode changes, and the dwc3 `id` node
(writing 0 forces host mode) stays root-only.

## Recovery

`bootable-recovery/0001-recovery-no-unverified-install-or-adb-on-user-builds.patch`
(Phone Vault) makes recovery on a user build (`ro.debuggable=0`) refuse packages
that fail signature verification, undeclared downgrades and SPL downgrades
without offering "Install anyway?", remove the "Enable ADB" and system
mount/format items, and never start recovery adbd (the explicit "Apply from
ADB" sideload remains for signed OTAs). Upstream keyed these on the
`ro.build.type` string alone. Userdebug development images, which the dev
ladder sideloads with the install-anyway tap, keep the upstream prompts. The
same patch applies to the Lineage 22.2 crosshatch tree and, with line offsets
only, to the Lineage 24.0 (Android 17) bluejay tree. `install-overlay.sh`
applies it with the other release patches.

`install-overlay.sh` records the exact patch bytes under `.repo`, but it also
checks whether a recorded patch is forward-applicable and repairs it when
needed. This ordering matters for deletion-only patches: reverse applicability
alone is not proof that a deletion has already occurred when Git could instead
insert a duplicate block. A recorded patch that neither applies nor
reverse-applies is accepted only when later patches of the same series are
recorded too, touch the same files, and undoing them (newest first) on a scratch
copy of those files leaves the patch reverse-applicable; otherwise the installer
fails instead of trusting the marker (e.g. a tree reset by a sync or the dev
ladder that lost the hardening).

## Evaluated but not imported

- `hardened_malloc`: current upstream explicitly supports the current Android
  generation and Linux GKI 6.1/6.6/6.12. Crosshatch uses Android 15 with a 4.9
  kernel, so importing the current allocator would be unsupported and would not
  satisfy the project's testability requirement.
- GrapheneOS USB port security UI: tightly coupled to newer Pixel USB HAL and
  hardware. Vault OS will instead expose only its signer transport in product
  policy and test the actual crosshatch USB functions.
- Google Play compatibility, Storage Scopes, network runtime permission, and
  general-purpose multi-profile features: irrelevant to an image with no Play
  services, browser, consumer apps, or secondary users.

Acceptance here means “selected for application and build testing,” not proven
production compatibility. `apply-hardening-patches.sh` must apply cleanly, the
framework must compile, and recovery/update negative tests must pass.
