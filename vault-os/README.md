# Vault OS

Vault OS is a small, auditable LineageOS-derived product for turning a Pixel
into a dedicated offline transaction signer. It is not GrapheneOS and does not
use GrapheneOS branding or update infrastructure.

| Phone | Role | Base | Ladder |
|---|---|---|---|
| Pixel 6a (`bluejay`) | launch target | LineageOS 24.0 / Android 17 | [`dev-ladder-bluejay/`](dev-ladder-bluejay/README.md), plan in [`docs/port-bluejay.md`](docs/port-bluejay.md) |
| Pixel 3 XL (`crosshatch`) | development phone | LineageOS 22.2 / Android 15 | [`dev-ladder/`](dev-ladder/README.md) |

The build outline below and the release scripts in `scripts/` are written for
crosshatch; the 6a uses the same `vendor/phonevault` product with its own device
directory (`device/phonevault/bluejay`) and the bluejay ladder scripts.

## Security boundary

- The phone displays and approves every transaction locally.
- The signer app has no Internet permission.
- The signer is an ordinary preinstalled system app, not a `priv-app`; its
  appliance authority comes only from explicit device-owner provisioning.
- USB is the transaction transport; the host never receives the private key.
- Production images use project-owned release and AVB keys.
- A locked bootloader and a user-installed AVB root of trust make modified
  boot/system images detectable.

This is experimental software. Do not protect valuable assets with it until the
image, update process, signer, and recovery procedure have been independently
reviewed.

The concrete trust boundary, required invariants, release evidence, and known
hardware limitations are recorded in `docs/threat-model.md`. The manual,
wipe-aware physical validation sequence is in `docs/crosshatch-bringup.md`.

## Build outline

The Android build itself needs a 64-bit Linux environment and substantial free
disk. The checked-in container workflow currently builds on macOS through an
`linux/amd64` Docker container; Rosetta makes Android's Kati graph generation
slow, but keeps the build isolated and reproducible. `container-run.sh` mounts
this repository read-only at `/workspace/phone-vault`, which is the canonical
path consumed by the build, signing, and packaging scripts.

1. Initialize and sync the pinned LineageOS 22.2 manifest described in
   `manifest/README.md`, including the crosshatch dependencies and proprietary
   blobs.
2. Build Phone Vault, then run `scripts/install-overlay.sh` in the build
   container. Bring-up images embed the non-debuggable `appliance` variant,
   which requires StrongBox but uses a local development certificate. Public
   releases require a verified APK signed by the dedicated offline app key.
3. Apply the recorded hardening patches with
   `scripts/apply-hardening-patches.sh`.
4. For the first physical bring-up, set `WITH_DEXPREOPT=false` only when
   Rosetta requires the documented development workaround, run
   `source build/envsetup.sh`, lunch `vault_crosshatch-bp1a-userdebug`, and
   build `target-files-package`. The resulting ADB-capable image is
   development-only.
   Production must be rebuilt as `vault_crosshatch-bp1a-user` with dexpreopt
   enabled on native x86-64 Linux.
5. Run `scripts/verify-appliance-target-files.sh` against that archive.
   The gate also inspects the recorded kernel configuration and rejects radio,
   camera, sensor-hub, and removed DSP drivers even when no userspace service
   references them. It rejects a zero rollback index and any top-level vbmeta
   flags, including Lineage development defaults that disable verification or
   hashtree enforcement. The only exemptions from the forbidden-artifact
   policy are the exact HAL client stub paths listed in
   `policy/permitted-interface-libraries.txt` (see `patches/README.md`).
6. For physical bring-up only, run `scripts/prepare-development-images.sh`
   with a new `/artifacts` bind mount. It reruns appliance policy, verifies the
   complete AVB chain against the development key, invokes Android's hermetic
   image-packaging tool, and emits checksummed fastboot images plus the public
   custom-key payload. Development packaging also requires the embedded signer
   APK to match the exact host-built SHA-256, not merely the publicly known
   development certificate. The extracted bundle must contain boot, dtbo,
   product, retrofit `super_empty`, system, system_ext, vendor, and enforcing
   root-vbmeta images plus exact-crosshatch fastboot metadata. It performs no
   device operation.
7. Inject the externally mounted release keys with `scripts/sign-release.sh
   INPUT /release-keys OUTPUT (PREVIOUS_RELEASE_DIR | --first-release)`. Before
   signing it runs the release-source gate (`scripts/verify-release-source.sh`:
   no adb default, early-adb init script, `DEBUG-` marker or backup file in
   `vendor/phonevault`/`device/phonevault`), the production ADB policy on the
   target-files, `dev-ladder/check-overrides.sh release`, and the AVB
   rollback-index gate (`scripts/verify-rollback-index.sh`: the index equals
   `vendor/phonevault/config/release-version.mk` and is strictly greater than
   the previous signed release manifest's). See `docs/release-config.md`.
   It reruns appliance policy and cryptographically verifies the signed vbmeta
   images before producing an OTA. It also re-signs every non-presigned APEX
   with project module/payload keys, then verifies the actual certificate of
   every installed APK/APEX and the embedded public key of every APEX payload
   against the offline public inventory. It enforces the exact APK certificate
   role recorded in signed metadata, the dedicated Phone Vault app identity,
   and the dedicated module identity for every APEX container; an arbitrary
   certificate from the owned-key set is not accepted. The signing pipeline
   also verifies the OTA's whole-file and A/B payload signatures and requires recovery to
   trust exactly the project release certificate. Build AOSP's hermetic
   `check_ota_package_signature` host tool before signing. The pipeline refuses
   development target-files, any non-`user` build, debug-enabled properties,
   non-release build tags after signing, or an archive without a
   dexpreoptimized ARM64 boot image. A
   checksummed `RELEASE-MANIFEST.txt` binds the build fingerprint, signer APK,
   AVB key and complete vbmeta digest, rollback index, OTA certificate, signed
   target-files, OTA, and deterministic `SOURCE-INVENTORY.txt` for the app,
   locked dependency/checksum inventories, policies, patches, manifests,
   tooling, and build overlay into one public release record. The same bundle
   exports every public certificate, the AVB bootloader-enrollment blob, and
   the APEX payload public key under `public-keys/`, with their digest inventory
   bound into the release manifest; it never copies private release keys.
   `scripts/verify-release-bundle-metadata.sh` independently checks the
   portable checksum set, exact manifest schema, embedded signer APK,
   fingerprint, source/public inventories, and exported identities. The
   cryptographic AVB-chain and OTA gates remain separately mandatory.

No script in `scripts/` unlocks, wipes, flashes, or relocks a device. The
development ladder does: `dev-ladder/flash-rung.sh` sideloads a rung OTA (and,
with `--wipe`, erases userdata and metadata from fastboot) and
`dev-ladder/wipe-data.sh` erases userdata and metadata. Both pin every adb and
fastboot call to one serial (`PV_SERIAL`), refuse to run while any other device
is attached, and refuse any erase without `PV_THROWAWAY_DEVICE=1`; use them only
on a development phone whose wallet holds nothing. `dev-ladder-bluejay/flash-mac.sh`
flashes and wipes the Pixel 6a ladder images from the bootloader and refuses
unless exactly one device is in fastboot. Nothing here ever relocks a bootloader.
`scripts/preflight-crosshatch.sh` verifies the complete development artifact
checksum set against an independently recorded checksum-manifest digest,
requires that every bundle file is covered exactly once, and reads the exact
product, lock, and A/B slot state from one explicit fastboot serial before the
manual bring-up procedure can continue.
After a development image boots, `scripts/audit-development-device.sh` records
and hashes a read-only ADB evidence bundle for Verified Boot state, ownership,
HOME resolution, managed lock-task state, SELinux, packages, processes, Binder services, declared
features, USB state, interfaces, appliance properties, the complete bootloader
vbmeta digest, and the exact installed Phone Vault APK bytes against the
development manifest. Passing it is a
bring-up gate, not a substitute for the locked production and transaction tests.

## Current status

The crosshatch product layer targets LineageOS 22.2 and the crosshatch device
tree at commit `3716221d2f4101155e1b868437f34de343d0e52d`; the 6a port targets
LineageOS 24.0. Development images of both phones boot and pass their ladders
on hardware. A full signed `user` build, boot test, USB test, radio audit,
rollback test, and successful relock still remain mandatory before any image
can be called a release. Status and open items: [`../ROADMAP.md`](../ROADMAP.md).
