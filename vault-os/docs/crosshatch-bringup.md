# Crosshatch physical bring-up and relock gate

This procedure is intentionally manual. Unlocking or relocking erases user
data, and flashing the wrong product can make recovery substantially harder.
No Phone Vault script performs those operations.

Authoritative Android Verified Boot documentation states that Pixel 2 and
later devices support the user-settable `avb_custom_key` root, that it can only
be changed while unlocked, and that a locked device booting the custom root
shows the yellow Verified Boot state:

- <https://source.android.com/docs/security/features/verifiedboot/device-state>
- <https://android.googlesource.com/platform/external/avb/+/master/README.md>

Google's factory-image documentation confirms that unlocking/flashing erases
data and recommends relocking after using a custom image:

- <https://developers.google.com/android/images>

## Release blockers before touching the phone

- The complete target-files build has succeeded.
- The target-files appliance policy and complete AVB chain verification pass.
- `prepare-development-images.sh` has produced a new, checksummed artifact
  directory; the SHA-256 digest it prints for `SHA256SUMS`, the app certificate,
  and the AVB public-key fingerprint are recorded outside the build host and
  artifact directory.
- The generated `android-info.txt` allows exactly `crosshatch` (not the
  upstream `crosshatch|blueline` family), and every image expected by the
  fastboot package exists.
- A current Google platform-tools `fastboot` sees exactly the intended serial.
- The phone contains no data that needs to survive. The battery is adequately
  charged and a known-good data cable/port is in use.
- A matching stock factory image and recovery instructions are available
  locally before the first write.

## Stage A: read-only bootloader preflight

Enter the bootloader with the hardware keys or `adb reboot bootloader`. Record,
with an explicit serial on every command, at least. The packaged helper performs
these checks, validates the complete development-bundle checksum manifest, and
refuses multiple connected fastboot devices:

```text
scripts/preflight-crosshatch.sh SERIAL NEW_DEVELOPMENT_ARTIFACT_DIRECTORY EXPECTED_SHA256SUMS_SHA256
```

The third argument must be the checksum-manifest digest recorded out of band
when packaging completed. A digest read from the artifact directory itself is
not independent evidence. The helper is strictly read-only. Its equivalent
device queries are:

```text
fastboot -s SERIAL devices
fastboot -s SERIAL getvar product
fastboot -s SERIAL getvar unlocked
fastboot -s SERIAL getvar current-slot
fastboot -s SERIAL getvar slot-count
```

Stop unless the product is `crosshatch`. Do not infer identity from the USB
port, a previously observed ADB serial, or a filename.

## Stage B: unlocked development boot

Only after the operator explicitly accepts the data wipe, use the platform
bootloader unlock flow and confirm it on the phone. Flash the verified image
ZIP with the platform-tools `fastboot update` mechanism, never with a wildcard
or an unreviewed third-party flash script.

Boot once while still unlocked. A successful launcher screen is insufficient;
run `scripts/audit-development-device.sh SERIAL NEW_EVIDENCE_DIRECTORY APP_SHA256 VBMETA_DIGEST`,
using `phonevault_app_sha256` and `vbmeta_digest_sha256` from the verified
development `MANIFEST.txt`. Record the audit's printed
`evidence_checksum_manifest_sha256` outside the evidence directory, then
exercise Android Open Accessory transport, approve and reject test
transactions, disconnect during approval/signing, reboot, and repeat. Confirm
that the host-side decoder matches every signed EIP-1559 field to the request
and that no rejection or interrupted session returns a signature.

Do not proceed if first boot requires manual setup, Phone Vault is not HOME,
sole user-0 device owner, and active managed lock-task package, StrongBox
initialization reports an error, SELinux is permissive,
a forbidden interface/service/process or modem remote-subsystem node exists,
or USB exposes a function other than accessory plus development-only ADB.

## Stage C: custom root and locked boot

Return to the bootloader. Recheck the serial and the SHA-256 manifest. While the
device is still unlocked, install the exact public-key metadata emitted beside
the verified image bundle:

```text
fastboot -s SERIAL flash avb_custom_key avb_pkmd.bin
```

The key payload is public, but its hash must equal the recorded development or
release channel value. Never substitute the private PEM file.

Only after the unlocked runtime gates pass, invoke the bootloader lock flow and
confirm the second data wipe on the device. The next boot must show the custom
key/yellow Verified Boot warning and then automatically recreate Phone Vault as
owner and HOME. For a userdebug bring-up build, rerun the read-only audit and
require `yellow:1:locked`. A production user build must not expose ADB, so its
locked evidence comes from boot UI, accessory tests, recovery/OTA behavior, and
bootloader state rather than an ADB exception.

If the locked image does not boot, do not erase the custom key reflexively.
Record the screen and slot state first, then recover through the documented
unlock flow, accepting that another wipe occurs.

## Stage D: update and rollback evidence

Before treating any build as a release:

1. Install a signed full OTA into the inactive slot and boot it locked.
2. Confirm the active slot, build fingerprint, app certificate, owner/HOME,
   USB behavior, and yellow Verified Boot state.
3. Demonstrate that an older signed build below the accepted rollback index is
   rejected.
4. Demonstrate recovery from a deliberately failed update without accepting an
   unsigned partition or silently clearing the custom root.
5. Archive command transcripts, photos of physical confirmation/warning
   screens, runtime audit bundles, transaction/USB negative-test logs, and all
   artifact hashes as one release evidence set.

Passing development bring-up does not make the Pixel 3 XL suitable for valuable
assets. Its vendor firmware and hardware platform are end-of-life; this target
exists to validate the constrained-appliance design before porting it to a
currently supported Pixel generation.
