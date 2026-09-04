Place the reproducibly built, release-signed signer APK here as
`PhoneVault.apk`. Record its SHA-256 digest in the release manifest.

`presigned: true` prevents the Android build from silently replacing the app's
signature. Device-owner provisioning is a separate, explicit operation.

Before copying a release APK, run `scripts/verify-signer-apk.sh` with the
expected release-certificate SHA-256. The gate rejects debug builds and any APK
requesting Android permissions.

`phonevault_core_hardware.xml` is the appliance feature allowlist installed in
place of Android's general-purpose handheld feature declaration. Keep it in
sync with the release artifact checks in `verify-appliance-target-files.sh`.
