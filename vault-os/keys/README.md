# Release keys

Never commit private release or AVB keys. Keep an encrypted offline backup and
document which public key belongs to each release channel.

For development only, create an AVB key with:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out avb.pem
avbtool extract_public_key --key avb.pem --output avb_pkmd.bin
```

The workspace helper `scripts/generate-development-avb-key.sh` creates the
development PEM pair beneath the ignored `keys/development/` directory without
overwriting an existing key. `install-overlay.sh` stages only this development
private key into the isolated source volume for bring-up builds.

Production private keys must not be stored in this workspace or Docker volume.
They are injected from offline release infrastructure only during a controlled
release build.

The `avb_pkmd.bin` public-key metadata is what a supported Pixel accepts in its
`avb_custom_key` partition. Installing it and changing bootloader lock state are
manual, data-wiping operations and are intentionally outside the build scripts.

`scripts/generate-release-keyset.sh` creates Android release/platform/shared/
media/module certificates, a dedicated APEX payload key, and a 4096-bit OS AVB
key only when an empty encrypted offline directory is bind-mounted at
`/release-keys`. It refuses ordinary workspace paths and existing keysets. The
Android tool prompts separately for each PKCS#8 password; use an isolated
release host and never record passwords in shell history or environment
variables.
The currently pinned Lineage `make_key` helper returns status 1 after successful
generation because its cleanup trap applies `exit 1` to ordinary `EXIT` as well
as interrupt signals. The wrapper tolerates only that exact pinned defect and
only after both generated PKCS#8 and X.509 files parse. A changed helper,
different status, missing output, truncated DER, or invalid certificate remains
fatal. An in-memory integration ceremony verifies all ten distinct Android key
roles, the separate AVB/APEX keys, permissions, public inventory, and overwrite
refusal without persisting test private keys.
The offline `public-key-inventory.txt` uses paths relative to its key directory,
so it remains verifiable after the encrypted key archive is moved or restored.

`scripts/sign-release.sh` replaces Android APK, OTA, and AVB keys in a target
files archive and generates an offline-installable signed OTA. It also requires
the external `/release-keys` mount, reruns the appliance artifact policy,
cryptographically verifies every generated vbmeta image against the release
AVB key, explicitly replaces each non-presigned APEX payload/container identity
with the offline APEX/module keys, and refuses to overwrite output artifacts.
Post-signing verification of the actual APK and APEX identities against the
public inventory remains a release blocker. Development keys must never sign a
public release.
The verifier also enforces certificate roles: Phone Vault must retain its
dedicated externally applied `phonevault-app` identity, ordinary APKs must
match their exact `META/apkcerts.txt` assignment, and every resignable APEX
container must use the dedicated `module` certificate. Merely finding a signer
in the broader owned-key set is insufficient, and unexpected `PRESIGNED`
packages fail closed.

The release bundle exports only public material beneath `public-keys/`,
including every X.509 certificate, the AVB enrollment blob, and the APEX
payload public key. `PUBLIC-KEY-INVENTORY.txt` hashes those files and its own
digest is bound into `RELEASE-MANIFEST.txt`; private `.pk8`, AVB, and APEX keys
remain exclusively on the external offline mount.
`scripts/verify-release-bundle-metadata.sh` validates these bindings after the
bundle is moved; `verify-signed-avb.sh` and `verify-ota-package.sh` provide the
separate cryptographic image-chain and OTA checks.

Phone Vault itself uses the dedicated `phonevault-app` certificate and remains
`PRESIGNED` in the OS build. Sign the non-debug, zero-permission release APK
with `scripts/sign-signer-apk.sh`, then pass its path and expected certificate
digest to `install-overlay.sh` through `PHONEVAULT_SIGNER_APK` and
`PHONEVAULT_SIGNER_CERT_SHA256`. The installer runs the APK security gate before
staging it.
