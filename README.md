# Phone Vault

An offline EVM signing appliance: a spare Pixel 3 XL running a hardened LineageOS build
("Vault OS") that boots straight into a kiosk signer app. The phone never has network access;
it shows a receive address, reveals a 24-word backup, and signs EIP-1559 transactions only after
the user reviews every decoded field on the phone's own screen.

## Security status — read this first

**Unaudited prototype. Test assets only. Do not store real funds.**

What exists today (2026-09-04): a BIP39 24-word seed (kernel CSPRNG + a software jitter source,
hash-combined, with startup sanity checks — see `vault-os/docs/entropy-design.md` for what is
and is not met), encrypted at rest by a non-exportable StrongBox key and stored as one
self-checking, journaled record; a 6-digit PIN gate with a verified erase after 10 failures;
session-bound lock/unlock/signing; two-phase wallet replacement; a host verifier that recovers
the signer and requires a pinned pairing.

What does not exist yet: restore from seed, mandatory backup verification, a first-run wizard,
multiple accounts, passphrase persistence, PIN change, message/EIP-712 signing, and — most
importantly — a **hardened, relocked, release-signed OS image**. The development phone runs an
unlocked bootloader with ADB enabled and a debug build that dumps its own screen for UI review.
`vault-os/docs/roadmap.md` §0 lists every debug-only setting that must be reverted, and §0.5
tracks the audit findings. Nothing here is "production-safe" until verified boot with a relocked
bootloader has been demonstrated.

"Lock" drops references to key material; it does not prove memory erasure. Replacing the
wallet changes the active key; it does not prove forensic erasure of prior storage history.

## Building

Prerequisites (not versioned): JDK 21, an Android SDK with platform 35 and build-tools 35.0.0,
Gradle 8.10.2. Point `JAVA_HOME` and `ANDROID_HOME` at them. The dependency graph is locked in
`app/gradle.lockfile` and every artifact's SHA-256 is in `gradle/verification-metadata.xml`;
Gradle refuses anything that does not match. Adding a dependency is a reviewed change made
with `gradle --write-locks --write-verification-metadata sha256` and both files committed.

```sh
gradle :app:testDebugUnitTest :app:assembleAppliance :app:assembleRelease
```

Build types:

- `debug` — installable everywhere; allows software-backed key wrapping on phones without
  StrongBox; UI dump enabled.
- `appliance` — what the development phone runs: non-debuggable, minified, requires StrongBox,
  **but** shares the debug source set's `DevTools` UI dump and is debug-signed. Its manifest
  carries `dev.phonevault.variant=dev-appliance`; `vault-os/scripts/verify-signer-apk.sh`
  refuses it.
- `release` — no dump code compiled in at all, install/uninstall of apps disallowed by device
  policy, `dev.phonevault.variant=release`. Signed separately by the release workflow.

Reproducibility: clean builds on different hosts are **payload-equivalent, not byte-identical**
— `classes.dex`, `resources.arsc` and the manifest match, the ZIP container does not. Compare
entry digests, not APK hashes, until the pinned build container and deterministic packaging
land (roadmap chunk 5).

## USB protocol

The desktop is the Android Open Accessory (AOA) USB host. Requests and responses are
newline-delimited UTF-8 JSON, limited to 32 KiB per request. A request must end with a newline
before disconnect, use a short ASCII request ID, and contain exactly the fields in its method
schema. Malformed UTF-8, truncated frames, missing fields, unknown fields, duplicate keys,
non-string values, and trailing JSON data fail closed. The phone answers only while unlocked;
an attach while locked or during a wallet replacement is parked until the vault is ready.

Address request:

```json
{"id":"address-1","method":"getAddress"}
```

EIP-1559 signing request (all integer quantities are canonical `0x` hex):

```json
{
  "id":"test-1",
  "method":"signEip1559",
  "chainId":"0xaa36a7",
  "nonce":"0x0",
  "maxPriorityFeePerGas":"0x3b9aca00",
  "maxFeePerGas":"0x77359400",
  "gasLimit":"0x5208",
  "to":"0x1111111111111111111111111111111111111111",
  "value":"0x0",
  "data":"0x"
}
```

The signer accepts only native transfers and canonical ABI-shaped `transfer(address,uint256)`
or `approve(address,uint256)` calls; arbitrary calldata fails closed. It displays the signing
address, network, recipient or approved address, raw `uint256` argument, target contract,
four-byte selector, maximum fee, nonce, and decoded arguments, and requires an
operation-specific review checkbox before **Sign** is enabled. The approval is bound to the
unlock session and to an immutable credential snapshot: a lock, a wallet replacement, or an
identity change after review cancels it. A selector and well-formed arguments do not prove the
target implements ERC-20/721 or behaves as expected; token identity and decimals are
unverified. Sensitive controls discard obscured touches.

## Desktop client

```sh
python -m pip install --require-hashes -r tools/requirements.txt
python tools/aoa_client.py pair          # once per host: compare the address with the PHONE's screen, then pin it
python tools/aoa_client.py sign-test     # waits for on-phone approval
```

`pair` is mandatory. The client recomputes the transaction hash from the signed bytes and
recovers the signer with its own Keccak/secp256k1 code (`tools/evm_verify.py`, no extra
dependencies); the recovered signer must equal both the address the phone claims **and the
address pinned at pairing**. Without a pairing the client refuses to accept any signature —
a self-consistent response from an unknown device proves nothing. The pairing file is written
privately (0600, atomic replace) and rejected on load if it is a symlink, group/world readable,
or owned by someone else. Rejections and device errors exit non-zero.

## Layout

- `app/` — the signer app (`SeedVault`, `VaultKeyStore` + `WalletPersistence`, `VaultPin`,
  `AccessoryTransport`, `EvmSigner`, `MainActivity`).
- `tools/` — host client, `evm_verify.py`, and `dev-device/` scripts that drive the
  development phone (throwaway devices only; see its README).
- `vault-os/` — the OS overlay, hardening patches, build/sign/verify scripts, policy tests,
  and docs (`roadmap.md`, `threat-model.md`, `entropy-design.md`).

## License

Apache-2.0 (`LICENSE`); see `NOTICE` for the open-core boundary (kernel patches remain
GPL-2.0) and third-party licenses, including the Press Start 2P font (SIL OFL 1.1,
`app/src/main/assets/fonts/OFL.txt`).
