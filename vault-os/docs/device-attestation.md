# Device attestation: is this phone genuine Phone Vault?

Status: implemented and unit-tested (phone JVM, companion Rust with real Google attestation
chains, host Python) and run on both development phones (see "Hardware results" below). Today's
phones are unlocked development devices and are reported as DEVELOPMENT, as they should be.
GENUINE needs the release keys and a relocked bootloader ([ROADMAP.md](../../ROADMAP.md), G2).

## Why

A hardware wallet bought from a reseller can be tampered with before it reaches the buyer
(swapped firmware, a modified app, a pre-generated seed). The buyer needs a check that does not
depend on trusting the seller or the phone's own screen. Android key attestation provides it:
the Titan M signs a statement about the key it just generated, the app that asked for it, and the
state of the boot chain, under a certificate chain that ends at a Google root key. The Mac
companion verifies that statement on every connection and before every send.

## What it proves (when the verdict is GENUINE)

1. **The keys are in a Titan M that Google certified.** The chain ends at a pinned Google
   hardware attestation root key, every link verifies, no certificate in it is on Google's
   revocation list, and the key description says StrongBox, consistent with the chain's own
   StrongBox intermediates.
2. **The bootloader is locked and booted Phone Vault firmware.** The root of trust is written by
   the bootloader into the Titan M before Android starts: `deviceLocked = true`, verified boot
   state Verified or SelfSigned, and `verifiedBootKey` equal to the pinned SHA-256 of the Phone
   Vault AVB key. Android cannot change these values after boot.
3. **The app holding the key is Phone Vault, signed by our release key.** The
   `attestationApplicationId` names exactly `dev.phonevault.signer` with exactly one signing
   certificate whose SHA-256 is pinned. This field is filled in by the OS (keystore2), so it is
   only as trustworthy as point 2: on a locked phone booting our signed images it is ours.
4. **The answer is fresh.** The attestation challenge equals the 32 random bytes the companion
   just generated; an old attestation cannot be replayed.
5. **This genuine device holds the paired wallet.** See "Address binding".
6. **The OS is not ancient.** `osPatchLevel` is at least `minOsPatchLevel`.

## What it does not prove

- **A genuine image can still be buggy or compromised at runtime.** Attestation says what booted,
  not that it is free of exploitable bugs. A kernel exploit on a genuine image could make the app
  lie about the wallet address (the binding is only as strong as the app, see below), although
  it still cannot change the root of trust or the app identity.
- **Physical attacks on the chip or the board**: fault injection, side channels, a replaced
  display or touch controller, a hardware implant. Those are outside what the Titan M reports.
- **Google root compromise, or a leaked batch attestation key** that Google has not yet revoked.
  The revocation list is checked when it can be fetched; between a leak and its revocation a
  forged attestation is possible. Pixel 3 uses factory-provisioned keys, which cannot be rotated.
- **That the seed was generated honestly.** It proves the firmware and the app are ours; the
  entropy design (`entropy-design.md`) is what the genuine app then does. A phone sold with a
  wallet already on it must be reset regardless.
- **Pixel 3 end of life.** Its vendor and Titan M firmware no longer get updates
  (`threat-model.md`, "Known limitations"). `vendorPatchLevel` will stay old.
- **Anything on an unlocked phone.** With the bootloader unlocked, the OS above the Titan M can
  be anything, so the app identity and the address statement could be forged by a modified OS.
  The Titan M still reports "unlocked" truthfully; that is why such a phone is never GENUINE.

## Protocol (USB, one exchange)

```text
→ {"id":"…","method":"attest","challenge":"<16..64 bytes, lowercase hex; the companion sends 32>"}
← {"id":"…","status":"ok","version":"1","address":"0x<40 lowercase hex>",
   "securityLevel":"StrongBox"|"TrustedEnvironment",
   "certificates":"<base64 DER leaf>,<base64 DER>,…,<base64 DER root>",
   "signature":"0x<DER ECDSA P-256 / SHA-256 by the attested key>"}
← {"id":"…","status":"error","error":"…"}
```

Same framing and limits as every other request (newline-framed flat JSON, schema-exact, ≤ 32 KiB
request; the response is ~5 KiB of the 64 KiB cap).

On the phone (`AttestationProtocol`, `AttestationKey`, `MainActivity.answerAttestation`):

1. Parse strictly: exactly `id`, `method`, `challenge`; the challenge is 16–64 bytes of lowercase hex.
2. Refuse a challenge already answered in this process (last 64 kept) and a second attestation
   while one is running.
3. Generate a fresh EC P-256 key `phone-vault-attest-v1` in StrongBox with
   `setAttestationChallenge(challenge)`; if StrongBox key generation fails, in the TEE, and say so.
4. Sign the binding message with it, read its certificate chain, **delete the key**.
5. Answer. Steps 3–5 run on a dedicated thread, so signing work on the crypto thread never
   waits behind a Titan M key generation (seconds).

No new permission. `setDevicePropertiesAttestationIncluded` is not used: it adds brand/model ID
attestation that the verdict does not need, and ID attestation fails outright
(`CANNOT_ATTEST_IDS`) when the IDs provisioned in the Titan M differ from the running build's
properties, as a custom OS's may. Unique-ID and attest-key features are not used either. The
release gate's permission allowlist (USE_BIOMETRIC only) is unchanged.

### Locked phone

While the vault is locked the request is **held, like `getAddress`**: the lock screen shows
"The connected host asks this phone to prove it is genuine Phone Vault hardware and firmware.
Unlock to continue." and nothing is sent until the PIN is entered; then it is answered through the
ordinary path. The attestation itself reveals nothing secret, but its answer names the wallet
address, and the USB data-lock rule is that no bytes leave a locked phone. The companion already
keeps asking a locked phone and completes when it is unlocked.

## Address binding (and why not a wallet signature)

```text
binding   = "PhoneVault-attest-v1" ‖ 0x00 ‖ len(challenge) (1 byte) ‖ challenge ‖ address (20 raw bytes)
signature = ECDSA-P256-SHA256(attested key, binding)
```

The companion verifies the signature with the public key in the attested leaf certificate.
Because that key was generated inside the Titan M for `dev.phonevault.signer`, on a locked phone
booting our firmware, for this challenge, and was deleted afterwards, the statement "this device
holds wallet 0x…" comes from the genuine app on the genuine device, now. The companion then also
requires the attested address to equal the paired address before it sends anything, and every
signature the wallet produces is still recovered and compared with that address.

Vectors shared by both sides: `app/src/test/resources/attestation-vectors.json`.

**Considered and rejected: also signing with the wallet key** (an EIP-191 personal message over
the same bytes, so the host can recover the address cryptographically). It would prove
possession of the wallet key independently of the app's honesty, but:

- it is a wallet-key signature the user never approved on the phone, which breaks invariant 1
  in `threat-model.md` ("cannot cause signing without a fresh on-device approval"), and the
  attestation runs automatically on every connection;
- a host chooses the challenge, so the phone would become an oracle for `personal_sign`
  signatures over host-influenced bytes. The fixed `PhoneVault-attest-v1` prefix, the length
  byte and the fixed total length make it unusable as a transaction, an EIP-712 digest or a SIWE
  message, but "no dApp anywhere accepts a personal_sign over this prefix" is a claim about the
  whole ecosystem that we cannot check;
- it adds nothing on a GENUINE phone: there the app is ours and already only reports its own
  address, and on a compromised phone a runtime exploit that can lie about the address can also
  use the wallet key.

The trade-off we accept: the address binding is as strong as the genuine app on a locked,
verified image (and is re-checked on every real signature), not independent of it. The attested
key itself can sign nothing else: it exists for one exchange, is single-purpose, and is not the
wallet key, so its signature cannot be replayed as anything Ethereum accepts.

## Verification on the companion (`companion/src-tauri/src/attest/`)

- **Roots** (`chain.rs`): Google's hardware attestation root public keys, pinned as
  SubjectPublicKeyInfo bytes: the RSA-4096 root (all its certificates, 2016–2022, share the key;
  the 2016 certificate that Pixel 3 chains still carry expired 2026-05-24, which is why the anchor
  is the key) and the ECDSA P-384 "Key Attestation CA1" root that signs chains from 2026-02-01.
  Source: <https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate>
  (also <https://android.googleapis.com/attestation/root>; a unit test re-derives both keys from
  that file).
- **Chain**: 2–8 DER certificates, v3, no trailing bytes; the last one's key is pinned; issuer =
  next subject; outer and inner signature algorithms agree; signatures verified with `ring`,
  restricted to RSA PKCS#1 v1.5 SHA-256/384/512 (2048–8192 bits) and ECDSA P-256/P-384 with
  SHA-256/384 (no SHA-1, no PSS). Validity of the certificates between leaf and root at the
  current time: not-yet-valid fails; expired fails except on factory-provisioned chains, which
  Google's own verifier (github.com/android/keyattestation) tolerates because those keys cannot be
  rotated; reported as a note. The leaf's own dates come from the phone's offline clock and are
  reported only, as in Google's verifier. The attestation extension must be in the leaf and in no
  other certificate (chain-extension attack).
- **KeyDescription** (`keydesc.rs`, strict DER reader `der.rs`): attestationVersion,
  attestationSecurityLevel, keyMintVersion, keyMintSecurityLevel, attestationChallenge, uniqueId,
  softwareEnforced and hardwareEnforced AuthorizationLists with purpose, algorithm, keySize,
  ecCurve, noAuthRequired, creationDateTime, origin, rootOfTrust {verifiedBootKey, deviceLocked,
  verifiedBootState, verifiedBootHash}, osVersion, osPatchLevel, attestationApplicationId
  {package names and versions, signature digests}, vendorPatchLevel, bootPatchLevel. Tags must be
  ascending; unknown tags are skipped; lengths, integers and booleans must be DER.
- **Revocation** (`revocation.rs`): <https://android.googleapis.com/attestation/status>, cached
  24 h (its `Cache-Control`), a cached copy up to 7 days old is used offline; otherwise "unknown",
  shown but not a failure. Serials are compared as lowercase hex without leading zeros. Only the
  public list is fetched; nothing about the phone is sent.
- **Crates** (pinned with `=`): `x509-parser 0.18.1` (parsing only), `ring 0.17.14` (already in
  the tree via rustls), `base64 0.22.1`; dev-only `rcgen 0.14.10` for synthetic test chains.

## Verdict policy (`policy.rs`, config `companion/src-tauri/attestation-policy.json`)

The policy file is compiled into the companion (not editable at run time). It pins the package,
the release and development signer certificate digests, the Phone Vault AVB key digests and the
minimum OS patch level.

**FAIL** (red; pairing, Send, message signing and WalletConnect requests are blocked) if any of:

- the answer is malformed, or the phone refuses for a reason other than "not ready"/"busy"
  (an app too old to attest fails: it cannot prove anything);
- the chain does not verify, ends at an unknown (or software) root, or carries the extension in a
  non-leaf certificate;
- a certificate in it is revoked;
- the challenge differs from the one sent (replay);
- software attestation; attestation and KeyMint security levels differ; the phone claims a
  different level than the certificate; the certificate claims StrongBox but the chain is not a
  StrongBox chain, or vice versa;
- the key was not generated in hardware (`origin` ≠ GENERATED), is not P-256, or its signature
  over the address binding does not verify;
- the app is not exactly `dev.phonevault.signer` with exactly one signer; the signer is unknown;
  or it is the development signer and Developer mode is off;
- verified boot FAILED (red); locked + Verified/SelfSigned with a boot key that is not a pinned
  Phone Vault key (stock firmware, or someone else's custom key); locked with an unverified
  state (inconsistent); locked and genuine-looking but below the minimum patch level.

**DEVELOPMENT** (amber; usable, "not safe for real funds") when nothing failed but any of:

- the bootloader is unlocked (orange) — "Development firmware: bootloader unlocked — not safe
  for real funds";
- the app is development-signed and the user turned on Developer mode (Settings → Device; the
  switch and the badge say so loudly);
- the key was attested by the TEE because StrongBox failed.

**GENUINE** (green) otherwise: StrongBox, our release signer, locked, Verified or SelfSigned with
a pinned Phone Vault boot key, current enough patch level, challenge and binding good, not revoked
(or revocation unknown, which is shown).

Note on boot state: the request for this feature said "verifiedBootState = Verified (green)".
A Pixel relocked with a **custom** AVB key (`fastboot flash avb_custom_key`, our release plan)
boots in the **SelfSigned (yellow)** state, with `verifiedBootKey` = SHA-256 of that key; green
means the OEM's own key, i.e. stock firmware. So the policy accepts Verified *or* SelfSigned, and
in both cases only with a pinned Phone Vault key; yellow with any other key fails.

Until the release keys exist, `releaseSignerSha256` and `avbKeySha256` are empty, so **no phone
can be GENUINE** with this build. `developmentSignerSha256` pins the build host's Android Debug
certificate (`d8eab12d…4b53`) that signs the dev appliance APK.

## In the companion

- Runs on identify (a phone appears), on pairing (the attestation names the address that is
  compared with the phone's screen) and before every Send/message signature. The Rust side caches
  the verdict per USB connection (dropped when the phone leaves the bus, at most 15 minutes) and
  runs it itself if the UI did not; the UI cannot skip it.
- Header badge Genuine / Development / Not genuine; a banner on Home for anything not genuine;
  a FAIL dialog; Settings → Device shows the details (boot state, lock, verified boot key and
  whether it is ours, Android version, patch levels, app and signer, key storage, chain, root,
  revocation) and the Developer mode switch.
- Pairing: "It matches" stays disabled until the device check passed for that same address.
- `cargo run --example attest_verify -- request.json response.json [--dev-mode]` runs the same
  verifier on a captured exchange (used by `attesttest.sh`).

- Accounts: the attestation binds the phone's ACTIVE account. A cached verdict for a
  different address (the user switched accounts on the phone during the same USB connection) is
  asked again once before a request is refused; pairing is per address, each address attested
  when it is paired.

## Tests

- Rust (`attest/tests.rs`, `der.rs`, `revocation.rs`): real chains published by Google in
  github.com/android/keyattestation (Pixel 3 StrongBox and TEE — the same SoC and Titan M as the
  Pixel 3 XL —, Pixel 9a on the new EC root, Pixel 9 Pro remotely provisioned) parsed field by
  field against Google's own expected values and verified to the pinned roots; tampering, broken
  links, unknown root, expiry rules, Google's invalid samples (non-DER boolean, out-of-order
  tags); every FAIL/DEVELOPMENT/GENUINE rule on real parses; synthetic end-to-end chains under an
  in-memory **test-only** root (never Google's, never written to disk) for our package, our
  binding signature, chain extension, fake StrongBox, substituted address and replayed challenge.
- Phone JVM (`AttestationProtocolTest`): shared vectors, request schema, response fields,
  signature format, challenge reuse, and source guards (no wallet key, no ID attestation, off the
  signing thread).
- Host: `tools/test_aoa_client.py` (response schema); `tools/dev-device/attesttest.sh` (phone).

## What changes at release

1. Create the release APK signing key; pin its certificate SHA-256 in `releaseSignerSha256`.
2. Create the release AVB key; flash it with `fastboot flash avb_custom_key`; pin
   `sha256(avb_pkmd.bin)` in `avbKeySha256` and confirm it equals `verifiedBootKey` reported by a
   relocked phone (`attesttest.sh` prints it).
3. Relock. A relocked phone booting our image reports locked + SelfSigned + our key → GENUINE.
4. Consider removing the development signer from release companion builds altogether, and
   raising `minOsPatchLevel` with each release.
5. Re-check Google's root list and revocation format at each release.


## Hardware results

Both runs used `aoa_client.py attest` on the phone side and the companion's `attest_verify`
example to verify the saved exchange.

**Pixel 3 XL (Titan M), development rung 2d-d.** StrongBox chain of 4 to the Google RSA root
(pinned by key; that root certificate expired 2026-05-24), factory provisioning, attestation v4 /
KeyMint 41, package `dev.phonevault.signer` with the development signer, binding to the paired
address, not revoked. Boot state: unlocked, orange, boot key all zeros. Verdict: **FAIL** with
Developer mode off (development signer), **DEVELOPMENT** with it on, as designed. Vendor/boot
patch level 2021-10-05 (the Pixel 3's last firmware).

**Pixel 6a (Titan M2), development rung b0.** StrongBox chain of 4 to the Google RSA root,
**factory provisioning**: no remote key provisioning is needed, so the offline vault can attest
on the 6a (this settles the open question in `port-bluejay.md` §6). Attestation/KeyMint 300,
OS 17.0.0, OS patch 2026-10, vendor patch 2026-07-05, boot patch 2026-10; unlocked/orange;
development signer; bound to the wallet address; not revoked. Verdict with Developer mode:
**DEVELOPMENT**. (The companion app must be closed while the Python client runs: it holds the
accessory.)

Still to run on a phone: the repeated-challenge refusal and the locked-phone hold
(`attesttest.sh` cases 2–3), and GENUINE on a relocked phone with release keys.
