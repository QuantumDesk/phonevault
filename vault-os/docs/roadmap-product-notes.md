# Product roadmap notes (2026-08-18)

Captured from the founder discussion during the first full-image bring-up.
These are design intents, not commitments; each item must be reconciled with
`threat-model.md` before implementation and gated like everything else.

## 1. Key lifecycle: stateless mode and a first-run wizard

(Updated 2026-09-04.) The signer now generates a BIP39 24-word seed
(`SeedVault`: kernel CSPRNG + software jitter, hash-combined, startup sanity
checks), wraps the mnemonic with a StrongBox AES key, derives m/44'/60'/0'/0/0,
shows the phrase on a full-screen reveal, and sits behind a 6-digit PIN with a
verified erase after 10 failures. Still missing: import/restore, mandatory backup
verification, first-run wizard, passphrase persistence, and any duress design
(see threat-model "Known limitations").

Planned:

- **Two explicit operating modes**, sharing the same kiosk/USB/approval boundary.
  Founder decision (2026-08-18): the device holds the wallet by default
  (*persistent* mode); *stateless* is offered as an option.
  - *Stateless* (SeedSigner-style): the seed is entered each session, the key
    exists only in application memory, power-off is the wipe. Nothing sensitive
    at rest; removes the forensic-erasure hedge and the backup/PIN/duress
    surface. Ideal as a commodity multisig cosigner.
  - *Persistent*: StrongBox-wrapped storage as today; mandatory for passkeys,
    whose credentials are inherently persistent.
- **On-device wizard** (inside the kiosk trust boundary): entropy generation
  with optional user-supplied entropy (dice rolls / typed entropy hashed
  together with system randomness), BIP-39 mnemonic display with a
  verify-back step, optional passphrase, standard derivation
  (BIP-44 `m/44'/60'/0'/0/x`) so seeds recover in any standard wallet, import
  of an existing seed, screenshots/overlays blocked (already enforced).
- Full OS-level amnesia (Tails-style) is not a good fit for Android: the
  framework needs `/data` for device-owner state and StrongBox-wrapped keys.
  Stateless mode is an app-level property, not an OS mode.

## 2. Entropy

The Snapdragon 845 hardware RNG feeds the kernel CRNG (`getrandom`), and Titan M
has its own TRNG for keys generated inside it. `SecureRandom` is therefore
hardware-seeded but not user-verifiable. User-supplied entropy mixing (above)
is the standard mitigation and is cheap to add.

## 3. Passkeys (FIDO2/WebAuthn authenticator)

A strong fit: passkey keys can be non-extractable P-256 inside StrongBox, which
is stronger than the EVM key today. Two transport designs:

1. Native CTAP2-over-USB-HID: re-enable `CONFIG_USB_CONFIGFS_F_HID`, add
   `hid` to the USB function allowlist, and bridge the unprivileged app to
   `/dev/hidg0` via a small privileged service. Best UX; largest change to the
   USB/kernel gates and the threat model.
2. Host bridge: keep AOA as the only phone transport, run CTAP over the JSON
   channel, and present a virtual FIDO HID device on the host (Linux `uhid`
   is straightforward; Windows/macOS harder). No phone-side surface change.

Either way: credential store (per-RP keys, user handles, counters), CTAP2
`getInfo`/`makeCredential`/`getAssertion`, user verification on the trusted
display, attestation decision. Phase 2, after boot and signing validation.

## 4. Licensing and trust model

The repository has no license file yet. The base is Apache-2.0 (LineageOS/AOSP)
and the kernel patches are GPL, so the image cannot be distributed with
withheld kernel changes. The trust argument of a self-built appliance is
auditability plus reproducibility, which the release tooling already targets
(signed release manifest, source inventory bound into the release, pinned
manifest, deterministic APK, AVB digests). Recommended: open-core with
everything inside the trust boundary open and reproducible (signer app, OS
overlay/patches, release tooling, host verifier); companion apps, services,
UX, and kits may stay proprietary. Decide the license deliberately.

## 5. Hardware target

Pixel 3 XL is end-of-life; it validates the design and tooling. A currently
supported Pixel is the real product target.

## 6. Optical (animated QR / BC-UR) transport

Animated-QR fountain codes (BC-UR, EIP-4527) are the industry's air-gap
transport and are already supported by major host wallets. Assessment:

- Outbound QR on the display (signed transaction, address) is cheap, adds no
  attack surface, and removes the need for any data to leave over USB.
  Candidate for an early follow-up.
- Inbound QR requires the camera, which this image deliberately removes. On
  this SoC the camera path (closed camx/chi HAL, ISP firmware, cameraserver,
  kernel drivers) is one of the largest opaque blobs on the phone, so
  "camera in" is not obviously safer than the small, open USB gadget path it
  would replace. If pursued, it must be a separate, gated build variant with a
  measured camera-stack exposure review, not the hardened default. It would
  also enable SeedQR entry for stateless mode.
