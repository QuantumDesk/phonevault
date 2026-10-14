# Roadmap

Where Phone Vault stands, what has to happen before anyone should trust it with real funds, and
what comes after. An item counts as done only when it is built, running on a real phone, and
tested there; "built" alone is marked as such.

Standing rules (these never move):

- Nothing is called production-safe until a hardened, release-signed image has been built,
  flashed, booted, tested, **and verified-boot relocking has been demonstrated** on the phone.
- Never sign a transaction whose decoded fields differ from what the user approved.
- Never weaken a release, provenance, USB, device-owner or audit gate to make a test pass.
- Never expose, commit or print private keys or seed material.

## Current status

**Pre-release. Development phones only. No real funds.**

### Phone app

Working on hardware (development phones, development images):

- **Keys:** BIP-39 24-word seed from three hash-combined sources (kernel `getrandom`, a Titan M
  StrongBox-derived stream, CPU jitter) with startup health tests; encrypted at rest by a
  non-exportable StrongBox key in one self-checking, journaled record. See
  [entropy-design.md](vault-os/docs/entropy-design.md) for which requirements are and are not met.
- **Access:** the vault PIN is the Android device credential: the Titan M throttles guesses, the
  seed key only works after the system verified the PIN, and 10 failures wipe the phone by device
  policy ([pin-credential-design.md](vault-os/docs/pin-credential-design.md)). Lock on
  screen-off and idle; sensitive actions ask for the PIN again.
- **Wallet lifecycle:** first-run create or restore, mandatory account-bound backup check before
  receiving or signing, restore over an existing wallet, two-phase wallet replacement, multiple
  accounts, optional passphrase wallets, SeedQR export, backup reminder, printable backup card.
- **EVM signing:** strict, schema-exact USB requests; native transfers, ERC-20
  (transfer / approve / transferFrom / increaseAllowance) with a pinned token list, NFT approvals
  and transfers, decoded Uniswap swaps; unexplained calldata and EIP-7702 delegations refused;
  address book with first-send and look-alike (address-poisoning) warnings; the companion's
  simulation shown as an untrusted claim with contradiction warnings.
- **Messages:** `personal_sign` and EIP-712 with plain-language review (sign-in, Permit2,
  orders) ([message-signing.md](vault-os/docs/message-signing.md)).
- **Bitcoin:** BIP-84 and BIP-86 (key path) accounts, PSBT review and signing; a signet
  transaction has been signed on a phone and confirmed.
- **Device attestation:** StrongBox key attestation bound to the active address
  ([device-attestation.md](vault-os/docs/device-attestation.md)); run on both phones, verdict
  DEVELOPMENT as expected for unlocked development images.

### Companion (macOS) and browser extension

Built and covered by automated tests (Rust unit tests, a browser mock, a headless-Chrome
end-to-end test of the extension bridge); partly exercised with a phone; not yet used end to end
by outside testers. Pairing with attestation, guided setup, balances and USD values, Send with
independent verification and explicit broadcast, speed up / cancel, incoming history,
NFTs, menu bar and notifications, WalletConnect, the EIP-6963 browser extension over native
messaging, and a watch-only Bitcoin wallet. Unsigned and not notarized.

### Vault OS

- **Pixel 3 XL (development):** the hardening ladder ([dev-ladder](vault-os/dev-ladder/README.md))
  has passed on hardware through rung 4b: automatic device-owner provisioning and kiosk, our AVB
  key with verity enforcing, the appliance VINTF manifest, kernel without radios, modem, camera,
  sensors, DSPs or extra USB functions, USB locked to accessory (+ adb on dev images) and
  device-only, and about 100 unused apps and services removed. The release configuration folds
  all of that in ([release-config.md](vault-os/docs/release-config.md)), but a `user` release
  build has not been booted yet.
- **Pixel 6a (launch target):** LineageOS 24.0 / Android 17 port
  ([port-bluejay.md](vault-os/docs/port-bluejay.md)); ladder
  ([dev-ladder-bluejay](vault-os/dev-ladder-bluejay/README.md)) rungs b0–b4c passed on hardware:
  hands-off factory boot into the kiosk, our development AVB key with verification on, unused
  kernel modules removed, USB lock-down, radios off, app strip. The app suites (first run, USB
  signing, message signing, credential) pass on b4c.

### Debug-only state on development images

Development rungs deliberately keep: a `userdebug` build with adb enabled and a pre-authorised
builder key, screenshots and the UI dump hook in the `appliance` app variant, app
install/uninstall allowed, test-key OTAs with "install anyway" in recovery, and an **unlocked
bootloader**. The release configuration removes each of these and the release gates refuse them;
none of it has been proven on a booted release image yet.

## Milestones to a release

Each milestone has an exit test that must pass on a real phone.

**G1 · Locked-down appliance.** The OS is a single-purpose signer.
- [x] Crosshatch ladder through rung 4b (USB functions, USB HAL host-role refusal, app strip).
- [x] Release defconfig keeps DWC3 dual-role (gadget-only never enumerated) and refuses the host
      role in user space.
- [ ] Further strip slices: telephony/radio framework with system_server gating, media, APEXes,
      vendor prune.
- [ ] `user` build: no adb, no dump hook, `FLAG_SECURE`, release overlay (no emergency-call
      kiosk escape).
- [ ] 6a: appliance VINTF manifest, camera/TPU/sensor slice, telephony rung, user build.
- Exit: user build on the phone; only AOA enumerates; full signing and credential suites pass;
  no crash-looping services; adb unreachable.

**G2 · Verifiable trust chain.** Anyone can check the phone is genuine and unmodified.
- [ ] Release keys generated offline in a documented key ceremony; signed OTAs; recovery that
      trusts only the release key.
- [ ] Our AVB key enrolled, bootloader relocked, refuse-to-boot on a tampered image demonstrated.
- [x] Device attestation built and run on both phones (DEVELOPMENT verdict on unlocked images).
- [ ] Pin the release app signer and release AVB key in
      `companion/src-tauri/attestation-policy.json`; a relocked phone reports GENUINE.
- [ ] Reproducible builds: pinned container, byte-identical app and OS images; public log of
      release hashes.
- Supply-chain stance: users flash their own phone (never a pre-flashed one from a reseller);
  attestation re-checks on every connection.
- Exit: a relocked phone shows "Genuine"; a reflashed or tampered phone shows "Not genuine" and
  will not pair; two independent builds produce the same hashes.

**G3 · A phone people can get.** Supported, still-patched hardware.
- [x] Port to the Pixel 6a (Titan M2) on LineageOS 24.0, firmware untouched.
- [ ] G1 and G2 exit tests pass on the 6a. The Pixel 3 XL stays a development phone.

**G4 · Wallet that works with real apps.**
- [x] Message and EIP-712 signing; token-aware review; multiple accounts; passphrase wallets;
      address book; Uniswap swap decoding; companion simulation.
- [ ] WalletConnect and the browser extension proven against real dApps by a person.
- [ ] Watch-only export for Rabby / MetaMask balance views.
- [ ] Signed, updatable token list (today it changes only with an app release); token metadata in
      EIP-2612 / Permit2 message reviews.
- [ ] Recovery interoperability tested by importing the phrase into other wallets.
- [ ] Bitcoin: companion screens used by a person; passphrase wallets for Bitcoin; mainnet only
      after signet use.
- Exit: end to end on mainnet with small amounts: connect, sign in, approve, swap, send, revoke.

**G5 · Companion people can install.**
- [ ] Signed and notarized macOS build with signed auto-update; then Windows and Linux.
- [ ] Onboarding from download to first confirmed send without help, plain errors, no dead ends.
- Exit: a new user goes from download to first confirmed send without help.

**G6 · Install, onboarding and support.**
- [ ] One-click flasher (WebUSB or desktop): unlock → flash → relock → attest, no build machine.
- [ ] Setup guide, recovery and "lost phone" docs, FAQ, support channel.
- [ ] Licensing obligations (GPL kernel sources, LineageOS/AOSP notices), disclaimers, privacy
      policy.
- Exit: three outside testers install from scratch using only the guide.

**G7 · Assurance and launch.**
- [ ] Independent audit of the app, the companion and the OS changes; fixes.
- [x] Public threat model, security contact and disclosure policy ([SECURITY.md](SECURITY.md)).
- [ ] Open repository, bug bounty, incident-response plan.
- [ ] Closed beta with capped amounts, then public release.
- Exit: audit report published with no open high-severity findings.

## Open items outside the milestones

- **Phone app structure:** split `MainActivity` into screens and a small state core, for
  auditability.
- **Approval screen polish:** amount and recipient large, address-book names, technical detail
  folded below.
- **PIN credential:** owner text on Android's own lock screen; `lifecycletest.sh` still expects the
  app-side attempt counter text.
- **Entropy:** the R7 diagnostics screen; the jitter collector is home-grown, not a vetted
  jitterentropy port.
- **Release UI:** move "Coming next" out of primary navigation in the shipped app.
- **OLED burn-in:** the kiosk shows the same screen for long periods; idle screen-off and
  pixel-shift exist, burn-in behaviour over months is unmeasured.
- **Dead-battery safety:** seed writes are atomic; boot on a near-dead battery and USB data while
  charging need explicit tests.
- **Update UX:** check, verify signature, apply, rollback-protect, for both OS and app.

## Later

- **Air-gapped QR (outbound first):** show addresses and signed payloads as animated BC-UR
  (EIP-4527) so nothing has to leave over USB. Inbound QR needs the camera, whose stack is one of
  the largest opaque blobs on the phone; if pursued it is a separate, gated build variant with its
  own exposure review, not the hardened default.
- **Host-wallet interop:** BC-UR account import and signing so existing wallets can drive the
  vault without impersonating another vendor's hardware.
- **Multisig (Safe) co-signer flow.**
- **Stateless mode:** the seed entered each session and held only in memory (SeedSigner-style),
  as an option next to the default persistent mode. An app-level mode, not an OS mode.
- **User-supplied entropy** (dice or typed) mixed into seed generation.
- **Passkeys (FIDO2/WebAuthn):** non-extractable P-256 keys in StrongBox, either over a USB HID
  function or bridged through the companion over the existing AOA channel.
- **Shamir backups (SLIP-39).**
- **Integrity dashboard:** release signature, verified-boot state, StrongBox, entropy health,
  OS version, battery condition.
- **Signing history** kept locally (hashes, timestamps, outcomes).
- **Duress / decoy wallets** and a tamper-evident boot image (a user-chosen phrase shown at
  every boot).

## Decisions recorded

- **License:** Apache-2.0, with patches to GPL code (Linux kernel) staying GPL-2.0. Everything
  inside the trust boundary is open and intended to be reproducible (see [NOTICE](NOTICE)).
- **Persistent by default:** the phone keeps the wallet; stateless operation would be an option.
- **Transport:** USB Android Open Accessory only. No Ledger/Trezor impersonation; wallet
  integrations go through the companion (WalletConnect, the browser extension).
- **Kiosk with the system credential:** the vault PIN is the Android credential, so file-based
  encryption protects the wallet at rest after every reboot before any app code runs.
- **No vendor, no customer list:** users flash their own phone; no registration, no telemetry,
  no mandatory accounts.
