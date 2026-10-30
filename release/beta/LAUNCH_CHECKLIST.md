# Phone Vault public beta: launch checklist (go / no-go)

Work top to bottom. Every line is a gate: the announcement goes out only when every **GO** box
is ticked. Owner: **user** (needs the user's hands, accounts, money or decision) or **Claude**
(can be prepared in the repository or on the build host; the user approves anything that
publishes). Nothing in this list has been published yet.

Status on 2026-10-30, from the repository (`main` at f07009f): beta1 and beta2 are built; beta1
booted but did not enumerate on USB; beta2 is built and not flashed; **beta3 does not exist yet**.

## A. Decisions before anything else

- [ ] **A1 · user** Agree the wording "public beta, small amounts only". README.md ("Do not use
      it for real funds"), ROADMAP.md, the website ("never real funds") and the install page
      ("test assets only") currently say no real funds at all. Decide, then make every place say
      the same thing (A3).
- [ ] **A2 · user** Waive or amend the repository rule that beta-test keys are replaced by
      offline-generated beta keys "before any phone is relocked to a beta key **or a beta goes to
      anyone outside the project**" (vault-os/release-bluejay/README.md, Keys). This launch ships
      beta-test keys to outside testers, so the rule must be changed on purpose and the README
      updated to say so, or an offline beta key set must be made first.
- [ ] **A3 · Claude** After A1/A2: align README.md status, ROADMAP.md ("Closed beta with capped
      amounts"), SECURITY.md "Supported versions" (the beta becomes the supported version),
      release-bluejay README, and the website copy.

## B. The beta3 image

- [ ] **B1 · Claude** Define `release-bluejay/beta3`: beta2 plus a signer app built from current
      `main` (beta2 carries beta1's APK, which predates the app reopening a stale USB accessory
      session, 354afa3). Version/channel `beta3`, `flash-beta3-mac.sh`.
- [ ] **B2 · Claude** Fix the genuine check for beta phones. The companion's
      `attestation-policy.json` pins only the development (Android Debug) app certificate; the
      beta app certificate `934c4f78…032f` is not listed, so the companion reports a beta phone
      as **Not genuine** ("signed by an unknown key") and blocks pairing, even in Developer mode.
      Add the beta-test certificate as a development signer (never as a release signer), with a
      test that a beta phone is Development with Developer mode on and Not genuine with it off.
      User reviews the change.
- [ ] **B3 · Claude** Build beta3 on the build host; all gates in release-bluejay/README.md
      pass; record SHA256SUMS and manifest.json hashes in the README.
- [ ] **B4 · Claude** Build the companion from the same commit as B2 (it must contain B2 and the
      USB handshake/probe changes) and record its version in the release notes.

## C. Hardware verification of beta3 on a Pixel 6a (no adb on this build)

All on a retail, non-Verizon Pixel 6a, flashed with the web installer, not a development tree.

- [ ] **C1 · user** Web installer `?check` on the phone passes (Chrome and Edge), then a full
      install; first boot reaches **SET PIN** with no taps; Google's unlocked warning only.
- [ ] **C2 · user** USB: the Mac sees exactly one Google device, product ID `0x2d00`, one
      interface (255/255/0); `adb devices` empty; no storage, network or MIDI device appears.
- [ ] **C3 · user + Claude** Pairing with the beta3 companion: genuine check shows
      **Development** (Developer mode on), Not genuine with Developer mode off; address compare;
      pairing stored.
- [ ] **C4 · user** Signing, each reviewed on the phone and sent with **Send to network**:
      ETH transfer, ERC-20 transfer, ERC-20 approve (UNLIMITED shown), NFT approve-all (danger
      shown) and its revoke, a Uniswap swap through the extension, `personal_sign` and a SIWE
      sign-in, an EIP-712 Permit2, an unexplained contract call (**refused**), a **Reject** that
      sends nothing. One WalletConnect session with a real site.
- [ ] **C5 · user** Bitcoin on signet: Native SegWit, Taproot, Nested SegWit, Legacy accounts
      added from the phone, receive, PSBT signed and sent for each; then one small mainnet
      Native SegWit send.
- [ ] **C6 · user** Reconnect: unplug/replug; vault locks with the cable in, then a new request
      (answered without a replug); companion quit and restarted; Mac sleep and wake.
- [ ] **C7 · user** Recovery-phrase restore: note addresses, erase by reinstalling, restore the
      phrase, same Ethereum and Bitcoin addresses; restore a known Ledger Live test phrase with
      Ledger Live numbering and compare accounts 1 to 3 with Ledger Live's addresses; 12-word
      phrase restore.
- [ ] **C8 · user** Locks and erase: screen-off lock, idle lock, recovery phrase asks for the
      PIN, ten wrong PINs erase the phone (on a throwaway wallet).
- [ ] **C9 · user** Recovery mode (bootloader → Recovery): no "Enable ADB", no "Install anyway".
      Note whether the lock screen shows an Emergency button (known, documented).
- [ ] **C10 · user** Back to stock with Google's Android Flash Tool works from a beta3 phone.

## D. Downloads and hosting

- [ ] **D1 · user** Cloudflare R2 bucket with `images.phonevault.org` as custom domain, CORS as
      in `website/lib/install/config.ts`, beta3 uploaded byte for byte under `bluejay/beta3/`.
- [ ] **D2 · Claude** Website installer config switched to beta3 (`IMAGE_BASE_URL`,
      `MANIFEST_SHA256`, `RELEASE`, bootloader/baseband if changed); install page text mentions
      beta3's companion.
- [ ] **D3 · user** `curl -sI -H 'Origin: https://phonevault.org' -H 'Range: bytes=0-15' …/super.img`
      answers 206 with CORS headers; phonevault.org/install?check passes on a real phone against
      the live host (not localhost).
- [ ] **D4 · user + Claude** `SHA256SUMS` and `manifest.json` published next to the images and on
      the release page, with the companion DMG and extension zip hashes added. Optional but
      recommended: a detached signature over SHA256SUMS with a published project key.
- [ ] **D5 · user** Website deployed with the release notes, tester guide, and status section
      updated (the 6a radio drivers and radio daemons are removed; migration features shipped).

## E. Repository and contacts

- [ ] **E1 · Claude** Pre-publication sweep: secret scan of the full history, no private keys or
      seed phrases, no internal host names or personal paths that should not be public, licence
      headers and NOTICE, GPL source obligations for the kernel patches and LineageOS notices.
- [ ] **E2 · Claude** CI green on `main` (companion, extension e2e, Android unit tests, Python,
      ShellCheck, Vault OS gates).
- [ ] **E3 · user** Repository made public; GitHub private vulnerability reporting turned on.
- [ ] **E4 · user** `security@phonevault.org` receives mail (send a test from outside); SECURITY.md
      no longer calls it a placeholder.
- [ ] **E5 · user** Bug channel chosen and live (GitHub Issues, a forum or a chat); every "TBD
      channel" in release/beta/ and on the site replaced with the link.

## F. Companion and extension distribution

- [ ] **F1 · Claude** Companion DMG built with `companion/scripts/build-dmg.sh` from the B4
      commit; SHA-256 recorded; tested on a second Mac with no developer tools (right-click → Open,
      USB pairing, browser connection).
- [ ] **F2 · user** (optional for the beta) Apple Developer ID, then a signed and notarized DMG
      (release/beta/COMPANION_DISTRIBUTION.md). If skipped, the tester guide's right-click → Open
      step stays.
- [ ] **F3 · Claude** Extension zip for unpacked install (`package-store.sh` →
      `…-chromium-unpacked.zip`, which keeps the `key` so the ID stays
      `fbomijndbpoddicmbngledanaafapmlk`, and the Firefox zip) published with SHA-256.
- [ ] **F4 · Claude + user** (store listings, may follow the launch) Companion pins the Chrome Web
      Store ID; store submissions from release/beta/STORE_LISTING.md; privacy policy URL live.

## G. Go / no-go

- [ ] **G1 · Claude** Fill every TBD in release/beta/ (hashes, links, version) and re-read the
      release notes against what C1–C10 actually showed; remove any feature that did not pass.
- [ ] **G2 · user** Final read of ANNOUNCEMENT_DRAFT.md; no claim beyond what passed.
- [ ] **G3 · user** Go / no-go. **No-go** if any of B2, C1–C8, D3, D4, E4, E5 is open.
