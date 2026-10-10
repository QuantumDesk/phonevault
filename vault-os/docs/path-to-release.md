# Path to a release people can trust

Working list from the 2026-09-23 product audit. Ordered: trust first, then reach. An item is
checked only when it is built, on a real phone, and tested there. `roadmap.md` keeps the history;
this file is the queue.

## Goals to distribution (2026-10-10)

Milestones in order. Each has an exit test; a milestone is done only when every exit test passes
on a real phone. The detailed checklists below (sections 1–5) feed these milestones.

**G1 · Locked-down appliance** — the OS is a single-purpose signer.
- Finish the ladder: 2d-d (USB functions, retry keeps DWC3 dual-role) → rung 3 (USB HAL refuses
  host role, no functions but AOA (+adb until rung 5)) → rung 4 (strip launcher, Elmyra and every
  app/service the vault doesn't use) → rung 5 (user build: no adb, no dump hook, FLAG_SECURE).
- Fix the release defconfig (patch 0001 turns DWC3 dual-role off, which kills USB enumeration).
- First boot after an OS update asks for the PIN once (today: twice when the app starts late).
- Exit: user build on a phone; only AOA enumerates; full signing/credential suites pass; no
  crash-looping services; `adb` unreachable.

**G2 · Verifiable trust chain** — a buyer can prove the phone is genuine and unmodified.
- Release keys generated offline (documented key ceremony); signed OTAs; our AVB key; relocked
  bootloader; demonstrated refuse-to-boot on a tampered image.
- Device attestation (Titan M key attestation, in progress): companion shows Genuine / Development /
  Not genuine and blocks pairing on Not genuine; pins our AVB key and app signer.
- Reproducible builds (pinned container, byte-identical app + OS) and a public log of release hashes.
- Supply-chain stance: users flash their own phone (never buy pre-flashed from a reseller), and
  attestation re-checks on every connection.
- Exit: a relocked phone shows "Genuine"; a reflashed/tampered phone shows "Not genuine" and won't
  pair; two independent builds produce the same hashes.

**G3 · A phone people can buy** — supported, still-patched hardware.
- Port to a current Pixel with Titan M2 (Pixel 8/8a/9 class: years of updates); Pixel 3 XL stays a
  dev target only (no security patches since 2022).
- Exit: G1 + G2 exit tests pass on the new model.

**G4 · Wallet that works with real apps**
- WalletConnect proven against real dApps; swaps: plain-language review of router calls
  (Uniswap Universal Router first), with simulation on the companion; refuse what can't be explained.
- Multiple accounts; optional BIP-39 passphrase; address book; watch-only export (Rabby/MetaMask).
- Signed, updatable token list; token metadata in Permit/Permit2 reviews.
- Recovery works in other wallets (BIP-39/44 test against MetaMask/Rabby imports).
- Exit: end-to-end on mainnet with small amounts: connect, sign-in, approve, swap, send, revoke.

**G5 · Companion people can install**
- Notarized macOS build, signed auto-update; Windows and Linux builds.
- Onboarding wizard (pair → attest → receive → first send), plain errors, no dead ends.
- Exit: a new user goes from download to first confirmed send without help.

**G6 · Install, onboarding and support**
- One-click flasher (WebUSB, like GrapheneOS's): unlock → flash → relock → attest. No build machine.
- Setup guide, printable backup card, recovery/"lost phone" docs, FAQ; website rewritten to match
  reality; support channel.
- Licensing (GPL kernel sources, LineageOS/AOSP notices), disclaimers, privacy policy.
- Exit: three outside testers install from scratch using only the guide.

**G7 · Assurance and launch**
- Independent audit (app, companion, OS changes) and fixes; public threat model; open repository;
  bug bounty; incident-response plan; security contact.
- Closed beta with capped amounts → public release.
- Exit: audit report published with no open high-severity findings.

## 1. Trust people can check (blocks any real-funds claim)

- [x] **Honest entropy claims.** Website said the seed uses the security chip's randomness; it did
      not (kernel RNG + home-grown CPU jitter). Site corrected 2026-09-23, and the verified-boot
      line now says "warns, not refuses, until the relock".
- [x] **Titan M entropy source.** A StrongBox-generated AES key encrypts zeros; the keystream and
      chip-generated IV depend only on randomness produced inside the Titan M. Mixed as a third
      source alongside kernel + jitter; shown on Device information. (entropy-design.md R2)
      *Verified on phone 2 2026-09-27: a fresh wallet lists kernel-getrandom, titan-m-strongbox and
      cpu-jitter, all passing health tests.*
- [ ] **PIN bound to the Android lock credential + Change PIN** (option A, chosen 2026-09-23;
      design in `pin-credential-design.md`). The vault PIN becomes the system PIN, the Titan M
      throttles guesses, the seed key only works after the system verifies it, 10 failures wipe by
      device policy. Stage 1 spike DONE on phone 2 (2026-09-23): kiosk + system PIN coexist; after a
      reboot Android's own PIN screen unlocks the encrypted storage once, then our UI takes over.
      Stages 2–3 WORKING on phone 2 (2026-09-24): device PIN installed, wallet migrated to the
      credential-bound key, unlock/reveal/sign/reboot pass. Boot double-PIN fixed; wipe-after-10 proved
      2026-09-24; factory first boot lands in the kiosk (USER_STARTED fallback) 2026-09-27; app updates
      re-provision HOME (MY_PACKAGE_REPLACED). Open: owner text on Android's lock screen, audit.
- [ ] **Finish the hardening ladder.** ~~2d-c (camera/media/sensors/DSP)~~ passed 2026-09-27 (+ 2d-c2/2d-c3: dead services removed, lock screen without clock, passed 2026-09-28) → ~~2d-d (USB functions)~~ passed 2026-10-10 →
      rung 3 (charge-only USB at the OS level) → rung 4 (strip unneeded apps/services in slices) →
      rung 5 (user build: no adb, no dump hook, no screenshots).
- [ ] **Signed releases + relocked bootloader.** Release-key OTA, recovery that trusts only it,
      relock, and a demonstrated refuse-to-boot on a tampered image.
- [ ] **Device attestation: a buyer can check the phone is genuine** (`device-attestation.md`).
      BUILT (2026-10-10, not yet run on a phone): USB `attest` (StrongBox key attests the Mac's
      challenge and signs its wallet address; wallet key never used), companion verifies the chain
      to Google's pinned roots, the KeyDescription, revocation, and shows Genuine / Development /
      Not genuine; FAIL blocks pairing and sending. Open: phone run of
      `tools/dev-device/attesttest.sh`; pin the release APK signer and the release AVB key in
      `companion/src-tauri/attestation-policy.json` and see a relocked phone report GENUINE.
- [ ] **Reproducible builds.** Pinned container, byte-identical app and OS images from source.
- [ ] **Independent audit** of the app, the companion and the OS changes.

## 2. Work with the apps people already use

- [x] **Message + EIP-712 signing** with plain-language review (logins, Permit2, orders).
      *Phone 2, 2026-09-27: `msgsigntest.sh` 6/6 — text sign + host verify, SIWE for another
      address flagged and rejected, unreadable bytes rejected, EIP-712 Mail signed + verified,
      Permit2 UNLIMITED flagged + verified, wrong-chain Permit2 flagged + rejected. Format and
      limits in `message-signing.md`. Companion card is basic until the UI rework lands.*
- [ ] **WalletConnect in the companion** — dApps connect to the companion, the phone signs.
- [ ] **Token awareness** — "50 USDC", not raw uint256. BUILT (2026-09-27, not yet run on a phone):
      30 tokens (USDC, USDT/USDT0, DAI, WETH, WBTC, cbBTC on the six allow-listed chains) in
      `res/raw/tokens.json`, SHA-256 pinned in the app and the companion, sources per entry in
      `app/token-list/SOURCES.md`; phone review for transfer / approve (UNLIMITED ≥ 2^255) /
      transferFrom / increaseAllowance, unknown contracts in raw base units; companion token
      balances, token Send, re-decoded verification, history. Open: phone run of
      `tools/dev-device/tokensigntest.sh`; a *signed, updatable* list (today it changes only
      with an app release); token metadata for EIP-2612 / Permit2 message reviews.
- [ ] **Watch-only export** for Rabby/MetaMask balance views; **multiple accounts**.

## 3. Companion as the product surface

- [ ] One main view: balance per network, Send, Receive (QR), history; pairing/node in Settings.
- [ ] Fiat values; fees in dollars; clear states (waiting → approve on phone → broadcast → confirmed).
- [ ] Signed + notarized macOS build with auto-update; then Windows and Linux.

## 4. Phone app

- [ ] Split `MainActivity` (≈2,000 lines) into screens + a small state core, for auditability.
- [ ] Approval screen: amount and recipient large, address-book names, technical detail folded.
- [ ] Printable backup card; optional passphrase wallets.

## 5. Distribution

- [ ] One-click flasher (web or Mac): unlock, flash, relock, verify — no build machine needed.
- [ ] A current model (Pixel 6-class, Titan M2), supported end to end.
- [ ] Open the repository at the first release candidate, with the threat model up front.
