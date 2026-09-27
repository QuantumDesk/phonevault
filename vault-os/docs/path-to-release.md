# Path to a release people can trust

Working list from the 2026-09-23 product audit. Ordered: trust first, then reach. An item is
checked only when it is built, on a real phone, and tested there. `roadmap.md` keeps the history;
this file is the queue.

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
- [ ] **Finish the hardening ladder.** ~~2d-c (camera/media/sensors/DSP)~~ passed 2026-09-27 → 2d-d (USB functions) →
      rung 3 (charge-only USB at the OS level) → rung 4 (strip unneeded apps/services in slices) →
      rung 5 (user build: no adb, no dump hook, no screenshots).
- [ ] **Signed releases + relocked bootloader.** Release-key OTA, recovery that trusts only it,
      relock, and a demonstrated refuse-to-boot on a tampered image.
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
