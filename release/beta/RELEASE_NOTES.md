# Phone Vault public beta: release notes

**Release:** 0.1.0-beta4 (Pixel 6a only) · **Status:** public beta, not yet independently audited ·
**Download:** [tag/v0.1.0-beta4](https://github.com/QuantumDesk/phonevault/releases/tag/v0.1.0-beta4)

> **Read this first.** This is a beta. Use it with small amounts only, amounts you can afford to
> lose. It has not been independently audited. The phone's bootloader stays **unlocked**, the
> genuine check reports **Development**, and the images are signed with **beta-test keys**, not
> release keys. Do not move your savings to it.

## What Phone Vault is

Phone Vault turns a Google Pixel 6a into an offline hardware wallet. You install Vault OS on the
phone: a stripped-down build of LineageOS that has no network, no app store and no browser, and
starts straight into one app, the signer. Your recovery phrase is created and kept on the phone.

On your Mac, Phone Vault Companion shows balances, prepares transactions and talks to the
network. A site in your browser reaches Phone Vault through the Phone Vault browser extension or
WalletConnect. Every request travels over the USB cable to the phone, the phone decodes it from
the exact bytes it would sign and shows what it does in plain words, and it signs only after you
approve on the phone's own screen. Your Mac then checks the signature on its own, and nothing
reaches the network until you click **Send to network**.

Why a phone: a Pixel 6a costs little second-hand, has Google's Titan M2 security chip, and a
screen large enough to show a whole address, the amount, the network and the fee at once.

## What is new in beta4

- Signer app 0.3.1. A request that arrives while the phone is locked is shown on the lock
  screen ("INCOMING REQUEST") and kept there until you enter the PIN. If the phone locks before
  you reviewed a request, your Mac is told at once: "The phone locked before this request was
  reviewed. Nothing was signed."
- A PIN prompt you dismiss (Back) no longer blocks the next action that needs the PIN.
- The companion waits for the phone to reconnect on its own after the USB link restarts,
  instead of failing on a phone that is briefly away.
- The genuine check recognises the beta: with **Developer mode** on it shows **Beta build:
  bootloader unlocked, not production. Small amounts only**; with it off, a beta phone is not
  accepted.
- Distributed as a GitHub release with a Mac install script (`install-beta4-mac.sh`).

## What works in this beta

### Ethereum and other EVM networks

- Networks: Ethereum, Base, OP Mainnet, Arbitrum One, Polygon, and the Sepolia test network.
- ETH transfers (EIP-1559) and ERC-20 tokens: transfer, approve, transferFrom,
  increaseAllowance. Tokens on the list built into the app are shown with their name and real
  units; any other token contract is shown as "Unknown token contract" with raw units.
- Approvals and Permit2 allowances at the maximum are called **UNLIMITED**.
- NFTs: transfers, single approvals, and collection-wide "approve all", which is shown as a
  danger. Revoking an approval is labeled as a revoke.
- Uniswap swaps decoded on the phone ("You give · You get at least · Recipient · Expires").
  Output going to another address, or a minimum of zero, is a danger warning. A swap the phone
  cannot fully model is refused.
- Messages: `personal_sign`, Sign-In with Ethereum (a sign-in for another site or address is
  flagged), and EIP-712 typed data including Permit and Permit2.
- Contract calls the phone cannot explain are **refused**, never signed blind. `eth_sign` and
  account delegation (EIP-7702) are refused by name.
- Address book and address-poisoning warnings: first send to an address, and addresses that
  only look like a past recipient, are flagged.
- The Mac's simulation of balance changes is shown on the phone as an unverified claim, with a
  warning when it contradicts what the transaction does.
- Sites: through the **Phone Vault browser extension** (Chrome, Brave, Edge; loaded unpacked
  from this release's zip), which lists Phone Vault in a site's wallet list (EIP-6963). Connecting to
  Uniswap through the extension has been done with a real phone. **WalletConnect** is built and
  covered by automated tests, but has not yet been used end to end by a person with a real phone
  and a real site: treat it as less tested.

### Bitcoin

- PSBT signing, with a watch-only wallet in the companion (balances from an Esplora server,
  mempool.space by default, or your own).
- Address types: **Native SegWit** (BIP-84, `bc1q…`, wpkh), **Taproot** (BIP-86 key path,
  `bc1p…`, tr), and for coins received in older wallets **Nested SegWit** (BIP-49, `3…`,
  sh-wpkh) and **Legacy** (BIP-44, `1…`, pkh). All from the same recovery phrase.
- Every output is shown with its full address. Change is called change only after the phone
  derives that address from your own keys. A fee that eats a large share of the amount is a
  danger warning.
- A signet transaction signed on a phone has been confirmed. Mainnet Bitcoin has had less use:
  start with a very small amount.
- Watch-only export to Sparrow (descriptor, fingerprint and xpub).

### Moving from Ledger or Trezor

- Restore a 12, 15, 18, 21 or 24-word recovery phrase on the phone's own keyboard (the phone
  creates 24-word phrases).
- **Account numbering**: Standard (`m/44'/60'/0'/0/n`, as MetaMask, Trezor and Rabby number
  accounts) or **Ledger Live** (`m/44'/60'/n'/0/0`), so a restored Ledger phrase shows the same
  Ethereum accounts. Account 1 is the same address under both. The choice is made on the phone and shown in its device
  information.
- Nested SegWit and Legacy Bitcoin accounts reach coins from older Ledger/Trezor wallets.
- The companion can list what an old wallet holds and give you the matching Phone Vault address
  for each asset, so you can move funds instead of restoring the old phrase. Moving keeps the old
  phrase off Phone Vault; restoring means that phrase then lives on two devices.
- These features are the newest in the beta and have had the least use. Check the first address
  of each account against your old wallet before you move anything.

### Recovery phrase and entropy

- New wallets get a 24-word BIP-39 recovery phrase made from three sources hashed together
  (SHA-512, domain-separated): the kernel's random generator (required), a stream derived from
  the Titan M2 security chip, and a CPU-timing jitter collector. Each source must pass startup
  health tests; if fewer than two are healthy the phone refuses or asks for your own entropy.
- Optional: add your own dice rolls during setup. They are mixed in and then discarded.
- Security → Device information → "Entropy at wallet creation" lists which sources were used and
  whether each passed.
- Honest limits: the jitter collector is home-grown, not a vetted implementation, and there is
  no independent raw-noise assessment of the sources. See
  [entropy-design.md](../../vault-os/docs/entropy-design.md).
- Backup: you must pass a spot check of the recovery phrase and confirm the address before the
  wallet can receive or sign. SeedQR and a printable backup card are available.

### Phone

- PIN: six digits, held by the security chip as the phone's lock credential. The chip slows
  down guessing, the wallet key works only after the chip has checked the PIN, and **ten wrong
  PINs erase the phone**.
- The vault locks when the screen turns off or after an idle time; the recovery phrase is shown
  only after you enter the PIN again.
- Multiple accounts, optional passphrase wallets (typed on the phone, never stored).
- USB: the phone appears to your Mac as a single accessory interface; no storage, network,
  MIDI or debugging interface. No adb in this build.
- Wi-Fi, Bluetooth, NFC, GPS and cellular modem drivers are removed from the kernel, and the
  radio daemons are removed.

## What does not work yet

- **Relocked bootloader.** The phone stays unlocked in this beta. Relocking needs release keys
  made in an offline key ceremony, which has not happened yet. Do not try to relock the phone
  yourself: a phone locked with a system Google does not recognise may not start.
- **Genuine verdict.** The genuine check can only report **Development** on a beta phone. A
  "Genuine" verdict needs release keys and a relocked phone.
- **Release signing.** Vault OS and the signer app are signed with beta-test keys generated on
  the build machine. The platform still carries LineageOS's public test keys. A future release
  will use new keys, which means re-installing and restoring from your recovery phrase.
- **Updates.** There is no over-the-air update. A new beta is installed by re-flashing, which
  erases the phone: keep your recovery phrase.
- **Reproducible builds** and a public log of release hashes.
- **Independent security audit.** All review so far has been internal.
- **Companion:** macOS on **Apple silicon** only (no Intel build in this release). Not signed
  or notarized yet: open it the first time with right-click → Open. No Windows or Linux build.
- **Extension:** not in the Chrome Web Store or Firefox Add-ons yet: load it unpacked in Chrome,
  Brave or Edge. No Firefox package in this release.
- **Web installer:** not available for this release. Install with the Mac script from the
  GitHub release.
- **Not supported:** ERC-1155 display, Bitcoin multisig and Taproot script paths, coin control,
  Tor, Bitcoin passphrase wallets, air-gapped QR signing, an in-app "erase wallet" button (erase
  by re-installing; see the tester guide).

## Known limitations and risks

- **Unlocked bootloader.** Anyone who has your phone in their hands for a few minutes could
  replace the system with one that lies to you. Keep the phone with you, and never use a phone
  that someone else installed. Google's warning about an unlocked bootloader appears at every
  start; that is expected in this beta.
- **Beta-test keys.** These keys exist only on the project's build machine and are not
  protected like release keys. Treat every beta image as development software.
- **Not audited.** There may be bugs that let a wrong transaction through, or that lose access.
  Your recovery phrase on paper is your backup for everything.
- **The phone's own labels.** The signer app on the phone still says "Development · test assets
  only" on its Wallet and PIN screens. For this beta, read it as the limits above: small amounts
  only. A later beta will change the wording.
- **Emergency-call button.** The lock screen can show "Emergency calls only" / an Emergency
  button. The radio drivers are removed, but this button is a path out of the locked screen that
  a later beta will remove.
- **Telephony and Wi-Fi frameworks** are still present in the system (their drivers are not);
  removing them is a later hardening step.
- The phone cannot see balances or existing allowances, and cannot prove what an unknown
  contract does. It explains what it can decode and refuses the rest.
- The companion reads balances, fees and NFTs from public servers or your own node. Those
  servers learn your addresses and your IP address. Run your own for privacy.
- The Pixel 6a receives Google security updates until July 2027. Vault OS does not change the
  phone's firmware; a newer beta is needed to follow Google's updates.
- Side channels, fault injection and hardware implants are outside what software can address.

## Supported hardware

| | |
|---|---|
| Phone | **Google Pixel 6a** (`bluejay`) only |
| Required | **OEM unlocking** must be switchable in Developer options. |
| Not supported | **Verizon** Pixel 6a phones (their bootloader cannot be unlocked). |
| Carrier-locked phones | Need a **carrier unlock** first (ask the carrier), then OEM unlocking becomes available. |
| Firmware | Google's bootloader `bluejay-17.0-15199431` and radio `g5123b-145971-260414-B-15201439` must already be on the phone. The installer checks both and writes nothing if they differ. |
| Firmware build | Google's Android 17 builds **CP2A.260605.012** and **CP2A.260705.006** carry both. Pixel phones cannot go back to an older bootloader: a phone that already has a newer one must wait for a later beta. |
| Computer | A Mac with **Apple silicon** (macOS 12 or later), **Chrome or Edge** (or Brave) for the extension, Google's `fastboot` (`brew install android-platform-tools`), and a USB-C **data** cable straight into the Mac. |

Other Pixels, including the Pixel 3 XL used for development, are not supported in this beta.

## Reporting bugs

- **Bugs and questions:** [GitHub Issues](https://github.com/QuantumDesk/phonevault/issues/new/choose)
  (the bug report form asks for the details below).
- **Security problems:** report privately, never in a public issue: GitHub's private
  vulnerability reporting ("Report a vulnerability" on the repository's Security tab). See
  [SECURITY.md](../../SECURITY.md).
- Never send your recovery phrase, PIN, passphrase or private keys to anyone, including us. Use a
  throwaway wallet when you show a problem.
- Helpful details: beta version (shown in Device information), companion version, macOS version, what you did,
  what you expected, what you saw, and a photo of the phone's screen.

## Verifying downloads

The release at [https://github.com/QuantumDesk/phonevault/releases/tag/v0.1.0-beta4](https://github.com/QuantumDesk/phonevault/releases/tag/v0.1.0-beta4) has these files:

| File | What |
|---|---|
| `super.img.part-aa`, `super.img.part-ab` | Vault OS `super.img` in two parts (GitHub allows 2 GiB per file); the install script joins them |
| `PhoneVault-beta4-images-bluejay.zip` | the boot images (`boot`, `vendor_boot`, `dtbo`, `pvmfw`, `vbmeta`, `vbmeta_system`, `vbmeta_vendor`) and `android-info.txt` |
| `install-beta4-mac.sh` | joins, unzips, checks every file, then runs the flash script |
| `flash-beta4-mac.sh` | the build's own flash script: reads the phone, asks you to type `FLASH`, writes slot a |
| `manifest.json` | each partition written, with file, size and SHA-256; build ID, fingerprint, signing key identities |
| `SHA256SUMS` | the build's own hash list (it also names build files that are not published) |
| `PhoneVault-Companion-0.1.0-beta4-arm64.dmg` | Phone Vault Companion for Apple silicon Macs, unsigned |
| `PhoneVault-Extension-0.1.0-beta4-chromium.zip` | the browser extension, to load unpacked (ID `fbomijndbpoddicmbngledanaafapmlk`) |
| `SHA256SUMS-assets` | SHA-256 of every file above |

Check the downloads on your Mac, in the folder that holds them:

```sh
shasum -a 256 -c SHA256SUMS-assets      # every line must say OK
```

`install-beta4-mac.sh` then checks `SHA256SUMS` against the SHA-256 built into the script, joins
`super.img`, and checks it and every image against `SHA256SUMS` before it runs any `fastboot`
command. `flash-beta4-mac.sh` checks them again before it writes. One mismatch stops both.

The same image hashes are recorded in the repository, in
[vault-os/release-bluejay/README.md](../../vault-os/release-bluejay/README.md#beta4-build-2026-10-30),
so you can compare against a second source.

- Beta-test key identities (for comparing with the genuine check's details):
  - AVB public key: sha256 `234b8f9bd98cac321ddda1a035cb4e8cfade4f96c63d0c081b6c9cdec4ea80f0`
  - Signer app certificate: sha256 `934c4f78f34daebc9f6733af217ff78bdb864fba20e408a1ad3ff5e00a7c032f`
- Hashes of the build's `SHA256SUMS` and `manifest.json`:
  - `SHA256SUMS`: `26fa3625b8350f204aeb76004f8d6e546500683da979ec4c491c502156eeeec4`
  - `manifest.json`: `e26f04427d7fde99235136c285f2f0482e751894e326f3bd9880ead4afb990be`
  - `super.img` (joined): `0cfda121bc35a4872a9f5f46f578d794bf9850151f7d79644c8e3844ac8585e3`
