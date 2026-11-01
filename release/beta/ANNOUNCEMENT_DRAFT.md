# Announcement draft: Phone Vault public beta

*Draft. Not for posting until every gate in LAUNCH_CHECKLIST.md is ticked. Replace each TBD.*

---

## Phone Vault public beta: a hardware wallet made from a Pixel 6a

Today we are opening a public beta of Phone Vault for the Google Pixel 6a.

**What it is.** Phone Vault turns a Pixel 6a into an offline signing device. You install Vault
OS, a stripped-down LineageOS build with no network, no app store and no browser, which starts
straight into one app. Your recovery phrase is created and kept on the phone. Your Mac prepares
transactions and talks to the network; the phone shows what each one does in plain words, and
signs only after you approve on its screen. Your Mac then checks the signature, and nothing goes
out until you click Send to network.

**Why a phone.** A second-hand Pixel 6a costs little, carries Google's Titan M2 security chip,
and has a screen big enough to show the whole address, the amount, the network and the fee at
once. Phone Vault adds the discipline: one purpose, the Wi-Fi, Bluetooth, NFC and cellular
drivers removed, a USB link that accepts one kind of message, and a phone that refuses any
contract call it cannot explain.

**What is in the beta.**

- Ethereum, Base, OP Mainnet, Arbitrum One and Polygon: ETH, tokens, NFT approvals with clear
  danger warnings, Uniswap swaps decoded on the phone, sign-ins and typed data.
- Sites through the Phone Vault browser extension (Chrome, Brave, Edge) or WalletConnect.
- Bitcoin with PSBT signing: Native SegWit, Taproot, and Nested SegWit and Legacy for older
  coins.
- Restore from Ledger or Trezor recovery phrases, including Ledger Live account numbering.
- A 24-word recovery phrase from three randomness sources, optionally with your own dice rolls;
  a PIN held by the security chip; ten wrong PINs erase the phone.
- A Mac install script that checks every file against the published hashes before it writes
  anything.

**The limits, plainly.**

- This is a beta. Use small amounts only, amounts you can afford to lose.
- It has not been independently audited. All review so far has been our own.
- The phone's bootloader stays unlocked in this beta, and the genuine check reports
  "Development". Relocking needs release keys made in an offline key ceremony, which has not
  happened yet.
- The images are signed with beta-test keys. A later release will need a reinstall and a restore
  from your recovery phrase.
- Pixel 6a only. Not Verizon models; carrier-locked phones need a carrier unlock first. The Mac
  companion app is not notarized yet, and there is no Windows or Linux version.

**How to join.**

1. Read the release notes and the tester guide: https://github.com/QuantumDesk/phonevault/releases/tag/v0.1.0-beta4 and
   https://github.com/QuantumDesk/phonevault/blob/main/release/beta/TESTER_GUIDE.md
2. Install with `install-beta4-mac.sh` from the release; it checks every file against the
   published SHA256SUMS first.
3. Tell us what breaks: https://github.com/QuantumDesk/phonevault/issues. Security problems
   privately, through GitHub's private vulnerability reporting (see SECURITY.md).

The code is open source under Apache-2.0: https://github.com/QuantumDesk/phonevault

---

*Short version (for a post with a character limit):*

> Phone Vault public beta is open: turn a Pixel 6a into an offline wallet for Ethereum and
> Bitcoin. Beta, small amounts only, not yet audited; the phone stays bootloader-unlocked for now.
> Install and release notes: https://github.com/QuantumDesk/phonevault/releases/tag/v0.1.0-beta4
