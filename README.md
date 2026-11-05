# Phone Vault

Phone Vault turns a spare Google Pixel into an offline hardware wallet. The phone runs
**Vault OS**, a stripped-down, kiosk-locked LineageOS build with no radios and no network, that
boots straight into a single signer app. Your computer prepares transactions; the phone shows
what each one really does, in plain language, and signs only after you approve it on the phone's
own screen. Keys never leave the phone.

- **Ethereum and EVM chains** (Ethereum, Base, OP Mainnet, Arbitrum One, Polygon, Sepolia):
  EIP-1559 transfers, ERC-20 and NFT calls, Uniswap swaps decoded into a readable review,
  `personal_sign`, EIP-712 typed data (Permit / Permit2), Sign-In with Ethereum checks. Calldata
  the phone cannot explain is refused, never blind-signed.
- **Bitcoin**: PSBT signing for native SegWit (P2WPKH) and Taproot key-path (P2TR) accounts, and
  for coins from older Ledger/Trezor-era wallets nested SegWit (P2SH-P2WPKH) and legacy (P2PKH),
  all from the same recovery phrase, with a watch-only wallet on the computer.
- **Device attestation**: the companion asks the phone's Titan M / M2 security chip to prove the
  phone runs genuine Phone Vault firmware and app.
- **Wallet features**: BIP-39 24-word backup with a mandatory backup check, restore, multiple
  accounts, optional passphrase wallets, SeedQR, address book with address-poisoning warnings.

## Status: public beta (Pixel 6a). Small amounts only.

**Public beta: small amounts only; bootloader unlocked; not independently audited.** The beta
images are signed with beta-test keys. Download, install steps and limits:
[0.1.0-beta5](https://github.com/QuantumDesk/phonevault/releases/tag/v0.1.0-beta5), the [tester guide](release/beta/TESTER_GUIDE.md) and the
[release notes](release/beta/RELEASE_NOTES.md). Report bugs in
[GitHub Issues](https://github.com/QuantumDesk/phonevault/issues/new/choose).

Do not move savings to it. It is not ready for more than small amounts until all of the
following exist:

1. **Signed releases** built from source by a reproducible pipeline, with a published release key.
2. A **relocked bootloader** with the project's own verified-boot key, demonstrated to refuse a
   tampered image.
3. An **independent security audit** of the app, the companion and the OS changes.

Beta phones run an unlocked bootloader without adb; development phones run an unlocked
bootloader with adb enabled. See [ROADMAP.md](ROADMAP.md)
for what is done and what is open, and the [threat model](vault-os/docs/threat-model.md) for
the trust boundary and known limitations.

## Supported phones

| Phone | Role | Base |
|---|---|---|
| **Pixel 6a** (`bluejay`, Tensor gs101, Titan M2) | public beta (0.1.0-beta5) | LineageOS 24.0 / Android 17 port ([port-bluejay.md](vault-os/docs/port-bluejay.md)) |
| Pixel 3 XL (`crosshatch`, Snapdragon 845, Titan M) | development phone only (no security updates since 2022) | LineageOS 22.2 / Android 15 |

## How it fits together

```
 browser dApp ──EIP-6963/1193──▶ extension ──native messaging──┐
 WalletConnect dApp ───────────────────────────────────────────┤
                                                               ▼
                 companion (macOS) ── verifies everything, broadcasts on your click
                                                               │ USB (Android Open Accessory)
                                                               ▼
                 phone: Vault OS + signer app ── review on screen, sign, never online
```

The phone is the only approval authority. The companion and browser are untrusted: they can
propose a malicious request, but they cannot get a signature unless the phone shows the decoded
request and you approve it. The companion then independently re-checks every signature before
it will broadcast. The wire format is in [vault-os/docs/protocol.md](vault-os/docs/protocol.md).

## Project map

| Path | What |
|---|---|
| [`app/`](app/) | Android signer app (Java, Gradle). Seed storage, PIN/credential gate, request parsing, review screens, EVM and Bitcoin signing. Token, NFT and router lists with their sources in [`app/token-list/`](app/token-list/SOURCES.md). |
| [`companion/`](companion/README.md) | macOS desktop companion (Tauri 2: Rust core + TypeScript UI). Pairing, attestation, balances, send, WalletConnect, browser bridge, Bitcoin watch-only wallet, independent verification. |
| [`extension/`](extension/README.md) | MV3 browser extension (Chrome, Brave, Edge; Firefox unpacked). Announces Phone Vault to dApps and forwards requests to the companion. |
| [`vault-os/`](vault-os/README.md) | Vault OS: product overlay, hardening patches, build/sign/verify scripts, release gates, policy tests, the development ladders for both phones, and design docs in [`vault-os/docs/`](vault-os/docs/). |
| [`tools/`](tools/) | Python reference USB client and verifiers (`aoa_client.py`, `evm_verify.py`, Bitcoin PSBT tools), token-list checker, backup-card generator, and [`tools/dev-device/`](tools/dev-device/README.md) on-phone test scripts (throwaway devices only). |
| [`.github/`](.github/workflows/ci.yml) | CI: companion (clippy, tests, TypeScript), extension end-to-end, Android unit tests, Python tests, ShellCheck. |

Key documents:

- [Threat model](vault-os/docs/threat-model.md)
- [USB protocol](vault-os/docs/protocol.md)
- [Device attestation](vault-os/docs/device-attestation.md)
- [Message signing](vault-os/docs/message-signing.md), [simulation](vault-os/docs/simulation.md),
  [browser extension](vault-os/docs/browser-extension.md),
  [companion architecture](vault-os/docs/companion-architecture.md)
- [Entropy design](vault-os/docs/entropy-design.md),
  [PIN bound to the Android credential](vault-os/docs/pin-credential-design.md)
- [Release configuration and gates](vault-os/docs/release-config.md)

## Getting started

Building, testing and the rules for development devices are in
[CONTRIBUTING.md](CONTRIBUTING.md). In short: the Android app builds with Gradle 8.10.2 + JDK 21,
the companion with Rust (pinned in `rust-toolchain.toml`) + Node 22, the extension with plain
Node, and the OS image on a 64-bit Linux build host with a LineageOS tree.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0 ([LICENSE](LICENSE)). See [NOTICE](NOTICE) for the licensing boundary (kernel and
other patches to GPL code stay GPL-2.0) and third-party components, including the Press Start 2P
font (SIL OFL 1.1, `app/src/main/assets/fonts/OFL.txt`).

## Support the work

Phone Vault is free and open source, with no investors and no token. If it's useful to you:

- **Ko-fi** (card or PayPal): https://ko-fi.com/halfaipg
- **Ethereum and EVM networks** (ETH, USDC and other tokens on Ethereum, Base, Arbitrum, Optimism, Polygon): `0xA218db26ed545f3476e6c3E827b595cf2E182533`
- **Bitcoin:** `bc1qdvmvswqt3z9a272ynv5adcag0uxt4hg0qzy2ap`

The same addresses are on [phonevault.org](https://phonevault.org/#support). Check that the two match before you send.

