# Companion architecture

The companion is the online half of Phone Vault: a macOS desktop app (Tauri 2, Rust core +
TypeScript UI) in [`companion/`](../../companion/README.md). It prepares requests, talks to the
offline phone over USB, verifies every response independently, and broadcasts only what the user
approved on the phone and then explicitly chose to broadcast. It never holds seed material and is
never an approval authority. What it does, screen by screen, is in the companion README; this
document covers the structure and the rules the code keeps.

## Trust boundary

The browser, dApps, WalletConnect relays, RPC and Esplora servers, the desktop OS, the companion
UI and the USB link are untrusted. The phone is the only signing and approval boundary: a
compromised host can propose a malicious request or lie in its own preview, but it must not be
able to obtain a signature unless the phone shows the decoded request and the user approves it
there. See [threat-model.md](threat-model.md) for the full model.

Invariants the companion keeps:

1. Seed material, private keys and PINs never exist on the desktop.
2. The phone parses and displays the exact request it signs; the companion's display is
   convenience, not authorization.
3. Every response is independently verified before it is used: the signed transaction is decoded
   field by field and compared with the request, its hash recomputed, the signer recovered and
   compared with the address pinned at pairing (EVM); message digests are recomputed from the
   original request with an independent implementation; Bitcoin PSBTs are checked byte for byte
   against the unsigned transaction, with every input run through libbitcoinconsensus.
4. Verified transactions stay in the Rust process; the UI can only ask to broadcast one by hash,
   so it can never broadcast bytes that were not verified.
5. Pairing pins addresses the user compared with the phone's own screen, and only after the
   device check (attestation) passed for that same address. Rotation is an explicit new pairing.
6. One phone request at a time (`aoa::take_turn`); cancellation, timeout and unplug end it.
7. No unauthenticated localhost HTTP or WebSocket service. The browser extension reaches the
   companion only through the browser's native messaging, from one pinned extension ID, and
   every site needs an explicit connection the user can revoke.
8. Local state holds public data only (paired addresses, history of public-chain facts, account
   descriptors, settings), in 0600 files inside a 0700 directory; a file readable by others or
   that is not a regular file (e.g. a symlink) is refused. No telemetry.

## Structure

Rust (`companion/src-tauri/src/`), where every security decision is made:

| Module | Role |
|---|---|
| `aoa.rs` | Android Open Accessory transport: accessory switch, interface claim, newline-framed JSON exchange, response caps, one-request-at-a-time turns |
| `pairing.rs` | the list of paired addresses (accounts, passphrase wallets) and the active one |
| `attest/` | device attestation: strict DER/KeyDescription parsing, chain verification to pinned Google root keys, revocation list, GENUINE / DEVELOPMENT / FAIL policy, Developer mode |
| `eth.rs` | Ethereum JSON-RPC: balance, nonce, fee quote, broadcast, receipt (node output is untrusted input) |
| `send.rs`, `verify.rs` | the send pipeline: quote → phone → independent verification → broadcast by hash |
| `replace.rs` | speed up / cancel as complete new same-nonce transactions through the same pipeline |
| `signing.rs`, `message.rs`, `siwe.rs` | `personal_sign` / EIP-712 with independent digest recomputation; Sign-In with Ethereum domain check |
| `sim.rs` | transaction simulation on the user's node; the result goes to the phone as an untrusted, display-only claim ([simulation.md](simulation.md)) |
| `tokens.rs`, `nft.rs`, `price.rs` | the phone's pinned token list (same bytes, same SHA-256), ERC-721 holdings, display-only USD prices |
| `history.rs`, `watcher.rs`, `tray.rs` | local activity history, background balance/incoming-transfer watcher, menu-bar item |
| `wc.rs` | WalletConnect v2 request policy (the SDK in the webview only moves messages) |
| `bridge.rs` | browser-extension bridge over native messaging ([browser-extension.md](browser-extension.md)) |
| `btc/` | watch-only Bitcoin: account checks, Esplora client, gap-limit scan, coin selection and PSBT building, verification of the phone's signed PSBT, background watcher |
| `backup_card.rs` | opens the bundled blank backup-card PDFs for printing |
| `audit_proofs.rs` | regression tests for security-audit findings |

TypeScript (`companion/src/`) renders the UI and runs the WalletConnect SDK; it holds no
signing logic and cannot bypass the Rust checks. A mock layer (`mock.ts`, `wc-mock.ts`) lets the
UI run in a browser without a phone.

The Rust modules were ported from the Python reference tools (`tools/aoa_client.py`,
`tools/evm_verify.py`), which remain the scripted reference used by the device test harness.
The verifiers are deliberately independent of the phone's Java implementation, so a defect on
one side is not reproduced on the other.

## Protocol

Request and response formats, limits and verification duties are specified in
[protocol.md](protocol.md).

## Platforms and distribution

- **macOS:** built and in use on development machines; unsigned and not notarized.
- **Windows and Linux:** not built. Windows needs AOA through WinUSB with a signed driver
  installation and no manual driver replacement; Linux needs udev rules that grant only the
  necessary device access without running as root.

Release requirements (open, tracked in [ROADMAP.md](../../ROADMAP.md) G5): pinned toolchains and
dependencies (already: `rust-toolchain.toml`, `Cargo.lock`, `package-lock.json`, SHA-pinned CI
actions), signed and notarized builds, signed update metadata with downgrade and wrong-key tests,
reproducible builds where platform signing permits.

## Open decisions

- Whether and how to support Windows and Linux (transport and packaging above).
- Watch-only export formats for other wallets (Rabby / MetaMask views).
- Optional signing history on the phone, the companion, or neither.
- Licensing boundary for any hosted services.
