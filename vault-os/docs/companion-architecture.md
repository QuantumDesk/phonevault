# Phone Vault companion application — architecture RFC

**Status:** Draft; planning only  
**Date:** 2026-09-04  
**Targets:** macOS, Windows, and Linux

The companion is the online half of Phone Vault. It prepares requests, talks to the offline
phone, verifies every response independently, and optionally hands signed transactions to a
browser wallet or RPC endpoint. It never holds seed material and it is never an approval
authority.

The repository currently ships only the Python AOA client in `tools/aoa_client.py`. A GUI,
browser integration, and packaged desktop releases do not exist yet. Product implementation
should follow the OS hardening and signed release-chain work; narrow transport and browser
feasibility spikes may happen earlier because their results affect protocol decisions.

## 1. Proposed decision

- Use a **Rust core** for protocol handling, USB I/O, pairing, and independent EVM verification.
- Use **Tauri 2** for a small macOS, Windows, and Linux desktop shell.
- Keep Android Open Accessory (AOA) over **libusb** as the first wired transport, subject to a
  Windows driver-install spike that does not require unsafe tools or instructions.
- Treat browser-wallet support as a separate adapter. Evaluate a **MetaMask Keyring Snap** first,
  then a dedicated extension using native messaging or bidirectional QR if the Snap sandbox
  cannot establish an adequately authenticated channel to the companion.
- Do not impersonate Ledger or Trezor. Their protocols, identifiers, and trust assumptions are
  not Phone Vault's contract.

Tauri supports the three target desktop platforms, libusb provides a portable userspace USB
layer, and MetaMask's Keyring API is designed for accounts managed by external signing systems.
Those facts make the proposal plausible, but they do not prove that MetaMask's current Snap
sandbox can safely reach a local USB bridge. That is an explicit feasibility gate.

## 2. Goals and non-goals

### Goals for version 1

1. Pair with one or more Phone Vault devices and pin the identity/address the user verified on
   the phone.
2. Import watch-only account descriptors without exposing a seed or private key.
3. Accept a supported unsigned EVM request, show an advisory desktop preview, and send the
   bounded canonical request to the phone.
4. Require approval on the phone, then independently decode and verify the returned signed
   transaction, hash, signer, request identifier, and requested fields.
5. Export the signed transaction or, when explicitly enabled, broadcast it through a
   user-selected RPC endpoint.
6. Behave consistently across macOS, Windows, and Linux, including disconnect, suspend,
   resume, timeout, and multiple-device cases.

### Non-goals for version 1

- Storing or reconstructing a seed, private key, mnemonic, or PIN on the desktop.
- Approving on behalf of the phone or weakening the phone's confirmation screen.
- Blind-signing arbitrary bytes or unsupported transaction types.
- A cloud account, mandatory telemetry, portfolio tracker, swap service, or dapp browser.
- Making desktop software the trust root for phone firmware or app updates.
- Claiming Ledger/Trezor compatibility by emulating either device.

## 3. Trust boundary and invariants

The browser, desktop OS, companion UI, USB host, RPC endpoint, and network are untrusted. The
phone is the sole signing and approval boundary. A compromised host can propose a malicious
request or lie in its preview; it must not be able to obtain a signature unless the phone shows
the authoritative details and the user approves them.

The implementation must preserve these invariants:

1. Seed material and private keys never cross the phone boundary.
2. The phone parses and displays the exact request it signs. The companion's display is
   convenience, not authorization.
3. Every request has a fresh session nonce and unique request identifier. Responses are bound
   to both and cannot be replayed into another session.
4. Inputs use canonical encodings, strict schemas, explicit capability negotiation, and small
   size/count limits. Unknown fields and unsupported operations fail closed.
5. The host independently reconstructs the transaction hash and recovers the signer. A mismatch
   in signer, pinned identity, chain, nonce, destination, value, calldata, fee, or request ID is
   a hard failure.
6. Only one phone approval may be pending per session. Cancellation, timeout, unplug, app lock,
   and process exit all terminate it.
7. No unauthenticated localhost HTTP or WebSocket service may expose signing. Any browser bridge
   must authenticate the extension, origin, session, and request, with explicit user pairing.
8. Logs and crash reports contain no seed material, PINs, decrypted secrets, or full sensitive
   payloads. Telemetry is absent by default.
9. Installers, binaries, and update metadata are signed. The companion cannot install an
   untrusted phone image or override phone-side signature and rollback checks.

Pairing reduces accidental use of a swapped or unknown device; it does not make a compromised
desktop trustworthy. Address or account rotation must be an explicit re-pairing event confirmed
against the phone's own screen.

## 4. Proposed architecture

The codebase should keep the security-critical core usable without the GUI:

```text
phonevault-protocol   canonical messages, versioning, limits, test vectors
phonevault-usb        AOA/libusb discovery, sessions, cancellation, hotplug
phonevault-verifier   independent EVM decoding, hashing, signer recovery
phonevault-core       pairing, request lifecycle, policy, secure local state
phonevault-cli        testable headless client and automation surface
phonevault-desktop    Tauri UI and platform packaging
browser adapter       Keyring Snap or extension; no signing logic
```

The desktop verifier must remain independent of the phone's signing implementation. Its results
should be cross-checked against the existing pure-Python verifier and published vectors rather
than sharing signing code that could reproduce the same defect on both sides.

Local state should contain only paired public identities, public account descriptors, user
preferences, and non-secret history. Use platform credential storage only where an
authentication secret is genuinely required; do not imply that ordinary public wallet metadata
becomes secret merely because it is stored there.

## 5. Protocol requirements

The first message exchange should negotiate a protocol major/minor version and bounded
capabilities, including supported chains, account types, transaction envelopes, typed-data
versions, and maximum message sizes. Incompatible major versions fail closed.

Every signing exchange should be a small state machine:

```text
connect → authenticate/pair → negotiate → submit request → phone approval
        → receive response → independently verify → export/broadcast → close
```

Protocol work must specify canonical integer and byte encodings, response correlation, timeout
and cancellation semantics, duplicate handling, and safe behavior after either process restarts.
The checked-in protocol package should include golden success and failure vectors before a GUI
depends on it.

## 6. Browser-wallet integration

MetaMask and other extensions will not discover the current AOA protocol as a Ledger or Trezor.
No MetaMask pull request is required for a standalone companion, but seamless use inside
MetaMask needs a supported integration surface.

The first spike should test a MetaMask Keyring Snap that exposes Phone Vault accounts through the
[MetaMask Keyring API](https://metamask.github.io/keyring-api/latest/) while delegating transport
to the companion. It passes only if the extension-to-companion channel can be authenticated,
origin-bound, narrowly permissioned, and reviewed without opening a generic local signing port.

If that fails, evaluate in this order:

1. A dedicated browser extension using the browser's native-messaging mechanism.
2. A first-class MetaMask hardware-wallet integration, accepting the larger review and
   maintenance burden.
3. Bidirectional QR based on an interoperable standard such as
   [ERC-4527](https://eips.ethereum.org/EIPS/eip-4527), once the phone can ingest requests as well
   as display responses.

An outbound signature QR alone is not a complete air-gapped browser flow: the phone must also
receive the unsigned request. Because the vault currently has no request-capture flow, wired USB
remains the primary version-1 path unless that product decision changes.

## 7. Platform risks

| Platform | Required proof before product work |
| --- | --- |
| Windows | AOA works through WinUSB with a signed, understandable installer and no Zadig-style manual driver replacement; unplug and sleep cannot wedge the client. |
| macOS | Intel and Apple Silicon builds work under the hardened runtime and notarization; USB access and reconnect behavior are reliable. |
| Linux | Documented udev rules grant only the necessary device access; packages work on the supported distributions without running the app as root. |

All three platforms need tests for hotplug, multiple connected devices, suspend/resume,
half-written messages, hostile lengths, blocked reads/writes, queue exhaustion, and abrupt phone
lock or reboot.

## 8. Release and supply-chain requirements

- Pin compiler, package-manager, Rust crate, JavaScript, Tauri, and libusb inputs.
- Produce an SBOM and dependency/advisory report for each release.
- Sign macOS, Windows, and Linux artifacts using their appropriate distribution mechanisms;
  notarize macOS releases and protect signing keys outside developer laptops.
- Publish hashes and signed update metadata. Test downgrade, wrong-key, tampered-package, and
  interrupted-update failures.
- Make builds reproducible where platform signing permits, and publish unsigned payload evidence
  when the final package signature necessarily differs.
- Keep automatic updates optional until their trust and rollback behavior have been audited.

The security-critical protocol, verifier, and transport core should remain publicly auditable.
Any different licensing decision for the UI or hosted services must not prevent independent
verification or force trust in a proprietary signing path.

## 9. Delivery sequence and gates

0. **Freeze the RFC.** Resolve open decisions, threat-model the host boundary, specify protocol
   vectors, and complete the Windows USB and MetaMask communication spikes.
1. **Rust CLI parity.** Pair, request a test signature, and reject every mismatch currently
   rejected by `tools/aoa_client.py`; cross-check both verifiers.
2. **Three-platform transport.** Pass disconnect, blocking-I/O, malformed-input, and lifecycle
   tests on physical or dedicated CI hosts.
3. **Desktop MVP.** Pair, display accounts, preview a request, invoke phone approval, verify, and
   export the signed transaction.
4. **Watch-only and broadcast.** Add account descriptors and optional explicit RPC broadcast,
   with chain and destination confirmation.
5. **Browser integration.** Ship only the adapter that passed the authenticated-channel review.
6. **Release audit.** Package, sign, negative-test updates, perform an external security review,
   and publish artifacts and hashes.

No milestone passes on a happy-path demo alone. Required gates include protocol fuzzing, hostile
USB tests, signer and payload mismatch tests, proof that no signature is produced after phone
lock or without phone approval, safe installer/uninstaller tests, and hands-on UX testing on all
three operating systems.

## 10. Open decisions

- Whether version 1 broadcasts transactions or only exports them to another wallet/tool.
- Whether a Keyring Snap can securely and portably reach the companion.
- Whether AOA remains the only wired protocol or a later HID/WebUSB mode is justified.
- Which account-descriptor/xpub formats the phone will expose and how address rotation works.
- Whether optional local signing history belongs on the companion, the phone, or neither.
- Final distribution channels and support matrix for Windows and Linux.
- Final licensing boundary for the desktop UI and any hosted services.

Useful upstream references: [Tauri](https://tauri.app/) and
[libusb](https://github.com/libusb/libusb/wiki).


## Addendum: several accounts (2026-10-11)

The phone can hold several accounts (m/44'/60'/0'/0/i) and passphrase wallets. The companion keeps
a list of paired addresses with labels ("Account 1", "Account 2 · passphrase") and one ACTIVE
address that the UI, the menu bar and the watcher show. Each address is paired on its own after
the user compared it with the phone's screen and the device check attested that address. A
request is pinned to the active address at the moment it starts: it names it in `from` (the phone
refuses it when another account is active there), the attestation must name it, and the recovered
signer must equal it. On identify the companion compares the phone's active account with the list
and offers to show it ("The phone is using Account 2") or to pair it if it is new.
