# Phone Vault Companion (macOS)

The host side of the signer. It never sees a key. It pairs with the phone over USB, reads
balance, nonce and fees from an Ethereum node, hands a transaction to the phone for review,
verifies what comes back on its own, and broadcasts only after you click Broadcast.

## What it does, in order

1. **Pair.** Reads the phone's address over USB and shows it. You compare it with the address on the
   phone's own Wallet screen, character by character, then pin it. The pin lives in
   `~/Library/Application Support/PhoneVault/paired-signer.json` (mode 0600; anything looser is refused).
2. **Wallet.** One main view: address (click to copy), balance on the selected network with a
   USD figure, a compact list of balances on every network, Send, Receive (QR code), and recent
   activity. Default network Base (`https://mainnet.base.org`); nodes are editable per network in
   Settings. The node is untrusted input: everything it supplies is shown here and on the phone
   before anything is signed. USD prices come from Coinbase's public spot endpoint (cached 60 s,
   display only; hidden when unavailable).
3. **Send.** A stepper: Details → Phone → Broadcast → Confirmed. Enter recipient (EIP-55 checked
   as you type) and amount (Max available), see the fee in ETH and USD, review the quote, then
   "Send to phone". The screen says "Review on your phone" only after the USB write to the phone
   completed (a `send-progress` event from Rust), with a Cancel. **You approve on the phone.**
   The returned signature is decoded field by field and compared with the quote, the hash is
   recomputed, and the signer is recovered and compared with the pinned pairing. The verified
   transaction stays in the Rust process; Broadcast (a separate click) sends it by hash, so the
   UI can never broadcast bytes that were not verified. Then the receipt is polled until it is
   confirmed or reverted. Every failure has a plain explanation and a retry.
4. **Activity and notifications.** Transactions broadcast from here, and balance increases seen
   while the app is open, are kept in `~/Library/Application Support/PhoneVault/history.json`
   (0600; public-chain facts only). A notification is shown when funds arrive (toggle in Settings).

Preview the UI without Tauri or a phone: `npm run dev` and open http://localhost:1420. With no
Tauri runtime the app uses fake data (marked PREVIEW DATA); `?paired=0`, `?phone=none` and
`?outcome=reject|timeout|verify|nophone|broadcastfail` exercise other states.

## Running it

- Plug the phone into this Mac and unlock it. If a Mac `adb` server is running it holds the USB
  interface: `adb kill-server` first. The app tells you when that is the problem.
- The phone opens its USB session only on a fresh plug-in; after the vault locks, unplug and
  reconnect the cable.
- The bundle is unsigned during development: right-click → Open the first time.

## Building

    npm install
    npm run tauri dev                       # development window
    npm run tauri build -- --bundles app    # → src-tauri/target/release/bundle/macos/

    (cd src-tauri && cargo test)            # verifier tests incl. the real phone-signature fixture

Requires Rust (cargo), Node 22, libusb (`brew install libusb`) and Xcode command-line tools.
Branding: see `brand/README.md`.

## Where the code came from

`src-tauri/src/aoa.rs` is a port of `tools/aoa_client.py` (same accessory identity, framing and
caps). `src-tauri/src/verify.rs` is a port of `tools/evm_verify.py` + `validate_response`, with the
Python test fixture (a real signature from the Pixel) as a unit test. The Python tools remain the
scripted reference used by the device harness.
