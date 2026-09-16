# Phone Vault Companion (macOS)

The host side of the signer. It never sees a key. It pairs with the phone over USB, reads
balance, nonce and fees from an Ethereum node, hands a transaction to the phone for review,
verifies what comes back on its own, and broadcasts only after you click Broadcast.

## What it does, in order

1. **Pair.** Reads the phone's address over USB and shows it. You compare it with the address on the
   phone's own Wallet screen, character by character, then pin it. The pin lives in
   `~/Library/Application Support/PhoneVault/paired-signer.json` (mode 0600; anything looser is refused).
2. **Wallet.** Address, balance, network and block from an https JSON-RPC node (default:
   `https://ethereum-rpc.publicnode.com`, editable). The node is untrusted input: everything it
   supplies is shown here and on the phone before anything is signed.
3. **Send.** Enter recipient and amount, get a quote (nonce, max fee, total). "Send to phone for
   approval" hands exactly those fields to the phone. **You approve on the phone.** The returned
   signature is decoded field by field and compared with the quote, the hash is recomputed, and
   the signer is recovered and compared with the pinned pairing. Only then does Broadcast become
   available, as a separate click.

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
