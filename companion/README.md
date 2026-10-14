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
   **Tokens.** Send can also move an ERC-20 from the token list built into the phone app
   (`app/src/main/res/raw/tokens.json`, compiled in here byte for byte and SHA-256 pinned on
   both sides; see `src-tauri/src/tokens.rs`). Balances for the listed tokens on the selected
   network (`balanceOf`) appear under Balances. A token send is `transfer(recipient, amount)` to
   the listed contract with no ETH; before it goes to the phone it is re-derived from the list,
   and after signing the calldata decoded from the signed bytes must match the recipient and
   amount you entered. The fee is still paid in ETH. The phone names the token from its own copy
   of the list; anything else it shows as "Unknown token contract".
4. **Activity and notifications.** Kept in `~/Library/Application Support/PhoneVault/history.json`
   (0600; public-chain facts only), with filters (All / Sent / Received / Pending, this network or
   all). A background watcher in Rust (`src-tauri/src/watcher.rs`) runs whether the window is open
   or closed to the menu bar, on your own nodes only (no explorer, no third party):
   * native balances on every network (the selected one every 20 s, the rest every 90 s);
   * **incoming ETH with real hashes:** after a balance increase it reads the block bodies since the
     previous reading (at most 40 blocks) for plain transfers to your address. If the gap is wider,
     or the ETH came from inside a contract call (an exchange's batch payout, a bridge, a contract
     withdrawal: no block body shows those without trace APIs), it records a "balance increase"
     without a hash, as before. A deposit and a send in the same window can cancel out and go
     unnoticed. No keyless explorer API was used: the reliable ones need keys, and any of them would
     learn your address.
   * **incoming ERC-20 with real hashes:** `Transfer` logs to your address from the built-in token
     list (eth_getLogs filtered by those contracts), over a recent window at first (≈ a day on
     Ethereum, 12 h on Base, 5 h on Optimism) and then continuously from where it stopped. Public
     nodes limit this differently (publicnode serves Polygon/Arbitrum logs only for the last minutes
     and refuses searches without a contract; mainnet.base.org rate-limits); Settings → Incoming
     transfers shows what each node allowed. Zero-value transfers (address poisoning) and unlisted
     tokens are ignored.
   * pending transactions sent from here are settled (see Speed up / cancel below);
   * a notification per incoming transfer (toggle in Settings). State: `watch-state.json` (0600).
5. **Speed up / cancel.** A pending transaction sent from this Mac shows Speed up and Cancel in
   Activity. Both are complete new transactions with the same nonce, quoted in Rust
   (`src-tauri/src/replace.rs`) from the signed fields kept in history: Speed up resends the same
   to/value/data/gas limit, Cancel is a 0-value transfer to your own address (21,000 gas). Both
   maxFeePerGas and maxPriorityFeePerGas are at least 12.5 % above the highest already sent for that
   nonce, or the current network fee if higher. `sign_start` re-checks the relationship against
   history, then the replacement goes through the same pipeline as any Send: the phone reviews it
   as a normal transaction, `verify.rs` checks the signature, Broadcast is a separate click. The Mac
   labels it "Replacement for tx 0x…". Whichever transaction of the nonce gets mined wins; history
   marks it confirmed/failed and the others dropped ("Replaced" / "Cancelled"); a nonce used by a
   transaction from elsewhere marks ours dropped. Transactions recorded before this version can only
   be cancelled (their data wasn't kept).
6. **Assets, NFTs, USD.** Home has Assets / NFTs / Activity tabs. Totals in USD: native coins at
   Coinbase spot, USDC/USDT/USDT0/DAI at $1 by definition (a depeg is not shown), WETH at the ETH
   price, WBTC/cbBTC at the BTC price. NFTs (`src-tauri/src/nft.rs`): ERC-721 tokens found from
   `Transfer` logs to your address in the recent window, confirmed with `ownerOf`, named with
   `name()`/`symbol()`. Nodes that refuse searches without a contract (most public ones) can't
   discover NFTs: add a collection by its contract (ERC-721 Enumerable, or that contract's logs).
   ERC-1155 is not shown. Metadata and images are fetched only when you click Load image, by Rust:
   https only (ipfs:// via the ipfs.io gateway), no redirects, no localhost/private IP literals,
   256 KiB JSON / 2 MiB image (PNG, JPEG, GIF, WebP, SVG), returned as a data: URL. The server
   hosting the image sees that request.
7. **Menu bar.** A padlock in the menu bar: balance on the selected network (with USD), Open,
   Copy receive address, Quit. Closing the window keeps the app (and notifications) running there;
   the Dock icon reopens it.
8. **Guided setup.** With nothing paired the app opens a full-screen stepper: plug in (live USB
   detection) → is it genuine (device check, big Genuine / Development / Not genuine; Not genuine
   stops with guidance; development phones only with Developer mode) → pair (compare the address on
   the phone) → receive (QR, waits for a small test deposit) → first send (optional) → done.
   Settings → Run setup again. Skippable once paired.
9. **One request on the phone at a time.** Every USB exchange (identify, device check, Send,
   WalletConnect, message signing) takes a turn (`aoa::take_turn`). A Send started while the phone
   is answering something else shows "Waiting for your phone" and continues by itself, instead of
   failing with "USB busy"; it can be cancelled while queued.

10. **WalletConnect (dApps).** Settings → WalletConnect → Project ID (free, from
   [cloud.reown.com](https://cloud.reown.com); stored only in this Mac's webview storage). Then
   "Connect a dApp" on the main view and paste the dApp's `wc:` link. The connection card shows
   the dApp, its URL and the WalletConnect Verify result (UNVERIFIED / DOMAIN MISMATCH / THREAT
   are shown prominently), the networks it asks for (only the phone's reviewed chains can be
   picked) and the methods. The account offered is always the paired address, read by Rust from
   the pairing file. Each request gets a card here first (reject it there and nothing reaches the
   phone), then goes through the existing verified commands: `eth_sendTransaction` → the Send
   flow's `sign_start` → `broadcast_verified` → the hash goes back to the dApp; `personal_sign` /
   `eth_signTypedData_v4` → `sign_message` / `sign_typed_data`. `eth_sign`, `eth_signTransaction`
   and anything unknown are refused with a JSON-RPC error. One request goes to the phone at a
   time; the rest wait in a visible queue. Request policy and parameter checks: `src-tauri/src/wc.rs`.
   The phone signs only what it can decode in full (native transfers, ERC-20 and NFT calls,
   pinned Uniswap routers; see `vault-os/docs/protocol.md`); any other contract call is shown
   with a warning here and refused by the phone.

11. **Browser extension.** Sites in Chrome, Brave or Edge can use Phone Vault directly: the
   extension (`extension/`, load unpacked) announces "Phone Vault" through EIP-6963 and passes each
   request, with the site's origin as the browser reports it, to this app over native messaging.
   Settings → Browser extension → Install browser connection writes the host manifest (pinned to
   the extension ID); connected sites are listed there with Revoke. Connections and requests get
   the WalletConnect cards above and the same phone → verify → broadcast pipeline; the rules are in
   `src-tauri/src/bridge.rs` (reusing `wc.rs`). Design and threat model:
   `vault-os/docs/browser-extension.md`.

12. **Bitcoin (watch-only).** Pick Bitcoin in the network menu (Testnet/Signet: Settings → Bitcoin →
   Developer toggle). *Add from phone* asks for Native SegWit (BIP-84, default) or Taproot (BIP-86) and
   an account number; the phone asks you to approve sharing that account's xpub (`btcGetAccount`).
   The answer is checked strictly (path, depth/child number, xpub network, and the descriptor must be
   exactly the one rebuilt here from fingerprint + path + xpub, checksum included), then the phone
   must show the first receive address (`btcShowAddress`) and you compare it before anything is
   stored (`btc-accounts.json`, 0600; re-derived and re-checked on every load). Balances and history
   come from an Esplora server (default mempool.space, blockstream.info as fallback; your own server
   in Settings, used alone), with gap-limit-20 discovery on the receive and change chains. Receive
   shows the next unused address with a QR and *Verify on phone*. Send: recipient (network and
   checksum checked, own addresses flagged), amount in BTC / sats / USD or Max, fee presets from the
   server's estimates (or custom sat/vB); every coin is checked against its previous transaction
   (hashed to its txid) before use; branch-and-bound / largest-first selection without dust change;
   PSBT v0 with nVersion 2, nSequence 0xfffffffd (RBF), witness_utxo, BIP-32 origins for inputs and
   change, non_witness_utxo for every P2WPKH input (required by the phone; PSBT ≤ 180 KiB, ≤ 100 inputs) →
   `btcSignPsbt` → `src-tauri/src/btc/verify.rs` (same unsigned transaction byte for byte, fee from
   this Mac's own amounts, one valid ECDSA/Schnorr signature per input by the key derived here,
   SIGHASH_ALL/DEFAULT only, witnesses assembled here, every input run through libbitcoinconsensus)
   → Broadcast (separate click, by txid) → confirmations. A pending send can be sped up (RBF, fee
   from the change, reviewed on the phone again). The background watcher refreshes Bitcoin accounts
   (2 min shown / 10 min others, full scan at most every 30 min), notifies incoming payments and puts
   the balance in the menu bar. Settings → Bitcoin → *Export to Sparrow* shows the descriptor
   (`wpkh([fp/84h/0h/0h]xpub/<0;1>/*)#…`), fingerprint and xpub; copy or save a .txt to Downloads.
   Privacy: the server learns all your addresses and your IP; run your own (Settings says so).

Preview the UI without Tauri or a phone: `npm run dev` and open http://localhost:1420. With no
Tauri runtime the app uses fake data (marked PREVIEW DATA); `?paired=0`, `?phone=none` and
`?outcome=reject|timeout|verify|nophone|broadcastfail` exercise other states. A pretend dApp
drives WalletConnect: `?wc=proposal|session|requests|noid`, `?wcverify=VALID|UNKNOWN|INVALID|SCAM`,
`?wctx=native|approve|swap` (see `src/wc-mock.ts`). `?paired=0` opens the guided setup;
`?deposit=N`, `?phonebusy=1`, `?history=0` are described in `src/mock.ts`. The browser extension: `?ext=connect|requests|sites|off`. Bitcoin: `?open=btc` (`&btc=0` no account yet, `&btcshow=mismatch`, `&btcverified=1`), `?open=btcsettings`.

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
