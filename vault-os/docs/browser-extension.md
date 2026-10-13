# Browser extension

The Phone Vault browser extension lets a web3 site use Phone Vault the way it uses any injected
wallet: the site lists "Phone Vault" next to the others (EIP-6963) and talks to an EIP-1193
provider. The extension holds nothing and decides nothing. It carries each request, together with
the site's origin as the browser reports it, to the Phone Vault Companion on the Mac. The companion
applies the same rules as for WalletConnect (`companion/src-tauri/src/wc.rs`), shows anything that
needs a person, and every signature still goes Mac card → phone review → Mac verification → (for
transactions) broadcast by the companion.

Code: `extension/` (MV3 extension), `companion/src-tauri/src/bridge.rs` (bridge, policy, native
host), `companion/src/extension.ts` (cards and Settings). Tests: `bridge.rs` unit tests and
`extension/test/e2e.mjs` (headless Chrome against the real bridge).

## Threat model

### What is protected

Unchanged from `threat-model.md`: the key never leaves the phone, and nothing is signed without a
fresh approval on the phone's own screen. The extension adds two things worth protecting on the Mac
side:

1. **The user's attention and intent.** A site must not be able to put a request in front of the
   user under another site's name, flood the user with cards, or get a signature the user did not
   see on the phone.
2. **Privacy.** A site the user never connected must not learn the user's address, balances or
   that Phone Vault is paired at all (beyond "a Phone Vault provider exists", which EIP-6963
   announces to every page by design).

### Who is untrusted

| Party | Trust | Why |
| --- | --- | --- |
| The web page (any script on it) | untrusted | It is the dApp. It can call the provider freely; that is the point of a provider. |
| Other pages, other tabs, other sites | untrusted | Must not reach the bridge at all. |
| The node (RPC) | untrusted | As today: it feeds quotes and read results, never decides what is signed. |
| The browser | trusted for origin attribution | It is the only party that knows which site a frame belongs to. If the browser is compromised, the attacker controls what the user sees anyway. |
| The extension's own code | trusted to route and to stamp the origin | Signed/loaded from this repository; it holds no secrets. A malicious replacement could misattribute origins, but cannot sign. |
| Other local processes of the same user | out of scope for origin integrity; in scope for "cannot sign" | Same-user malware can already drive the browser, read the app's files and fake clicks. The phone review is what stops it from obtaining signatures. |
| Other local users, other machines | untrusted | Must not reach the bridge. |

### Invariants

1. **No signature without phone review.** The bridge cannot sign. Requests that need a signature
   are queued for the companion's cards, and approving a card runs the unchanged pipeline: the
   phone shows the full request, the companion verifies the returned signature against the pinned
   signer and the exact request (`verify.rs`), and transactions are broadcast by the companion only
   by hash of a transaction verified in this session (`send.rs`). Rejecting on the Mac means nothing
   reaches the phone.
2. **No keys on the Mac.** Nothing new is stored except the list of connected sites
   (`browser-sites.json`, 0600: origin, paired address at connect time, approved networks, active
   network).
3. **The origin shown is the browser's.** The background worker takes the origin from
   `MessageSender.origin` (falling back to the sender URL) of the content script's port, which the
   browser sets for the frame the script runs in. Anything the page writes is ignored for
   attribution (tested: a page posting a message with `origin: "https://app.uniswap.org"` is still
   attributed to its real origin). Only the top frame is served (`all_frames: false`, `frameId`
   check), so an embedded third-party iframe cannot ask in the embedding site's name. The companion
   re-validates the origin's form (`bridge::normalize_origin`): `https://host[:port]`, plus `http://`
   for `localhost` / `127.0.0.1` / `[::1]` only, shown with a "LOCAL PAGE" warning; ASCII hosts only
   (internationalized names arrive and are shown as punycode, so a homograph is visible as `xn--…`).
4. **Unconnected sites learn nothing.** Before the user approves a connection a site gets
   `eth_chainId` (the default network), `eth_accounts` → `[]`, and may ask `eth_requestAccounts`
   (one card per site at a time; further asks get `-32002`). Everything else that touches the
   account, the node or the phone is refused with `4100`.
5. **The account is never the site's choice.** `eth_accounts` / `eth_requestAccounts` answer with
   the paired address read from the pairing file by Rust. A permission is bound to the address that
   was paired when the user connected; after re-pairing, old permissions are inactive and are
   revoked.
6. **Same method policy as WalletConnect.** `wc::route` and `wc::normalize_tx` check every
   signing and switching request before it is queued (from = paired address, chainId = the site's
   network, hex quantities, size caps, typed data parsed with the phone's own strict parser).
   `eth_sign`, `eth_signTransaction`, `wallet_addEthereumChain`, `wallet_requestPermissions`,
   subscriptions and everything unknown are refused (`4200`).
7. **Bounded.** Frames: 512 KiB in, just under 1 MiB out (Chrome's host limit); the page and the
   worker refuse requests over 384 KiB before sending. Rate: 60-request bursts, 20/s sustained, per
   site in the companion and per tab in the worker. At most 4 requests waiting per site, 8 per
   registrable domain (a site's subdomains together; simplified eTLD+1: the last two labels, three
   under a short list of two-label suffixes such as `co.uk` or `github.io`) and 16 in total; 16 node
   calls in flight. After the user rejects a connection, new connection requests from that
   registrable domain are refused at once with `4001` and no window or notification for 30 s,
   doubling on each further rejection up to 10 minutes; an approved connection resets it. The webview can only answer a request with what the verified
   pipeline produces (a 32-byte transaction hash, a 65-byte signature, or `null` for a network
   switch), and never supplies accounts.

### Transport: native messaging, not a localhost port

The two options were Chrome native messaging and a WebSocket on `127.0.0.1` with a pairing secret
and Origin checks. Native messaging is used, because:

- **Nothing listens on the network.** A localhost port is reachable by every website the user
  visits (via `fetch`/WebSocket from the page) and by every local process. It would need DNS
  rebinding defences (Host header checks), Origin allow-listing (spoofable by non-browser clients),
  and a secret that the extension must store and every local process could try to read or brute
  force. With native messaging there is no port to find.
- **The browser authenticates the extension.** Chrome starts the host only for the extension IDs
  listed in the host manifest (`allowed_origins`, pinned to `fbomijndbpoddicmbngledanaafapmlk`;
  Firefox: `allowed_extensions`). The ID is fixed by the public key in the extension's manifest.
  A different extension, or a web page, cannot open the channel.
- **Installation is an explicit user action.** The host manifest is written only when the user
  clicks Settings → Browser extension → Install browser connection, and removed by Remove.

The host process is the companion executable itself, started by the browser with the extension's
origin as its argument (`main.rs` → `bridge::native_host_main`). It relays frames between the
browser (stdin/stdout) and the running companion over a Unix socket at
`~/Library/Application Support/PhoneVault/bridge.sock`: directory 0700, socket 0600. On accept the
companion checks the peer's user ID (`getpeereid`) and that the peer process is the same executable
(`LOCAL_PEERPID` + `proc_pidpath`), then that the relay's caller is the pinned extension. A
same-user process could still start the relay by hand and pretend to be the browser; that is the
out-of-scope same-user case above, and the phone review is what makes it harmless. The relay never
parses or acts on requests; if the companion is not running it answers "not running" and exits.

### What the extension does not protect against

- A malicious or compromised browser, or a malicious extension with access to all sites (it can
  read and alter the page the user sees, including our provider's answers).
- Phishing by a real origin: `app-uniswap.help` is shown as exactly that. The connection card
  states the address comes from the browser; it does not judge it.
- Sign-in phishing: a `personal_sign` whose text is a Sign-In with Ethereum (EIP-4361) message for
  another domain than the asking origin (first-line domain, or the `URI:` host) is refused before
  any card (`4100`, "Blocked: <site> asked you to sign in to <domain>…"), and the app shows the
  same line. WalletConnect requests get the same check against Verify's origin when Verify says
  VALID; otherwise the card carries a DANGER note that the asking site is unverified.
- A site the user connected asking for many signatures: each one is a card on the Mac and a review
  on the phone; rate and queue limits keep it bounded, the user rejects.
- Read-only node calls from connected sites go to the user's configured node, which therefore sees
  them (as with any wallet's RPC).

## Behaviour

### Provider and announcement

`inpage.js` runs in the page's world at `document_start` and:

- announces `{ uuid, name: "Phone Vault", icon: <companion/brand/icon.svg as data URI>, rdns:
  "dev.phonevault" }` with `eip6963:announceProvider`, and again on every `eip6963:requestProvider`;
- exposes an EIP-1193 provider (`request`, `on`/`removeListener`, events `connect`,
  `accountsChanged`, `chainChanged`, `disconnect`; legacy `enable()`);
- sets `window.ethereum` only if no other wallet has (it never replaces another wallet).

### Methods

| Method | Not connected | Connected |
| --- | --- | --- |
| `eth_chainId`, `net_version` | default network (Base) | the site's active network |
| `eth_accounts` | `[]` | `[paired address]` |
| `eth_requestAccounts` | connection card | `[paired address]` |
| `wallet_switchEthereumChain` | 4100 | approved network: immediate + `chainChanged`; another network the phone supports: card; others 4902 |
| `eth_sendTransaction` | 4100 | `wc::normalize_tx`, then card → node quote → phone → verify → broadcast → hash |
| `personal_sign`, `eth_signTypedData_v4` | 4100 | `wc::route`, then card → phone → verify → signature |
| read-only: `eth_blockNumber`, `eth_call`, `eth_estimateGas`, `eth_feeHistory`, `eth_gasPrice`, `eth_getBalance`, `eth_getBlockByHash`, `eth_getBlockByNumber`, `eth_getBlockTransactionCountByNumber`, `eth_getCode`, `eth_getLogs`, `eth_getStorageAt`, `eth_getTransactionByHash`, `eth_getTransactionCount`, `eth_getTransactionReceipt`, `eth_maxPriorityFeePerGas` | 4100 | forwarded to the user's node for the site's network (node checked to answer for that chain; result or `{code, message, data}` passed back, sizes capped) |
| `wallet_getPermissions` | `[]` | `[{parentCapability: "eth_accounts"}]` |
| `wallet_revokePermissions` | `null` | disconnects the site |
| everything else (`eth_sign`, `eth_signTransaction`, `wallet_addEthereumChain`, …) | 4200 | 4200 |

Read-only calls are forwarded rather than refused because dApps rely on the wallet's provider for
reads after connecting (balances, allowances, gas estimates, receipts); routing them to the node
the user chose keeps them on infrastructure the user already trusts for quotes. They are limited
to the list above and to connected sites.

### In the companion

- **Connection card** ("BROWSER CONNECTION REQUEST"): the site's address as reported by the
  browser, a local-page warning when it is `http://localhost`, the networks to allow (only the
  phone's reviewed ones), the account (paired address). Connect or Reject.
- **Request cards**: exactly the WalletConnect cards and queue, one request to the phone at a time.
  If the tab is closed or navigates while a request waits, it disappears; if that happens after
  the phone signed, nothing is broadcast and the signature is not sent anywhere.
- **Settings → Browser extension**: bridge status, Install browser connection / Remove (writes or
  removes `dev.phonevault.json` in the NativeMessagingHosts folder of each browser that has a
  profile: Chrome, Brave, Edge, Chromium, Firefox), the pinned extension ID, connected sites with
  their networks and Revoke.

## Installing (owner)

1. Build the extension: `cd extension && node build.mjs` (→ `dist/chrome`, `dist/firefox`).
2. Chrome / Brave / Edge: open `chrome://extensions` (`brave://extensions`, `edge://extensions`),
   turn on Developer mode, Load unpacked → `extension/dist/chrome`. The ID shown must be
   `fbomijndbpoddicmbngledanaafapmlk`.
3. Open Phone Vault Companion from `/Applications` (not from the DMG or Downloads: a translocated
   copy is refused), Settings → Browser extension → Install browser connection.
4. Reload open dApp tabs. The site's wallet list shows Phone Vault; connecting shows the card in
   the companion.

Firefox (128+): `about:debugging` → This Firefox → Load Temporary Add-on → `extension/dist/firefox/manifest.json`.
Built from the same sources; not covered by the automated test.

Development note: a browser-started host cannot read an executable under `~/Documents` (macOS
privacy protection); with `npm run tauri dev` from such a checkout the host hangs until access is
granted. Use the bundled app in `/Applications`, or a checkout outside protected folders.

## Tests

- `cargo test --manifest-path companion/src-tauri/Cargo.toml bridge`: origin normalization, frame
  codec and caps, the method policy for connected / unconnected / other-pairing sites, rate limits,
  result shapes the webview may return, node reply sanitizing, sites file permissions and
  validation, host manifest install / outdated / foreign / remove in a temporary home, native host
  caller checks, and two socket tests against the real server (connect, queue, reject, switch,
  caps, cancel, revoke, disconnect cleanup, a second instance cannot take the socket, a relay for
  another extension is dropped, rate limiting under a burst).
- `cd extension && npm test`: builds the extension, runs Chrome for Testing headless with a
  temporary profile (`--load-extension`) and a host manifest in that profile, serves
  `test/page.html` on 127.0.0.1, and drives it over CDP. The host is
  `companion/src-tauri/examples/bridge_e2e.rs`: the real bridge on a temporary socket and a
  scripted user that approves connections and network switches and rejects every signing request.
  It checks the EIP-6963 announcement, the pre-connect answers, connecting, events, switching, that
  signing requests reach the queue and that refused ones do not, the size limit, origin attribution
  under a spoofing attempt, and revocation. Neither the real Chrome profile nor the real companion
  socket is touched.
