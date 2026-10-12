# Phone Vault browser extension

Makes Phone Vault show up in web3 sites' wallet lists (EIP-6963, name "Phone Vault", rdns
`dev.phonevault`) with an EIP-1193 provider. It holds no keys and decides nothing: requests go to
Phone Vault Companion on this Mac over native messaging, the companion shows them, and every
signature is approved on the phone. Design and threat model: `vault-os/docs/browser-extension.md`.

## Build

    node build.mjs          # → dist/chrome (Chrome, Brave, Edge, Chromium), dist/firefox

No dependencies. Node 18+.

## Load unpacked

Chrome, Brave or Edge:

1. Open `chrome://extensions` (or `brave://extensions`, `edge://extensions`).
2. Turn on **Developer mode**.
3. **Load unpacked** → choose `extension/dist/chrome`.
4. Check the ID is `fbomijndbpoddicmbngledanaafapmlk` (fixed by the `key` in the manifest; the
   companion only lets this ID start its bridge).

Then, in Phone Vault Companion (run from `/Applications`): **Settings → Browser extension →
Install browser connection**. Reload any open dApp tabs. The toolbar popup shows whether the
companion is reachable and whether the current site is connected.

Firefox 128+: `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on…** →
`extension/dist/firefox/manifest.json` (built from the same sources; not covered by the automated test).

## Files

- `src/inpage.js`: page world. EIP-6963 announcement, EIP-1193 provider, events.
- `src/content.js`: isolated world, top frame only. Carries messages page ↔ worker.
- `src/background.js`: service worker. Stamps the browser-reported origin, rate and size limits,
  native messaging to `dev.phonevault`.
- `src/popup.*`: toolbar popup.
- `build.mjs`: copies sources, writes both manifests, embeds `companion/brand/icon.svg` as the
  EIP-6963 icon, syntax-checks the output.

## Test

    npm test     # = node build.mjs && node test/e2e.mjs

Headless Chrome for Testing (from `CHROME_PATH` or the puppeteer cache; branded Chrome no longer
loads unpacked extensions from the command line) with a temporary profile, against the real bridge
code (`companion/src-tauri/examples/bridge_e2e.rs`, which rejects every signing request). Needs
cargo. Writes `test/output/extension-test-dapp.png`.
