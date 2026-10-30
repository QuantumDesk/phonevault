# Phone Vault extension: store listing kit

For the Chrome Web Store (Chrome, Brave, Edge users) and Firefox Add-ons (AMO). Nothing here is
submitted yet.

## Build the packages

```sh
extension/scripts/package-store.sh                 # -> extension/dist/store/ (gitignored)
OUT_DIR=/tmp/pv-store extension/scripts/package-store.sh
```

Output: `phone-vault-extension-<version>-chrome.zip` and `-firefox.zip` (for the stores),
`-chromium-unpacked.zip` (for testers loading it unpacked: keeps the manifest `key`, so the ID the
companion admits), and `SHA256SUMS`. File times are fixed, so the same sources give the same
hashes. The script rebuilds from `extension/src` with `build.mjs`, removes the Chrome
`key`, adds Firefox's data-collection declaration, and fails if the manifest gains a permission,
host permission, web-accessible resource, remote script, `eval`/`new Function`, `fetch` or any
file other than the eleven it expects.

## Before the first submission (blocking)

1. **Extension ID.** The unpacked build has a fixed ID, `fbomijndbpoddicmbngledanaafapmlk`, from
   the `key` in its manifest, and the companion's browser connection admits **only** that ID
   (`companion/src-tauri/src/bridge/mod.rs`, `CHROME_EXTENSION_ID`; the host manifest's
   `allowed_origins`). The Chrome Web Store refuses a manifest with a `key` and assigns its own
   ID; Edge Add-ons, if used, assigns another. A store-installed extension therefore cannot reach
   the companion until the companion pins the store ID(s) next to the unpacked one. Do the first
   upload as a draft (unlisted), read the assigned ID, add it to the companion (allowed origins
   become a list), release a companion with it, then publish.
2. **Firefox ID.** `browser-extension@phonevault.dev` uses the `.dev` domain while the site is
   `phonevault.org`. AMO accepts any e-mail-style ID, but it can never change after the first
   submission: decide now (changing it later also needs a companion change).
3. **Firefox minimum version.** `data_collection_permissions` is read by Firefox 140 and later;
   the manifest says `strict_min_version: 128.0`. AMO's linter may warn. Either raise the minimum
   to 140 or accept the warning.
4. A public **privacy policy URL** (the text below can be the whole policy) and a **support URL**
   (the bug channel).

## Permissions and why each is needed

| Permission / access | Why |
|---|---|
| `nativeMessaging` | The only way the extension talks to Phone Vault Companion on the user's Mac; there is no network connection and no local port. |
| `activeTab` | Lets the toolbar popup read the address of the tab the user is looking at, only when the user opens the popup, to show whether that site is connected and to offer Disconnect. |
| Content scripts on `https://*/*` | A wallet must be available on any site the user chooses to use; the scripts announce Phone Vault (EIP-6963) and carry the site's requests to the companion. They read nothing from the page. |
| Content scripts on `http://localhost`, `127.0.0.1`, `[::1]` | For sites the user runs on their own computer (development); the companion marks them "LOCAL PAGE". |
| Top frame only (`all_frames: false`) | Not a permission, a restriction: embedded third-party frames cannot ask in the site's name. |

Not requested: `tabs`, `storage`, `cookies`, `webRequest`, `scripting`, `host_permissions`,
optional permissions, `web_accessible_resources`, `externally_connectable`.

Store review note: the content-script match pattern `https://*/*` counts as broad host access and
triggers an in-depth review on the Chrome Web Store. The justification above is the answer for the
"host permission justification" field.

## Short description (132 characters max)

> Use your Phone Vault with web3 sites. Requests go to Phone Vault Companion on your Mac; you
> approve every signature on your phone.

(130 characters.)

## Long description

> Phone Vault turns a Google Pixel 6a into an offline hardware wallet. This extension lets sites
> in your browser use it: Phone Vault appears in a site's wallet list next to other wallets
> (EIP-6963), with a standard Ethereum provider (EIP-1193).
>
> The extension holds no keys and makes no decisions. It passes each request, with the site's
> address as your browser reports it, to Phone Vault Companion on your Mac. The companion shows
> you which site is asking and what it asks for; you can Reject it there. Anything that needs a
> signature goes over the USB cable to the phone, which decodes the request itself, explains it
> in plain words, and signs only after you approve on the phone's screen. Your Mac then checks
> the signature, and nothing reaches the network until you click Send to network.
>
> Sites you have not connected see no address and no balance. Contract calls the phone cannot
> explain are refused, not signed blind.
>
> Requires: a Pixel 6a running Phone Vault, and Phone Vault Companion on a Mac (Settings →
> Browser extension → Install browser connection).
>
> Phone Vault is a public beta: for small amounts only, not yet independently audited. The beta
> phone's bootloader stays unlocked and its genuine check reports Development.
>
> Open source (Apache-2.0). Report security problems privately: see SECURITY.md in the
> repository.

Category: Chrome Web Store "Developer Tools" or "Productivity" (wallets usually list under
Productivity); AMO "Privacy & Security" is not appropriate (it does not protect browsing), use
"Other".

## Privacy practices (both stores)

- **Single purpose:** connect web3 sites to the user's Phone Vault hardware wallet through
  Phone Vault Companion on the same computer.
- **Data collected:** none. The extension sends no data to any server, the developer or any
  third party. It has no analytics, no telemetry, no accounts.
- **Data handled locally:** a site's request and the site's origin are passed over native
  messaging to Phone Vault Companion on the same computer, and the answer is passed back to the
  page. Nothing is stored by the extension (no `storage` permission).
- **Remote code:** none. All code is in the package; no `eval`, no remotely hosted scripts, no
  network requests from the extension.
- Chrome Web Store certifications: does not sell or transfer user data to third parties; does
  not use or transfer data for purposes unrelated to the single purpose; does not use or transfer
  data to determine creditworthiness or for lending.
- Firefox: `data_collection_permissions.required = ["none"]` in the manifest.

## Screenshots checklist

Chrome Web Store: 1280×800 or 640×400 PNG/JPEG, 1 to 5. AMO: any size, at least one. Use a
throwaway wallet on the Sepolia test network; no real addresses or balances.

- [ ] A site's wallet list (for example Uniswap's "Connect a wallet") with **Phone Vault**
      listed.
- [ ] The companion's connection card for that site (site name, LOCAL PAGE warning not shown).
- [ ] The phone's review of a swap ("You give · You get at least · Recipient"), photographed or
      captured on a development phone.
- [ ] The toolbar popup: companion reachable, site connected, Disconnect.
- [ ] The phone refusing a contract call it cannot explain.
- [ ] Store icon 128×128 (`extension/icons/icon-128.png`); Chrome promo tile 440×280 (to make).
- [ ] Check every screenshot for real addresses, balances, recovery-phrase screens: none.

## Submission steps (when the gates in LAUNCH_CHECKLIST.md pass)

1. Run `package-store.sh`; record the zips' SHA-256.
2. Chrome Web Store developer dashboard: new item → upload the chrome zip → fill the listing,
   privacy practices and permission justifications from this file → visibility **Unlisted** for
   the first round → submit for review.
3. AMO developer hub: submit a new add-on → "On this site" → upload the firefox zip → source
   code: not required (no minification or bundling), but link the repository → listing text from
   this file → submit.
4. Update `TESTER_GUIDE.md` step 9 with the store links once listed.
