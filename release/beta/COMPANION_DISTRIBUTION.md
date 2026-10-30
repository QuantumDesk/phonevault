# Phone Vault Companion: building and distributing the macOS DMG

Script: [`companion/scripts/build-dmg.sh`](../../companion/scripts/build-dmg.sh). It builds, checks
and hashes the DMG. It uploads nothing.

## Unsigned beta DMG (today)

Requirements: macOS, Xcode command-line tools, Rust via rustup (the toolchain is pinned in
`rust-toolchain.toml`), Node 22 at `~/.nvm/versions/node/v22.23.2/bin` (or set `NODE_BIN`).

```sh
# keep build output outside the checkout (optional)
export CARGO_TARGET_DIR=~/pv-build/companion-target
OUT_DIR=~/pv-dist companion/scripts/build-dmg.sh
```

What it does:

1. Checks Node 22, cargo, and the four backup-card PDFs the bundle embeds
   (`tools/backup-card/out/`).
2. `npm ci`, then `npx tauri build --bundles dmg` (the frontend is built by `beforeBuildCommand`).
3. Verifies the DMG (`hdiutil verify`), mounts it read-only, and checks the app inside: its
   architecture, and that the executable links only system libraries (libusb is static).
4. Prints the SHA-256 and, with `OUT_DIR`, copies the DMG plus a `.sha256` file there.

The result is `Phone Vault Companion_<version>_aarch64.dmg`: **Apple silicon only**. For Intel
Macs build a universal DMG (`rustup target add x86_64-apple-darwin aarch64-apple-darwin`, then
`UNIVERSAL=1 companion/scripts/build-dmg.sh`).

Unsigned apps are blocked by Gatekeeper on a double-click. Testers open it once with right-click
→ Open (or System Settings → Privacy & Security → Open Anyway). The tester guide says so.

Local proof build, 2026-10-30 (main f07009f + `rusb` "vendored"): `Phone Vault
Companion_0.1.0_aarch64.dmg`, 6.4 MB, arm64, ad-hoc signature only, system libraries only. Not
published. The first attempt without "vendored" linked `/opt/homebrew/opt/libusb/lib/libusb-1.0.0.dylib`
and would not have started on a Mac without Homebrew's libusb; the script now refuses that.

## Signed and notarized DMG (once an Apple Developer ID exists)

### One-time setup (owner: user)

1. Enroll in the Apple Developer Program (organization account, so the certificate names the
   project rather than a person, if wanted).
2. Create a **Developer ID Application** certificate (Xcode → Settings → Accounts → Manage
   Certificates, or developer.apple.com → Certificates). Install it in the login keychain of the
   build Mac. Check: `security find-identity -v -p codesigning`.
3. Create notarization credentials, preferably an **App Store Connect API key** (Users and Access
   → Integrations → Team Keys, role Developer). Download `AuthKey_<KEYID>.p8` once; store it
   outside the repository (for example `~/.phonevault-keys/apple/`, mode 0600).
4. Never commit any of this. `.gitignore` already refuses `.env*`; keep the variables in the
   shell or a keychain-backed helper.

### Environment (placeholders)

```sh
export APPLE_SIGNING_IDENTITY="Developer ID Application: <ORG NAME> (<TEAMID>)"
# preferred: API key
export APPLE_API_ISSUER="<issuer-uuid>"
export APPLE_API_KEY="<KEYID>"
export APPLE_API_KEY_PATH="$HOME/.phonevault-keys/apple/AuthKey_<KEYID>.p8"
# or: Apple ID with an app-specific password
# export APPLE_ID="<developer-apple-id@example.org>"
# export APPLE_PASSWORD="<app-specific-password>"
# export APPLE_TEAM_ID="<TEAMID>"
```

Then the same command:

```sh
OUT_DIR=~/pv-dist companion/scripts/build-dmg.sh
```

With `APPLE_SIGNING_IDENTITY` set, Tauri signs the app with the hardened runtime, submits it to
Apple's notary service, waits for the result and staples the ticket. The script refuses to start
if the identity is missing from the keychain or no notarization credentials are set, and
afterwards runs `codesign --verify --deep --strict`, `xcrun stapler validate` and `spctl -a -t
open` on the result.

### Entitlements to check before the first signed build

The hardened runtime blocks some things that work unsigned. Before the first signed release,
test on a clean Mac that:

- USB to the phone works (libusb through IOKit needs no entitlement outside the App Sandbox; the
  app is not sandboxed).
- The browser connection works: the browser starts the companion executable as the native
  messaging host; the host path in the manifest is the signed app's executable.
- WalletConnect (network) and notifications work.

If anything fails, add an `Entitlements.plist` under `bundle.macOS.entitlements` in
`tauri.conf.json` with only the entitlement that fixes it, and note why.

### Manual notarization (fallback, or to re-check)

```sh
xcrun notarytool submit "Phone Vault Companion_<ver>_aarch64.dmg" \
  --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER" --wait
xcrun notarytool log <submission-id> --key … --key-id … --issuer …   # if it was rejected
xcrun stapler staple "Phone Vault Companion_<ver>_aarch64.dmg"
spctl -a -vvv -t open --context context:primary-signature "Phone Vault Companion_<ver>_aarch64.dmg"
```

## Publishing (not done by the script)

1. Upload the DMG and its `.sha256` next to the release (the same place as the images'
   `SHA256SUMS`); add the DMG's hash to the release's `SHA256SUMS`.
2. Update the tester guide's download link and drop the right-click → Open step once notarized.
3. Auto-update (Tauri updater with its own signing key) is a later step; until then testers
   download each new DMG.
