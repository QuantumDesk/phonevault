# Contributing to Phone Vault

Thanks for helping. Phone Vault is a hardware wallet, so the bar is: every change keeps the
phone the only approval authority, keeps the review honest about what is signed, and never
weakens a release, provenance, USB, device-owner or audit gate to make something pass.

Read the [threat model](vault-os/docs/threat-model.md) before changing anything on the signing
path, and the [USB protocol](vault-os/docs/protocol.md) before changing anything on either side
of the cable. Security bugs go through [SECURITY.md](SECURITY.md), not public issues.

## Ground rules

- **Never commit key material**: no seed phrases (other than the public BIP-39 test vectors),
  private keys, keystores (`*.jks`, `*.keystore`, `*.pk8`, `*.pem` private halves), adb keys,
  `.env` files, pairing files or device dumps. `.gitignore` covers the usual names; check
  `git status` before every commit anyway. Release keys live outside the tree by policy.
- **Never weaken a gate to make a test pass.** If a gate is wrong, fix the gate in its own
  reviewed change, with a test that shows why.
- **Keep the phone strict.** Requests are parsed schema-exact and fail closed; calldata the phone
  cannot fully explain is refused. A new request type, field or decoder needs phone tests,
  companion tests and an update to `vault-os/docs/protocol.md`.
- **Pinned inputs stay pinned.** Dependencies are locked and hash-verified on every side (Gradle
  lockfile + verification metadata, `Cargo.lock`, `package-lock.json`, hash-pinned
  `tools/requirements.txt`, SHA-pinned GitHub Actions). Changing one is a reviewed change with
  the lock/verification files committed alongside.
- Small, focused commits with a message that says what changed and why.

## Android signer app (`app/`)

Prerequisites (not versioned): **JDK 21**, an **Android SDK** with platform 35 and build-tools
35.0.0, and **Gradle 8.10.2** (there is no wrapper in the repository). Point `JAVA_HOME` and
`ANDROID_HOME` (or `ANDROID_SDK_ROOT`) at them.

```sh
gradle :app:testDebugUnitTest                 # JVM unit tests (what CI runs)
gradle :app:assembleDebug                     # installable on any phone, software key fallback
gradle :app:assembleAppliance                 # dev-appliance: what development images embed
gradle :app:assembleRelease                   # release variant (signed separately)
```

Build types:

- `debug`: installable everywhere; allows software-backed key wrapping on phones without
  StrongBox; UI dump enabled.
- `appliance`: what development images run. Non-debuggable and minified, requires StrongBox,
  **but** shares the debug source set's `DevTools` UI dump and is debug-signed. Its manifest
  carries `dev.phonevault.variant=dev-appliance`, and `vault-os/scripts/verify-signer-apk.sh`
  refuses it.
- `release`: no dump code compiled in, app install/uninstall disallowed by device policy,
  `dev.phonevault.variant=release`. Signed by the release process, never by a developer key.

The dependency graph is locked in `app/gradle.lockfile`, and every artifact's SHA-256 is in
`gradle/verification-metadata.xml`. Gradle refuses anything that does not match. To add or
update a dependency, run `gradle --write-locks --write-verification-metadata sha256 …` and
commit both files.

Reproducibility today: clean builds on different hosts are payload-equivalent (`classes.dex`,
`resources.arsc` and the manifest match) but not byte-identical at the ZIP level. Compare entry
digests, not APK hashes, until the pinned build container and deterministic packaging land.

## Companion (`companion/`, macOS)

Prerequisites: Rust (the toolchain in `rust-toolchain.toml` is installed automatically by
`rustup`), Node 22 (`.nvmrc`), libusb (`brew install libusb`) and the Xcode command-line tools.

```sh
cd companion
npm ci
npx tsc --noEmit                          # TypeScript
npm run build                             # frontend (embedded by the Rust build)
(cd src-tauri && cargo clippy --locked -- -D warnings)
(cd src-tauri && cargo test --locked)     # verifiers, attestation, Bitcoin, WalletConnect policy
npx tauri dev                             # development window
npx tauri build --bundles app             # → src-tauri/target/release/bundle/macos/
npm run dev                               # UI preview with mock data, no phone needed (see README)
```

Details, mock-data switches and what each module does: [companion/README.md](companion/README.md)
and [vault-os/docs/companion-architecture.md](vault-os/docs/companion-architecture.md).

## Browser extension (`extension/`)

No dependencies; Node 18+. The end-to-end test needs Chrome for Testing (`CHROME_PATH`) and
cargo (it builds the real companion bridge as the native host).

```sh
cd extension
npm test          # = node build.mjs && node test/e2e.mjs
```

## Host tools (`tools/`, Python)

```sh
python -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes --no-deps -r tools/requirements.txt
python -m unittest discover -s tools -p 'test_*.py' -v
```

`tools/requirements.txt` is hash-pinned; regenerate it with hashes when you change it. The
Bitcoin test scripts additionally use `embit` on the host (see `tools/dev-device/README.md`).

## Vault OS (`vault-os/`)

Policy and gate tests run without an Android tree (bash and Python 3; a few need extra host
tools, which the script names when they are missing):

```sh
for t in vault-os/tests/*.sh; do bash "$t" || echo "FAIL: $t"; done
python3 vault-os/tests/test_forbidden_policy_coverage.py
```

Building an image needs a 64-bit Linux build host with several hundred GB of free disk and a
LineageOS tree (22.2 for the Pixel 3 XL, 24.0 for the Pixel 6a). The outline is in
[vault-os/README.md](vault-os/README.md); the step-by-step ladders are
[vault-os/dev-ladder/README.md](vault-os/dev-ladder/README.md) (Pixel 3 XL; the archived rungs are
summarised in [vault-os/docs/hardening-ladder.md](vault-os/docs/hardening-ladder.md)) and
[vault-os/dev-ladder-bluejay/README.md](vault-os/dev-ladder-bluejay/README.md) (Pixel 6a).
Paths in those documents are placeholders (`$LINEAGE_TREE`, `$OUT_DIR`, `<build-host>`); set
them for your machine.

**Development adb key.** Development rungs are userdebug images with adb pre-authorised for the
builder. No adb key is committed: the rung sync scripts read your public adb key from the path
in `PV_DEV_ADB_KEY` (for example `~/.android/adbkey.pub`) and install it only inside the build
tree. Release builds carry no adb key and the release-source gate refuses one.

No script in `vault-os/scripts/` unlocks, wipes, flashes or relocks a phone. The ladder flash
scripts do, and refuse to erase anything without `PV_THROWAWAY_DEVICE=1`.

## On-phone tests (`tools/dev-device/`)

These scripts drive a **development phone** over adb and USB. Rules:

- Use a **throwaway phone and a throwaway wallet only**. `PV_THROWAWAY_DEVICE=1` is required;
  every wrong PIN counts toward the 10-attempt erase, and several scripts wipe or replace the
  wallet.
- Never put real funds, a real seed phrase, or a PIN you use anywhere else on a development
  phone. Development images allow screenshots and adb by design.
- `PV_TEST_PIN` defaults to the one test PIN in `tools/dev-device/env.sh` (export it to use
  another, e.g. for a phone set up with an older test PIN) and is never printed; treat any PIN
  that appears in a log or report as burned.
- `PV_WORDS_FILE` holds the throwaway phrase (mode 0600). Delete it when the wallet is retired.
  Never commit it or paste it anywhere.
- Keep only one phone attached, or set `ANDROID_SERIAL`.

The script list and conventions are in [tools/dev-device/README.md](tools/dev-device/README.md).

## Continuous integration

[.github/workflows/ci.yml](.github/workflows/ci.yml) runs on every push and pull request:

| Job | What |
|---|---|
| Companion | `npm ci`, `npx tsc --noEmit`, `npm run build`, `cargo clippy --locked -D warnings`, `cargo test --locked` (macOS) |
| Extension | build, syntax check, headless Chrome end-to-end against the real bridge |
| Android | `gradle :app:testDebugUnitTest` (JDK 21, SDK 35, Gradle 8.10.2) |
| Python | hash-pinned install, `unittest discover -s tools -p 'test_*.py'` |
| ShellCheck | every tracked `*.sh` at warning level |

Run the relevant commands locally before opening a pull request; a change on the signing path
should also say which on-phone scripts were run, on which phone and rung.
