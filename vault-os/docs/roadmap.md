# Phone Vault — Product Roadmap

Status: living document (2026-09-04). Prioritized feature roadmap from the state of the
appliance as of the first booting, branded, kiosk-locked build. Reconcile every item with
`threat-model.md` and `entropy-design.md` before building; design intents from the founder
discussion live in `roadmap-product-notes.md` and are integrated here rather than repeated.

Standing rules (from the original brief; these never move):

- Nothing is "production-safe" until the hardened image is built, inspected, flashed, booted,
  tested, **and verified-boot relocking has been demonstrated**.
- Never sign a transaction whose decoded fields differ from what the user approved.
- Never weaken the release, provenance, USB, device-owner, or audit gates to make tests pass.
- Never expose, commit, or print private keys or seed material.

## 0. Where we are (2026-09-04)

Working today, on the Pixel 3 XL (crosshatch), LineageOS 22.2 / Android 15 base:

| Area | State |
|---|---|
| Boot | Boots straight into the vault app (device owner + kiosk/lock-task, keyguard disabled), survives reboot |
| Brand | Mono/pixel boot animation, wallpaper, in-app theme (Press Start 2P + monospace) |
| Keys | BIP39 24-word seed from kernel CSPRNG + a software jitter source, hash-combined with startup sanity checks (`SeedVault`; see `entropy-design.md` "Implementation status" — R2/R7 NOT met), StrongBox-wrapped at rest, EVM key at m/44'/60'/0'/0/0 |
| Access | In-app 6-digit PIN gate, wipe-after-10 with verified erase (fail-closed), lock on screen-off / 2-min idle, seed view 60 s, USB attach parked behind the gate |
| Signing | EIP-1559 decode → approval screen → sign (`Eip1559Request` / `EvmSigner`), strict schema, ABI-padding checks, unlimited-allowance DANGER |
| Transport | USB accessory (AOA) JSON channel only |
| UI | Home (QR receive + address + status), full-screen recovery phrase, dark approval sheet |
| Build loop | gradle on cachy → `adb install -r` in seconds; OS image via sideload OTA |

**Flashed-device state vs. checked-in source.** The table above and the list below describe the
*development device as flashed* (built from a working tree on the build box with debug knobs).
The checked-in `vault-os/` pipeline still declares the appliance stripping, `BoardConfigVault.mk`
and the release gates; those are *not what is running on the phone*. Do not read either as the
other.

**Debug-only state that MUST be reverted for any release** (tracked so it can't be forgotten):

- `WITH_ADB_INSECURE=true`, `PRODUCT_ADB_KEYS` (pre-authorized host key), `ro.adb.secure=0`
- `VAULT_ALLOW_SCREENSHOTS=true` in the appliance build type (lifts FLAG_SECURE + DO screen-capture block)
- `DISALLOW_INSTALL_APPS` / `DISALLOW_UNINSTALL_APPS` removed from the kiosk restriction set
- The 235-line `overrides:` appliance stripping is fully disabled (`DEBUG48`)
- OTA is test-key signed and the recovery does not trust it ("install anyway")
- Verity is off (`--flags 3`); bootloader unlocked
- `BoardConfigVault.mk` is orphaned (never included) — the board-level hardening is not applied

## 0.5 Tier 0 — coherent and safe baseline (from the 2026-09-04 audit)

Added after an independent audit of the PIN chunk. Chunk 2 is paused until the open items
below are closed and re-audited.

| Finding | Status (2026-09-04) |
|---|---|
| Wipe-after-10 could fail open (erase error swallowed, PIN cleared anyway) | ✅ fixed: `secureErase()` verifies seed + alias are gone; `VaultPin` keeps the PIN and returns `ERASE_FAILED` (vault "SEALED", no further guesses, only the erase retries); attempt counter committed *before* comparison. Unit-tested. |
| Auto-lock defeated by late-finishing load/regeneration | ✅ fixed: session token captured by every crypto task, checked on the UI thread before credentials are published. |
| Seed-reconstructing material retained after lock | ✅ fixed: `SourceReport` is status-only; contributions, health sample, digest, entropy and BIP39 seed zeroed. |
| Dev appliance persistently screenshots the recovery phrase | ✅ contained: dump code moved to `src/debug/java/DevTools.java` (shared by the appliance build type), release compiles a no-op stub — release APK verified to contain zero dump strings. Manifest `dev.phonevault.variant` marker; `verify-signer-apk.sh` refuses anything but `release` (tested: appliance rejected, test-signed release passes). The **dev appliance still dumps the phrase by design** — never load funds on a dev build. |
| Regeneration showed a stale QR / overwrote before backup | ✅ fixed: two-phase (prepare → show NEW phrase → Activate/Cancel/timeout/lock) and address + QR render atomically. Verified on device. |
| Lock file / verification metadata missing zxing | ✅ regenerated and checked in; workspace APKs rebuilt from current source; installed APK hash == workspace appliance APK. |
| APT never executed (64-byte samples vs 512 window) | ✅ fixed: 1024-byte health sample per source; new test proves a collapsed source fails APT. Claims downgraded in `entropy-design.md`. |
| Transport leaked descriptor/executor on error | ✅ fixed: single-shot `fail()` releases resources, listener told once. |
| `longValueExact` (API 31) on minSdk 28 | ✅ replaced with a range check. |
| No `dataExtractionRules` | ✅ added: cloud backup and device transfer fully excluded. |
| Passphrase identity would change after restart | ✅ contained: passphrase parameter removed from storage APIs until a persisted flag exists. |
| **Re-audit round 2 (2026-09-04):** PIN verify/save could unlock a stopped activity | ✅ fixed: `lock()` invalidates the session even when already locked; `onStop` clears `foreground`; PIN callbacks carry the gate's token and `unlock(s)` refuses stale/hidden. `onResume` re-creates the gate. Reproduced on device (6th digit + immediate sleep → "pin result discarded: stale session", back to LOCKED). |
| Round 2: replacement committed before session check; pending flag cleared before publish | ✅ fixed: commit + credential publish + flag clear are one step under `stateLock`, which `lock()` also takes to bump the session; the seed timeout is cancelled once Activate is pressed. |
| Round 2: failed attempt-counter reset still reported OK | ✅ fixed: reset commit must succeed or `verify` throws; failure-injection test added. |
| Round 2: backup reveal crossed unlock sessions | ✅ fixed: reveal captures the session token. |
| Round 2: replacement ownership racy (shared Boolean) | ✅ fixed: `replacementOp` token; only the owning flow can release the flag. |
| Round 2: "no seed material after lock" too strong | ✅ reworded (drops references; String mnemonic / BigInteger key are GC-managed); decrypted mnemonic bytes and jitter intermediates now zeroed. |
| Round 2: transport release untested | ✅ `AccessoryTransportLifecycleTest` (4 tests) via a stream-based test seam. |
| Round 2: appliance hash differs across build hosts | ⚠️ **payload-equivalent, not byte-reproducible.** `classes.dex`, `resources.arsc`, `AndroidManifest.xml` and all extracted entries are identical between hosts and the auditor's rebuild even used the same certificate, yet the archives differ from byte 285 (ZIP/packaging encoding, before the signature block). Byte-reproducibility needs a pinned build container + deterministic packaging (chunk 5); until then verify by entry digests, not APK hash. |
| **Re-audit round 3 (2026-09-04):** Cancel after Activate could still replace the wallet | ✅ fixed: explicit replacement state machine under `stateLock` (IDLE → PREPARING → PREPARED → COMMITTING → IDLE). Activate = the single PREPARED→COMMITTING transition; it disables both buttons and removes the timeout; Cancel/timeout are refused once COMMITTING; `lock()`/`deactivate()` reset the state under the same lock. Device: cancel kept `0x775d…`, activate → `0x7097…`, persisted. |
| Round 3: USB could connect during replacement | ✅ fixed: attach is parked while the state is not IDLE (replayed after completion/cancel); the commit re-validates `transport == null && !requestPending` inside the locked step. |
| Round 3: transport callbacks before publication | ✅ fixed: `open()` returns an inactive session; MainActivity publishes then calls `start()`; a throwing `onConnected` or construction failure ends the session cleanly. Tests: nothing fires before start, hostile listener. |
| Round 3: deactivate outside the session lock | ✅ fixed: `deactivate()` bumps the session, clears creds/replacement state under `stateLock`; `loadKey` publish also requires `operational`. |
| Round 3: reproducibility wording | ✅ corrected (payload-equivalent, not byte-reproducible; see row above). |
| Round 3: secret buffers (encrypt input, failed draws, PIN keypad) | ✅ zeroed: encryption input bytes in `finally`; `first` draw zeroed unless handed off; keypad uses a fixed `char[]` that is zeroed on reset/submit. |
| Round 3: release lacked `DISALLOW_INSTALL_APPS`/`DISALLOW_UNINSTALL_APPS`; flag didn't exist | ✅ `VAULT_ALLOW_APP_UPDATES` buildConfig added (debug/appliance true, release false) and the two restrictions are applied when false. |
| Round 3: host verifier trusted `transactionHash` and `address` | ✅ `tools/evm_verify.py` (pure-Python Keccak-256, RLP, secp256k1 recovery — no new dependency): `validate_response` recomputes the hash from the signed bytes and recovers the signer, comparing to the claimed address and an optional `expected_signer`. The existing fixture is a real phone signature (recovers to `0x5d57…` at parity 0). Tests: 9 crypto vectors + 4 tamper cases; `test-usb-client-policy.sh` now runs both and greps for the checks. |
| Round 3: threat model / product notes stale | ✅ "Known limitations" and product-notes §1 rewritten for the seed + PIN implementation. |
| **Re-audit round 4 (2026-09-04):** failed wallet commit left the identity indeterminate | ✅ fixed: the wallet is ONE self-checking record (`WalletRecord`: magic + iv + ciphertext + SHA-256) in ONE file written via `AtomicFile` (temp → fsync → rename), read back from disk and byte-compared; a `wallet_write_pending` journal flag is committed BEFORE the write and cleared only after read-back. `loadOrCreate()` refuses to mint a wallet while the journal is pending. On `PersistenceException` the activity drops the OLD runtime key too and locks; the next unlock reconciles from disk. Legacy two-key prefs are migrated on first load (device-verified: address unchanged, legacy keys removed, `PVW3` file present, journal clear). `WalletRecordTest`: every single-bit flip, truncation and trailing byte rejected. |
| Round 4: parked USB replayed only after success | ✅ fixed: `hideBackup()` is the single terminal path (cancel / timeout / success) and drains the parked intent; prepare/commit failure paths drain too; a locked vault keeps it for the next unlock. |
| Round 4: signing not bound to the unlock session | ✅ fixed: approval captures the session token; check → sign → send run as ONE step under `stateLock`; `lock()`/`deactivate()` now close the transport INSIDE the same lock, so the outcome is linearized (signed-and-sent before the lock, or nothing computed after it). |
| Round 4: host `--expect-address` optional | ✅ fixed: a signature is refused without a pinned signer. New `pair` command fetches the address, tells the user to compare it with the phone's own display, and pins it (0600 file in `~/.config/phone-vault/`); `sign-test` loads it (or an explicit override). Tests: unpinned refused, invalid refused, pairing file round-trip. |
| Round 4: vulnerable / unnecessary crypto packaged | ✅ contained: blanket `-keep class org.web3j.**` removed — release DEX has no PQC, no Jackson, no WalletFile (policy test greps the DEX); Bouncy Castle pinned forward to 1.85.2 (on the signing path; unit tests pass against it). Jackson stays in the *graph* at 2.17.1 (unpackaged); web3j 6.x is a separate migration. |
| Round 4: replacement state machine untested; `Generation` kept `Credentials`; `VaultPin.set` zeroing; stale roadmap rows | ✅ `ReplacementState` extracted + 6 tests (cancel-after-activate refused, stale tokens inert, reset); `Generation` no longer holds a key; `set()` zeroes on every path; rows corrected. |
| Round 4 (found by me): dev screenshot hook dropped taps | ✅ the on-UI-thread PNG encode after every touch starved input dispatch in fast keypad bursts; dumps are now coalesced and encoded off-thread. Dev-only code; not in release. |
| Round 2: real StrongBox erase unproven | ✅ **proven on hardware 2026-09-04** (user-approved): 10 wrong PINs on the throwaway wallet → log `wallet erased after 10 failed PIN attempts` → SET PIN screen. `wallet.pvw3` gone, preferences hold no PIN/seed/journal keys, and the SET PIN screen itself proves `secureErase()` verified the StrongBox alias was deleted (the PIN is only cleared after a verified erase; otherwise the vault seals). |
| Repository has no commits | ✅ repo initialised inside `phone-vault/`, first commit pushed to github.com/QuantumDesk/phonevault (private); `.gitignore` excludes build output, `downloads/`, `reference/`, `.venv`, all key material (dev AVB private key), pairing file, dumps. Apache-2.0 `LICENSE` + `NOTICE` (GPL-2.0 boundary for kernel patches). |
| Device PIN disclosed in test report | ✅ retired by the erase above; the phone sits at SET PIN for the owner to choose a private PIN. (Scripted tests will need that PIN; keep it out of any report.) |
| OS overlay fails its owner-provisioning gate; early ADB in `common.mk` | ⏳ part of the re-hardening ladder (chunk 4). |
| Host verifier doesn't recompute hash / recover signer | ✅ closed in round 3 (see below); round 4 makes the pinned signer mandatory. |
| source-init syncs a moving branch; unpinned container | ⏳ open (release-trust chunk). |
| Threat model / product notes describe the pre-seed, pre-PIN implementation | ✅ closed in round 3. |
| Dependency advisories (Jackson, Bouncy Castle via web3j) | ⏳ open: not on the signing path; bump web3j / narrow keep rules. |

## 1. Tier 1 — A *usable* signer (functional gaps)

Ordered by impact. Each is app-layer work on the fast loop unless noted.

1. **PIN / unlock + auto-lock + wipe-after-N.** ✅ v1 shipped 2026-09-04 (`VaultPin`,
   `PinScreen`): salted PBKDF2 PIN, persistent attempt counter, `secureErase()` (ciphertext +
   StrongBox alias) at 10 failures, lock on screen-off and 2-min idle, seed view auto-hides at
   60 s, USB attach queued behind the gate and the AOA session closed on lock. Rationale:
   because the keyguard is disabled for boot-into-app, the StrongBox key's
   `setUnlockedDeviceRequired` no longer gates anything — the in-app PIN is the real gate.
   Still open: **v2** derive an additional wrap layer from the PIN so a rooted attacker holding
   the StrongBox key still needs the PIN; change-PIN screen; exercise the wipe path in tests.
2. **Restore from seed.** We can only generate. Import an existing 24-word phrase
   (`SeedVault.deriveEvm` exists; needs UI + BIP39 checksum feedback).
3. **Backup verification.** After showing the phrase, require re-entry of N random words.
4. **Air-gap QR signing (outbound first).** Display signed tx / address as animated BC-UR
   (EIP-4527). Cheap, no new attack surface, lets *nothing* leave over USB. Inbound (camera)
   is a separate gated variant — see §5.
5. **Message + typed-data signing.** `personal_sign` and EIP-712 with domain display (dApp
   logins, Permit). Same approval discipline as transactions.
6. **Multiple accounts** (m/44'/60'/0'/0/x switcher) and **passphrase (25th word)** UI —
   engine supports both.
7. **Clear-signing via offline ABI database.** Ship decoders for the top contracts (USDC,
   Uniswap, Safe…) so approvals read "Approve unlimited USDC to Uniswap Router". This is the
   headline advantage of a 6-inch screen over a dongle and directly attacks blind signing.
8. **Address book + address-poisoning defense.** Saved destinations ("→ Coinbase (saved)")
   and a loud warning when a destination *resembles* a known one but differs.
9. **First-run wizard** (inside the kiosk boundary): create-or-restore → entropy (optional
   dice/typed) → phrase → verify → optional passphrase → PIN. Persistent mode default,
   stateless mode offered (per product notes §1).

## 2. Tier 2 — *Trustworthy* with real funds (release gates)

None of these are optional for a release; several are hard rules.

1. **Re-hardening ladder.** Re-introduce the appliance stripping in boot-tested chunks
   (apps → media/camera → telephony/radio with a *correct* system_server gating patch for the
   netd-class removals → mainline APEXes → curated vendor prune). Each chunk: build, sideload,
   boot, gate.
2. **Wire `BoardConfigVault.mk`** properly (VINTF manifest/matrix, kernel config fragment,
   AVB key) — today's build silently ignores it.
3. **Signed OTA + trusted recovery.** Sign updates with a release key the recovery trusts;
   rollback protection. Removes the "install anyway" prompt and closes an unsigned-update hole.
4. **Verified boot + relock, demonstrated.** Custom AVB key, `--flags 0`, relock the
   bootloader, prove the device refuses an unsigned image.
5. **Offline enforcement.** No radios at the OS/kernel level, not just DO restrictions.
6. **USB data-lock.** Charge-only by default; the AOA data function is enabled only while an
   explicit signing session is active. Defeats charger/juice-jacking exposure.
7. **Titan M as an independent entropy source** (`entropy-design.md` R2) + the R7
   diagnostics screen.
8. **Secure erase.** Wipe the seed *and* the StrongBox wrapping alias, with confirmation.
9. **Key attestation.** Prove keys live in the SE; expose an attestation a companion can verify
   ("genuine, unrooted vault") — the phone-only trust feature.
10. **Reproducible builds + published digests.** Anyone can rebuild and match the running image;
    pairs with the release manifest tooling that already exists.
11. **Duress / decoy** (optional decoy wallet, passphrase-hidden wallets — plausible deniability).
12. **Tamper-evident boot image.** User-chosen phrase/image shown at every boot; its absence
    means the device was swapped or tampered (evil-maid defense).

## 3. Tier 3 — *Adoptable* (interop, ecosystem)

1. **Host-wallet interop.** Keystone-style BC-UR account import + signing so MetaMask / Rabby
   / Safe drive the vault as a signer. This is the answer to "how do we get MetaMask to support
   us" — speak the transport they already speak.
2. **Watch-only export (xpub).** Balances on a normal phone/desktop without touching the vault.
3. **Multisig (Safe) co-signer flow.** The serious-holder use case.
4. **Companion app** (the online half) and **phonevault.org** (docs, verifier, release digests).
5. **Signing history / audit log** (offline, local): hashes, timestamps, outcomes.
6. **Integrity dashboard**: entropy health (R7), StrongBox state, verified-boot state, app
   signature, battery — "is my device okay?"
7. **Passkeys (FIDO2/WebAuthn)** — phase 2, strong fit for StrongBox (product notes §3).
8. **Shamir backup (SLIP-39)** and **SeedQR** backup/restore.

## 4. Lifecycle & physical realities (easy to forget, expensive to ignore)

- **OLED burn-in.** A kiosk shows the same screen forever; the Pixel 3 XL OLED *will* burn in
  within months. Idle screen-off/dim + subtle periodic pixel-shift of static elements. Should
  be in the first real release. (Mono theme helps, does not solve.)
- **Dead-battery safety.** Old batteries fail mid-use: seed writes must be atomic; boot with a
  near-dead battery must be graceful; charging must not enable USB data (see USB data-lock).
- **Update UX.** Check, verify signature, apply, rollback-protect — for both OS and app.
- **Hardware target.** crosshatch validates design + tooling; a currently supported Pixel is
  the real product target (product notes §5).

## 5. Open design decisions (decide deliberately, record in `threat-model.md`)

1. **Camera-in (inbound QR).** The camera stack (closed camx/chi HAL, ISP firmware,
   cameraserver, kernel drivers) is one of the largest opaque blobs on the SoC, so "QR in" is
   *not* obviously safer than the small open USB gadget path. Position: outbound QR in the
   hardened default; inbound QR only as a **separate gated build variant** with a measured
   camera-exposure review. It would also unlock SeedQR entry for stateless mode.
2. **Stateless vs persistent.** Persistent by default (founder decision); stateless as an
   option — an app-level mode, not an OS mode.
3. **Licensing.** Apache-2.0 base + GPL kernel patches ⇒ open-core: everything inside the trust
   boundary open + reproducible; companion/services may stay proprietary. Pick the license.
4. **Kiosk vs device keyguard.** Keyguard is disabled for boot-into-app; the in-app PIN is the
   gate. Revisit whether a re-enabled keyguard adds defense-in-depth once PIN exists.

## 6. Proposed build order (next five chunks)

1. **Device security & lifecycle chunk** — ✅ done 2026-09-04: PIN/unlock, attempt-limit wipe,
   auto-lock, seed-view timeout, idle screen-off (DO `SCREEN_OFF_TIMEOUT`=60 s) + 1 dp
   pixel-shift, app-layer USB data-lock. OS-level gadget lock stays in chunk 4.
2. **Wallet completeness chunk** — restore-from-seed, backup verification, multiple accounts,
   passphrase UI, first-run wizard.
3. **Outbound QR chunk** — BC-UR animated QR for address + signed payloads; message/EIP-712
   signing with the same approval discipline.
4. **Re-hardening ladder** — chunked, boot-tested; wire `BoardConfigVault.mk`; USB data-lock at
   the OS layer; offline enforcement.
5. **Release-trust chunk** — signed OTA + trusted recovery, custom AVB key, verified boot,
   **relock demonstration**, reproducible-build digests. Only after this does anything get
   called production-safe.

Positioning note (2026-09-04, Trezor/ShipMonk breach: 67k more customers' names, phones, home
addresses leaked; Ledger 2020: 270k): the leak is of the *act of buying* a hardware wallet.
Phone Vault has no vendor, no order, no shipment, no customer list — "no box to ship, no list
to leak." A real, defensible advantage; keep it true (no registration, no telemetry, no
mandatory accounts).
