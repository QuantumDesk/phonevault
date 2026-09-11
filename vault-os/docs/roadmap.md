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

**Flashed-device state vs. checked-in source.** This section is superseded by the re-hardening
ladder (`vault-os/dev-ladder/README.md`), which is the authoritative record of what the phone
runs. As of 2026-09-05 the device is on **rung 2c**: automatic owner provisioning, wired
`BoardConfigVault.mk`, verity/hashtree **enforcing** under our AVB key (`ro.boot.veritymode=
enforcing`), and the appliance VINTF manifest are all live and boot-tested. The remaining debug
state below is what the LATER rungs still remove; each line notes its rung.

**Debug-only state that MUST be reverted for any release** (tracked so it can't be forgotten):

- `WITH_ADB_INSECURE=true`, `PRODUCT_ADB_KEYS` (pre-authorized host key), `ro.adb.secure=0` — **still present** (rung 5, user build)
- `VAULT_ALLOW_SCREENSHOTS=true` in the appliance build type (lifts FLAG_SECURE + DO screen-capture block) — **still present** (rung 5)
- `DISALLOW_INSTALL_APPS` / `DISALLOW_UNINSTALL_APPS` removed from the kiosk restriction set — **still present in dev** (release build re-adds them via `VAULT_ALLOW_APP_UPDATES=false`)
- The 235-line `overrides:` appliance stripping is disabled — **partially reverted**: `LineageSetupWizard` restored at rung 1b; the rest is rung 4 (in slices)
- OTA is test-key signed and the recovery does not trust it ("install anyway") — **still present** (chunk 5, signed OTA + trusted recovery)
- Verity — ✅ **now enforcing** under our key (rung 2b); bootloader still **unlocked** (relock is chunk 5)
- `BoardConfigVault.mk` — ✅ **now wired** (rung 2a): AVB key + board-info + VINTF (rung 2c); kernel fragment is rung 2d, USB peripheral-lock is rung 3

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
| **Found on hardware 2026-09-10:** the transport read the accessory node byte-by-byte; `f_accessory` returns one USB packet per `read()` and discards the unrequested remainder, so every host request lost all but its first byte ("USB connected · waiting for a request" forever). Present since the initial import; unit tests use in-memory streams and could not see it. | ✅ fixed (`ae39175`): the transport buffers the accessory input (16 KiB ≥ the gadget bulk buffer) inside the constructor so the seam-tested path is the real path; regression test feeds packet-sized reads through a fake that fails on any single-byte read. Device: `pair` returns the on-screen address; a mainnet-shaped 0.5 ETH transfer was reviewed and approved on the phone and the host verified hash + recovered signer against the pinned pairing. |
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
| **Re-audit round 5 (2026-09-04):** blocking USB write under `stateLock` let a non-reading host stall `lock()` | ✅ fixed: `AccessoryTransport.send()` only enqueues into a bounded queue (4) drained by a single writer thread; a full queue fails the session; `close()` is non-blocking (flag, descriptor close, interrupt). Tests: send < 200 ms and close < 500 ms with a stuck `OutputStream`; overflow ends the session. |
| Round 5: legacy cleanup / journal clearing ignored `commit()`; legacy wallet could resurrect | ✅ fixed: `WalletPersistence` (pure Java, fault-injected) settles the identity with ONE atomic flag commit (remove legacy keys, clear journal, set permanent `wallet_v3_established`) whose result AND read-back are checked; failure keeps the journal and the write is reported as uncertain. Once established, a missing record is *sealed* — never legacy fallback, never a fresh wallet — until a verified erase. 11 fault-injection tests (write/torn/read/commit faults, restart reconciliation, migration, erase). |
| Round 5: pairing file permissions | ✅ fixed: O_EXCL/O_NOFOLLOW temp + fchmod 0600 + fsync + atomic replace; load rejects symlinks, non-regular files, foreign owner, group/world bits (tested, including a pre-existing 0666 file). |
| Round 5: device harness unsafe | ✅ rewritten on `lib.sh`: `PV_THROWAWAY_DEVICE=1` required, dev-appliance variant + expected screen asserted before any tap, PIN from `PV_TEST_PIN`/silent prompt (never logged; wrong PIN derived from it), `set -euo pipefail`, every outcome asserted, `--write-locks` removed from deploy. |
| Round 5: docs | ✅ README rewritten (status, pair step, payload-equivalence, build prerequisites); OFL text + copyright shipped with the font; dependency row corrected. |
| Round 2: real StrongBox erase unproven | ✅ **proven on hardware 2026-09-04** (user-approved): 10 wrong PINs on the throwaway wallet → log `wallet erased after 10 failed PIN attempts` → SET PIN screen. `wallet.pvw3` gone, preferences hold no PIN/seed/journal keys, and the SET PIN screen itself proves `secureErase()` verified the StrongBox alias was deleted (the PIN is only cleared after a verified erase; otherwise the vault seals). |
| Repository has no commits | ✅ repo initialised inside `phone-vault/`, first commit pushed to github.com/QuantumDesk/phonevault (private); `.gitignore` excludes build output, `downloads/`, `reference/`, `.venv`, all key material (dev AVB private key), pairing file, dumps. Apache-2.0 `LICENSE` + `NOTICE` (GPL-2.0 boundary for kernel patches). |
| Device PIN disclosed in test report | ✅ retired by the erase above; the phone sits at SET PIN for the owner to choose a private PIN. (Scripted tests will need that PIN; keep it out of any report.) |
| OS overlay fails its owner-provisioning gate; early ADB in `common.mk` | ⏳ part of the re-hardening ladder (chunk 4). |
| Host verifier doesn't recompute hash / recover signer | ✅ closed in round 3 (see below); round 4 makes the pinned signer mandatory. |
| source-init syncs a moving branch; unpinned container | ⏳ open (release-trust chunk). |
| Threat model / product notes describe the pre-seed, pre-PIN implementation | ✅ closed in round 3. |
| Dependency advisories (Jackson, Bouncy Castle via web3j) | ✅ round 4: BC pinned to 1.85.2, blanket keep rule removed, Jackson/PQC absent from the release DEX (policy-tested). Jackson stays in the graph at 2.17.1 (unpackaged); web3j 6.x migration is a separate item. |

## 0.6 Chunk 4 — re-hardening ladder (in progress, 2026-09-04)

Tracked rung by rung in `vault-os/dev-ladder/README.md` (rung log + per-rung checklist). Order
agreed with the auditor: (1) automatic owner provisioning, (2) wire `BoardConfigVault.mk`,
(3) OS-level USB data-lock + peripheral-only enforcement, (4) package/service/HAL/kernel
stripping in small slices, (5) a `user` build with no ADB, dump hook, debug keys or update
exceptions. Every rung: policy gates → build → sideload → boot → owner/kiosk → PIN lifecycle →
persisted identity → USB signing, with the 2026-09-02 image kept as rollback.

## 0.7 UX review (2026-09-04) — what "product-ready" means for the app chunk after the ladder

Keep the visual language (high-contrast appliance identity, simple locked/home/recovery/approval
states, prominent address + QR, review discipline, attempt feedback, two-phase regeneration).
The gap is **onboarding**: a real user must never reach Home with an unverified backup.

**One enforced first-run flow:** `Set PIN → Create or Restore → Show phrase → Verify random
words → Confirm address → Home`. Receiving and signing are blocked until backup verification
completes.

Must-haves before real users (in this order, after OS rungs 1–5):

1. Restore from seed.
2. Mandatory backup verification (random-word re-entry; a full ordered confirmation or a
   restore-and-address-match drill for real funds).
3. PIN-derived storage wrapping and Change PIN.
4. MetaMask-compatible transport (see §3 item 1: exact Keystone/EIP-4527 UR flows, which need
   an inbound path or a host bridge — outbound QR alone is insufficient) plus watch-only/xpub
   export, which it depends on.
5. `personal_sign` and EIP-712 for dApp authentication.
6. An integrity screen: release signature, verified-boot state, StrongBox, OS version, battery
   condition.

UI changes queued with that chunk: move **Regenerate wallet** out of Home into an
advanced/settings area; approvals show action, amount, recipient, network and maximum fee first
with raw technical details collapsed below; raise the 7 sp pixel labels (accessibility); mark
the receive address as network-agnostic and warn to verify the destination chain; show the
wipe policy on every PIN screen, not only on creation. (0.3.0 addressed most of these.)

For the eventual **release** UI (audit note 2026-09-08): move **Coming next** out of primary
navigation — keep it during development, but the shipped device should center working actions,
not a menu of planned features.

**Restore-from-seed status (2026-09-09):** the validated import core is in and tested against
external reference vectors (`SeedRestore` + `SeedRestoreTest`: the canonical 12-word phrase
derives the world-published `0x9858…eda94`, proving BIP39/BIP44 correctness independently, not
against itself). Storage reuses the journaled commit path (`VaultKeyStore.restore`).

The **first-run wizard** now exists in the app (built, unit-tested, not yet exercised on the
phone): after Set PIN, an empty vault no longer silently mints a wallet — `loadKey()` branches
on `hasWallet()` to a **Create or Restore** choice. Create: generate → fresh-PIN confirm →
phrase pages → 3-word spot check → confirm address → Home. Restore: an on-device a–z keyboard
(no system IME, so it survives rung-4 stripping) with BIP39 autocomplete fills 24 slots →
count/wordlist/checksum validation → the derived address is shown for confirmation *before*
anything is saved → journaled commit → Home with the backup marked verified-by-entry. Typed
words are wiped on lock.

**Drill proven on the Pixel 3 XL, 2026-09-11** (throwaway wallet, driven over adb with the
`pvlib.sh` text/bounds helpers on cachy): create → phrase → 3-of-3 spot check → address confirm
→ Home → USB pair (address matches the screen) → mainnet-shaped 0.5 ETH transfer reviewed and
approved on the phone, host verified hash + recovered signer → wipe-after-10 erase → SET PIN →
Create-or-Restore → 24 words typed on the on-device keyboard → "Is this your wallet?" showed the
ORIGINAL address → restore → Home → `adb reboot` → kiosk still LOCKED, unlock shows the same
address → sign again: identical transaction hash (deterministic signing with the same key).
Two device-only bugs found and fixed on the way: the accessory packet-read bug (`ae39175`,
§0.5) and invisible keyboard letters (`cc4dab5`). **Restore over an existing wallet** landed
2026-09-11 (`b34b8bd`): Security → Restore a different wallet → fresh PIN → the same entry
screens, owned by the replacement state machine (PREPARED at address confirm, COMMITTING at
"Yes, replace"), USB excluded, cancel keeps the current wallet. Drilled both ways on the phone
(throwaway → public `abandon…art` vector `0xf278…1cdb` → back) via the ported harness
(`tools/dev-device/restoretest.sh replace`).

Honesty note: signing is deliberately narrow (EIP-1559 transfers + canonical `transfer`/
`approve`). "MetaMask-compatible" and "generally usable with dApps" are future claims until
items 4–5 exist.

## 0.8 Feature, UX/UI, and security audit (2026-09-05)

The [audit report](feature-ux-security-audit-2026-09-05.md) reviews source at `1483fbe`,
records fresh JVM/host tests, and defines device acceptance tests. It is a source-based review;
no phone was connected to the audit host. Findings remain open until implemented and verified.

New priorities affecting the current app: make Reject/Sign a single terminal state transition;
bind all sensitive confirmations and secret access to their originating session; hide receiving
addresses/QRs until authoritative wallet loading succeeds; and prevent USB approvals during
seed viewing. Correct the total-fee promise on chains with additional fee components and distinguish
queued signatures from delivered responses.

The report also carries forward the recovery/onboarding and PIN-wrapping blockers, measures the
small-label contrast gap, and specifies an approval/recovery redesign. Broader product claims
require a maintained hardware target, an explicit software-signing threat model, completed
relock/release evidence, and independent review. See its feature matrix and delivery sequence
before expanding the companion, message signing, or advanced wallet features.

## 1. Tier 1 — A *usable* signer (functional gaps)

**0.3.0 source update (2026-09-05; not yet phone-verified):** the
[UI handoff](ui-0.3.0-handoff.md) records the implemented app sweep, full 24-word backup gate,
fresh PIN for sensitive actions, approval-state fixes, honest fee coverage, and settings/feature
pages. Historical rows above still describe 0.2.0 hardware evidence. Planned feature pages are
informational; restore, PIN-derived wrapping/change, accounts, passphrases, and browser adapters
remain unimplemented. Audit findings are not considered hardware-closed by the local build.

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
4. **Companion app** (the online half): the cross-platform design, trust boundary, browser
   integration options, and delivery gates are tracked in
   [`companion-architecture.md`](companion-architecture.md). This is planning, not a shipped GUI.
   **phonevault.org** remains the home for docs, verifier, and release digests.
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
