# Phone Vault 0.3.0 — UI, security interactions, and cachy handoff

Date: 2026-09-05. Based on `1483fbec13ce8d9666eacaaada546f80a112bc7a`.
Status: implemented and built locally; physical phone verification pending.

## What changed

The native Android app now has Wallet, Security, and Coming next navigation, a dark/mint visual
system with the pixel wordmark, readable body text, scrollable pages, proper button roles and
pressed/disabled states, 56 dp standard controls, and a matching app icon.

Working controls: Lock now; persistent standard/large text; 30/60/120-second idle lock; local
device/build/charge information; fresh-PIN backup access; four-word recovery pages; a randomized
24-position backup check; and guarded wallet replacement. The PIN screen always shows remaining
attempts and the erase policy, with explicit submission on the final attempt. Screen off still
locks immediately and the appliance screen-off policy stays at 60 seconds.

Receiving and USB signing require successful identity loading and a completed backup check bound
to that account. An existing wallet upgrades without changing its seed or PIN, but must complete
the new check once because it has no stored check record. Initial creation still uses the existing
generator; a complete create-or-restore wizard is not implemented.

Backup reveal/check and replacement require a fresh PIN. These flows exclude USB and use
full-screen pages with session ownership, not surviving confirmation dialogs. All 24 positions
are checked in random order using six dictionary choices per position; this is a recognition
check, not an independent restore drill. A wrong answer fails the current check. Replacement
requires the current account's prior backup check and a full check of the new candidate before
Activate can be reached. Cancel/timeout keeps the current wallet.

Recovery words hide after 60 seconds without interaction, with a visible countdown and a five
minute session cap. A normal wallet can be reopened with the same words after reauthentication.
An unactivated replacement is discarded on timeout/lock; discard its partial NEW backup and
retain the current wallet's backup. Managed-memory erasure is not claimed.

Approval is full-screen, with critical action/amount/party/network/account information before
expandable technical fields. An `ApprovalDecision` permits only one decision: Reject wins while
reviewing, or Sign becomes irreversible and disables Reject. Lock still cancels queued work.
Receipts distinguish a created/queued signature from confirmed delivery, broadcast, or settlement.

Chain IDs are now restricted to reviewed profiles: 1, 11155111, 8453, 10, 42161, 137. Fees are
labelled as execution-gas bounds, with additional-fee limitations explained for applicable chains.
Token calldata remains deliberately narrow and unverified; no authenticated token metadata was
added. This UI must not be described as full clear signing for arbitrary dapps.

## Planned feature pages

Restore, PIN change/derived wrapping, accounts, passphrases, desktop companion, browser wallets,
typed-data signing, verified token details, signed updates, advanced recovery, and passkeys are
informational pages. Each says it is planned and changes no wallet setting. No dummy toggle or
fake successful operation is exposed.

Device information reports local observations and limitations. It does not claim attestation,
verified relock, measured battery health, or that EVM signing occurs in StrongBox.

## Verification completed on the Mac

- 83 JVM tests in each of debug and release, 11 suites per variant. The variants run the same
  scenarios, not 166 unique tests. New coverage includes competing Sign/Reject decisions,
  cancellation of queued signing, stale sensitive-flow tokens, full backup-position coverage,
  persistence failure, account binding, and chain/fee rules.
- 26 host tests and the host policy suite passed.
- Release lint: no errors, 13 warnings (down from 45 before this sweep). Remaining warnings
  include existing platform/orientation and localization/accessibility-lint issues.
- Appliance and unsigned release APKs built successfully with offline dependency resolution.
- App build policy, including forbidden release DEX content, and owner provisioning policy with
  negative fixtures passed. `bash -n` on the modified device harness passed.
- Appliance APK v2 signature verifies. This is the Mac's development signer, not a release key.

Local artifact SHA-256:

```text
app/build/outputs/apk/appliance/app-appliance.apk
f3aa927f8d064aeb1ab5cc212e34d3190eac1e3a479fdaaa683b471f29575834

app/build/outputs/apk/release/app-release-unsigned.apk
c8bbf69d9ea06e93babe7fce760a2888f2e386cdd13825309f6bcfa611744a64
```

The appliance version is `0.3.0-dev-appliance`, versionCode 3. Its certificate SHA-256 is
`d8eab12db9f77634d1663d66df9928c184a2c91df03e3ea78abcddd64f114b53`.
A rebuild/sign on cachy may produce a different archive hash; record its own provenance.

## Cachy integration and installation

No remote credentials are required to prepare this change. No SSH connection, flash, erase,
uninstall, signing-key change, git commit, or push was performed in this pass.

The Mac handoff patch is generated at `app/build/outputs/phonevault-ui-0.3.0.patch`. It includes
the source/tests, these notes, and the earlier uncommitted companion/audit documents so the
documentation links remain coherent. Transfer that patch to cachy, inspect the remote worktree,
and run `git apply --check` there before applying. The baseline is recorded above. Reconcile any
concurrent app edits instead of force-applying or overwriting the other agent's work.

Build on cachy with its existing JDK/SDK and development keystore:

```sh
gradle --offline :app:testDebugUnitTest :app:testReleaseUnitTest :app:assembleAppliance :app:assembleRelease :app:lintRelease
bash vault-os/tests/test-usb-client-policy.sh
bash vault-os/tests/test-app-build-policy.sh
bash vault-os/tests/test-owner-provisioning-policy.sh
```

If offline dependencies are unavailable, use the established verified dependency provisioning;
do not regenerate or weaken lockfiles/checksum verification to make a build pass.

An ordinary app update is sufficient; no OS OTA or userdata wipe is needed for this UI change.
Use the existing cachy signing identity so `adb install -r` can update the installed app. If Android
reports a signing mismatch, stop and rebuild with the matching development key. Do not uninstall
or erase to work around it. The Mac APK is an inspectable artifact, not a promise of install
compatibility with the phone's existing signer.

Use a direct `adb install -r app/build/outputs/apk/appliance/app-appliance.apk` after checking
the target and signer. Avoid the legacy `deploy.sh` for this pass: it also rewrites provisioning
settings and requests downgrade allowance, neither of which this UI update requires.

## Required phone acceptance pass

Run on the development phone with test assets only. The user enters the PIN on the phone. Keep
PINs and recovery words out of logs, screenshots, patches, and chat messages.

1. Install as an update, confirm version/installed hash and kiosk ownership. Existing seed and PIN
   must survive. Unlock should show the backup gate, not a stale QR. Loading failure must show an
   unavailable screen with no address.
2. Open Security, preferences, information, and every planned feature page. Test standard and
   large text, scrolling, long labels, touch feedback, and Back/Lock. Capture only non-sensitive
   screens for visual review; confirm no labels, buttons, or significant address digits clip.
3. View/check the backup using fresh on-phone PIN authentication. Check all 24 positions and
   confirm the account. Check mismatch/restart/cancel behavior. After successful completion,
   address and QR must identify the same account and persist after relock/reboot.
4. With a confirmation/reauth/phrase/check/replacement page active, sleep or lock. The old action
   must not survive or publish into a later session. Partial PIN input must be cleared.
5. Attach USB while locked, loading, backup-unverified, reauthenticating, showing words, checking
   words, and replacing. No signing dialog may cover a sensitive screen. Once ready, pair with the
   Python client and verify a disposable Sepolia signing round-trip.
6. Exercise Reject, double Sign, Sign then attempted Reject, disconnect, and lock. Each approval
   owns one result; no rejected request may later yield a signature. Check honest delivery status
   and a subsequent request after every outcome.
7. On a throwaway wallet only, check replacement: cancel keeps the current address; activation
   requires a new full backup check; successful activation updates address and QR together and
   survives reboot. Exercise timeout and lock before activation; discard partial candidate notes.
8. Verify 30/60/120-second app idle settings, immediate screen-off lock, backup inactivity
   countdown, and session cap. Deliberate last-attempt/wipe tests require separate explicit
   authorization for the target throwaway wallet; they are not part of this install instruction.

The old `tools/dev-device` coordinate harness is fenced to 0.2.0. Do not bypass that fence:
keypad locations and the post-unlock/backup/replacement paths changed. Port the harness using
live UI bounds and these new states before automating PIN entry. The development dump now
skips sensitive flows; it is intentionally unsuitable for extracting backup answers.

## Remaining audit work

F01/F03/F04/F05/F10/F11 have app changes in this build; F07/F08/F09 have UI improvements.
F02 is partially addressed by mandatory backup gating; restore and the complete wizard remain.
F06 (trusted token semantics), PIN-derived wrapping/change, production hardware, OS hardening,
release chain/relock, external attestation, and independent security/physical review remain open.
No finding is declared phone-verified by this handoff. Update the roadmap only after recording
the resulting build and actual device evidence.
