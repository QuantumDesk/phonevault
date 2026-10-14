# Phone Vault — feature, UX/UI, and security audit

Date: 2026-09-05. Source baseline: `1483fbec13ce8d9666eacaaada546f80a112bc7a`.
Includes the existing uncommitted companion RFC and its README/roadmap links.

## Assessment and scope

Phone Vault has a useful foundation: strict transaction parsing, independent host verification,
pinned signer pairing, durable wallet storage, and a distinctive appliance interface. It is not
ready for real funds. Recovery and approval behavior remain release blockers, and the present
hardware and runtime architecture do not substantiate a claim of being the most secure hardware
wallet.

This is a source-based audit with fresh local tests and a review of upstream design references.
It is not a penetration test, certification, or hands-on visual sign-off. `adb devices -l`
returned no connected devices. No current application screenshots were available in the tracked
tree. Layout risks below are identified from Android view construction; clipping, dialog timing,
scannability, and physical input behavior require the device acceptance tests specified below.
Historical hardware results in the roadmap and rung log were read, not repeated.

No application behavior was changed during this audit. P1 means a release-blocking loss,
authorization, or recovery risk under the stated conditions; P2 means a substantial usability,
reliability, or product-trust gap. Existing acknowledged gaps are distinguished from new findings.

## Fresh verification

| Check | Result |
| --- | --- |
| Debug JVM tests | 71 passed, 8 suites |
| Release JVM tests | 71 passed, 8 suites; same scenarios, not 71 additional unique tests |
| Host verifier/client policy | 26 tests passed; policy script passed |
| Release Android lint | Completed: 45 warnings, no errors |
| Physical phone / new UI screenshots | Unavailable on this host |
| On-device first boot, wipe, relock, OTA | Not repeated in this audit |

Command: Gradle 8.10.2 with the local JDK/SDK, `--offline :app:testDebugUnitTest
:app:testReleaseUnitTest :app:lintRelease`, plus `bash vault-os/tests/test-usb-client-policy.sh`.
The build emitted an SDK XML tooling-version warning. Passing JVM tests do not cover Android
activity/dialog interaction: there is no checked-in `app/src/androidTest` suite. Existing device
scripts cover useful PIN/replacement paths, but not the new interleavings below.

## Findings

### F01 — P1: Reject can report cancellation after Sign without cancelling signing

**New; confirmed control-flow defect, device timing not reproduced.** In
[`MainActivity.showApproval`](../../../app/src/main/java/dev/phonevault/signer/MainActivity.java#L1037),
Sign disables itself and the checkbox, then queues a crypto task. Reject remains enabled. Its
callback sends `rejected` and clears `requestPending`, but does not invalidate the approval or
cancel the queued job. The signing task checks session/transport/identity, not a rejected state.

Interleaving: tap Sign; before the executor finishes, tap Reject. The host can receive a
rejection and a valid signature for the same request. It already received user authorization
via Sign, so this is not signing with no prior approval; the defect is promising revocation
when revocation did not occur. Clearing the shared pending flag also allows another request
while the first job still owns a terminal outcome.

**Required change:** one approval state machine with an atomic irreversible transition and one
terminal outcome. Reject must remain effective throughout review. Once signing becomes
irreversible, the UI must say so and stop offering successful cancellation. Bind pending-state
cleanup to the owning request, as the replacement flow already does.

**Acceptance:** hold the signing executor behind a latch; exercise Sign→Reject, Reject→Sign,
double taps, next-request arrival, lock, and unplug. A request that terminates as rejected must
never yield a signature. Each request owns exactly one terminal result.

### F02 — P1: A new wallet can receive and sign before backup; no restore exists

**Existing gap, confirmed.** [`unlock`](../../../app/src/main/java/dev/phonevault/signer/MainActivity.java#L283)
shows Home and calls `loadKey`; [`loadOrCreate`](../../../app/src/main/java/dev/phonevault/signer/VaultKeyStore.java#L74)
creates and persists a wallet on empty storage. There is no durable backup-verification state or
create/restore choice. Replacement activation also has no proof that either backup is usable.

A user can fund an address without ever seeing its phrase, then lose the wallet to device
failure, replacement, or the documented ten-attempt erase. Standard BIP39 recovery elsewhere
may be possible with a correct phrase; Phone Vault cannot currently perform or test that journey.

**Required change:** persist an onboarding state bound to the wallet identity. Creation must
follow Set PIN → Create → record words → verify backup → confirm account/address → Ready.
Restoration needs its own branch: Set PIN → Restore → enter and validate words on the phone →
passphrase/account selection where supported → compare expected address → Ready. Do not force
restored wallets through a needless new-seed reveal flow.

Only Ready may export a receiving address or sign over USB. Random-word checks are useful initial
friction, but a repeatable full backup check and restore/address-match drill provide stronger
evidence. A verification flag must not survive replacement for the wrong seed.

**Acceptance:** interrupt every onboarding step with power loss and reboot. No unverified created
wallet becomes Ready. Wrong checksum, missing word, wrong order, wrong passphrase, and wrong
derivation must produce a safe, understandable outcome. A real throwaway recovery drill must
recover matching addresses in an independent compatible implementation.

### F03 — P1: Recovery reveal lacks fresh authentication and complete modal lifecycle control

**New audit finding; source-confirmed, modal survival needs device reproduction.** An unlocked
user can reach the entire seed through Recovery phrase → Show, with no new PIN challenge.
[`confirmRevealBackup`](../../../app/src/main/java/dev/phonevault/signer/MainActivity.java#L603)
and the replacement confirmation keep their dialogs only in local variables. `lock()` dismisses
`approvalDialog`, not these sensitive confirmations.

The reveal callback captures its session when Show is clicked, rather than when the confirmation
was opened. [`showBackup`](../../../app/src/main/java/dev/phonevault/signer/MainActivity.java#L624)
decrypts before its eventual UI-side session/unlocked check. Consequently the code does not
enforce a pre-decryption locked-state guard. A surviving confirmation after lock can trigger
decryption while locked, although the final UI check prevents displaying the phrase while locked.
A confirmation surviving into a later unlocked session could obtain that later session's token.

**Required change:** fresh, purpose-bound PIN authorization for seed reveal and destructive wallet
operations; register and dismiss every sensitive modal on lock/deactivate; capture the originating
session and wallet identity before confirmation; revalidate before secret access and publication.
Do not hold a global UI state lock through slow keystore I/O as a shortcut.

**Acceptance:** open each confirmation, then idle-lock, sleep/wake, deactivate, and unlock again.
The old confirmation must disappear and be unusable. Instrument a fake secret store to prove no
new decrypt starts from a stale or locked action. A person handed an already-unlocked phone must
still need the PIN to reveal the seed.

### F04 — P1: Home can show an obsolete receiving address during failed identity reconciliation

**New; confirmed control flow, requires storage-fault UI test.** The same Home view retains its
address and QR across locks. `unlock()` displays it immediately, before asynchronous key loading.
[`loadKey`](../../../app/src/main/java/dev/phonevault/signer/MainActivity.java#L809) handles a load
failure by changing status text only. The replacement persistence-failure path deliberately drops
credentials and locks because the durable identity is uncertain, but it does not clear the old
receiving identity.

After an uncertain replacement, unlocking can therefore expose the previous address/QR while
the store is reconciling, and leave it visible if reconciliation fails. Signing refuses without
credentials, but a receiving QR remains actionable. It may direct funds to an identity that is
no longer available on the device.

**Required change:** explicit Loading, Ready, and Sealed/Recovery-required screens. Hide address,
QR, and wallet actions until the authoritative disk identity loads successfully. Carry the
storage explanation onto the locked/error screen; currently the message is written to Home just
before `lock()` replaces it with a generic PIN gate.

**Acceptance:** inject a replacement write that reaches disk but fails settlement, then a failed
reconcile. At no frame may the old QR be presented as ready. A healthy retry must display text
and QR for the same reconciled identity.

### F05 — P1: “Maximum network fee” is not a valid total-fee promise for every accepted chain

**New; confirmed calculation and upstream fee-model mismatch.**
[`maximumFeeEth`](../../../app/src/main/java/dev/phonevault/signer/Eip1559Request.java#L271)
always uses `gasLimit × maxFeePerGas`. The parser accepts arbitrary positive chain IDs and names
Optimism/Base, yet the approval labels the result “Maximum network fee.” OP Stack transactions
can additionally owe L1 data and operator fees, as described in the
[official fee documentation](https://docs.optimism.io/op-stack/transactions/fees).

Native amounts are also universally scaled by 18 decimals. That assumption needs an explicit
supported-chain contract instead of silently applying to any chain ID.

**Required change:** reviewed chain profiles covering native units, transaction support, and fee
semantics. Show “Maximum execution fee” when that is all the signed fields bound. Explain any
additional fee that cannot be independently bounded offline; do not upgrade host estimates into
trusted maxima. Refuse unsupported networks by default or require a clearly specified expert mode.

**Acceptance:** Ethereum and OP Stack fixtures produce correct, distinct fee explanations. Unknown
chain IDs never inherit a trusted symbol, decimal scale, or total-fee guarantee. A malicious host
cannot lower the phone's displayed bound using unsigned metadata.

### F06 — P1 product gate: Decoded token arguments are not yet understandable asset approval

**Existing limitation, confirmed.** The parser deliberately accepts only two selector-shaped
contract calls and honestly labels interface/decimals as unverified. The screen displays a raw
`uint256`, including an explicit maximum-value warning. That is good defensive behavior, but it
does not let most users determine how many tokens they authorize or which asset they approve.

**Required change:** introduce reviewed, authenticated metadata bound to chain ID and exact
contract address, with a version/revocation policy. Clearly distinguish verified identity from
unverified execution behavior, including proxy changes. For ordinary users, refuse contract
actions whose meaning cannot be explained safely. Keep any expert raw mode explicitly scoped.
Do not accept symbols/decimals supplied by a connected host as authoritative.

**Acceptance:** spoofed symbol, wrong-chain metadata, wrong contract, maximum allowance, zero
allowance/revoke, NFT-shaped approve, unusual decimals, and proxy metadata changes are covered.
Users must identify asset, amount, recipient/spender, network, and authorization scope without
reading ABI hex. This is the practical bar behind
[human-readable transaction review](https://developers.ledger.com/docs/device-app/integration/design-guidelines/transactions).

### F07 — P2: Approval typography and information hierarchy make mistakes harder to spot

**Measured from source; physical reading test outstanding.**
[`detail`](../../../app/src/main/java/dev/phonevault/signer/MainActivity.java#L1103) uses 7 sp pixel
labels and 14 sp values. `VaultTheme.FAINT` (`#606268`) has approximately 3.32:1 contrast on
`BG` (`#060608`) and 3.12:1 on `SURFACE` (`#0f1014`). This is below the 4.5:1 normal-text
benchmark in [WCAG contrast guidance](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum).
Critical labels and recovery word numbers use this color.

The approval is a long dialog with routine gas details before its checkbox. A checkbox at the
end does not establish comprehension; generic red warnings on routine operations encourage
habituation. Ordinary themed buttons are clickable TextViews with static backgrounds and no
explicit minimum target size or pressed/disabled/focus state design. PIN cells are 64 dp high;
those already meet the height recommendation.

**Required change:** retain pixel art for the wordmark and decorative headings. Use legible type
for financial meaning, addresses, seed words, and controls. Target 16–18 sp body values and
12–14 sp labels, with at least 4.5:1 contrast for normal text. Provide at least 48×48 dp touch
targets, as recommended by [Android](https://developer.android.com/guide/topics/ui/accessibility/views/apps-views).

Use a full-screen review with a short intent summary, critical fields, distinct permission
warnings, and explicit final approval. Keep action, full recipient/spender, chain, contract,
amount, and fee limitations in the required review; only routine raw details may be secondary.
Preserve an effective Reject throughout review. Any hold-to-confirm needs an accessible option.

**Acceptance:** normal and large text, lowest practical brightness, long addresses, and maximum
supported numeric values remain legible. Confirm focus order, button semantics, visible touch
feedback, and no truncation of significant digits. Accessibility-service support needs an explicit
trust decision; do not enable arbitrary Android services simply to claim accessibility.

### F08 — P2: Seed backup is a timed, fixed-layout transcription task

**Confirmed implementation; clipping risk requires rendering.**
[`buildBackupView`](../../../app/src/main/java/dev/phonevault/signer/MainActivity.java#L736) puts all
24 words in two columns inside a non-scrolling layout. Twelve rows each have 18 dp vertical
padding plus 17 sp text. Headers, captions, and replacement's two actions consume the remaining
height. There is no accommodation for large text or longer words. The phrase disappears after a
fixed 60 seconds even while the user is interacting; a replacement timeout discards its candidate.

This gives a user about 2.5 seconds per word including understanding the instructions. Partial
backups and starting over with a different candidate are foreseeable errors.

**Required change:** numbered pages of a few large words, clear progress, Back/Next, Hide now,
and safe resume of the same pending identity. Distinguish an inactivity timeout from an absolute
secret-display limit and show a useful countdown. After reauthentication, resume the same
encrypted pending onboarding candidate or clearly require discarding its partial backup.

**Acceptance:** longest BIP39 words, large text, slow transcription, interruption halfway through,
and timeout on every page. A user must never accidentally combine words from two candidates.

### F09 — P2: PIN and destructive-action UX hides essential consequences

**Existing gap, confirmed.** The ordinary LOCKED subtitle omits the wipe policy and persistent
attempts remaining; the count is shown after a wrong entry and disappears when the gate is rebuilt.
The sixth digit submits automatically. Change PIN is absent, any six-digit pattern is accepted,
and there is no visible Lock now action. Recovery phrase and Regenerate wallet are Home actions.
Fresh authentication and backup verification are absent from replacement.

**Required change:** show attempts remaining and the erase consequence on every relevant gate,
including after reboot. Use an unmistakable last-attempt state and consider an explicit Submit
when one attempt remains. Offer Change PIN with atomic rewrap, visible Lock now, and a guided
forgotten-PIN recovery route. Put replacement/wipe in Security settings with backup evidence and
fresh authentication. Warn about obvious weak PIN patterns without claiming a pattern checker
makes a six-digit PIN strong.

**Acceptance:** slow/fast taps, backspace, repeated taps, last attempt, reboot with one attempt,
failed storage writes, and interrupted PIN change. No scripted destructive test may be run on a
valuable wallet. Document that physical access can cause deliberate denial of service by exhausting
attempts; recoverability is part of the security design.

### F10 — P2: Seed viewing is not exclusive with newly arriving USB activity

**New; confirmed state omission.** `confirmRevealBackup` checks USB only when opening its
confirmation. Neither confirmation nor ordinary phrase display occupies replacement state.
[`handleIntent`](../../../app/src/main/java/dev/phonevault/signer/MainActivity.java#L908) parks only
when locked or replacing. A host attached after the initial check can connect and present a
signing dialog over the phrase; timeout can replace its underlying screen as well.

There is no direct seed-export method over USB in this path. The defect is mixing secret backup
and untrusted-host approval contexts despite the instruction to disconnect first.

**Required change:** a single sensitive-screen state excludes signing during backup reveal,
backup verification, PIN change, and recovery. Park or reject incoming work predictably; leaving
the flow returns to a clear host request prompt.

**Acceptance:** attach at every transition, including while the confirmation is open and while
decryption is pending. No approval may cover a phrase screen and no timeout may silently resume
host signing work.

### F11 — P2: The UI reports delivery before the USB writer delivers anything

**New; confirmed semantics.** After `source.send(response)` succeeds, MainActivity reports
“signature returned.” [`AccessoryTransport.send`](../../../app/src/main/java/dev/phonevault/signer/AccessoryTransport.java)
only enqueues; its writer can subsequently fail, or close can clear the queue. Conversely, once
bytes reach a host, unplugging cannot revoke them. There is no persistent user-facing receipt or
protocol delivery acknowledgement.

**Required change:** distinguish signed, queued, written, and host-acknowledged outcomes where
observable. A host acknowledgement is not proof of broadcast or settlement. After uncertainty,
say the signature may have reached the host and guide the user to check before proposing a new
transaction. Keep a minimal local receipt only after deciding its privacy/retention policy.

**Acceptance:** fail the writer before any bytes, mid-frame, and after a full write. Status must
never claim rejected, not signed, or revoked when a valid signature may exist. Re-sending the
same signed transaction and proposing a new nonce are different actions in the companion UX.

### F12 — P2: Roadmap security promises need tighter definitions before implementation

**Documentation/design finding.** The roadmap treats EIP-712 as dapp authentication, says key
attestation proves keys live in the secure element and a “genuine, unrooted vault,” and proposes
a personalized boot image as tamper evidence. Each needs narrower claims:

- EIP-712 defines typed-data signing, not harmless login. For example,
  [ERC-2612 permit](https://eips.ethereum.org/EIPS/eip-2612) changes allowance using a signature.
  Separate authentication, permits, orders, and other permissions; show scope, spender, domain,
  chain, nonce, and deadline as applicable. Unsupported types stay refused. The
  [EIP-712 standard](https://eips.ethereum.org/EIPS/eip-712) also requires applications to handle
  replay protection; a domain name supplied in the payload is not verified browser origin.
- The EVM key is software-derived and used in Android memory. StrongBox holds an AES wrapping
  key. Attesting a supported hardware key and measured boot state does not prove secp256k1
  execution happened inside the secure element, nor rule out every runtime compromise. Define
  challenge freshness, verification roots, measured fields, and limitations before a green badge.
- A copied personal boot image can look correct on a compromised system. It is a recognition
  aid, not cryptographic evidence of untampered hardware or software.
- The standalone companion RFC is a proposal. Current AOA does not automatically become
  MetaMask/Rabby/Keystone support. Prove each adapter and inbound request path separately.

**Acceptance:** every security badge and interoperability claim has a named measurement,
verification procedure, failure state, and explicit boundary. Avoid a single “secure” light
derived from the phone's own unverified assertions.

## Architecture blockers beyond UI

| Boundary | Current evidence | Requirement before a high-assurance product claim |
| --- | --- | --- |
| Hardware lifecycle | Pixel 3 XL; Google lists it as no longer receiving OS/security updates | Select a maintained target with a documented firmware/update horizon; verify custom AVB enrollment, relock, recovery, and USB restrictions on that target |
| Signing isolation | StrongBox wraps the seed; software secp256k1 key and mnemonic enter Android memory | Explicitly accept this threat model or investigate a separate signer/secure execution design with supported secp256k1 and trustworthy approval; a newer phone alone does not change this boundary |
| PIN enforcement | PBKDF2 verifier and attempts live in app preferences; PIN is not an encryption input | PIN-derived wrapping with reviewed parameters, atomic migration/change, and a threat model for offline guessing, preference rollback, and compromised app/OS access; a six-digit KDF alone is not hardware rate limiting |
| Boot/release | Rung 1b recorded as boot-tested; subsequent hardening/relock is still pending in this source snapshot | Complete the ladder, release signing ceremony, runtime inspection, locked boot verification, rejected downgrade, and interrupted-update recovery |
| Entropy | Kernel CSPRNG plus conditioned custom jitter; no independent Titan M contribution or diagnostics UI | Review source provenance and independence, retain honest claims, and resolve the design's unmet requirements; health-test passes on conditioned bytes do not measure raw entropy |
| Assurance | Useful unit tests and historical device exercises | Independent human review and physical attack testing proportionate to the intended value and attacker model, published scope/results, and a security-update/disclosure process |

Google's [support lifecycle](https://support.google.com/pixelphone/answer/4457705?hl=en) confirms
the Pixel 3 XL support limit. Android documents the distinction between
[hardware-protected key material and possible unauthorized key use after compromise](https://developer.android.com/privacy-and-security/keystore).
These are architectural constraints; more screens or additional currencies do not resolve them.

## Feature completeness and proposed product order

| User job | Current state | Proposed next evidence |
| --- | --- | --- |
| Initialize safely | PIN, automatic wallet creation | Persistent create/restore wizard, verified backup, interrupted-setup recovery |
| Recover after failure | Phrase reveal only | Full on-device import and repeatable backup check, independent address-match drill |
| Receive confidently | Full raw address and QR | Ready-state gating, account identity, checksum formatting, chain guidance; no stale QR |
| Send native assets | EIP-1559 via Python host, on-phone approval | Supported-chain profiles, honest fees, comprehensible review, deterministic cancellation |
| Send tokens / manage approvals | Selector-shaped calls with unverified raw amount | Authenticated asset metadata and understandable permission scope |
| Use browser dapps | No general integration or message signing | One working audited adapter; bounded message/typed-data types with permission-aware review |
| Manage accounts | One fixed derivation path | Explicit account/path discovery and watch-only export; passphrase recovery semantics before hidden-wallet UX |
| Operate long-term | Prototype lifecycle | Signed updates, migration/rollback tests, battery and device-failure guidance, verifiable integrity evidence |
| Desktop companion | Planning RFC; Python CLI exists | Pair → request → phone review → independent verify → clear outcome on each supported desktop OS |

Recommended sequence:

1. Close F01, F03, and F04 alongside the ongoing hardening work; these affect the existing app.
2. Complete the hardened release and recovery chain. In parallel planning, settle the intended
   production hardware and signing-isolation boundary.
3. Implement the recoverable onboarding lifecycle, backup check, PIN wrapping/change, and clear
   error states before exposing a ready receiving address.
4. Redesign approval and recovery typography/layout, add honest chain/asset/fee semantics, and
   perform device usability testing.
5. Ship one companion/browser path with independent verification and bounded signing support.
6. Add accounts and passphrase flows only with tested recovery. Defer passkeys, duress/decoy,
   Shamir, and broad multi-chain support until the core lifecycle passes its gates.

## UI direction

Keep the dark appliance identity and pixel lock/wordmark. Use the phone's screen area to make
the important choices obvious. Proposed top-level destinations are Wallet, Review, and Security.
Wallet shows the selected account, full checksum address, receive action, connection state, and
Lock now. Security contains backup check/reveal, PIN change, integrity details, updates, and the
separately guarded destructive actions. Avoid pretending an offline vault knows current balances.

Review should first answer: what action, which asset, how much, to whom or what spender, on which
network, what permission, and what fee is actually bounded. Receipt text should describe what the
device knows about the signature, not invent a network settlement status. Show test/development
status consistently on the locked screen and approval, not just in the Home footer.

## Required physical UX evaluation

Use throwaway wallets and public test fixtures only. Do not capture actual recovery phrases in
audit screenshots. Test on the target device with normal and large text, low brightness, and
long fields; retain redacted images of safe states plus build/device provenance.

Recruit an initial mix of novice and experienced users. Have them create and verify a backup,
restore and match an address, identify a substituted recipient, distinguish transfer from
allowance, reject excessive fees, recover from unplug, and handle the last PIN attempt. Record
completion, assistance, misunderstandings, errors, and elapsed time. Any observed irreversible
mistake blocks release; zero mistakes in a small study is necessary evidence, not proof of safety.

Add deterministic Android tests for the findings' state transitions. Re-run the physical paths
after layout, lifecycle, storage, transport, or signing changes. A polished screenshot and a
passing parser suite cannot substitute for these recovery and authorization exercises.
