# Phone Vault threat model

Phone Vault is a constrained, offline EVM signing appliance. It is not a
general-purpose hardened phone and is not yet suitable for valuable assets.
This document defines the intended boundary so build-time and runtime claims
can be tested rather than inferred from source configuration.

## Assets and trust boundary

The protected asset is the secp256k1 private key and the user's authority to
approve a specific transaction. The display, touchscreen, Phone Vault app,
Android framework, kernel, bootloader, secure element, and verified system
images are inside the trusted computing base. The connected desktop, browser,
dapp, USB cable, transaction request, token metadata, and network are
untrusted.

The Pixel boot ROM, bootloader, baseband firmware, Titan M firmware, and other
immutable or vendor firmware remain hardware-platform dependencies. Replacing
Android does not remove those supply-chain or end-of-life risks.

The Mac companion's dApp transports (WalletConnect, and the browser extension in
`browser-extension.md`) are host-side conveniences on the untrusted side of this boundary:
they can queue requests for review, never sign or bypass the on-device approval.

## Required invariants

1. The host can request an address or propose a transaction, but cannot obtain
   private-key material or cause signing without a fresh on-device approval.
2. The approval screen must be derived from the exact parsed fields that are
   passed to the signer and must show the exact signing address. Each approval
   binds the transaction and displayed address to one immutable credential
   snapshot; a changed active identity invalidates the approval. Key replacement
   is excluded while USB is connected, replacement is in progress, or an
   approval is pending. Opaque calldata and unsupported transaction types fail
   closed. USB frames must be complete, valid UTF-8 and schema-exact; truncated
   frames, duplicate keys, trailing data, and unknown or missing transaction
   fields are rejected rather than interpreted with defaults. The approval UI
   blocks screenshots, rejects fully or partially obscured touches, and keeps
   signing disabled until the user selects the review acknowledgement below the
   decoded fields.
3. Only native EIP-1559 transfers and canonical ABI-shaped
   `transfer(address,uint256)`, `approve(address,uint256)`,
   `transferFrom(address,address,uint256)` or `increaseAllowance(address,uint256)`
   calls (exact length: missing or trailing bytes, dirty address padding, zero
   addresses and native value on a token call are refused) are accepted during
   the prototype phase, plus — since 2026-10-11 — canonical ERC-721/1155
   `setApprovalForAll`/`safeTransferFrom`/`safeBatchTransferFrom` and calls to the
   pinned Uniswap routers that decode completely (see "Safety you can see"
   below). Every other non-empty calldata is refused with a reason shown on the
   phone; nothing is offered for blind approval. A four-byte selector and well-formed arguments do not
   authenticate the target contract's interface or execution semantics; the
   technical details show the exact selector and calldata. Token symbol and
   decimals come only from the token list built into the APK
   (`res/raw/tokens.json`, SHA-256 pinned in `TokenList`, sources in
   `app/token-list/SOURCES.md`), matched by chain and contract address; a
   contract not in that list is shown as "Unknown token contract" with the raw
   amount in base units and never a guessed symbol, and a list that fails its
   pin is refused whole. The list is trusted only as far as the APK signature
   and its cited sources; it is not updatable at runtime (signed updatable
   lists are future work). Approvals at or above 2^255 are shown as UNLIMITED. Besides transactions, only `personal_sign` (EIP-191
   0x45) and strictly parsed `eth_signTypedData_v4` (EIP-712) messages are
   accepted; raw `eth_sign` is refused. Their review and the signed digest come
   from one parsed object, and the host recomputes the digest independently
   before using a signature (see `message-signing.md`).
4. The appliance app does not become operational until it is device owner and
   kiosk/device policy has been enforced. Ordinary Android installations remain
   usable for development without pretending to be an appliance. Device-owner
   authority must not be conflated with Android `priv-app` placement; the signer
   remains an ordinary preinstalled system app with zero requested permissions.
   Framework first-boot provisioning independently rejects missing, non-system,
   or privileged configured owner packages before granting authority.
5. Production key wrapping must be StrongBox-backed. The raw EVM key exists in
   application memory while the signer is running because Android Keystore does
   not expose secp256k1 signing on this device.
6. The production USB port is a peripheral/sink and exposes only Android Open
   Accessory signing transport. Userdebug may additionally expose ADB. Network,
   media, audio, diagnostic, serial, and USB-host roles fail closed in the HAL.
   The kernel is gadget-only and does not compile the corresponding storage,
   media, diagnostic, cellular, or host-mode configfs/DWC3 functions.
7. The image starts no Wi-Fi, cellular, Bluetooth, NFC, GNSS, location, VPN,
   tethering, network-stack, or network-time service. Vendor HAL enforcement is
   activated by an immutable vendor-namespaced property, independent of system
   property access. Forbidden apps, daemons, HAL services, feature declarations,
   VINTF contracts, and init triggers are release blockers. The appliance owns
   a minimal VINTF manifest rather than inheriting Crosshatch's general-purpose
   radio, sensor, camera, neural, voice, and media-service declarations. The
   matching radio, camera, sensor-hub, and removed DSP kernel drivers are also
   disabled, not merely left dormant behind missing userspace. This includes
   Qualcomm's MSS QDSP6 modem firmware loader, so removing RMNET/IPA is not
   mistaken for preventing the baseband from being booted. Android's
   connectivity API/APEX code may remain where it is part of the platform boot
   class path, but its framework services are not started; top-level `netd`,
   multicast-DNS, and network-administration executables are removed and the
   `netd` core init action is gated by the immutable offline property. Android's
   general BPF loader remains boot infrastructure because non-network graphics
   components require it; retaining it does not authorize a network service.
8. The bootloader is locked against the project's installed AVB root. Every
   released partition descriptor, chained vbmeta image, OTA package, and
   presigned Phone Vault APK must verify against the recorded project keys.
   Top-level vbmeta must carry a positive rollback index and AVB flags must be
   zero; a correctly signed vbmeta that disables verification or hashtree
   enforcement is treated as unsigned for release purposes.
9. Runtime updates cannot install an untrusted APEX or downgrade below accepted
   rollback indices. Recovery signature parsing must reject ambiguous signer
   sets.

## Required evidence before release

- A pinned source manifest with clean, attributable local patches.
- A deterministic source inventory binding the app, policy, patch, manifest,
  build-overlay, and release-tool bytes to the public release manifest.
- A locked app dependency graph and reviewed SHA-256 inventory for build
  plugins, metadata, host-specific tools, and transitive libraries; the release
  app must build without repository access and independently repeated clean
  builds must produce the same deterministic v2-signed APK bytes.
- Reproducible or independently repeated builds with matching artifact hashes.
- A passing target-files policy scan, forbidden-kernel-config scan, and
  cryptographic AVB descriptor check, plus actual APK/APEX container and APEX
  payload verification against the project public-key inventory. The evidence
  must record zero vbmeta flags, a positive rollback index, and the complete
  chained-vbmeta digest observed again at runtime. The published AVB enrollment
  and APEX binary public-key blobs must be re-derived from, and match, their
  exported PEM identities; the release bundle must reject unrecognized public
  files and contain no private-key material.
- Successful first boot with automatic owner/HOME provisioning after a wipe.
- Runtime service, process, interface, feature, property, SELinux, and USB-role
  audits on physical crosshatch hardware.
- Negative transaction tests, USB fuzzing, disconnect/reconnect tests, and
  confirmation that rejection never returns a signature. Physical-test host
  tooling must independently decode the returned typed transaction and compare
  every encoded EIP-1559 field with the request.
- Successful custom-key enrollment, bootloader relock, boot-key fingerprint
  recording, OTA installation, rejected downgrade, and recovery from a failed
  update.
- Independent review of the app, platform patches, release tooling, and key
  ceremony.

## Known limitations

- Pixel 3 XL is end-of-life and no longer receives current vendor firmware or
  full platform security support. It is a low-cost proof-of-concept target, not
  the eventual high-assurance recommendation.
- The wallet is a BIP39 24-word seed (see `entropy-design.md` "Implementation
  status" for what the generator does and does not meet) behind an in-app 6-digit
  PIN with a verified erase after 10 failures. The 0.3.0 source requires an account-bound
  24-word backup check before receiving or signing, and fresh PIN authorization for seed
  access/replacement; physical validation of the new UI is pending. There is still no seed
  import, independent restore drill in-app, duress, or inheritance, and the
  PIN is not yet folded into the at-rest wrapping (a rooted attacker with the
  StrongBox key does not need it). Replacing the wallet (two-phase: new phrase
  shown, then explicit activate) changes the active key but does not prove
  forensic erasure of old process memory or flash history; "lock" drops
  references to key material, it does not prove memory erasure.
- The signer cannot determine offline whether a native recipient is a contract,
  or prove that selector-shaped calldata actually executes ERC-20/ERC-721
  semantics without trusted contract code and state. Token name/symbol/decimals
  are shown only for contracts in the APK's built-in list (a curated snapshot,
  not an on-chain proof: a listed contract that is later upgraded or paused is
  not noticed); every other contract is shown as unknown with raw base units.
  The phone cannot see balances or existing allowances, so increaseAllowance
  totals are unknown to it.
- Physical side channels, malicious replacement displays/touch controllers,
  fault injection, compromised silicon, and vendor firmware implants are not
  solved by a custom Android image.
- Removing the Linux MSS modem loader, firmware, services, interfaces, and
  remote-subsystem nodes is necessary evidence but cannot by itself prove that
  proprietary bootloader/PMIC code never powers RF hardware. Physical bring-up
  must treat that as an explicit measurement gap rather than claiming a
  software-only RF guarantee.
- Build scripts and static gates are evidence only after the resulting image is
  built, inspected, booted, relocked, and tested on the device.

New features must preserve these invariants or update this document with the
new trusted components and corresponding negative tests.

## Device attestation (2026-10-10)

The companion asks the phone to attest a fresh challenge on every connection and before every
signature (`device-attestation.md`). A StrongBox key generated for that challenge signs the wallet
address; the wallet key is not used and no review screen is involved, so invariant 1 is unchanged.
New trusted inputs: Google's attestation root keys (pinned in the companion), Google's revocation
list (best effort), and the Titan M's root-of-trust report. It proves locked Phone Vault firmware
and the release-signed app on certified hardware; it does not prove a genuine image is
uncompromised at runtime, resist physical attacks, or survive a Google root or batch-key
compromise. No phone can be GENUINE until the release APK signer and AVB key are pinned.

## 0.3.0 app interaction boundary (2026-09-05)

The updated app presents full-screen native pages for review and sensitive work. A request owns
an `ApprovalDecision`: reject can win during review, while a successful Sign transition disables
rejection. Session invalidation can still cancel queued signing. A successful transport enqueue
does not prove delivery; receipt copy must preserve that uncertainty.

`SensitiveFlow` excludes USB while PIN reauthentication, seed viewing/checking, or replacement is
active. Authorization is checked before secret access, after acquiring the store, and before UI
publication. Lock can invalidate a secret operation already authorized; this is not a claim of
cancelling a keystore operation mid-execution or of erasing every managed-memory copy.

`BackupCheck` stores a public account address after every position in a 24-word recognition
challenge is answered correctly and the account is confirmed. Receiving/signing are gated on
that proof matching the loaded identity. This is a usability safeguard, not an anti-root or
rollback-resistant hardware record and not an independent restoration test. Missing proof on
upgrade requires a check without replacing the wallet. Replacement requires the old proof and
a new full challenge before activation. Backup/PIN state remains app-managed until PIN-derived
wrapping and stronger storage threat-model work land.

The development dump skips sensitive flows, but external screen capture remains available on
the development OS. Physical UI verification and the hardened/relocked release remain required.

## Safety you can see (2026-10-11)

Display-only additions to the review; none of them changes what is signed, and every review is
still built from the one parsed `Eip1559Request` / `MessageRequest` that is signed.

**Unknown calldata (behavior check).** Before this change the parser already refused any
calldata that was not one of the four canonical ERC-20 calls (`Erc20Call.decode` threw), so the
phone never offered opaque calldata for blind signing; the host got an error and the phone only
updated its status line. Now the explained set grows (NFT calls; pinned Uniswap routers), every
other non-empty calldata is still refused — `RequestRefusal.unknownCall`: "This contract call
can't be explained by the phone, so it was refused and nothing was signed", with the contract and
selector — and the refusal is also shown on the phone as a full screen. Native transfers with
empty calldata stay allowed; when the recipient is a contract the phone knows (listed token,
listed NFT collection, pinned router) the review adds a WARNING that coin sent straight to it is
usually lost, otherwise a note that the phone cannot tell a wallet from a contract.

**EIP-7702.** Refused by name ("Account delegation (EIP-7702) is not supported: it can hand
control of this wallet to a contract"): a request carrying `authorizationList` or `type` 0x4; a
`personal_sign` whose bytes are `0x05 ‖ rlp([chain_id, address, nonce])`; typed data whose
primary type is a 7702 authorization (an "…Authorization" type with a nonce and an address, or a
name containing 7702) or an ERC-7710 `Delegation`. The signer only ever encodes type 0x02
(EvmSigner), so a set-code transaction was already impossible; message digests (0x19 prefixes)
cannot equal a 7702 authorization digest (0x05), so the message checks are defense in depth
against a host passing a delegation off as an ordinary message. The companion independently
refuses dApp transactions of a type other than 0/2 and unknown fields such as `authorizationList`.

**NFT calls.** `setApprovalForAll(op, true)` is a DANGER review ("Lets 0x… move EVERY NFT in this
collection, now and in future"); `false` is a revoke. ERC-721 `approve(to, id)` and
`transferFrom(from, to, id)` share their selectors with ERC-20; the phone uses its lists to
disambiguate: a contract in the token list is fungible, a contract in the small pinned NFT list
(`NftCollections`, `app/token-list/NFT-SOURCES.md`) is an NFT, and an unlisted contract shows BOTH
meanings under a WARNING ("Two possible meanings…") rather than being refused — the decoded
fields (two addresses and one uint256) are identical in both readings, so nothing shown differs
from what is signed, and refusing would break existing unknown-token transfers. Collection names
come only from the pinned list, never from the host.

**Uniswap swaps.** Only calls to router addresses pinned per chain (`UniswapRouters`, sources in
`app/token-list/ROUTER-SOURCES.md`) are decoded; the same calldata to any other address is an
unknown contract call. Universal Router 2.0/2.1 `execute` with commands V2/V3 swaps, WRAP_ETH,
UNWRAP_WETH, SWEEP, TRANSFER, PAY_PORTION(_FULL_PRECISION), PERMIT2_PERMIT (spender must be the
router), PERMIT2_TRANSFER_FROM (to the router only) and V4_SWAP (exact-in/out single and
multi-hop, SETTLE, SETTLE_ALL, TAKE, TAKE_ALL, TAKE_PORTION), and SwapRouter02
`exactInput(Single)`/`exactOutput(Single)`/`unwrapWETH9`/`refundETH`/`sweepToken`/`multicall`.
All inputs must be canonical ABI (decoded, re-encoded, compared byte for byte) so the router's
assembly decoding reads the values the phone showed. A conservative model of the router's
balances turns the commands into "You give · You get at least · Recipient · Expires"; the swap is
REFUSED ("This swap uses features the phone can't explain; nothing was signed") for any other
command or V4 action, the allow-revert flag, native coin left unused, a spend of a router balance
the transaction never funded, an unsettled V4 delta, a price-limited SwapRouter02 swap, or more
than 64 bytes appended after `execute()` (up to 64 — apps' tracking tags — are shown and are
never read by the router). DANGER for output to another address and for a zero minimum; WARNING
for unknown tokens (raw base units), pool hooks, fees above 1%, unlimited Permit2 allowances and
missing deadlines. Deadlines are shown as written (UTC); the offline clock is not trusted.

**Address book, history, look-alikes.** The phone records, per wallet, each address it signed a
transfer to (or approved as spender/operator) with the first date and a count, in app-private
files (`files/safety/`, FBE credential-encrypted like the wallet's preferences, written
atomically), after the signature is created — "sent" therefore means "signed on this phone".
Reviews say "First time sending to this address" (WARNING) or "Sent here N times before", and
flag a DIFFERENT address that shares the first 4 and last 4 hex characters (or ≥7 end characters,
or is within one edit at each 6-character end) of a past recipient or contact as DANGER, with
both full addresses in an aligned 4-character chunk grid. Contact names are typed on the phone
(no PIN to add, rename or delete: names never change what is signed) and come only from the
phone; the request schema has no field a host could use to label an address. Limits: the history
is not wiped by the in-app 10-wrong-PIN erase of the wallet (in credential mode, wrong PINs reset
the whole phone); it is a local convenience record, not an integrity-protected log, and a rooted
attacker could edit it to suppress a first-time warning — which is why every review still shows
the full address.

## Stronger backups (2026-10-11)

**Printable backup card** (`tools/backup-card/make_card.py` → `tools/backup-card/out/*.pdf`, A4 and
US Letter, with a 25 × 25 or 29 × 29 SeedQR grid). The PDFs are generated deterministically by a
dependency-free script (`--check` fails when the checked-in files are stale) and are the same for
every user: 24 numbered word lines, date, an "Account 1 address first 4 / last 4" line (public, to
tell cards apart), copy 1/2, the grid with the fixed QR function patterns pre-printed, and short
instructions (never photograph or type it, two copies in separate places, a passphrase is not on
the card). The companion only opens the bundled file in the system viewer (`open_backup_card`,
fixed names, no path from the UI). No recovery word, SeedQR or other secret ever reaches the Mac;
a filled-in card is as sensitive as the phrase itself.

**SeedQR on the phone** (`SeedQr`, `SeedQrView`). SeedSigner's specification
(https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md): CompactSeedQR = the
BIP-39 entropy (32 bytes for 24 words, checksum bits dropped) in byte mode without ECI, error
correction L, version 2 (25 × 25); Standard SeedQR = 4-digit word indices (96 digits), numeric mode,
L, version 3 (29 × 29). The symbol comes from ZXing (already used for the receive QR); its mode,
version and level are checked after encoding and the screen refuses rather than show anything
else. Tests decode the generated matrices with ZXing's decoder against all nine published vectors
and check that the card's pre-printed modules match. The SeedQR is the phrase in another form, so
it lives only inside the existing sensitive flow: same PIN gate and seed-key path as "Show recovery
phrase", no USB session (attaches are parked), FLAG_SECURE in release, the seed idle/session timer,
no ☰ menu, Hide/Back/lock clear it, the modules are wiped on hide, the view is excluded from
accessibility, and the development UI dump skips it. It is not offered for an un-activated
replacement wallet. The Java `String` passed to ZXing and ZXing's internal buffers cannot be wiped;
this is the same managed-memory limitation as the mnemonic string itself.

**"Check your backup" reminder** (`BackupReminder`). Non-secret metadata in the app's preferences:
the day of the last successful check (written in the same commit as `BackupCheck.record`, so a
spot check, replacement or restore restarts it), the interval (off / 30 / 90 / 180 days, default
90) and a 14-day snooze. Home shows a card only for a verified wallet with no USB session, request
or approval in progress; it runs the existing spot check (no phrase shown unless a word is wrong
and the user chooses "Review"). The offline clock is not trusted for anything else: a clock that
goes backwards never shows the card, one that jumps ahead can only show it early. It never blocks
receiving or signing.
