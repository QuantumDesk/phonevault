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
   the prototype phase. A four-byte selector and well-formed arguments do not
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
