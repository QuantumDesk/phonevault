# Security policy

Phone Vault is a hardware wallet. A vulnerability here can cost people their funds, so please
report it privately and give us time to fix it before anything is published.

## Reporting a vulnerability

- **Email:** security@phonevault.org (placeholder address until the project's public launch;
  it will be confirmed here before the first release).
- **GitHub:** once the repository is public, use
  [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  ("Report a vulnerability" on the Security tab). Do not open a public issue for a security bug.

Please include:

- what is affected (phone app, Vault OS image, companion, browser extension, host tools) and the
  commit or version;
- the impact as you understand it (e.g. "a host can obtain a signature the phone did not show",
  "the seed survives a wipe", "the companion broadcasts bytes it did not verify");
- steps to reproduce, a proof of concept, or the relevant code path;
- whether you need the phone hardware to reproduce it.

We aim to acknowledge a report within 3 working days, agree on a fix and disclosure timeline
with you, and credit you in the advisory unless you prefer otherwise. There is no bug bounty yet.

## Scope

In scope:

- **Signer app** (`app/`): anything that lets a host or another app obtain a signature the user
  did not review and approve on the phone; review screens that misrepresent what is signed;
  seed or key exposure; PIN / credential / wipe bypass; backup, restore and replacement flaws.
- **Vault OS** (`vault-os/`): kiosk or lock-task escape, any network, radio or USB function
  reachable that the image claims to remove, verified-boot, release-signing or rollback gate
  bypasses, build or release scripts that accept artifacts they should refuse.
- **Companion** (`companion/`): broadcasting anything that was not independently verified,
  verification bypasses (EVM, messages, Bitcoin PSBTs, attestation), pairing confusion, local
  file permission problems, unsafe handling of node, WalletConnect or browser-bridge input.
- **Browser extension** (`extension/`): origin spoofing, cross-site request injection, bypass of
  the companion's per-site connection.
- **Host tools** (`tools/`): verifier bypasses in `evm_verify.py` / `aoa_client.py` /
  Bitcoin tools.
- The design itself: flaws in the [threat model](vault-os/docs/threat-model.md) or
  [protocol](vault-os/docs/protocol.md).

Out of scope:

- Findings that require an **unlocked bootloader, adb, or a development build**. Development
  images are deliberately debuggable; the documented debug-only deviations
  ([release-config.md](vault-os/docs/release-config.md), the dev-ladder READMEs) are known.
  A way for such a deviation to reach a release build *is* in scope.
- Physical attacks the threat model lists as out of scope (e.g. chip-level fault injection on
  the Titan M), and attacks on the Pixel firmware or Google's services themselves (report those
  to Google).
- Third-party dApps, RPC nodes, Esplora servers or WalletConnect relays, except where the
  companion trusts them in a way the documentation says it does not.
- Social engineering, spam, and denial of service against project infrastructure.

## Supported versions

Phone Vault has not had a release yet. Only the **latest pre-release** (the current `main`
branch) receives fixes. There are no long-term or backported versions.

## Please do not

- test against phones, wallets or funds that are not yours;
- publish details, exploits or proof-of-concept code before a fix is available and the
  disclosure date we agreed on has passed;
- access, modify or delete other people's data, or degrade project infrastructure;
- put seed phrases, private keys, PINs or real wallet addresses in reports. Use throwaway
  wallets (the public BIP-39 test vectors are fine).
