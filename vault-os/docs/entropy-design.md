# Vault OS — Entropy & Seed Generation Design

Status: design + partial implementation (`app/.../SeedVault.java`, `HealthTests.java`,
`AndroidEntropySources.java`). See "Implementation status" below for exactly which requirements
the code meets today; treat every unmet row as a release blocker.
Context: EVM signing appliance on Pixel 3 XL (crosshatch), Titan M secure element.

## Why this document exists

Hardware wallets keep getting burned on entropy, and the failures are almost never
"the math was wrong" — they're **architecture** failures. The ColdCard case (firmware
redesign shipped 2025) is the canonical example and the thing we must not repeat.

The defining property of entropy bugs: **you cannot feel a weak seed.** A 128-bit-secure
seed and a catastrophically-weak seed look byte-for-byte plausible on screen. There is no
thermometer. So the design has to be *structurally* safe — safe even when a component
silently fails — because we will never observe the failure directly.

## The ColdCard failure, decomposed

Three distinct mistakes, each of which we address separately below:

1. **Single-source dependency.** The device had 3 hardware RNGs (MCU + 2 secure elements)
   but only *one* was actually plumbed into the seed. The whole seed rode on one pipe.
2. **Present-but-not-connected.** A 2021 change disconnected even that one. The RNGs kept
   running; their output just never reached the seed. "Claimed a source it didn't use."
3. **Fail-silent.** No health check. Cold water came out of the tap and nothing screamed.

Their fix was not a one-line patch — it was a full pipeline redesign: connect *all* sources,
mix them, and *force* user-supplied entropy on top. Everyone else (Trezor since v1, Jade,
BitBox02, Foundation Passport) already mixed multiple sources from day one.

## What the Pixel 3 actually gives us (correcting an earlier assumption)

We previously assumed "old phones have no hardware RNG, so entropy is software-only."
**That is wrong**, and correcting it matters for both design and trust. The device has
**two independent hardware entropy sources plus a well-audited kernel pool**:

- **Titan M (H1) secure element** — hardware TRNG, reachable via StrongBox/Keymaster.
- **Snapdragon 845 QRNG** — SoC hardware RNG, feeds `/dev/hw_random`.
- **Linux kernel CSPRNG** (`getrandom(2)`) — continuously mixes `hw_random` + interrupt
  jitter + timing. This is the same "mix everything" pool the good vendors trust.

So the platform is well-positioned. The risk is entirely in whether *we* wire the mixing
and the health checks correctly.

## Design rules (each maps to a ColdCard failure)

### R1 — Mix ≥3 independent sources; never depend on one
The seed's raw entropy is a hash-combine of independent inputs:

```
seed_entropy = SHA-512(
      DS                        // domain-separation constant, e.g. "vault-os/seed/v1"
   ‖  getrandom(32)             // kernel CSPRNG (already mixes QRNG + jitter)
   ‖  titanM_random(32)         // Titan M TRNG, pulled SEPARATELY from the kernel path
   ‖  user_entropy              // dice rolls and/or BIP39 passphrase material (may be empty)
   ‖  jitter_sample(32)         // in-app CPU-timing jitter collector (cheap belt-and-suspenders)
)[:32]                          // 256-bit → BIP39 24-word mnemonic
```

Property we require: **any single good input yields a safe output.** If Titan M is wedged
but `getrandom` is healthy → safe. If the kernel pool were somehow poisoned but Titan M is
healthy → safe. If both fail but the user rolled real dice → safe. No input is load-bearing
alone. (This is why it's a hash-combine, not a weighted XOR where one dominant-but-cold
source can wash out the others — see R5.)

### R2 — Pull Titan M entropy *independently*, don't just trust the kernel path
`getrandom()` already folds in `/dev/hw_random` (the SoC QRNG). But to have Titan M as a
*truly independent* pipe (not the same water reported twice), request random bytes from the
secure element directly via a StrongBox operation, not by assuming the kernel already
included it. Two independent hardware sources > one hardware source counted twice.

### R3 — Verify every claimed source is live *at generation time*
This is the direct antidote to "present but not connected." Before mixing, each source runs
a liveness + sanity check, and the result is recorded:

- `getrandom` returns without `EINTR`/short read; two successive 32-byte pulls differ.
- Titan M returns bytes; two pulls differ; the call actually reached the SE (not a stub).
- Jitter collector accumulated the required number of distinct timing samples.

If a source we *claim to use* is missing, that is not a silent degrade — see R4.

### R4 — Fail LOUD; never silently emit a weak seed
Run standard health tests on the raw sources before they're trusted:

- **NIST SP 800-90B** startup health tests on each raw source: Repetition Count Test and
  Adaptive Proportion Test. (These catch stuck/constant/low-rate outputs.)
- A basic distribution sanity check (byte histogram not wildly skewed) as a coarse backstop.

Policy on failure:
- If **≥2 independent sources are healthy** → proceed.
- If only **1** source is healthy → **stop, warn the user explicitly**, and require them to
  add user entropy (dice/passphrase) before continuing. Do not auto-proceed on one pipe.
- If **0** sources are healthy → refuse to generate. Cold-shower prevention. No seed is
  better than a weak seed the user believes is strong.

### R5 — Hash-combine, not weak XOR
ColdCard "mixed in tiny bits of heat" — token contributions a single cold dominant source
overwhelmed. We concatenate full-width contributions and run them through SHA-512 with
domain separation, so every input has equal cryptographic weight in the output. No input is
merely "sprinkled in."

### R6 — Offer (and for the paranoid, force) user entropy — mixed IN, never replacing
- **Dice mode**: user rolls physical dice; the entropy is a *first-class input to R1's hash*,
  not a replacement for the device sources unless they explicitly choose full-manual.
- **BIP39 passphrase**: supported as the easy top-layer add-on (the video's recommendation).
  Clearly flagged as an advanced feature that becomes part of the backup and must be tested.

### R7 — Prove it, don't assert it (the trust/audit rule)
For every source we say we use, there must be a way to *demonstrate it contributed*:
- A diagnostics screen showing each source's health-test result at generation time.
- Deterministic test vectors for the mix function (given fixed inputs → known seed) so the
  hash-combine itself is auditable and CI-tested.
- The entire pipeline is open-source, so anyone (or an LLM pointed at the repo) can verify
  it. This is a trust advantage ColdCard's partly-closed firmware could not offer.

## Vault-OS-specific notes

- **Camera & sensors are disabled** by our hardening, so we do *not* use them as entropy
  sources (some wallets do). Kernel CSPRNG + Titan M + user entropy is more than sufficient;
  the tradeoff is we must get the remaining sources *provably* right (R3/R4/R7).
- **The seed must be exportable** (24-word backup), so we cannot use non-exportable StrongBox
  keys *as* the wallet key. We **generate** the seed in-app from the R1 mix, then optionally
  **wrap it at rest** with a Titan M key. (Interacts with the stateless-mode option — see
  [ROADMAP.md](../../ROADMAP.md), "Later".)
- The msm-4.9 kernel is older; confirm the RNG driver (`qcom-rng`/`hw_random`) is present and
  feeding the pool, and that `getrandom` blocks until the pool is initialized at first boot
  (never read `/dev/urandom` pre-seed).

## Explicit anti-patterns (things that would make us ColdCard)

- ❌ Reading the seed from a single source (even a hardware one).
- ❌ Claiming "uses Titan M" without a runtime check that Titan M actually contributed.
- ❌ Weighted/token mixing where one source can dominate.
- ❌ Proceeding to generate when sources fail their health tests.
- ❌ Any code path where a degraded RNG produces a seed the UI presents as normal.

## Implementation status

What `SeedVault` / `AndroidEntropySources` / `HealthTests` actually deliver today — stated
conservatively so the claim never exceeds the code:

| Requirement | Status |
|---|---|
| R1 domain-separated SHA-512 hash-combine of every healthy source + user entropy | ✅ implemented, unit-tested |
| R2 ≥2 independent *hardware* sources | ⚠️ **implemented, verified on hardware, not reviewed:** sources are kernel `getrandom` (required), `titan-m-strongbox` (a StrongBox-generated AES key + chip-chosen IV encrypting zeros; the keystream depends only on Titan M randomness) and an ad-hoc SHA-256-conditioned CPU-jitter collector (optional). A fresh wallet on a development phone lists all three, passing their health tests. The jitter collector is home-grown, not a vetted jitterentropy port, and no raw-noise assessment exists. |
| R3 liveness (two successive draws differ) | ✅ per source |
| R4 startup health tests | ⚠️ **partial.** RCT, APT and a distribution check now run over a 1024-byte per-source sample (an earlier version checked only 64 bytes, so the APT *never executed*). They run on *conditioned* output, so they are a stuck/collapsed-source backstop, not an SP 800-90B raw-noise assessment. |
| R4 fail-loud policy (≥2 healthy proceed / 1 needs user entropy / 0 refuse) | ✅ implemented, unit-tested |
| R5 equal-weight mixing | ✅ |
| R6 user entropy input | ✅ optional dice rolls during wallet setup, mixed with the device sources and discarded after creation |
| R7 diagnostics screen | ✅ Security → Device information → "Entropy at wallet creation" lists each source and whether it passed its health tests (names and pass/fail only; contributions are zeroed after mixing) |

Memory hygiene: source contributions, the health sample, the SHA-512
digest, the 32-byte entropy and the BIP39 seed are all zeroed in `finally` blocks; the only
surviving representation is the mnemonic (String) and web3j's `BigInteger` private key, both
of which are unavoidable with the current library and are dropped on lock.

Until R2 and a reviewed raw-noise assessment exist, describe the generator as "kernel CSPRNG
plus a mixed-in software jitter source with startup sanity checks", not as entropy-design
compliant.

## Open items

- Choose the jitter-entropy implementation (e.g., a vetted CPU-jitter collector) vs. dropping
  it and relying on kernel+TitanM+user only.
- Decide the exact StrongBox call used to extract independent Titan M randomness on this
  Keymaster version, and confirm it doesn't merely proxy the kernel pool.
- Wallets restored from words, or created before source reporting existed, show "Not recorded"
  on the diagnostics screen; that is expected.
