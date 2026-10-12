# Transaction simulation (2026-10-11)

Before anything goes to the phone, the Mac companion simulates the exact transaction on the
user's own node and shows what it would do to the wallet's balances. The phone shows the Mac's
result as an **untrusted claim**, in its own box below the phone's own review, and checks it
against what the phone itself decoded.

## What it proves, and what it doesn't

* **A lying Mac can show fake numbers. It cannot change what the phone decodes or signs.** The
  claim is display data: it is never part of the signed bytes (`EvmSigner` reads only the
  transaction fields), it never feeds the phone's decoding, and the companion's `verify.rs` (and
  `tools/aoa_client.py`) never read it. Tests prove signing and verification are byte-identical
  with and without a claim, even a lying one (`HostSimulationTest.theClaimIsNeverSigned`,
  `verify::the_host_simulation_field_never_affects_verification`).
* The phone is offline: it cannot check the numbers, only whether they **contradict** what the
  calldata means. A contradiction gets a red row: "The Mac's simulation does not match what this
  transaction does — trust the phone's review above." A consistent claim is still only a claim.
* Simulation answers "what would this do on top of block N on this node". The node is trusted for
  the simulation only: a malicious node can lie about balances or reverts. State can change before
  inclusion (front-running, price moves, a token's owner pausing it). Swaps are still bounded by
  the decoded minimums the phone shows, not by the simulated amount.
* What it adds: changes the phone's decoding cannot see, e.g. a contract pulling tokens through an
  earlier approval during a call the phone decoded as something else, a native send to a contract
  that does more than receive, a token that taxes transfers; and reverts caught before you pay a
  fee for a failed transaction.

## Mac side (`companion/src-tauri/src/sim.rs`, `companion/src/simulation.ts`)

Every review card simulates: Send, token send, speed-up/cancel, WalletConnect and
browser-extension `eth_sendTransaction`. The call is `eth_simulateV1` with
`traceTransfers: true` (native-coin movements appear as Transfer logs from
`0xEeee…EEeE`), `validation: false`, from the paired address with the exact `to`, `value`, `data`
and **gas limit** that will be signed, on top of the latest block (read together with its base
fee). From the logs it computes the paired wallet's changes:

* native coin, including the estimated fee = gas used × min(max fee, base fee + priority fee)
  (rollups add an L1 data fee that is not included; the card says so);
* ERC-20 `Transfer` (3 topics) — symbol and decimals from the built-in token list (the phone's
  list); unknown tokens in raw base units with the address;
* ERC-721 `Transfer` (4 topics) and ERC-1155 `TransferSingle` / `TransferBatch` — NFTs in/out by
  token ID;
* `Deposit` / `Withdrawal` of the chain's canonical wrapped native coin (WETH9 emits no Transfer on
  wrap/unwrap); the same events from any other contract are ignored.

Outcomes and what the card allows:

| status | shown | send button |
|---|---|---|
| `ok` | "Your balance changes (simulated)": −100 USDC, −0.000066 ETH … | Send to phone |
| `reverts` | "Reverts: *reason*" (Error(string), Panic codes, custom-error selector, out of gas, insufficient funds) | **Blocked**: no override |
| `no_changes` | "Balance changes unavailable on this node" — fallback: `eth_call` says it does not revert, `eth_estimateGas` fits the gas limit | Send to phone |
| `unavailable` | "Couldn't simulate: *why*" (node down, odd answer) | **Send anyway** |

The revert block is enforced in Rust too: `send::sign_start` refuses a quote whose latest
simulation in this session reverted (SendError kind `reverts`), whichever card it came from. No
third-party simulation service and no API keys are used: only the node in Settings.

### Node support (checked 2026-10-11)

All six default nodes answer `eth_simulateV1` with `traceTransfers`
(`sim::tests::live_default_nodes`, run with `cargo test -- --ignored`):

| chain | default node | eth_simulateV1 |
|---|---|---|
| Ethereum (1) | ethereum-rpc.publicnode.com | yes |
| Base (8453) | mainnet.base.org | yes |
| Optimism (10) | optimism-rpc.publicnode.com | yes |
| Arbitrum One (42161) | arbitrum-one-rpc.publicnode.com | yes |
| Polygon (137) | polygon-bor-rpc.publicnode.com | yes |
| Sepolia (11155111) | ethereum-sepolia-rpc.publicnode.com | yes |

Others probed: eth.drpc.org, base-rpc.publicnode.com, mainnet.optimism.io,
arb1.arbitrum.io/rpc, sepolia.base.org — yes; cloudflare-eth.com — no (-32601, so the eth_call
fallback; at the time its eth_call also failed, giving "unavailable"); polygon-rpc.com,
rpc.sepolia.org, rpc.flashbots.net — refused or unreachable without a key.

## Wire format (optional, `signEip1559` only)

```json
"hostSimulation": {
  "changes": [
    {"asset": "native", "delta": "-66112467575160", "symbol": "ETH", "decimals": 18},
    {"asset": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "delta": "-100000000", "symbol": "USDC", "decimals": 6},
    {"asset": "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", "delta": "-1", "tokenId": "1"}
  ],
  "node": "ethereum-rpc.publicnode.com",
  "block": "0x18f603b"
}
```

Strict, like the rest of the request (`HostSimulation.java`); a malformed claim refuses the whole
request:

* exactly `changes`, `node`, `block`; each change exactly `asset` + `delta`, optionally `symbol`,
  `decimals`, `tokenId`; nothing else (the transaction's own field set stays exact too);
* `asset`: `"native"` or a lower-case 0x address (not zero); `delta`: non-zero canonical decimal
  integer, magnitude < 2^256; `tokenId`: canonical decimal < 2^256, not for `native`, excludes
  `decimals`; `decimals`: JSON integer 0–36; `symbol`: 1–16 of `[A-Za-z0-9.+_-]`;
* at most 16 changes, no asset (+token ID) twice; `node`: host[:port] only, ≤ 100 characters (the
  companion strips scheme, credentials, path and query); `block`: canonical hex quantity < 2^63;
* only for EIP-1559 requests: message requests keep their exact field sets and refuse it.

The companion sends it only for a complete `ok` simulation with ≤ 16 changes. A shared vector
(`app/src/test/resources/host-simulation-vector.json`) is produced by the Rust side from a
recorded node answer and parsed by the JVM test.

## Phone side (`SimulationCheck.java`)

The box "THE MAC'S SIMULATION · NOT VERIFIED BY THIS PHONE" sits below the review and the
technical details: "The Mac says your balance changes by" (amounts named from the phone's own
token/NFT lists; for an unknown token, raw base units with the Mac's label only in quotes, marked
unverified), "Simulated by the Mac" (node, block, "this phone cannot check any of these numbers"),
then any mismatch rows. The approval prompt, the sign button and the phone's own rows are
unchanged by the claim.

From the same parsed request it signs, the phone derives the change each asset may show:

| decoded call | expected |
|---|---|
| native transfer of v | native −v (0 if sent to itself); to a listed token contract (WETH) a gain of that token is allowed |
| ERC-20 `transfer(p, a)` | token −a (0 if p is this wallet) |
| `transferFrom(f, p, a)` | token +a if p is this wallet, −a if f is; on an unlisted contract also the ERC-721 reading (NFT #a ±1) — either reading may match |
| `approve` / `increaseAllowance` / `setApprovalForAll` | nothing moves |
| NFT `safeTransferFrom` / batch | each token ID ±1 (ERC-721) or ±amount (ERC-1155) |
| Uniswap swap | each "you give" exactly or at most, each "you get" exactly or at least (the decoded bounds); payouts to this wallet's own address may add gains |

The native coin is then widened by the fee: down to −(gas limit × max fee) more on Ethereum,
Sepolia and Polygon; on Base, Optimism and Arbitrum only the upper end is checked (their L1 data
fee has no offline bound). Fungible amounts tolerate 2 base units (rebasing-token rounding).

It is a **contradiction** (red DANGER row) when:

1. a decoded asset's claimed change (missing = 0) is outside its range — e.g. the phone decoded
   "send 100 USDC" and the Mac claims −0, −1 or +100 USDC, or a native send whose ETH stays;
2. the Mac claims a gain the decoded call gives no way to get (the phone sees only outflow) —
   e.g. +5 ETH on a token transfer, any token on an approval;
3. the Mac names a token from the phone's list with another symbol or other decimals (or the native
   coin with another symbol / not 18 decimals).

A claimed **loss** of an asset the decoding doesn't move is not a contradiction — a contract can
use an earlier approval — but gets a WARNING row: "The Mac also reports changes that the phone's
decoding of this call does not explain … if you did not expect this, reject."

## Tests

* JVM `HostSimulationTest` (23): optional field; exact field sets; canonical/limited numbers,
  strings, sizes and duplicates; message requests refuse the field; never signed (byte-identical
  signature, identical review); the shared Mac vector; contradictions for transfers (missing,
  smaller, reversed, other token, mislabelled, gains), extra outflows (warning only), self
  transfers, unknown tokens, native fee bounds (L1 and rollup), WETH deposit, approvals, the
  ERC-20/721 ambiguity, NFTs by token ID, swaps (min out, exact in, unexpected gains, ETH in).
* Rust `sim::tests` (15, + 1 ignored live test): deltas from recorded mainnet `eth_simulateV1`
  answers (USDC transfer, ETH send, WETH deposit, BAYC transfer, ETH→USDC swap through
  SwapRouter02 where the router's internal wrap and pool transfers net out), ERC-1155 batches,
  spoofed Deposit events, reverts (Error(string), insufficient funds), Panic and custom errors,
  the eth_call fallback (no revert, revert, gas limit too low, node failure), the phone claim's
  schema and node-label sanitising, the 16-change limit, per-transaction caching. Plus
  `verify::the_host_simulation_field_never_affects_verification`.
* Device: `tools/dev-device/simtest.sh` (not yet run on a phone).

## On-phone test steps (manual)

1. Pair as usual (`usbsigntest.sh`), unlock, complete the backup check.
2. `aoa_client.py sign-test --chain-id 0x1 --gas-limit 0x186a0 --to 0xa0b8…eb48 --data <transfer 100 USDC> --host-simulation honest.json`:
   the review reads "Send 100 USDC"; below the technical details the box shows −100 USDC and
   −0.000066 ETH, "Simulated by the Mac … cannot check", no red row. Approve: the host verifies.
3. Same with a lying claim (`+5 ETH`, no USDC): the same review, plus the red row naming both
   problems. Reject.
4. Same with an extra key in the claim: the phone answers "hostSimulation fields do not match
   schema" and shows nothing to approve.
5. Same without the field: no box.
6. On the Mac, with a node from Settings: send more USDC than the wallet holds → "Reverts: ERC20:
   transfer amount exceeds balance", the send button is blocked, nothing reaches the phone.
