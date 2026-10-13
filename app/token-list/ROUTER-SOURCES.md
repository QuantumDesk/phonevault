# Pinned Uniswap routers: sources

`UniswapRouters.java` pins the router contracts whose calldata the phone decodes into a swap
review (`UniversalRouter.java`, `SwapDecoder.java`). A call to any other address is an unknown
contract call and is refused. Like the token list, the pins change only with an app release.

## Sources (fetched 2026-10-11)

Every address is in BOTH of these, character for character (case-insensitive):

- **Docs (v4)** — Uniswap, "Uniswap v4 Deployments", https://developers.uniswap.org/contracts/v4/deployments
  (redirected from docs.uniswap.org/contracts/v4/deployments): the "Universal Router",
  "Universal Router 2.1.1" and "Universal Router 2.1.2" rows per chain.
- **Docs (v3)** — Uniswap, per-chain v3 deployment pages, e.g.
  https://developers.uniswap.org/contracts/v3/reference/deployments/ethereum-deployments
  (also `base-`, `arbitrum-`, `optimism-`, `polygon-deployments`): the `SwapRouter02` and
  `UniversalRouter` rows (Ethereum page: mainnet and Sepolia columns).
- **Repo** — `Uniswap/universal-router`, branch `main`, `deploy-addresses/{mainnet,optimism,polygon,base,arbitrum,sepolia}.json`
  (`UniversalRouterV2`, `UniversalRouterV2_1_1`, `UniversalRouterV2_1_2`).

| Chain | Router | Address (EIP-55) | Version |
|---|---|---|---|
| 1 Ethereum | Universal Router 2.0 | 0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af | UR_2_0 |
| 1 | Universal Router 2.1.1 | 0x4C82D1fBFe28C977cBB58D8C7FF8FCF9F70a2cCA | UR_2_1 |
| 1 | Universal Router 2.1.2 | 0x23617e59A5925b2A4Bf75d73ff6711cD0b29De85 | UR_2_1 |
| 1 | SwapRouter02 | 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45 | SWAP_ROUTER_02 |
| 10 OP Mainnet | Universal Router 2.0 | 0x851116D9223fabED8E56C0E6b8Ad0c31d98B3507 | UR_2_0 |
| 10 | Universal Router 2.1.1 | 0x8B844f885672f333Bc0042cB669255f93a4C1E6b | UR_2_1 |
| 10 | Universal Router 2.1.2 | 0xC09255D86DB563cBc11C2fCf4a0C512e160111B4 | UR_2_1 |
| 10 | SwapRouter02 | 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45 | SWAP_ROUTER_02 |
| 137 Polygon | Universal Router 2.0 | 0x1095692A6237d83C6a72F3F5eFEdb9A670C49223 | UR_2_0 |
| 137 | Universal Router 2.1.1 | 0x8B844f885672f333Bc0042cB669255f93a4C1E6b | UR_2_1 |
| 137 | Universal Router 2.1.2 | 0xDc264714F68d84CF29BC605589405E78bDBE7C9f | UR_2_1 |
| 137 | SwapRouter02 | 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45 | SWAP_ROUTER_02 |
| 8453 Base | Universal Router 2.0 | 0x6fF5693b99212Da76ad316178A184AB56D299b43 | UR_2_0 |
| 8453 | Universal Router 2.1.1 | 0xFdf682F51FE81Aa4898F0AE2163d8A55c127fbC7 | UR_2_1 |
| 8453 | Universal Router 2.1.2 | 0xd6145b2D3F379919E8CdEda7B97e37c4b2Ca9c40 | UR_2_1 |
| 8453 | SwapRouter02 | 0x2626664c2603336E57B271c5C0b26F421741e481 | SWAP_ROUTER_02 |
| 42161 Arbitrum One | Universal Router 2.0 | 0xA51afAFe0263b40EdaEf0Df8781eA9aa03E381a3 | UR_2_0 |
| 42161 | Universal Router 2.1.1 | 0x8B844f885672f333Bc0042cB669255f93a4C1E6b | UR_2_1 |
| 42161 | Universal Router 2.1.2 | 0x2d01411773c8C24805306E89A41F7855C3c4Fe65 | UR_2_1 |
| 42161 | SwapRouter02 | 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45 | SWAP_ROUTER_02 |
| 11155111 Sepolia | Universal Router 2.1.1 | 0x7DfD4F31be6814D2906BDE155c3e1B146EAc1468 | UR_2_1 |
| 11155111 | Universal Router 2.1.2 | 0x7E4f6c5e954Da5c61B3423D81E2277431Ac043f3 | UR_2_1 |
| 11155111 | SwapRouter02 | 0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E | SWAP_ROUTER_02 |

Wrapped native token (the routers' `WETH9` immutable; used to explain WRAP/UNWRAP): Ethereum
`0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`, OP Mainnet and Base `0x4200000000000000000000000000000000000006`,
Arbitrum `0x82aF49447D8a07e3bd95BD0d56f35241523fBab1`, Polygon WPOL `0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270`,
Sepolia `0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14`. Where the token list lists that chain's WETH it is
the same contract (checked by `SwapReviewTest`); WPOL is not in the token list and is labelled from this pin.

## On-chain checks (2026-10-11, public RPC nodes)

For every pinned address: `eth_getCode` is non-empty; the runtime code embeds the chain's wrapped
native token (an immutable) and, for the Universal Routers, the chain's v4 PoolManager (from the
v4 deployments page); SwapRouter02's `WETH9()` returns the wrapper above. Code sizes are identical
per release on every chain (2.0: 19,499 bytes; 2.1.1: 24,546; 2.1.2: 24,380; SwapRouter02: 24,497),
which is how the per-version input layouts are tied to the deployed bytecode.

**Deliberately left out:** Sepolia's "Universal Router" 2.0 row (`0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b`):
its code is 19,540 bytes, not the 19,499 of every mainnet 2.0, so it is a different build whose
input layout this phone has not been checked against. Universal Router 1.x (older; NFT-marketplace
commands; not on the current docs pages) and the original SwapRouter (`0xE592…1564`) are also not pinned.

## Version semantics used by the decoder

From the tagged sources (`Uniswap/universal-router` tags `2.0.0`, `2.1.1`, `2.1.2`:
`contracts/libraries/Commands.sol`, `contracts/base/Dispatcher.sol`, `contracts/modules/Payments.sol`,
`contracts/modules/uniswap/v3/V3SwapRouter.sol`, `.../v2/V2SwapRouter.sol`; `Uniswap/v4-periphery`
at the submodule commits those tags pin — `444c526b` for 2.0.0, `3231810e` for 2.1.1, `545a5d2a` for
2.1.2 — `src/V4Router.sol`, `src/interfaces/IV4Router.sol`, `src/libraries/Actions.sol`,
`ActionConstants.sol`; `Uniswap/swap-router-contracts` `contracts/V3SwapRouter.sol`,
`libraries/Constants.sol`, `base/PeripheryPaymentsExtended.sol`):

- 2.0: V2/V3 swap inputs `(address,uint256,uint256,bytes|address[],bool)`; command mask `0x3f`.
- 2.1.x: those inputs gain a trailing `uint256[] minHopPriceX36`; V4 swap structs gain
  `minHopPriceX36` (`uint256` for single-hop, `uint256[]` for paths); mask `0x7f`; new commands
  `0x07` and `0x40` (0x40 is refused).
- Commands `0x00…0x0c` (except `0x03`, `0x07` on 2.0) and `0x10` keep the same meaning in all three.
- `CONTRACT_BALANCE` = 2^255 (Universal Router) but `0` (SwapRouter02's `amountIn`).
- Recipients `address(1)` = the caller, `address(2)` = the router, in both routers' swap functions;
  SwapRouter02's `unwrapWETH9`/`sweepToken` do not map them (the phone refuses them there).

## Real transactions used as test vectors

`app/src/test/resources/swap-vectors.json`: 23 transactions (15 Ethereum, 8 Base) fetched on
2026-10-11 with `eth_getBlockByNumber` from public RPC nodes, each with its explorer link
(etherscan.io / basescan.org); 21 decode, 2 are refused on purpose (`WRAP_ETH` to a third address;
a SwapRouter02 price-limited partial fill).

The same file also holds 5 SYNTHETIC entries (`"tx": "synthetic-…"`, each with a `"synthetic"`
description and no explorer link): hand-built attack and edge cases that real traffic does not
supply — a zero-minimum swap output paid back in the coin the wallet also gave (SwapRouter02
`unwrapWETH9`, Universal Router `UNWRAP_WETH` and `SWEEP`), which must show the No-minimum DANGER
rather than "unused input"; a 5% `PAY_PORTION` (shown as OTHER ADDRESS); a fee to the zero address
(refused). Their calldata comes from an independent Python ABI encoder and `SwapReviewTest`
re-encodes it with web3j and compares.
