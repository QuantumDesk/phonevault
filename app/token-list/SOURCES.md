# Built-in token list: sources

`app/src/main/res/raw/tokens.json` is the ERC-20 list compiled into the APK (as `R.raw.tokens`)
and into the Mac companion (`companion/src-tauri/src/tokens.rs` uses `include_bytes!` on the same
file). It is display metadata only: it turns a raw `uint256` into "50 USDC" on the review screen.
It never changes what is signed.

(This file lives outside `res/raw` on purpose: Android resource names cannot contain a second dot,
and `tokens.sources.md` would collide with `tokens.json` as `R.raw.tokens`.)

## Integrity

- The SHA-256 of `tokens.json` is pinned twice: `TokenList.PINNED_SHA256` (phone) and
  `tokens::PINNED_SHA256` (companion). Both refuse the whole list if the bytes differ, so the list
  changes only together with a code change and an app release. On the phone a refused list makes
  every contract "unknown" and the review says why.
- Loader rules (same on both sides): strict JSON (no duplicate keys, no unknown fields), version
  1, chain in the phone's allow-list, address in exact EIP-55 casing and not zero, symbol 1-11
  ASCII letters/digits, name printable ASCII, decimals 0-36, no duplicate address or symbol per
  chain.
- Tests: `TokenListTest` (JVM) checks the file against the pin, the rules, and an independent
  second entry of the Circle USDC addresses. `tokens.rs` tests check the file against the
  companion pin AND the pin written in `TokenList.java`, so the two cannot drift.
- `tools/verify_token_list.py` asks public nodes for each contract's `symbol()`/`decimals()`
  (second check; last run 2026-09-27: all 30 decimals match; on-chain symbols match except
  USDT0 on Optimism/Arbitrum whose on-chain symbol is `USD₮0` with a non-ASCII ₮, listed as the
  ASCII `USDT0` the Uniswap list and USDT0 docs use).
- Signed, updatable lists are future work ([ROADMAP.md](../../ROADMAP.md), G4).

## Changing the list

1. Edit `tokens.json` (one entry per line, EIP-55 addresses: `cast to-check-sum-address`).
2. Add the entry's source below.
3. `shasum -a 256 app/src/main/res/raw/tokens.json` and update BOTH pins.
4. `python3 tools/verify_token_list.py`, the JVM tests and `cargo test`.

## Sources (fetched 2026-09-27)

Abbreviations for the canonical lists, as fetched that day:

- **Circle** — Circle, "USDC contract addresses", https://developers.circle.com/stablecoins/usdc-contract-addresses (issuer).
- **Tether** — Tether, "Supported protocols", https://tether.to/en/supported-protocols/ (issuer; lists Ethereum USD₮).
- **USDT0** — USDT0 deployments, https://docs.usdt0.to/technical-documentation/deployments (issuer of USDT0; "Token" row per chain).
- **Sky** — Sky (MakerDAO) chainlog, https://chainlog.sky.money/api/mainnet/active.json (`MCD_DAI`; L1 DAI bridges).
- **Superchain** — Superchain Token List v10.0.1769 (2026-09-08), https://static.optimism.io/optimism.tokenlist.json (canonical list for OP Mainnet and Base).
- **Arbitrum** — Arbitrum "Arb Whitelist Era" v2.0.0 (2026-09-27), https://tokenlist.arbitrum.io/ArbTokenLists/arbed_arb_whitelist_era.json (canonical bridge list).
- **Polygon** — Polygon "Popular Tokens" v3 (2026-09-22), https://api-polygon-tokens.polygon.technology/tokenlists/popular.tokenlist.json (`wrappedTokens`, PoS entries).
- **Uniswap** — Uniswap Labs Default list v22.21.0 (2026-09-23), https://tokens.uniswap.org (multi-chain; used as a cross-check everywhere, and as the source for cbBTC and Sepolia WETH).
- **Coinbase** — Coinbase announcements of cbBTC (same address on every chain), https://www.coinbase.com/blog/coinbase-wrapped-btc-cbbtc-is-now-live and, for Arbitrum, https://x.com/coinbase/status/1858918988815695926 (coinbase.com refuses automated fetches; the address is confirmed by the Uniswap list and on chain).
- **on-chain** — an `eth_call` made on 2026-09-27 against the chain itself (e.g. an L2 token's `l1Token()`/`remoteToken()` pointing at the Ethereum original, or a bridge's `l2Token()`).

| Chain | Symbol | Address | Dec | Source |
|---|---|---|---|---|
| 1 Ethereum | USDC | 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 | 6 | Circle; Uniswap |
| 1 | USDT | 0xdAC17F958D2ee523a2206206994597C13D831ec7 | 6 | Tether; Uniswap |
| 1 | DAI | 0x6B175474E89094C44Da98b954EedeAC495271d0F | 18 | Sky `MCD_DAI`; Uniswap |
| 1 | WETH | 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 | 18 | Uniswap; Superchain; Arbitrum (L1 entries) |
| 1 | WBTC | 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599 | 8 | Uniswap; Superchain; Arbitrum (L1 entries) |
| 1 | cbBTC | 0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf | 8 | Coinbase; Uniswap |
| 10 OP Mainnet | USDC | 0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85 | 6 | Circle ("OP Mainnet"); Superchain; Uniswap |
| 10 | USDT0 | 0x01bFF41798a0BcF287b996046Ca68b395DbC1071 | 6 | USDT0 (Optimism "Token"); Superchain; Uniswap |
| 10 | USDT | 0x94b008aA00579c1307B0EF2c499aD98a8ce58e58 | 6 | Superchain; Uniswap. Bridged: on-chain `l1Token()` = Ethereum USDT. Name says "bridged from Ethereum". |
| 10 | DAI | 0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1 | 18 | Superchain; Uniswap; on-chain: Sky `OPTIMISM_DAI_BRIDGE.l2Token()` |
| 10 | WETH | 0x4200000000000000000000000000000000000006 | 18 | Superchain (OP Stack predeploy); Uniswap |
| 10 | WBTC | 0x68f180fcCe6836688e9084f035309E29Bf0A2095 | 8 | Superchain; Uniswap; on-chain `l1Token()` = Ethereum WBTC |
| 137 Polygon | USDC | 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359 | 6 | Circle ("Polygon PoS"); Polygon; Uniswap |
| 137 | USDT0 | 0xc2132D05D31c914a87C6611C10748AEb04B58e8F | 6 | USDT0 (Polygon PoS "Token"); Polygon (USDT → symbol USDT0); Uniswap (as USDT). On-chain symbol `USDT0`. |
| 137 | DAI | 0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063 | 18 | Polygon (PoS mapping of Ethereum DAI); Uniswap |
| 137 | WETH | 0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619 | 18 | Polygon (PoS mapping of ETH); Uniswap |
| 137 | WBTC | 0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6 | 8 | Polygon (PoS mapping of Ethereum WBTC); Uniswap |
| 8453 Base | USDC | 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 | 6 | Circle; Superchain; Uniswap |
| 8453 | USDT | 0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2 | 6 | Superchain. Bridged: on-chain `l1Token()` = Ethereum USDT. Not issued by Tether on Base; name says "bridged from Ethereum". |
| 8453 | DAI | 0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb | 18 | Superchain; Uniswap; on-chain `remoteToken()` = Ethereum DAI |
| 8453 | WETH | 0x4200000000000000000000000000000000000006 | 18 | Superchain (OP Stack predeploy); Uniswap |
| 8453 | cbBTC | 0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf | 8 | Coinbase; Uniswap |
| 42161 Arbitrum One | USDC | 0xaf88d065e77c8cC2239327C5EDb3A432268e5831 | 6 | Circle ("Arbitrum"); Uniswap |
| 42161 | USDT0 | 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9 | 6 | USDT0 (Arbitrum One "Token"); Uniswap |
| 42161 | DAI | 0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1 | 18 | Arbitrum; Uniswap; on-chain: Sky `ARBITRUM_DAI_BRIDGE.l2Dai()` |
| 42161 | WETH | 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1 | 18 | Arbitrum; Uniswap |
| 42161 | WBTC | 0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f | 8 | Arbitrum; Uniswap |
| 42161 | cbBTC | 0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf | 8 | Coinbase (Arbitrum announcement); Uniswap |
| 11155111 Sepolia | USDC | 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238 | 6 | Circle ("Ethereum Sepolia", testnet); Superchain |
| 11155111 | WETH | 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14 | 18 | Uniswap (Sepolia) |

Deliberately left out: bridged USDC.e (legacy, superseded by native USDC on every chain above),
USDT on Arbitrum/Polygon under the symbol "USDT" (those addresses are now USDT0 and are listed
as such), WBTC on Base (none in the canonical lists), DAI/WBTC on Sepolia (no issuer deployment).
