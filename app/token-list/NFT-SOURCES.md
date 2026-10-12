# Built-in NFT collection list: sources

`NftCollections.java` names a handful of ERC-721 collections on the review and tells the phone
that `approve`/`transferFrom` on them move an NFT, not fungible tokens. Display only; it never
changes what is signed. Any other contract is reviewed as an "unknown collection" — its name is
never guessed and never taken from the host. Changes only with an app release.

## Sources (fetched 2026-10-11)

| Chain | Name shown | Address (EIP-55) | Source | On chain |
|---|---|---|---|---|
| 1, 10, 137, 42161 | Uniswap V3 Positions | 0xC36442b4a4522E871399CD717aBDD847Ab11FE88 | Uniswap v3 deployment pages, `NonfungiblePositionManager` (developers.uniswap.org/contracts/v3/reference/deployments/*) | `name()` "Uniswap V3 Positions NFT-V1" |
| 8453 | Uniswap V3 Positions | 0x03a520b32C04BF3bEEf7BEb72E919cf822Ed34f1 | same (Base page) | same |
| 11155111 | Uniswap V3 Positions | 0x1238536071E1c677A632429e3655c799b22cDA52 | same (Ethereum page, Sepolia column) | same |
| 1 | Uniswap v4 Positions | 0xbD216513d74C8cf14cf4747E6AaA6420FF64ee9e | Uniswap v4 deployments page, `PositionManager` (developers.uniswap.org/contracts/v4/deployments) | `name()` "Uniswap v4 Positions NFT" |
| 10 | Uniswap v4 Positions | 0x3C3Ea4B57a46241e54610e5f022E5c45859A1017 | same | same |
| 8453 | Uniswap v4 Positions | 0x7C5f5A4bBd8fD63184577525326123B519429bDc | same | same |
| 42161 | Uniswap v4 Positions | 0xd88F38F930b7952f2DB2432Cb002E7abbF3dD869 | same | same |
| 137 | Uniswap v4 Positions | 0x1Ec2eBf4F37E7363FDfe3551602425af0B3ceef9 | same | same |
| 11155111 | Uniswap v4 Positions | 0x429ba70129df741B2Ca2a85BC3A2a3328e5c09b4 | same | same |
| 1 | ENS .eth names | 0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85 | ENS docs, "Deployments", Base Registrar (https://docs.ens.domains/learn/deployments) | no `name()`; ERC-721 by ERC-165 |

Every entry answers `supportsInterface(0x80ac58cd)` (ERC-721) with true on its chain
(`eth_call`, public RPC nodes, 2026-10-11). `NftReviewTest` checks the EIP-55 casing and the
chain allow-list.

Deliberately left out: popular art collections (BAYC, Azuki, …) — there is no issuer-published
address page this project could fetch and cite alongside an on-chain check; they are reviewed as
unknown collections, which is the safe default.
