// Networks the phone has a reviewed profile for (must match `quote` in lib.rs). The node is
// untrusted input: anything it supplies is shown here and on the phone before anything is signed.

export interface Network { id: number; name: string; short: string; rpc: string; explorer: string; symbol: string; l2: boolean; testnet: boolean }

export const NETWORKS: Network[] = [
  { id: 8453, name: "Base", short: "Base", rpc: "https://mainnet.base.org", explorer: "https://basescan.org", symbol: "ETH", l2: true, testnet: false },
  { id: 1, name: "Ethereum", short: "Ethereum", rpc: "https://ethereum-rpc.publicnode.com", explorer: "https://etherscan.io", symbol: "ETH", l2: false, testnet: false },
  { id: 10, name: "Optimism", short: "OP", rpc: "https://optimism-rpc.publicnode.com", explorer: "https://optimistic.etherscan.io", symbol: "ETH", l2: true, testnet: false },
  { id: 42161, name: "Arbitrum One", short: "Arbitrum", rpc: "https://arbitrum-one-rpc.publicnode.com", explorer: "https://arbiscan.io", symbol: "ETH", l2: true, testnet: false },
  { id: 137, name: "Polygon", short: "Polygon", rpc: "https://polygon-bor-rpc.publicnode.com", explorer: "https://polygonscan.com", symbol: "POL", l2: false, testnet: false },
  { id: 11155111, name: "Sepolia", short: "Sepolia", rpc: "https://ethereum-sepolia-rpc.publicnode.com", explorer: "https://sepolia.etherscan.io", symbol: "ETH", l2: false, testnet: true },
];

export const DEFAULT_CHAIN = 8453;
export const byId = (id: number): Network => NETWORKS.find((n) => n.id === id) ?? NETWORKS[0];
/** Display name of a chain id; unknown ids read "chain <id>". */
export const netName = (id: number): string => NETWORKS.find((n) => n.id === id)?.name ?? `chain ${id}`;
