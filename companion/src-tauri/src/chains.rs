//! The EVM networks this app knows: exactly the chains the phone has a reviewed profile for
//! (Eip1559Request.supportedChain; tested in wc.rs). Every per-chain fact lives in this one table.

/// One network. The three names are the spellings the UI already shows in different places; they
/// are kept apart on purpose rather than changing what any screen says.
pub struct Chain {
    pub id: u64,
    /// In a quote's `network` field (Send, token send, speed-up, WalletConnect/extension review).
    pub quote_name: &'static str,
    /// In WalletConnect and browser-extension text (session proposals, switch-chain, errors).
    pub dapp_name: &'static str,
    /// In the menu-bar item and incoming-payment notifications.
    pub watch_name: &'static str,
    /// The native coin.
    pub symbol: &'static str,
    /// A rollup that also charges an L1 data fee nobody can bound in advance.
    pub l1_data_fee: bool,
    /// The wrapped native coin (WETH, or WPOL on Polygon): its Deposit/Withdrawal logs count as
    /// balance changes in a simulation.
    pub wrapped_native: &'static str,
    /// The node used when Settings names none.
    pub default_rpc: &'static str,
    /// Initial log window in blocks for the watcher and NFT scan (≈ the last day, or what public
    /// nodes still serve without an archive token).
    pub log_window: u128,
}

/// In the order the watcher checks them.
pub const CHAINS: [Chain; 6] = [
    Chain {
        id: 8453,
        quote_name: "Base",
        dapp_name: "Base",
        watch_name: "Base",
        symbol: "ETH",
        l1_data_fee: true,
        wrapped_native: "0x4200000000000000000000000000000000000006",
        default_rpc: "https://mainnet.base.org",
        log_window: 21_600,
    },
    Chain {
        id: 1,
        quote_name: "Ethereum Mainnet",
        dapp_name: "Ethereum",
        watch_name: "Ethereum",
        symbol: "ETH",
        l1_data_fee: false,
        wrapped_native: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        default_rpc: "https://ethereum-rpc.publicnode.com",
        log_window: 7_200,
    },
    Chain {
        id: 10,
        quote_name: "Optimism",
        dapp_name: "Optimism",
        watch_name: "Optimism",
        symbol: "ETH",
        l1_data_fee: true,
        wrapped_native: "0x4200000000000000000000000000000000000006",
        default_rpc: "https://optimism-rpc.publicnode.com",
        log_window: 9_000,
    },
    Chain {
        id: 42161,
        quote_name: "Arbitrum One",
        dapp_name: "Arbitrum One",
        watch_name: "Arbitrum One",
        symbol: "ETH",
        l1_data_fee: true,
        wrapped_native: "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
        default_rpc: "https://arbitrum-one-rpc.publicnode.com",
        log_window: 20_000,
    },
    Chain {
        id: 137,
        quote_name: "Polygon",
        dapp_name: "Polygon",
        watch_name: "Polygon",
        symbol: "POL",
        l1_data_fee: false,
        wrapped_native: "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",
        default_rpc: "https://polygon-bor-rpc.publicnode.com",
        log_window: 2_000,
    },
    Chain {
        id: 11155111,
        quote_name: "Sepolia Testnet",
        dapp_name: "Sepolia (testnet)",
        watch_name: "Sepolia",
        symbol: "ETH",
        l1_data_fee: false,
        wrapped_native: "0xfff9976782d46cc05630d1f6ebab18b2324d6b14",
        default_rpc: "https://ethereum-sepolia-rpc.publicnode.com",
        log_window: 7_200,
    },
];

/// The chain ids, in table order.
pub const IDS: [u64; CHAINS.len()] = {
    let mut ids = [0; CHAINS.len()];
    let mut i = 0;
    while i < CHAINS.len() {
        ids[i] = CHAINS[i].id;
        i += 1;
    }
    ids
};

pub fn get(id: u64) -> Option<&'static Chain> {
    CHAINS.iter().find(|c| c.id == id)
}

/// The phone has a reviewed profile for this chain.
pub fn allowed(id: u64) -> bool {
    get(id).is_some()
}

/// The same for a chain id read as u128 (from a node or a quote).
pub fn allowed_u128(id: u128) -> bool {
    u64::try_from(id).is_ok_and(allowed)
}

/// The native coin's symbol; "ETH" for a chain not in the table.
pub fn native_symbol(id: u64) -> &'static str {
    get(id).map_or("ETH", |c| c.symbol)
}

/// A rollup with an L1 data fee (Base, Optimism, Arbitrum One).
pub fn has_l1_data_fee(id: u128) -> bool {
    u64::try_from(id).ok().and_then(get).is_some_and(|c| c.l1_data_fee)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_consistent() {
        let mut ids = IDS.to_vec();
        ids.sort();
        ids.dedup();
        assert_eq!(ids, vec![1, 10, 137, 8453, 42161, 11155111]);
        for c in &CHAINS {
            assert!(crate::verify::is_address(c.wrapped_native) && c.wrapped_native == c.wrapped_native.to_lowercase());
            assert!(c.default_rpc.starts_with("https://") && c.log_window >= 1_000);
        }
        assert_eq!(IDS.iter().filter(|c| has_l1_data_fee(**c as u128)).count(), 3);
        assert!(!allowed(56) && !allowed_u128(u128::from(u64::MAX) + 1));
        assert_eq!((native_symbol(137), native_symbol(56)), ("POL", "ETH"));
    }
}
