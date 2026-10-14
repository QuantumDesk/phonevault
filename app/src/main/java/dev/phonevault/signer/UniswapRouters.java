package dev.phonevault.signer;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Uniswap router contracts the phone can explain, pinned per chain. A swap is only decoded when
 * the transaction's {@code to} is one of these addresses on that chain; the same calldata sent to
 * any other contract is refused as an unknown contract call.
 *
 * <p>Sources (both must agree, see {@code app/token-list/ROUTER-SOURCES.md}): Uniswap's deployment
 * pages (developers.uniswap.org v4 deployments and v3 per-chain deployments) and the
 * universal-router repository's {@code deploy-addresses/*.json}; each address was then checked on
 * chain (non-empty code, identical code size per release across chains, the chain's wrapped native
 * token and PoolManager embedded as immutables; SwapRouter02's {@code WETH9()} returns the listed
 * wrapper).
 */
final class UniswapRouters {
    private UniswapRouters() {}

    enum Version {
        /** Universal Router 2.0.0: V2/V3 swap inputs are (recipient, amount, amount, path, payerIsUser). */
        UR_2_0("Universal Router 2.0"),
        /** Universal Router 2.1.1 / 2.1.2: V2/V3 inputs and V4 swap structs gain minHopPriceX36. */
        UR_2_1("Universal Router 2.1"),
        /** SwapRouter02 (swap-router-contracts): exactInput/exactOutput(+Single), multicall. */
        SWAP_ROUTER_02("SwapRouter02");

        final String label;
        Version(String label) { this.label = label; }
        boolean universal() { return this != SWAP_ROUTER_02; }
    }

    static final class Router {
        final long chainId;
        final String address;      // lower-case
        final Version version;
        /** The router's wrapped-native token (WETH9 immutable), lower-case. */
        final String wrappedNative;
        /** Symbol for the wrapped native token when it is not in the token list (WPOL on Polygon). */
        final String wrappedSymbol;

        Router(long chainId, String address, Version version, String wrappedNative, String wrappedSymbol) {
            this.chainId = chainId;
            this.address = address.toLowerCase(Locale.ROOT);
            this.version = version;
            this.wrappedNative = wrappedNative.toLowerCase(Locale.ROOT);
            this.wrappedSymbol = wrappedSymbol;
        }
    }

    static final String WETH_1 = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    static final String WETH_OP_STACK = "0x4200000000000000000000000000000000000006";
    static final String WETH_42161 = "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1";
    static final String WPOL_137 = "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270";
    static final String WETH_11155111 = "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14";

    /** {chainId, EIP-55 address, version}. Change only with ROUTER-SOURCES.md. */
    static final String[][] ENTRIES = {
            {"1", "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af", "UR_2_0"},
            {"1", "0x4C82D1fBFe28C977cBB58D8C7FF8FCF9F70a2cCA", "UR_2_1"},
            {"1", "0x23617e59A5925b2A4Bf75d73ff6711cD0b29De85", "UR_2_1"},
            {"1", "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "SWAP_ROUTER_02"},
            {"10", "0x851116D9223fabED8E56C0E6b8Ad0c31d98B3507", "UR_2_0"},
            {"10", "0x8B844f885672f333Bc0042cB669255f93a4C1E6b", "UR_2_1"},
            {"10", "0xC09255D86DB563cBc11C2fCf4a0C512e160111B4", "UR_2_1"},
            {"10", "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "SWAP_ROUTER_02"},
            {"137", "0x1095692A6237d83C6a72F3F5eFEdb9A670C49223", "UR_2_0"},
            {"137", "0x8B844f885672f333Bc0042cB669255f93a4C1E6b", "UR_2_1"},
            {"137", "0xDc264714F68d84CF29BC605589405E78bDBE7C9f", "UR_2_1"},
            {"137", "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "SWAP_ROUTER_02"},
            {"8453", "0x6fF5693b99212Da76ad316178A184AB56D299b43", "UR_2_0"},
            {"8453", "0xFdf682F51FE81Aa4898F0AE2163d8A55c127fbC7", "UR_2_1"},
            {"8453", "0xd6145b2D3F379919E8CdEda7B97e37c4b2Ca9c40", "UR_2_1"},
            {"8453", "0x2626664c2603336E57B271c5C0b26F421741e481", "SWAP_ROUTER_02"},
            {"42161", "0xA51afAFe0263b40EdaEf0Df8781eA9aa03E381a3", "UR_2_0"},
            {"42161", "0x8B844f885672f333Bc0042cB669255f93a4C1E6b", "UR_2_1"},
            {"42161", "0x2d01411773c8C24805306E89A41F7855C3c4Fe65", "UR_2_1"},
            {"42161", "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "SWAP_ROUTER_02"},
            // Sepolia: the "2.0" Universal Router there is a different build (code size differs from
            // every mainnet 2.0 deployment), so it is deliberately NOT listed.
            {"11155111", "0x7DfD4F31be6814D2906BDE155c3e1B146EAc1468", "UR_2_1"},
            {"11155111", "0x7E4f6c5e954Da5c61B3423D81E2277431Ac043f3", "UR_2_1"},
            {"11155111", "0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E", "SWAP_ROUTER_02"},
    };

    private static final Map<String, Router> BY_KEY;

    static {
        Map<String, Router> map = new HashMap<>();
        for (String[] e : ENTRIES) {
            long chain = Long.parseLong(e[0]);
            Router r = new Router(chain, e[1], Version.valueOf(e[2]), wrappedNative(chain), chain == 137 ? "WPOL" : "WETH");
            map.put(chain + ":" + r.address, r);
        }
        BY_KEY = Collections.unmodifiableMap(map);
    }

    static String wrappedNative(long chainId) {
        if (chainId == 1) return WETH_1;
        if (chainId == 10 || chainId == 8453) return WETH_OP_STACK;
        if (chainId == 42161) return WETH_42161;
        if (chainId == 137) return WPOL_137;
        if (chainId == 11155111) return WETH_11155111;
        throw new IllegalArgumentException("no wrapped native token for chain " + chainId);
    }

    /** The pinned router at {@code address} on {@code chainId}, or null. */
    static Router lookup(long chainId, String address) {
        return address == null ? null : BY_KEY.get(chainId + ":" + address.toLowerCase(Locale.ROOT));
    }
}
