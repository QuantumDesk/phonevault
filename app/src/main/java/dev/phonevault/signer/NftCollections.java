package dev.phonevault.signer;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * The small NFT collection list compiled into the APK. Display metadata only: it names a
 * collection on the review and tells the phone that {@code approve}/{@code transferFrom} on that
 * contract move an NFT, not fungible tokens. It never changes what is signed. Any contract not
 * listed here is an unknown collection: its name is never guessed and never taken from the host.
 *
 * <p>Pinned in code (the APK signature covers it); every entry is cited in
 * {@code app/token-list/NFT-SOURCES.md} and checked on chain (ERC-165 {@code 0x80ac58cd} and
 * {@code name()}), and {@code NftReviewTest} re-checks the casing and the chain allow-list.
 */
final class NftCollections {
    private NftCollections() {}

    static final class Collection {
        final long chainId;
        final String address;   // lower-case
        final String name;
        final String standard;  // "ERC-721"

        Collection(long chainId, String address, String name, String standard) {
            this.chainId = chainId;
            this.address = address.toLowerCase(Locale.ROOT);
            this.name = name;
            this.standard = standard;
        }
    }

    /** {chainId, EIP-55 address, name, standard}. Change only with NFT-SOURCES.md. */
    static final String[][] ENTRIES = {
            {"1", "0xC36442b4a4522E871399CD717aBDD847Ab11FE88", "Uniswap V3 Positions", "ERC-721"},
            {"10", "0xC36442b4a4522E871399CD717aBDD847Ab11FE88", "Uniswap V3 Positions", "ERC-721"},
            {"137", "0xC36442b4a4522E871399CD717aBDD847Ab11FE88", "Uniswap V3 Positions", "ERC-721"},
            {"42161", "0xC36442b4a4522E871399CD717aBDD847Ab11FE88", "Uniswap V3 Positions", "ERC-721"},
            {"8453", "0x03a520b32C04BF3bEEf7BEb72E919cf822Ed34f1", "Uniswap V3 Positions", "ERC-721"},
            {"11155111", "0x1238536071E1c677A632429e3655c799b22cDA52", "Uniswap V3 Positions", "ERC-721"},
            {"1", "0xbD216513d74C8cf14cf4747E6AaA6420FF64ee9e", "Uniswap v4 Positions", "ERC-721"},
            {"10", "0x3C3Ea4B57a46241e54610e5f022E5c45859A1017", "Uniswap v4 Positions", "ERC-721"},
            {"8453", "0x7C5f5A4bBd8fD63184577525326123B519429bDc", "Uniswap v4 Positions", "ERC-721"},
            {"42161", "0xd88F38F930b7952f2DB2432Cb002E7abbF3dD869", "Uniswap v4 Positions", "ERC-721"},
            {"137", "0x1Ec2eBf4F37E7363FDfe3551602425af0B3ceef9", "Uniswap v4 Positions", "ERC-721"},
            {"11155111", "0x429ba70129df741B2Ca2a85BC3A2a3328e5c09b4", "Uniswap v4 Positions", "ERC-721"},
            {"1", "0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85", "ENS .eth names", "ERC-721"},
    };

    private static final Map<String, Collection> BY_KEY;

    static {
        Map<String, Collection> map = new HashMap<>();
        for (String[] e : ENTRIES) {
            Collection c = new Collection(Long.parseLong(e[0]), e[1], e[2], e[3]);
            map.put(c.chainId + ":" + c.address, c);
        }
        BY_KEY = Collections.unmodifiableMap(map);
    }

    /** The listed collection at {@code address} on {@code chainId}, or null. */
    static Collection lookup(long chainId, String address) {
        return address == null ? null : BY_KEY.get(chainId + ":" + address.toLowerCase(Locale.ROOT));
    }
}
