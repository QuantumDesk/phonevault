package dev.phonevault.signer;

import org.web3j.crypto.Keys;

import java.util.Locale;

/**
 * How the address book and recipient history name an address. EVM addresses are lowercase
 * {@code 0x…}; Bitcoin addresses are {@code btc:<network>:<address>} (network
 * bitcoin/testnet/signet, address exactly as the phone renders it: lowercase bech32 or
 * case-sensitive base58), so the same string on two networks is two different entries. A
 * history "wallet" is the EVM account address, or {@code btc-wallet:<network>:<fingerprint>}.
 */
final class AddressKeys {
    private AddressKeys() {}

    static final String BTC = "btc:";
    static final String BTC_WALLET = "btc-wallet:";
    private static final String NETWORKS = "(bitcoin|testnet|signet)";

    static String btc(BtcNetwork network, String address) { return normalize(BTC + network.wire + ":" + address); }

    static boolean isBtc(String key) { return key != null && key.startsWith(BTC); }

    /** Canonical form of an address key; throws IllegalArgumentException for anything else. */
    static String normalize(String key) {
        if (key == null) throw new IllegalArgumentException("not an address");
        if (Addresses.isEvm(key)) return Addresses.lowercase(key);
        if (key.matches(BTC + NETWORKS + ":([a-z0-9]{14,90}|[1-9A-HJ-NP-Za-km-z]{25,35})")) return key;
        throw new IllegalArgumentException("not an address");
    }

    /** Canonical form for lookups (no validation): EVM keys are case-insensitive, Bitcoin ones are not. */
    static String canon(String key) { return isBtc(key) ? key : key.toLowerCase(Locale.ROOT); }

    static String walletKey(String key) {
        if (key == null) throw new IllegalArgumentException("not a wallet");
        if (Addresses.isEvm(key)) return Addresses.lowercase(key);
        if (key.matches(BTC_WALLET + NETWORKS + ":[0-9a-f]{8}")) return key;
        throw new IllegalArgumentException("not a wallet");
    }

    /** The Bitcoin address inside a key (or the key itself for EVM). */
    static String address(String key) { return isBtc(key) ? key.substring(key.indexOf(':', BTC.length()) + 1) : key; }

    /** "bitcoin" / "testnet" / "signet", or null for EVM. */
    static String network(String key) { return isBtc(key) ? key.substring(BTC.length(), key.indexOf(':', BTC.length())) : null; }

    /** Full address as shown on screens: EIP-55 checksum for EVM, the address for Bitcoin. */
    static String display(String key) { return isBtc(key) ? address(key) : Keys.toChecksumAddress(key); }

    /** "0xAbCd…1234" or "bc1qcr8t…306fyu". */
    static String shortForm(String key) {
        if (isBtc(key)) return shortBtc(address(key));
        return Addresses.shortEvm(key);
    }

    static String shortBtc(String address) {
        return Addresses.shorten(address, 8, 6, 16);
    }

    /** Network suffix for a contact list ("" for EVM). */
    static String networkSuffix(String key) {
        String n = network(key);
        return n == null ? "" : " · " + BtcNetwork.fromWire(n).label;
    }
}
