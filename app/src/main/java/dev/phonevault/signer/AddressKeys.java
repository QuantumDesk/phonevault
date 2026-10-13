package dev.phonevault.signer;

import org.web3j.crypto.Keys;

import java.util.Locale;

/**
 * How the address book and recipient history name an address. EVM addresses are lowercase
 * {@code 0x…} (as before); Bitcoin addresses are {@code btc:<network>:<address>} (network
 * bitcoin/testnet/signet, address exactly as the phone renders it: lowercase bech32 or
 * case-sensitive base58), so the same string on two networks is two different entries. A
 * history "wallet" is the EVM account address, or {@code btc-wallet:<network>:<fingerprint>}.
 */
final class AddressKeys {
    private AddressKeys() {}

    static final String BTC = "btc:";
    private static final String BTC_WALLET = "btc-wallet:";
    private static final String NETWORKS = "(bitcoin|testnet|signet)";

    static String btc(BtcNetwork network, String address) { return normalize(BTC + network.wire + ":" + address); }

    static boolean isBtc(String key) { return key != null && key.startsWith(BTC); }

    /** Canonical form of an address key; throws IllegalArgumentException for anything else. */
    static String normalize(String key) {
        if (key == null) throw new IllegalArgumentException("not an address");
        if (key.matches("0x[0-9a-fA-F]{40}")) return key.toLowerCase(Locale.ROOT);
        if (key.matches("btc:" + NETWORKS + ":([a-z0-9]{14,90}|[1-9A-HJ-NP-Za-km-z]{25,35})")) return key;
        throw new IllegalArgumentException("not an address");
    }

    /** Canonical form for lookups (no validation): EVM keys are case-insensitive, Bitcoin ones are not. */
    static String canon(String key) { return isBtc(key) ? key : key.toLowerCase(Locale.ROOT); }

    static String walletKey(String key) {
        if (key == null) throw new IllegalArgumentException("not a wallet");
        if (key.matches("0x[0-9a-fA-F]{40}")) return key.toLowerCase(Locale.ROOT);
        if (key.matches("btc-wallet:" + NETWORKS + ":[0-9a-f]{8}")) return key;
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
        String c = Keys.toChecksumAddress(key);
        return c.substring(0, 6) + "…" + c.substring(c.length() - 4);
    }

    static String shortBtc(String address) {
        return address.length() <= 16 ? address : address.substring(0, 8) + "…" + address.substring(address.length() - 6);
    }

    /** Network suffix for a contact list ("" for EVM). */
    static String networkSuffix(String key) {
        String n = network(key);
        return n == null ? "" : " · " + BtcNetwork.fromWire(n).label;
    }
}
