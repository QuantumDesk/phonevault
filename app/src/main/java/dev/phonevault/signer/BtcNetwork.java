package dev.phonevault.signer;

/**
 * The Bitcoin networks the phone signs for. Testnet and signet share address and extended-key
 * encodings (and BIP-44 coin type 1), so a coin's network is ultimately the host's claim: the
 * phone names it prominently and in amber on every test-network screen.
 */
enum BtcNetwork {
    BITCOIN("bitcoin", "Bitcoin", 0, "bc", 0x00, 0x05, 0x0488B21E, "BTC"),
    TESTNET("testnet", "Bitcoin TESTNET", 1, "tb", 0x6F, 0xC4, 0x043587CF, "tBTC"),
    SIGNET("signet", "Bitcoin SIGNET", 1, "tb", 0x6F, 0xC4, 0x043587CF, "sBTC");

    /** Wire name in USB requests. */
    final String wire;
    /** What the screens call it. */
    final String label;
    /** BIP-44 coin type (hardened in paths). */
    final int coinType;
    final String hrp;
    final int p2pkhVersion, p2shVersion;
    /** Extended public key version bytes (xpub / tpub). */
    final int xpubVersion;
    final String unit;

    BtcNetwork(String wire, String label, int coinType, String hrp, int p2pkhVersion, int p2shVersion, int xpubVersion, String unit) {
        this.wire = wire;
        this.label = label;
        this.coinType = coinType;
        this.hrp = hrp;
        this.p2pkhVersion = p2pkhVersion;
        this.p2shVersion = p2shVersion;
        this.xpubVersion = xpubVersion;
        this.unit = unit;
    }

    boolean test() { return this != BITCOIN; }

    static BtcNetwork fromWire(String value) {
        for (BtcNetwork n : values()) if (n.wire.equals(value)) return n;
        throw new IllegalArgumentException("Unsupported Bitcoin network (bitcoin, testnet or signet)");
    }
}
