package dev.phonevault.signer;

import java.util.Arrays;
import java.util.Locale;

/**
 * The watch-only view of the standard wallet's Bitcoin accounts on one network, derived from the
 * SAME BIP-39 seed as the EVM accounts: the master fingerprint and the account-level public keys
 * m/84'/coin'/a' (P2WPKH, BIP-84), m/86'/coin'/a' (P2TR, BIP-86), and, for coins received by a
 * Ledger/Trezor-era wallet restored from the same phrase, m/49'/coin'/a' (P2SH-P2WPKH, BIP-49) and
 * m/44'/coin'/a' (P2PKH, BIP-44), for a = 0…19 (the USB "account" 1…20). No private key is kept: everything below the account level (receive/change
 * addresses, change and input verification) uses public derivation.
 *
 * <p>Built inside the seed-key window ({@link #derive}) and cached in memory for the unlocked
 * session only; never persisted, so a modified file cannot make the phone call a foreign output
 * "change".
 */
final class BtcWallet {
    static final int ACCOUNTS = SeedVault.MAX_ACCOUNT_INDEX + 1; // 20, as for EVM
    /** Highest address index btcShowAddress accepts. */
    static final int MAX_ADDRESS_INDEX = 9_999;
    /** Highest receive/change index accepted in a PSBT derivation (non-hardened). */
    static final int MAX_PSBT_INDEX = 999_999;

    enum Type {
        P2WPKH("p2wpkh", 84, "wpkh(", ")", "Native SegWit"),
        P2TR("p2tr", 86, "tr(", ")", "Taproot"),
        /** BIP-49 "Nested SegWit": P2WPKH wrapped in P2SH (3… / 2…). */
        P2SH_P2WPKH("p2sh-p2wpkh", 49, "sh(wpkh(", "))", "Nested SegWit"),
        /** BIP-44 "Legacy": P2PKH (1… / m…, n…). */
        P2PKH("p2pkh", 44, "pkh(", ")", "Legacy");

        final String wire;
        final int purpose;
        final String descriptorOpen, descriptorClose;
        final String label;

        Type(String wire, int purpose, String descriptorOpen, String descriptorClose, String label) {
            this.wire = wire;
            this.purpose = purpose;
            this.descriptorOpen = descriptorOpen;
            this.descriptorClose = descriptorClose;
            this.label = label;
        }

        /** Signed with ECDSA over a 33-byte key named in PSBT_IN/OUT_BIP32_DERIVATION (everything but Taproot). */
        boolean ecdsa() { return this != P2TR; }

        static Type fromWire(String v) {
            for (Type t : values()) if (t.wire.equals(v)) return t;
            throw new IllegalArgumentException("Unsupported Bitcoin address type (p2wpkh, p2tr, p2sh-p2wpkh or p2pkh)");
        }

        /** The type whose BIP-44-style purpose is {@code purpose}, or null. */
        static Type forPurpose(int purpose) {
            for (Type t : values()) if (t.purpose == purpose) return t;
            return null;
        }
    }

    final BtcNetwork network;
    private final byte[] fingerprint;
    private final Bip32.Key[][] accounts = new Bip32.Key[Type.values().length][ACCOUNTS];

    private BtcWallet(BtcNetwork network, byte[] fingerprint) {
        this.network = network;
        this.fingerprint = fingerprint;
    }

    /** Derive every account's public key from the BIP-39 seed. Private intermediates are destroyed. */
    static BtcWallet derive(byte[] seed, BtcNetwork network) {
        Bip32.Key master = Bip32.master(seed);
        try {
            BtcWallet w = new BtcWallet(network, master.fingerprint());
            for (Type t : Type.values()) {
                Bip32.Key coin = Bip32.derive(master, t.purpose | Bip32.HARDENED, network.coinType | Bip32.HARDENED);
                try {
                    for (int a = 0; a < ACCOUNTS; a++) {
                        Bip32.Key account = Bip32.child(coin, a | Bip32.HARDENED);
                        w.accounts[t.ordinal()][a] = account.neuter();
                        account.destroy();
                    }
                } finally {
                    coin.destroy();
                }
            }
            return w;
        } finally {
            master.destroy();
        }
    }

    /** The private key at m/purpose'/coin'/account'/change/index, for signing. The caller destroys it. */
    static Bip32.Key derivePrivate(byte[] seed, BtcNetwork network, Type type, int account, int change, int index) {
        checkAccount(account);
        Bip32.Key master = Bip32.master(seed);
        try {
            return Bip32.derive(master, type.purpose | Bip32.HARDENED, network.coinType | Bip32.HARDENED,
                    account | Bip32.HARDENED, change, index);
        } finally {
            master.destroy();
        }
    }

    byte[] fingerprint() { return fingerprint.clone(); }

    /** Lowercase 8-hex master fingerprint (descriptor convention). */
    String fingerprintHex() { return BtcCrypto.hex(fingerprint); }

    Bip32.Key account(Type type, int account) {
        checkAccount(account);
        return accounts[type.ordinal()][account];
    }

    static void checkAccount(int account) {
        if (account < 0 || account >= ACCOUNTS) throw new IllegalArgumentException("Bitcoin account must be 1-" + ACCOUNTS);
    }

    int[] accountPath(Type type, int account) {
        return new int[] {type.purpose | Bip32.HARDENED, network.coinType | Bip32.HARDENED, account | Bip32.HARDENED};
    }

    /** "m/84'/0'/0'". */
    String accountPathString(Type type, int account) { return Bip32.pathString(accountPath(type, account)); }

    String addressPathString(Type type, int account, int change, int index) {
        return accountPathString(type, account) + "/" + change + "/" + index;
    }

    String xpub(Type type, int account) { return account(type, account).serializePublic(network.xpubVersion); }

    /** wpkh([fp/84h/0h/0h]xpub…/<0;1>/*)#checksum; tr(…), sh(wpkh(…)) or pkh(…) for the other types. */
    String descriptor(Type type, int account) {
        String body = type.descriptorOpen + "[" + fingerprintHex() + "/" + type.purpose + "h/" + network.coinType + "h/"
                + account + "h]" + xpub(type, account) + "/<0;1>/*" + type.descriptorClose;
        return Descriptors.withChecksum(body);
    }

    /** Compressed public key at …/change/index (public derivation from the account key). */
    byte[] publicKey(Type type, int account, int change, int index) {
        if (change != 0 && change != 1) throw new IllegalArgumentException("change must be 0 or 1");
        if (index < 0 || index > MAX_PSBT_INDEX) throw new IllegalArgumentException("address index out of range");
        Bip32.Key k = Bip32.derive(account(type, account), change, index);
        return k.pub.clone();
    }

    /** The output script paying to the key at …/change/index. */
    byte[] scriptPubKey(Type type, int account, int change, int index) {
        return scriptFor(type, publicKey(type, account, change, index));
    }

    static byte[] scriptFor(Type type, byte[] compressedPub) {
        switch (type) {
            case P2WPKH: return BtcScript.p2wpkh(BtcCrypto.hash160(compressedPub));
            case P2SH_P2WPKH: return BtcScript.p2sh(BtcCrypto.hash160(redeemScript(compressedPub)));
            case P2PKH: return BtcScript.p2pkhScript(BtcCrypto.hash160(compressedPub));
            default: return BtcScript.p2tr(BtcCrypto.taprootOutputKey(Arrays.copyOfRange(compressedPub, 1, 33)));
        }
    }

    /** BIP-49 redeem script: the P2WPKH witness program 0x0014 ‖ HASH160(pubkey). */
    static byte[] redeemScript(byte[] compressedPub) { return BtcScript.p2wpkh(BtcCrypto.hash160(compressedPub)); }

    String address(Type type, int account, int change, int index) {
        return BtcScript.address(scriptPubKey(type, account, change, index), network);
    }

    /** "Account 1 · Native SegWit". */
    static String accountLabel(Type type, int account) {
        return String.format(Locale.ROOT, "Account %d · %s", account + 1, type.label);
    }
}
