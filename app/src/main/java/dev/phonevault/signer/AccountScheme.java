package dev.phonevault.signer;

import org.web3j.crypto.Bip32ECKeyPair;

/**
 * How a wallet numbers its Ethereum accounts ("Account numbering"). Both read the same recovery
 * phrase; they differ only in which BIP-32 path "Account N" is:
 * <ul>
 *   <li>{@link #STANDARD}: m/44'/60'/0'/0/i — MetaMask, Trezor, Rabby, Phone Vault's default;</li>
 *   <li>{@link #LEDGER_LIVE}: m/44'/60'/i'/0/0 — Ledger Live (one hardened account per account).</li>
 * </ul>
 * Account 1 (i = 0) is the same address under both: m/44'/60'/0'/0/0. That address is the wallet's
 * identity ({@link AccountBook#walletId}), so switching numbering never changes which wallet this is.
 */
enum AccountScheme {
    STANDARD("standard", "Standard"),
    LEDGER_LIVE("ledger-live", "Ledger Live");

    private static final int HARDENED = Bip32ECKeyPair.HARDENED_BIT;

    /** The USB spelling ({@code listAddresses} "scheme", getAddress "scheme"). */
    final String wire;
    /** What the phone's screens call it. */
    final String label;

    AccountScheme(String wire, String label) {
        this.wire = wire;
        this.label = label;
    }

    /** Exactly "standard" or "ledger-live"; anything else throws. */
    static AccountScheme fromWire(String wire) {
        for (AccountScheme s : values()) if (s.wire.equals(wire)) return s;
        throw new IllegalArgumentException("scheme must be \"standard\" or \"ledger-live\"");
    }

    /** The BIP-32 path of account {@code index} (0-based), below the master key. */
    int[] path(int index) {
        if (index < 0 || index > SeedVault.MAX_ACCOUNT_INDEX) throw new IllegalArgumentException("account index out of range");
        return this == STANDARD
                ? new int[] {44 | HARDENED, 60 | HARDENED, 0 | HARDENED, 0, index}
                : new int[] {44 | HARDENED, 60 | HARDENED, index | HARDENED, 0, 0};
    }

    /** "m/44'/60'/0'/0/3" or "m/44'/60'/3'/0/0". */
    String pathString(int index) {
        path(index); // range check
        return this == STANDARD ? "m/44'/60'/0'/0/" + index : "m/44'/60'/" + index + "'/0/0";
    }

    /** The pattern for help text: "m/44'/60'/0'/0/n" or "m/44'/60'/n'/0/0". */
    String pathPattern() { return this == STANDARD ? "m/44'/60'/0'/0/n" : "m/44'/60'/n'/0/0"; }
}
