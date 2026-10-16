package dev.phonevault.signer;

import org.web3j.crypto.Keys;

/**
 * Non-secret description of the key the phone is signing with right now: which account of which
 * wallet, under which account numbering. Published together with the credentials (MainActivity,
 * under its state lock) so every screen and USB answer names the same identity the key belongs to.
 */
final class SigningAccount {
    final int index;
    /** "Account 2" or the label typed on the phone. */
    final String name;
    /** True for a passphrase ("25th word") wallet. */
    final boolean passphrase;
    /** BIP-32 master fingerprint of the wallet (shown for passphrase wallets). */
    final String fingerprint;
    /** Lowercase 0x address. */
    final String address;
    /** The wallet's account numbering: which path this account's key was derived at. */
    final AccountScheme scheme;

    SigningAccount(int index, String name, boolean passphrase, String fingerprint, String address) {
        this(index, name, passphrase, fingerprint, address, AccountScheme.STANDARD);
    }

    SigningAccount(int index, String name, boolean passphrase, String fingerprint, String address, AccountScheme scheme) {
        if (scheme == null) throw new IllegalArgumentException("no account numbering");
        this.index = index;
        this.name = name;
        this.passphrase = passphrase;
        this.fingerprint = fingerprint;
        this.address = AccountBook.address(address);
        this.scheme = scheme;
    }

    /** "Account 2" or "Account 2 (passphrase wallet)". */
    String headline() { return passphrase ? name + " (passphrase wallet)" : name; }

    /**
     * The approval-screen row: who signs, in full. Ledger Live numbering adds its path (Account 2
     * is a different address there), so the user can match it with the other wallet.
     */
    String signingWith() {
        return headline() + (passphrase ? " · fingerprint " + fingerprint : "")
                + (scheme == AccountScheme.STANDARD ? "" : " · Ledger Live numbering " + path())
                + "\n" + Keys.toChecksumAddress(address);
    }

    String path() { return scheme.pathString(index); }

    /** getAddress extras: 1-based account number and wallet kind (no label, no fingerprint). */
    String accountNumber() { return String.valueOf(index + 1); }
    String walletKind() { return passphrase ? "passphrase" : "standard"; }
}
