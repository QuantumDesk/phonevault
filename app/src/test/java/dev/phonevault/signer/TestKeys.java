package dev.phonevault.signer;

import org.web3j.crypto.Credentials;

/** Well-known public test keys and phrases. Never real funds. */
final class TestKeys {
    private TestKeys() {}

    /** A widely published example private key (never holds funds). */
    static final Credentials EVM_KEY = Credentials.create("4c0883a69102937d6231471b5dbb6204fe51296170827966f278a5e6f4f4f5f");

    /** BIP-39 test vector: 12 words, all "abandon" but the checksum word. */
    static final String ABANDON_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /** BIP-39 test vector: 24 words, all "abandon" but the checksum word. */
    static final String ABANDON_24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
            + "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
}
