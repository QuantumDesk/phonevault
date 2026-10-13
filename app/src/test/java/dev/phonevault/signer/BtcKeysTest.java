package dev.phonevault.signer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.Arrays;

/**
 * BIP-32 test vector 1, and the BIP-84 / BIP-86 published vectors for the "abandon … about"
 * mnemonic: account xpubs, keys and addresses derived from the same BIP-39 seed the EVM path uses.
 */
public final class BtcKeysTest {
    static final String MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    private static final int H = Bip32.HARDENED;

    static byte[] seed() { return SeedVault.bip39Seed(MNEMONIC, ""); }

    static BtcWallet wallet(BtcNetwork network) { return BtcWallet.derive(seed(), network); }

    /** zpub → the same key in standard xpub encoding (the phone exports xpub/tpub, not SLIP-132). */
    static String zpubToXpub(String zpub) {
        byte[] b = Base58.decodeCheck(zpub);
        byte[] v = BtcCrypto.unhex("0488b21e");
        System.arraycopy(v, 0, b, 0, 4);
        return Base58.encodeCheck(b);
    }

    @Test public void bip32TestVector1() {
        Bip32.Key m = Bip32.master(BtcCrypto.unhex("000102030405060708090a0b0c0d0e0f"));
        int x = 0x0488B21E;
        assertEquals("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", m.serializePublic(x));
        assertEquals("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", Bip32.derive(m, H).serializePublic(x));
        assertEquals("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", Bip32.derive(m, H, 1).serializePublic(x));
        assertEquals("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5", Bip32.derive(m, H, 1, 2 | H).serializePublic(x));
        assertEquals("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV", Bip32.derive(m, H, 1, 2 | H, 2).serializePublic(x));
        assertEquals("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", Bip32.derive(m, H, 1, 2 | H, 2, 1000000000).serializePublic(x));
        // public derivation agrees with private derivation (non-hardened steps)
        Bip32.Key parentPub = Bip32.derive(m, H, 1, 2 | H).neuter();
        assertEquals(Bip32.derive(m, H, 1, 2 | H, 2, 1000000000).serializePublic(x), Bip32.derive(parentPub, 2, 1000000000).serializePublic(x));
        try { Bip32.child(parentPub, H); fail("hardened from a public key"); } catch (IllegalArgumentException expected) { }
        // parse round trip
        assertEquals(m.serializePublic(x), Bip32.parsePublic(m.serializePublic(x), x).serializePublic(x));
    }

    @Test public void destroyZeroesTheSecret() {
        Bip32.Key m = Bip32.master(seed());
        byte[] secret = m.privateKey();
        m.destroy();
        assertFalse(m.hasPrivate());
        assertArrayEquals(new byte[32], secret);
    }

    @Test public void bip84Vectors() {
        BtcWallet w = wallet(BtcNetwork.BITCOIN);
        assertEquals("73c5da0a", w.fingerprintHex());
        assertEquals("m/84'/0'/0'", w.accountPathString(BtcWallet.Type.P2WPKH, 0));
        assertEquals(zpubToXpub("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"),
                w.xpub(BtcWallet.Type.P2WPKH, 0));
        assertEquals("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c", BtcCrypto.hex(w.publicKey(BtcWallet.Type.P2WPKH, 0, 0, 0)));
        assertEquals("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", w.address(BtcWallet.Type.P2WPKH, 0, 0, 0));
        assertEquals("03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77", BtcCrypto.hex(w.publicKey(BtcWallet.Type.P2WPKH, 0, 0, 1)));
        assertEquals("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", w.address(BtcWallet.Type.P2WPKH, 0, 0, 1));
        assertEquals("03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6", BtcCrypto.hex(w.publicKey(BtcWallet.Type.P2WPKH, 0, 1, 0)));
        assertEquals("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", w.address(BtcWallet.Type.P2WPKH, 0, 1, 0));
        // private derivation (what signing uses) gives the same key as BIP-84's WIF KyZpNDKn…
        Bip32.Key k = BtcWallet.derivePrivate(seed(), BtcNetwork.BITCOIN, BtcWallet.Type.P2WPKH, 0, 0, 0);
        byte[] wif = Base58.decodeCheck("KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d");
        assertArrayEquals(Arrays.copyOfRange(wif, 1, 33), k.privateKey());
        k.destroy();
    }

    @Test public void bip86Vectors() {
        BtcWallet w = wallet(BtcNetwork.BITCOIN);
        assertEquals("xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
                w.xpub(BtcWallet.Type.P2TR, 0));
        String[][] v = {
                {"0", "0", "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115", "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"},
                {"0", "1", "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145", "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb", "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"},
                {"1", "0", "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef", "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc", "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"},
        };
        for (String[] r : v) {
            int change = Integer.parseInt(r[0]), index = Integer.parseInt(r[1]);
            byte[] pub = w.publicKey(BtcWallet.Type.P2TR, 0, change, index);
            assertEquals(r[2], BtcCrypto.hex(Arrays.copyOfRange(pub, 1, 33)));
            assertEquals(r[3], BtcCrypto.hex(BtcCrypto.taprootOutputKey(Arrays.copyOfRange(pub, 1, 33))));
            assertEquals("5120" + r[3], BtcCrypto.hex(w.scriptPubKey(BtcWallet.Type.P2TR, 0, change, index)));
            assertEquals(r[4], w.address(BtcWallet.Type.P2TR, 0, change, index));
        }
    }

    @Test public void testnetAccountsAndDescriptors() {
        // Independent values: embit 0.8.0 (tools/btc_fixtures.py session)
        BtcWallet t = wallet(BtcNetwork.TESTNET);
        assertEquals("m/84'/1'/0'", t.accountPathString(BtcWallet.Type.P2WPKH, 0));
        assertEquals("tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M", t.xpub(BtcWallet.Type.P2WPKH, 0));
        assertEquals("wpkh([73c5da0a/84h/1h/0h]tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)#lxek0ef2",
                t.descriptor(BtcWallet.Type.P2WPKH, 0));
        assertEquals("tr([73c5da0a/86h/1h/19h]tpubDDfvzhdVV4uoiJftotfajj1LJxH41kCvzPpnvx7Mci711F9Nw4oEaYsHRcmMqLxgF7BVwgzur1gbRVKCQka7ewude4yMdgPXHgJZJMPe56j/<0;1>/*)#8ke5zlp8",
                t.descriptor(BtcWallet.Type.P2TR, 19));
        BtcWallet m = wallet(BtcNetwork.BITCOIN);
        assertEquals("wpkh([73c5da0a/84h/0h/1h]xpub6CatWdiZiodmYVtWLtEQsAg1H9ooS1bmsJUBwQ83FE1Fyk386FWcyicJgEZv3quZSJKA5dh5Lo2PbubMGxCfZtRthV6ST2qquL9w3HSzcUn/<0;1>/*)#0gc743qk",
                m.descriptor(BtcWallet.Type.P2WPKH, 1));
        assertTrue(Descriptors.valid(m.descriptor(BtcWallet.Type.P2TR, 0)));
        // signet shares testnet's encodings
        assertEquals(t.xpub(BtcWallet.Type.P2TR, 3), wallet(BtcNetwork.SIGNET).xpub(BtcWallet.Type.P2TR, 3));
        assertTrue(t.address(BtcWallet.Type.P2WPKH, 0, 0, 0).startsWith("tb1q"));
        try { m.account(BtcWallet.Type.P2WPKH, 20); fail("account 21"); } catch (IllegalArgumentException expected) { }
    }

    @Test public void sameSeedAsTheEvmWallet() {
        // The fingerprint SeedVault shows for passphrase wallets is the same master key.
        assertEquals("73C5DA0A", SeedVault.masterFingerprint(seed()));
        assertEquals("73c5da0a", wallet(BtcNetwork.BITCOIN).fingerprintHex());
    }
}
