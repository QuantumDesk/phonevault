package dev.phonevault.signer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.Locale;

/**
 * Bech32 / Bech32m (BIP-173 and BIP-350 test vectors, all of them), Base58Check, the standard
 * address encodings, and BIP-380 descriptor checksums.
 */
public final class BtcEncodingTest {

    // ---- BIP-173 "valid Bech32" + BIP-350 "valid Bech32m" strings
    private static final String[] VALID_BECH32 = {
            "A12UEL5L", "a12uel5l",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl",
    };
    private static final String[] VALID_BECH32M = {
            "A1LQFN3A", "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
    };
    // ---- BIP-173 / BIP-350 invalid strings (either variant)
    private static final String[] INVALID_STRINGS = {
            " 1nwldj5", "\u007f1axkwrx", "\u00801eym55h",
            "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
            "pzry9x0s0muk", "1pzry9x0s0muk", "x1b4n0q5v", "li1dgmt3", "de1lg7wtÿ", "A1G7SGD8", "10a06t8", "1qzzfhee",
            " 1xj0phk", "\u007f1g6xzxy", "\u00801vctc34",
            "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
            "qyrz8wqd2c9m", "1qyrz8wqd2c9m", "y1b0jsk6g", "lt1igcx5c0", "in1muywd", "mm1crxm3i", "au1s5cgom", "M1VUXWEZ",
            "16plkw9", "1p2gdwpf",
    };
    // ---- BIP-350 valid segwit addresses → scriptPubKey
    private static final String[][] VALID_ADDRESSES = {
            {"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"},
            {"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
            {"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"},
            {"BC1SW50QGDZ25J", "6002751e"},
            {"bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323"},
            {"tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
            {"tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
            {"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
    };
    // ---- BIP-350 invalid segwit addresses + BIP-173 ones that stay invalid
    private static final String[] INVALID_ADDRESSES = {
            "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
            "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
            "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
            "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
            "bc1pw5dgrnzv",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
            "bc1gmk9yu",
            // BIP-173 list
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", "bc1rw5uspcuh",
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
            // BIP-173 v1+ addresses with a Bech32 checksum: invalid since BIP-350
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
            "BC1SW50QA3JX3S", "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
    };

    static int vectorCount() {
        return VALID_BECH32.length + VALID_BECH32M.length + INVALID_STRINGS.length + VALID_ADDRESSES.length + INVALID_ADDRESSES.length;
    }

    @Test public void bech32AndBech32mStrings() {
        for (String s : VALID_BECH32) {
            Bech32.Decoded d = Bech32.decode(s);
            assertEquals(s, Bech32.Encoding.BECH32, d.encoding);
            assertEquals(s.toLowerCase(Locale.ROOT), Bech32.encode(d.hrp, d.data, d.encoding));
        }
        for (String s : VALID_BECH32M) {
            Bech32.Decoded d = Bech32.decode(s);
            assertEquals(s, Bech32.Encoding.BECH32M, d.encoding);
            assertEquals(s.toLowerCase(Locale.ROOT), Bech32.encode(d.hrp, d.data, d.encoding));
        }
        for (String s : INVALID_STRINGS) {
            try {
                Bech32.decode(s);
                fail("accepted " + s);
            } catch (IllegalArgumentException expected) { }
        }
    }

    @Test public void segwitAddresses() {
        for (String[] v : VALID_ADDRESSES) {
            String lower = v[0].toLowerCase(Locale.ROOT);
            String hrp = lower.substring(0, 2);
            Bech32.WitnessProgram w = Bech32.decodeSegwit(hrp, v[0]);
            byte[] spk = BtcCrypto.unhex(v[1]);
            assertEquals(v[0], w.version == 0 ? 0 : 0x50 + w.version, spk[0] & 0xff);
            assertEquals(spk.length - 2, w.program.length);
            assertArrayEquals(java.util.Arrays.copyOfRange(spk, 2, spk.length), w.program);
            assertEquals(lower, Bech32.segwitAddress(hrp, w.version, w.program));
        }
        for (String a : INVALID_ADDRESSES) {
            for (String hrp : new String[] {"bc", "tb"}) {
                try {
                    Bech32.decodeSegwit(hrp, a);
                    fail("accepted " + a);
                } catch (IllegalArgumentException expected) { }
            }
        }
    }

    @Test public void standardScriptsRenderAsAddresses() {
        // BIP-350 / BIP-84 / BIP-86 examples
        assertEquals("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", BtcScript.address(BtcCrypto.unhex("0014751e76e8199196d454941c45d1b3a323f1433bd6"), BtcNetwork.BITCOIN));
        assertEquals("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", BtcScript.address(BtcCrypto.unhex("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), BtcNetwork.BITCOIN));
        assertEquals("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", BtcScript.address(BtcCrypto.unhex("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"), BtcNetwork.SIGNET));
        // P2PKH / P2SH: the Bitcoin wiki's classic examples (hash160 → address)
        assertEquals("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", BtcScript.address(BtcCrypto.unhex("76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac"), BtcNetwork.BITCOIN));
        assertEquals("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", BtcScript.address(BtcCrypto.unhex("a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87"), BtcNetwork.BITCOIN));
        assertEquals(BtcScript.Kind.OP_RETURN, BtcScript.kind(BtcCrypto.unhex("6a0b68656c6c6f20776f726c64")));
        assertEquals(BtcScript.Kind.OP_RETURN, BtcScript.kind(BtcCrypto.unhex("6a")));
        assertEquals("pushes must be well formed", BtcScript.Kind.UNKNOWN, BtcScript.kind(BtcCrypto.unhex("6a0b6865")));
        assertEquals("bare multisig has no address", BtcScript.Kind.UNKNOWN, BtcScript.kind(BtcCrypto.unhex("5121" + "02" + "11".repeat(32) + "51ae")));
        assertEquals("future witness versions are refused", BtcScript.Kind.UNKNOWN, BtcScript.kind(BtcCrypto.unhex("5210751e76e8199196d454941c45d1b3a323")));
        assertEquals("bc1q w508 d6qe jxtd\ng4y5 r3za rvar y0c5\nxw7k v8f3 t4",
                BtcScript.grouped("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 4));
    }

    @Test public void base58check() {
        byte[] payload = BtcCrypto.unhex("0077bff20c60e522dfaa3350c39b030a5d004e839a");
        assertEquals("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Base58.encodeCheck(payload));
        assertArrayEquals(payload, Base58.decodeCheck("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        try { Base58.decodeCheck("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"); fail(); } catch (IllegalArgumentException expected) { }
        try { Base58.decode("0OIl"); fail(); } catch (IllegalArgumentException expected) { }
        assertEquals("1111", Base58.encode(new byte[4]));
    }

    @Test public void descriptorChecksums() {
        // BIP-380 test vectors
        assertTrue(Descriptors.valid("raw(deadbeef)#89f8spxm"));
        assertFalse(Descriptors.valid("raw(deadbeef)"));
        assertFalse(Descriptors.valid("raw(deadbeef)#"));
        assertFalse(Descriptors.valid("raw(deadbeef)#89f8spxmx"));
        assertFalse(Descriptors.valid("raw(deadbeef)#89f8spx"));
        assertFalse(Descriptors.valid("raw(deedbeef)#89f8spxm"));
        assertFalse(Descriptors.valid("raw(deedbeef)##9f8spxm"));
        assertFalse(Descriptors.valid("raw(Ü)#00000000"));
        assertEquals("89f8spxm", Descriptors.checksum("raw(deadbeef)"));
        // Independent: embit 0.8.0 add_checksum for this wallet's account descriptors (tools/btc_fixtures.py)
        assertEquals("qf45pmyh", Descriptors.checksum("wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/<0;1>/*)"));
        assertEquals("xf07c0qd", Descriptors.checksum("tr([73c5da0a/86h/0h/0h]xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/<0;1>/*)"));
    }
}
