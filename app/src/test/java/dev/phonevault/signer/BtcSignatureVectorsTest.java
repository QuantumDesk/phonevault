package dev.phonevault.signer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Published signature vectors: BIP-340 (every row of test-vectors.csv: signing and verification),
 * BIP-341 wallet test vectors (every scriptPubKey tweak and every key-path spending input:
 * SigMsg, sighash, tweaked key, signature), and the BIP-143 P2WPKH / P2SH-P2WPKH examples.
 */
public final class BtcSignatureVectorsTest {

    static String resource(String name) throws Exception {
        try (InputStream in = BtcSignatureVectorsTest.class.getResourceAsStream("/btc/" + name)) {
            if (in == null) throw new IllegalStateException("missing test resource " + name);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) > 0; ) out.write(buf, 0, n);
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    @Test public void bip340AllVectors() throws Exception {
        String[] lines = resource("bip340-test-vectors.csv").split("\r?\n");
        int signed = 0, verified = 0;
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].trim().isEmpty()) continue;
            String[] f = lines[i].split(",", -1);
            String index = f[0], sk = f[1], pk = f[2], aux = f[3], msg = f[4], sig = f[5];
            boolean expected = "TRUE".equals(f[6]);
            byte[] message = BtcCrypto.unhex(msg);
            if (!sk.isEmpty()) {
                byte[] produced = BtcCrypto.signSchnorr(BtcCrypto.unhex(sk), message, BtcCrypto.unhex(aux));
                assertEquals("vector " + index, sig.toLowerCase(), BtcCrypto.hex(produced));
                assertEquals("vector " + index + " public key", pk.toLowerCase(),
                        BtcCrypto.hex(Arrays.copyOfRange(BtcCrypto.pubCompressed(BtcCrypto.unhex(sk)), 1, 33)));
                signed++;
            }
            assertEquals("vector " + index + " verification", expected,
                    BtcCrypto.verifySchnorr(BtcCrypto.unhex(pk), message, BtcCrypto.unhex(sig)));
            verified++;
        }
        assertEquals(19, verified);
        assertEquals(8, signed);
    }

    @Test public void bip341ScriptPubKeyVectors() throws Exception {
        JSONArray all = new JSONObject(resource("bip341-wallet-test-vectors.json")).getJSONArray("scriptPubKey");
        for (int i = 0; i < all.length(); i++) {
            JSONObject v = all.getJSONObject(i);
            byte[] internal = BtcCrypto.unhex(v.getJSONObject("given").getString("internalPubkey"));
            JSONObject mid = v.getJSONObject("intermediary");
            byte[] root = mid.isNull("merkleRoot") ? null : BtcCrypto.unhex(mid.getString("merkleRoot"));
            assertEquals(mid.getString("tweak"), BtcCrypto.hex(BtcCrypto.tapTweak(internal, root)));
            byte[] q = BtcCrypto.taprootOutputKey(internal, root);
            assertEquals(mid.getString("tweakedPubkey"), BtcCrypto.hex(q));
            JSONObject exp = v.getJSONObject("expected");
            assertEquals(exp.getString("scriptPubKey"), BtcCrypto.hex(BtcScript.p2tr(q)));
            assertEquals(exp.getString("bip350Address"), BtcScript.address(BtcScript.p2tr(q), BtcNetwork.BITCOIN));
        }
        assertEquals(7, all.length());
    }

    @Test public void bip341KeyPathSpendingVectors() throws Exception {
        JSONObject k = new JSONObject(resource("bip341-wallet-test-vectors.json")).getJSONArray("keyPathSpending").getJSONObject(0);
        JSONObject given = k.getJSONObject("given");
        BtcTx tx = BtcTx.parse(BtcCrypto.unhex(given.getString("rawUnsignedTx")), BtcTx.MAX_PREV_IO);
        JSONArray utxos = given.getJSONArray("utxosSpent");
        long[] amounts = new long[utxos.length()];
        byte[][] scripts = new byte[utxos.length()][];
        for (int i = 0; i < utxos.length(); i++) {
            amounts[i] = utxos.getJSONObject(i).getLong("amountSats");
            scripts[i] = BtcCrypto.unhex(utxos.getJSONObject(i).getString("scriptPubKey"));
        }
        JSONArray inputs = k.getJSONArray("inputSpending");
        byte[] zeroAux = new byte[32];
        for (int i = 0; i < inputs.length(); i++) {
            JSONObject in = inputs.getJSONObject(i);
            JSONObject g = in.getJSONObject("given"), mid = in.getJSONObject("intermediary");
            int index = g.getInt("txinIndex"), hashType = g.getInt("hashType");
            byte[] root = g.isNull("merkleRoot") ? null : BtcCrypto.unhex(g.getString("merkleRoot"));
            byte[] priv = BtcCrypto.unhex(g.getString("internalPrivkey"));
            assertEquals("input " + index, mid.getString("internalPubkey"), BtcCrypto.hex(Arrays.copyOfRange(BtcCrypto.pubCompressed(priv), 1, 33)));
            byte[] tweaked = BtcCrypto.taprootTweakedPrivate(priv, root);
            assertEquals("input " + index, mid.getString("tweakedPrivkey"), BtcCrypto.hex(tweaked));
            byte[] msg = tx.sigMsgTaproot(index, amounts, scripts, hashType, null);
            assertEquals("input " + index + " SigMsg", mid.getString("sigMsg"), BtcCrypto.hex(msg));
            byte[] sighash = BtcCrypto.taggedHash("TapSighash", msg);
            assertEquals("input " + index + " sighash", mid.getString("sigHash"), BtcCrypto.hex(sighash));
            byte[] sig = BtcCrypto.signSchnorr(tweaked, sighash, zeroAux);
            String witness = BtcCrypto.hex(sig) + (hashType == 0 ? "" : String.format("%02x", hashType));
            assertEquals("input " + index + " signature", in.getJSONObject("expected").getJSONArray("witness").getString(0), witness);
            assertTrue(BtcCrypto.verifySchnorr(Arrays.copyOfRange(scripts[index], 2, 34), sighash, sig));
        }
        assertEquals(7, inputs.length());
    }

    @Test public void bip143NativeP2wpkhExample() {
        BtcTx tx = BtcTx.parse(BtcCrypto.unhex("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"), BtcTx.MAX_IO);
        byte[] priv = BtcCrypto.unhex("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
        byte[] pub = BtcCrypto.pubCompressed(priv);
        assertEquals("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357", BtcCrypto.hex(pub));
        assertEquals("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1", BtcCrypto.hex(BtcScript.p2wpkh(BtcCrypto.hash160(pub))));
        byte[] sighash = tx.sighashSegwitV0(1, BtcScript.p2pkhScript(BtcCrypto.hash160(pub)), 600_000_000L, BtcTx.SIGHASH_ALL);
        assertEquals("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670", BtcCrypto.hex(sighash));
        byte[] der = BtcCrypto.signEcdsa(priv, sighash);
        // Bitcoin Core's RFC 6979 signature from the BIP
        assertEquals("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee", BtcCrypto.hex(der));
        assertTrue(BtcCrypto.verifyEcdsa(pub, sighash, der));
        sighash[0] ^= 1;
        assertFalse(BtcCrypto.verifyEcdsa(pub, sighash, der));
    }

    @Test public void bip143P2shP2wpkhExample() {
        BtcTx tx = BtcTx.parse(BtcCrypto.unhex("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"), BtcTx.MAX_IO);
        byte[] priv = BtcCrypto.unhex("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf");
        byte[] pub = BtcCrypto.pubCompressed(priv);
        assertEquals("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873", BtcCrypto.hex(pub));
        byte[] sighash = tx.sighashSegwitV0(0, BtcScript.p2pkhScript(BtcCrypto.hash160(pub)), 1_000_000_000L, BtcTx.SIGHASH_ALL);
        assertEquals("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6", BtcCrypto.hex(sighash));
        assertEquals("3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb",
                BtcCrypto.hex(BtcCrypto.signEcdsa(priv, sighash)));
    }

    @Test public void ecdsaIsLowSAndStrictDer() {
        byte[] priv = BtcCrypto.unhex("0000000000000000000000000000000000000000000000000000000000000001");
        for (int i = 0; i < 64; i++) {
            byte[] digest = BtcCrypto.sha256(new byte[] {(byte) i});
            byte[] der = BtcCrypto.signEcdsa(priv, digest);
            java.math.BigInteger[] rs = BtcCrypto.parseDer(der);
            assertTrue(rs[1].compareTo(BtcCrypto.HALF_N) <= 0);
            assertArrayEquals(der, BtcCrypto.der(rs[0], rs[1]));
            // the high-S twin is refused
            assertFalse(BtcCrypto.verifyEcdsa(BtcCrypto.pubCompressed(priv), digest, BtcCrypto.der(rs[0], BtcCrypto.N.subtract(rs[1]))));
        }
    }
}
