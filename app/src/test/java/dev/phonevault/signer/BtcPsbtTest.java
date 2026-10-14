package dev.phonevault.signer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * PSBT parsing against the BIP-174 / BIP-371 vectors, the end-to-end signing cross-check against
 * an independent implementation (embit, tools/btc_fixtures.py), the review's classification and
 * warnings, and every refusal rule.
 */
public final class BtcPsbtTest {
    private static final byte[] ZERO_AUX = new byte[32];

    // ------------------------------------------------------------------ helpers

    static JSONObject fixtures() throws Exception { return new JSONObject(BtcSignatureVectorsTest.resource("psbt-e2e.json")); }

    static JSONObject fixture(String name) throws Exception {
        JSONArray cases = fixtures().getJSONArray("cases");
        for (int i = 0; i < cases.length(); i++) if (cases.getJSONObject(i).getString("name").equals(name)) return cases.getJSONObject(i);
        throw new AssertionError("no fixture " + name);
    }

    static Psbt psbt(JSONObject fixture) throws Exception { return Psbt.parse(Base64.getDecoder().decode(fixture.getString("psbt"))); }

    static BtcPsbtReview review(Psbt p, BtcNetwork n) throws RequestRefusal {
        return BtcPsbtReview.build(p, n, BtcKeysTest.wallet(n), null, new BtcAmountMemory());
    }

    static RequestRefusal refusal(Psbt p, BtcNetwork n) {
        try {
            review(p, n);
            fail("signed what should be refused");
            return null;
        } catch (RequestRefusal r) {
            assertEquals(BtcPsbtReview.REFUSED_TITLE, r.title);
            assertTrue(r.getMessage(), r.getMessage().endsWith("Nothing was signed."));
            return r;
        }
    }

    static void assertRefused(Psbt p, BtcNetwork n, String fragment) {
        String m = refusal(p, n).getMessage();
        assertTrue(m, m.contains(fragment));
    }

    static String value(BtcPsbtReview r, String label) {
        for (MessageReview.Row row : r.summary) if (row.label.equals(label)) return row.value;
        return null;
    }

    static boolean has(BtcPsbtReview r, String label, String fragment) {
        for (MessageReview.Row row : r.summary) if (row.label.equals(label) && row.value.contains(fragment)) return true;
        return false;
    }

    /** Mutable copy of a PSBT's maps, re-serialized by {@link #bytes}. */
    static final class Maps {
        final List<Psbt.Entry> global;
        final List<List<Psbt.Entry>> in = new ArrayList<>(), out = new ArrayList<>();
        Maps(Psbt p) {
            global = new ArrayList<>(p.global);
            for (List<Psbt.Entry> m : p.inputs) in.add(new ArrayList<>(m));
            for (List<Psbt.Entry> m : p.outputs) out.add(new ArrayList<>(m));
        }

        byte[] bytes() {
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            o.write(0x70); o.write(0x73); o.write(0x62); o.write(0x74); o.write(0xff);
            write(o, global);
            for (List<Psbt.Entry> m : in) write(o, m);
            for (List<Psbt.Entry> m : out) write(o, m);
            return o.toByteArray();
        }

        Psbt parse() { return Psbt.parse(bytes()); }

        static void write(ByteArrayOutputStream o, List<Psbt.Entry> m) {
            for (Psbt.Entry e : m) { BtcTx.varBytes(o, e.key); BtcTx.varBytes(o, e.value); }
            o.write(0);
        }

        void replace(List<Psbt.Entry> map, int type, Psbt.Entry with) {
            for (int i = 0; i < map.size(); i++) if (map.get(i).type == type) { map.set(i, with); return; }
            map.add(with);
        }

        void remove(List<Psbt.Entry> map, int type) { map.removeIf(e -> e.type == type); }

        Psbt.Entry get(List<Psbt.Entry> map, int type) { return Psbt.find(map, type); }

        /** Replace the unsigned transaction. */
        void tx(BtcTx tx) { replace(global, Psbt.GLOBAL_UNSIGNED_TX, Psbt.entry(Psbt.GLOBAL_UNSIGNED_TX, new byte[0], tx.serializeLegacy())); }
    }

    static byte[] witnessUtxo(long amount, byte[] script) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        BtcTx.u64(o, amount);
        BtcTx.varBytes(o, script);
        return o.toByteArray();
    }

    static byte[] origin(byte[] fp, int... path) {
        byte[] v = new byte[4 + 4 * path.length];
        System.arraycopy(fp, 0, v, 0, 4);
        for (int i = 0; i < path.length; i++) for (int b = 0; b < 4; b++) v[4 + 4 * i + b] = (byte) (path[i] >>> (8 * b));
        return v;
    }

    static final int H = Bip32.HARDENED;

    // ------------------------------------------------------------------ BIP-174 / BIP-371 vectors

    @Test public void bip174AndBip371Vectors() throws Exception {
        JSONObject v = new JSONObject(BtcSignatureVectorsTest.resource("psbt-vectors.json"));
        JSONArray valid = v.getJSONArray("valid"), invalid = v.getJSONArray("invalid");
        for (int i = 0; i < valid.length(); i++) {
            JSONObject c = valid.getJSONObject(i);
            byte[] raw = Base64.getDecoder().decode(c.getString("base64"));
            Psbt p;
            try {
                p = Psbt.parse(raw);
            } catch (IllegalArgumentException e) {
                throw new AssertionError("valid vector refused: " + c.getString("case") + ": " + e.getMessage());
            }
            assertArrayEquals("round trip: " + c.getString("case"), raw, p.serialize());
        }
        for (int i = 0; i < invalid.length(); i++) {
            JSONObject c = invalid.getJSONObject(i);
            byte[] raw;
            try {
                raw = Base64.getDecoder().decode(c.getString("base64"));
            } catch (IllegalArgumentException notEvenBase64) {
                continue;
            }
            try {
                Psbt.parse(raw);
                fail("invalid vector accepted: " + c.getString("case"));
            } catch (Psbt.InvalidPsbt expected) { }
        }
        assertEquals(16, valid.length());
        assertEquals(31, invalid.length());
    }

    @Test public void validVectorsAreStillNotSignedByPolicy() throws Exception {
        // Structurally valid is not signable: none of the BIP vectors belongs to this wallet.
        JSONArray valid = new JSONObject(BtcSignatureVectorsTest.resource("psbt-vectors.json")).getJSONArray("valid");
        for (int i = 0; i < valid.length(); i++) {
            Psbt p = Psbt.parse(Base64.getDecoder().decode(valid.getJSONObject(i).getString("base64")));
            refusal(p, BtcNetwork.BITCOIN);
        }
    }

    // ------------------------------------------------------------------ end to end (independent cross-check)

    @Test public void signaturesMatchAnIndependentImplementation() throws Exception {
        JSONObject all = fixtures();
        assertEquals("73c5da0a", all.getString("fingerprint"));
        JSONArray cases = all.getJSONArray("cases");
        for (int c = 0; c < cases.length(); c++) {
            JSONObject f = cases.getJSONObject(c);
            String name = f.getString("name");
            BtcNetwork network = BtcNetwork.fromWire(f.getString("network"));
            BtcRequest req = BtcRequest.parse(new JSONObject().put("id", "e2e-" + c).put("method", "btcSignPsbt")
                    .put("network", network.wire).put("psbt", f.getString("psbt")));
            BtcPsbtReview r = review(req.psbt, network);
            assertEquals(name, f.getLong("fee"), r.fee);

            // classification: own change verified, everything else a recipient
            JSONArray outs = f.getJSONArray("outputs");
            for (int i = 0; i < outs.length(); i++) {
                JSONObject o = outs.getJSONObject(i);
                BtcPsbtReview.Out out = r.outputs.get(i);
                assertEquals(name + " output " + i, o.getBoolean("change"), out.change);
                assertEquals(name + " output " + i, !o.isNull("own") && !o.getBoolean("change"), out.ownElsewhere || out.ownReceive);
                if (!o.isNull("address")) assertEquals(o.getString("address"), out.address);
                else assertEquals(BtcScript.Kind.OP_RETURN, out.kind);
            }

            byte[] signed = BtcPsbtSigner.sign(r, BtcKeysTest.seed(), new SecureRandom(), ZERO_AUX);
            JSONObject response = BtcRequest.signedResponse(req.id, signed);
            assertEquals("approved", response.getString("status"));
            Psbt out = Psbt.parse(Base64.getDecoder().decode(response.getString("psbt")));
            // everything the host sent is preserved; only signatures were added
            for (int i = 0; i < out.inputs.size(); i++) assertEquals(req.psbt.inputs.get(i).size() + 1, out.inputs.get(i).size());
            assertArrayEquals(req.psbt.tx.serializeLegacy(), out.tx.serializeLegacy());

            JSONArray sigs = f.getJSONArray("signatures");
            List<byte[][]> witnesses = new ArrayList<>();
            for (int k = 0; k < sigs.length(); k++) {
                JSONObject s = sigs.getJSONObject(k);
                List<Psbt.Entry> map = out.inputs.get(s.getInt("input"));
                if (s.getString("type").equals("partial_sig")) {
                    Psbt.Entry e = Psbt.find(map, Psbt.IN_PARTIAL_SIG);
                    assertNotNull(name, e);
                    assertEquals(s.getString("pubkey"), BtcCrypto.hex(e.keyData));
                    assertEquals(name + " ECDSA input " + k, s.getString("sig"), BtcCrypto.hex(e.value));
                    witnesses.add(new byte[][] {e.value, e.keyData});
                } else {
                    Psbt.Entry e = Psbt.find(map, Psbt.IN_TAP_KEY_SIG);
                    assertNotNull(name, e);
                    assertEquals(name + " Schnorr input " + k, s.getString("sig"), BtcCrypto.hex(e.value));
                    witnesses.add(new byte[][] {e.value});
                }
            }
            // finalize like the host would and compare the whole network transaction
            byte[] finalTx = finalize(out.tx, witnesses);
            assertEquals(name, f.getString("finalTx"), BtcCrypto.hex(finalTx));
            assertEquals(name, f.getString("txid"), BtcCrypto.hex(BtcCrypto.reversed(out.tx.txid())));
            // the size estimate is never below the real size, and at most 1 vB per ECDSA input above it
            long actual = (3L * out.tx.serializeLegacy().length + finalTx.length + 3) / 4;
            int ecdsa = 0;
            for (BtcPsbtReview.SignInput in : r.inputs) if (in.type == BtcWallet.Type.P2WPKH) ecdsa++;
            assertTrue(name + " vsize " + r.vsize + " vs " + actual, r.vsize >= actual && r.vsize <= actual + ecdsa);
        }
    }

    /** SegWit serialization with the given witness stacks (all inputs SegWit). */
    static byte[] finalize(BtcTx tx, List<byte[][]> witnesses) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        BtcTx.u32(o, tx.version);
        o.write(0); o.write(1);
        BtcTx.compact(o, tx.inputs.size());
        for (BtcTx.Input in : tx.inputs) { o.write(in.prevTxid, 0, 32); BtcTx.u32(o, in.vout); BtcTx.varBytes(o, in.scriptSig); BtcTx.u32(o, in.sequence); }
        BtcTx.compact(o, tx.outputs.size());
        for (BtcTx.Output out : tx.outputs) BtcTx.output(o, out);
        for (byte[][] w : witnesses) { BtcTx.compact(o, w.length); for (byte[] item : w) BtcTx.varBytes(o, item); }
        BtcTx.u32(o, tx.locktime);
        return o.toByteArray();
    }

    @Test public void signaturesVerifyAndTaprootUsesFreshRandomness() throws Exception {
        Psbt p = psbt(fixture("p2tr-send-with-change"));
        BtcPsbtReview r = review(p, BtcNetwork.BITCOIN);
        byte[] a = BtcPsbtSigner.sign(r, BtcKeysTest.seed(), new SecureRandom());
        byte[] b = BtcPsbtSigner.sign(r, BtcKeysTest.seed(), new SecureRandom());
        byte[] sigA = Psbt.find(Psbt.parse(a).inputs.get(0), Psbt.IN_TAP_KEY_SIG).value;
        byte[] sigB = Psbt.find(Psbt.parse(b).inputs.get(0), Psbt.IN_TAP_KEY_SIG).value;
        assertFalse("BIP-340 aux randomness differs per signature", Arrays.equals(sigA, sigB));
        byte[] sighash = p.tx.sighashTaproot(0, new long[] {r.inputs.get(0).amount}, new byte[][] {r.inputs.get(0).script}, 0);
        byte[] outputKey = Arrays.copyOfRange(r.inputs.get(0).script, 2, 34);
        assertTrue(BtcCrypto.verifySchnorr(outputKey, sighash, sigA));
        assertTrue(BtcCrypto.verifySchnorr(outputKey, sighash, sigB));
    }

    @Test public void signingWithAnotherSeedFails() throws Exception {
        BtcPsbtReview r = review(psbt(fixture("p2wpkh-send-with-change")), BtcNetwork.BITCOIN);
        byte[] other = SeedVault.bip39Seed(BtcKeysTest.MNEMONIC, "a passphrase");
        try {
            BtcPsbtSigner.sign(r, other, new SecureRandom());
            fail("signed with a different wallet than the reviewed one");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("differs from the reviewed key"));
        }
    }

    // ------------------------------------------------------------------ review content

    @Test public void reviewShowsRecipientChangeAndFee() throws Exception {
        BtcPsbtReview r = review(psbt(fixture("p2wpkh-send-with-change")), BtcNetwork.BITCOIN);
        assertEquals("Send 0.01234567 BTC", r.title);
        assertEquals("BITCOIN TRANSACTION REVIEW", r.kicker);
        assertEquals("Bitcoin", value(r, "Network"));
        assertEquals("0.01234567 BTC to\nbc1q 50rt rmj2 f8vl 9tem\n8qpf w36y lw5j g9j2 9e5z\na5", value(r, "Send"));
        assertEquals("0.00263000 BTC · bc1q8c6f…pcp6el · m/84'/0'/0'/1/0", value(r, "Change back to your wallet ✓"));
        String fee = value(r, "Network fee");
        assertTrue(fee, fee.startsWith("0.00002433 BTC (") && fee.endsWith(" sat/vB)"));
        assertEquals("Account 1 · Native SegWit (m/84'/0'/0')\n2 coins, 0.01500000 BTC", value(r, "Spending from"));
        assertNull(value(r, MessageReview.DANGER));
        assertNull(value(r, MessageReview.WARNING));
        assertEquals(1, r.parties.size());
        assertEquals("btc:bitcoin:bc1q50rtrmj2f8vl9tem8qpfw36ylw5jg9j29e5za5", r.parties.get(0).address);
        assertEquals("btc-wallet:bitcoin:73c5da0a", r.walletKey);
        boolean rbf = false;
        for (MessageReview.Row row : r.details) if (row.label.equals("Replace-by-fee")) rbf = row.value.startsWith("Yes");
        assertTrue(rbf);
    }

    @Test public void testnetIsNamedAndDataOutputsShown() throws Exception {
        BtcPsbtReview r = review(psbt(fixture("testnet-mixed-opreturn")), BtcNetwork.TESTNET);
        assertEquals("BITCOIN TESTNET · TEST COINS", r.kicker);
        assertTrue(value(r, BtcPsbtReview.TEST_NETWORK).startsWith("Bitcoin TESTNET"));
        assertEquals("Send 0.00600000 tBTC", r.title);
        assertNotNull(value(r, "Data output (12 bytes)"));
        assertTrue(has(r, "Spending from", "Account 1 · Native SegWit (m/84'/1'/0')"));
        assertTrue(has(r, "Spending from", "Account 2 · Taproot (m/86'/1'/1')"));
        // the same PSBT claimed for mainnet: its keys use coin type 1, so nothing matches
        assertRefused(psbt(fixture("testnet-mixed-opreturn")), BtcNetwork.BITCOIN, "outside this wallet's Bitcoin accounts");
    }

    @Test public void legacyAndScriptRecipientsAreShownAsAddresses() throws Exception {
        BtcPsbtReview r = review(psbt(fixture("p2wpkh-account-2-legacy-recipients")), BtcNetwork.BITCOIN);
        assertEquals(3, r.parties.size());
        assertTrue(has(r, "Send", "16yH 2E12"));
        assertTrue(has(r, "Send", "38Sq vnn4"));
        // Taproot "change" for coins spent from Native SegWit: this wallet's key (checked), but not
        // where the wallet app looks for change. A normal output with a WARNING and its full path.
        assertFalse(r.outputs.get(3).change);
        assertTrue(r.outputs.get(3).ownElsewhere);
        assertEquals("m/86'/0'/1'/1/0", r.outputs.get(3).path);
        assertNull(value(r, "Change back to your wallet ✓"));
        assertTrue(has(r, MessageReview.WARNING, "To your wallet: Account 2 · Taproot, path m/86'/0'/1'/1/0, which your wallet app may not show"));
        assertEquals("Send 0.00799000 BTC", r.title);
    }

    /** A copy of {@code p} whose output {@code index} pays this wallet's key at account/change/i, with its derivation. */
    static Psbt ownOutput(Psbt p, int index, BtcWallet.Type type, int account, int change, int i) {
        BtcWallet w = BtcKeysTest.wallet(BtcNetwork.BITCOIN);
        byte[] pub = w.publicKey(type, account, change, i);
        Maps m = new Maps(p);
        List<BtcTx.Output> outs = new ArrayList<>(p.tx.outputs);
        outs.set(index, new BtcTx.Output(p.tx.outputs.get(index).value, BtcWallet.scriptFor(type, pub)));
        m.tx(new BtcTx(p.tx.version, new ArrayList<>(p.tx.inputs), outs, p.tx.locktime, false));
        m.out.get(index).clear();
        m.out.get(index).add(Psbt.entry(Psbt.OUT_BIP32_DERIVATION, pub, origin(w.fingerprint(), 84 | H, H, account | H, change, i)));
        return m.parse();
    }

    @Test public void changeMustBeTheSpentAccountAndTypeWithinTheIndexWindow() throws Exception {
        Psbt p = psbt(fixture("p2wpkh-send-with-change")); // spends m/84'/0'/0'/0/0 and /0/1
        // the fixture's own change (account 1, /1/0) and the gap-limit edge: highest input index 1 + 20
        assertTrue(review(ownOutput(p, 1, BtcWallet.Type.P2WPKH, 0, 1, 0), BtcNetwork.BITCOIN).outputs.get(1).change);
        BtcPsbtReview edge = review(ownOutput(p, 1, BtcWallet.Type.P2WPKH, 0, 1, 21), BtcNetwork.BITCOIN);
        assertTrue(edge.outputs.get(1).change);
        assertNotNull(value(edge, "Change back to your wallet ✓"));
        // one past the gap limit: own, but shown as a normal output with a WARNING
        BtcPsbtReview far = review(ownOutput(p, 1, BtcWallet.Type.P2WPKH, 0, 1, 22), BtcNetwork.BITCOIN);
        assertFalse(far.outputs.get(1).change);
        assertTrue(far.outputs.get(1).ownElsewhere);
        assertNull(value(far, "Change back to your wallet ✓"));
        assertTrue(has(far, MessageReview.WARNING, "To your wallet: Account 1 · Native SegWit, path m/84'/0'/0'/1/22, which your wallet app may not show"
                + " (it is far beyond the addresses your wallet app scans (gap limit))"));
        assertEquals("Send 0.01497567 BTC", far.title);
        // the old rule's extreme: index 999,999 of account 20
        BtcPsbtReview extreme = review(ownOutput(p, 1, BtcWallet.Type.P2WPKH, 19, 1, 999_999), BtcNetwork.BITCOIN);
        assertFalse(extreme.outputs.get(1).change);
        assertTrue(has(extreme, MessageReview.WARNING, "Account 20 · Native SegWit, path m/84'/0'/19'/1/999999"));
        // change chain of ANOTHER account (not spent from), low index
        BtcPsbtReview other = review(ownOutput(p, 1, BtcWallet.Type.P2WPKH, 1, 1, 0), BtcNetwork.BITCOIN);
        assertFalse(other.outputs.get(1).change);
        assertTrue(has(other, MessageReview.WARNING, "Account 2 · Native SegWit, path m/84'/0'/1'/1/0"));
        assertTrue(has(other, MessageReview.WARNING, "(it is change for a different account or address type than the coins spent)"));
        // an own RECEIVE address of another account stays "Your own address ✓" within the first 20 (gap limit)
        BtcPsbtReview receive = review(ownOutput(p, 1, BtcWallet.Type.P2WPKH, 1, 0, 19), BtcNetwork.BITCOIN);
        assertTrue(receive.outputs.get(1).ownReceive);
        assertTrue(has(receive, "Your own address ✓", "m/84'/0'/1'/0/19"));
        // ... but not past it
        BtcPsbtReview farReceive = review(ownOutput(p, 1, BtcWallet.Type.P2WPKH, 1, 0, 20), BtcNetwork.BITCOIN);
        assertFalse(farReceive.outputs.get(1).ownReceive);
        assertTrue(has(farReceive, MessageReview.WARNING, "path m/84'/0'/1'/0/20, which your wallet app may not show (it is far beyond"));
        // a receive address of the spent account: up to highest input index (1) + 20
        assertTrue(review(ownOutput(p, 1, BtcWallet.Type.P2WPKH, 0, 0, 21), BtcNetwork.BITCOIN).outputs.get(1).ownReceive);
        assertTrue(review(ownOutput(p, 1, BtcWallet.Type.P2WPKH, 0, 0, 22), BtcNetwork.BITCOIN).outputs.get(1).ownElsewhere);
        assertEquals(20, BtcPsbtReview.GAP_LIMIT);
    }

    /** Replaces input {@code index}'s coin by output 0 of a fresh previous transaction paying {@code script}. */
    static Psbt withCoin(Psbt p, int index, long value, byte[] script, boolean nonWitness) {
        Maps m = new Maps(p);
        List<BtcTx.Input> fake = new ArrayList<>();
        fake.add(new BtcTx.Input(new byte[32], 7, new byte[0], 0xffffffffL));
        List<BtcTx.Output> outs = new ArrayList<>();
        outs.add(new BtcTx.Output(value, script));
        BtcTx prev = new BtcTx(2, fake, outs, 0, false);
        List<BtcTx.Input> ins = new ArrayList<>(p.tx.inputs);
        BtcTx.Input old = ins.get(index);
        ins.set(index, new BtcTx.Input(prev.txid(), 0, old.scriptSig, old.sequence));
        m.tx(new BtcTx(p.tx.version, ins, new ArrayList<>(p.tx.outputs), p.tx.locktime, false));
        m.replace(m.in.get(index), Psbt.IN_WITNESS_UTXO, Psbt.entry(Psbt.IN_WITNESS_UTXO, new byte[0], witnessUtxo(value, script)));
        m.remove(m.in.get(index), Psbt.IN_NON_WITNESS_UTXO);
        if (nonWitness) m.in.get(index).add(Psbt.entry(Psbt.IN_NON_WITNESS_UTXO, new byte[0], prev.serializeLegacy()));
        return m.parse();
    }

    @Test public void segwitV0InputsMustCarryTheirPreviousTransaction() throws Exception {
        Psbt p = psbt(fixture("p2wpkh-send-with-change"));
        for (int i = 0; i < 2; i++) assertNotNull(Psbt.find(p.inputs.get(i), Psbt.IN_NON_WITNESS_UTXO));
        review(p, BtcNetwork.BITCOIN);
        // either input without it: refused
        for (int i = 0; i < 2; i++) {
            Maps m = new Maps(p);
            m.remove(m.in.get(i), Psbt.IN_NON_WITNESS_UTXO);
            assertRefused(m.parse(), BtcNetwork.BITCOIN, "Input " + (i + 1) + " is a Native SegWit coin without its previous transaction");
        }
        // a previous transaction that is not the one spent (wrong txid) never parses
        Maps wrong = new Maps(p);
        wrong.replace(wrong.in.get(1), Psbt.IN_NON_WITNESS_UTXO, Psbt.find(p.inputs.get(0), Psbt.IN_NON_WITNESS_UTXO));
        try { wrong.parse(); fail(); } catch (Psbt.InvalidPsbt e) { assertTrue(e.getMessage(), e.getMessage().contains("does not match its outpoint")); }
        // the witness UTXO must match the previous transaction's output (amount AND script)
        BtcTx.Output real = Psbt.witnessUtxo(Psbt.find(p.inputs.get(1), Psbt.IN_WITNESS_UTXO).value);
        Maps lie = new Maps(p);
        lie.replace(lie.in.get(1), Psbt.IN_WITNESS_UTXO, Psbt.entry(Psbt.IN_WITNESS_UTXO, new byte[0], witnessUtxo(real.value + 100_000, real.script)));
        assertRefused(lie.parse(), BtcNetwork.BITCOIN, "Input 2: the previous transaction and the witness UTXO disagree about the coin");
        // a consistent coin built here is accepted
        BtcPsbtReview ok = review(withCoin(p, 1, 600_000, real.script, true), BtcNetwork.BITCOIN);
        assertEquals(1_600_000, ok.totalIn);
        assertRefused(withCoin(p, 1, 600_000, real.script, false), BtcNetwork.BITCOIN, "without its previous transaction");
        // Taproot: every signature commits to all amounts, so no previous transaction is needed
        Psbt tr = psbt(fixture("p2tr-send-with-change"));
        assertNull(Psbt.find(tr.inputs.get(0), Psbt.IN_NON_WITNESS_UTXO));
        review(tr, BtcNetwork.BITCOIN);
        // the testnet fixture mixes a P2WPKH input (with it) and a Taproot input (without)
        Psbt mixed = psbt(fixture("testnet-mixed-opreturn"));
        assertNotNull(Psbt.find(mixed.inputs.get(0), Psbt.IN_NON_WITNESS_UTXO));
        assertNull(Psbt.find(mixed.inputs.get(1), Psbt.IN_NON_WITNESS_UTXO));
        review(mixed, BtcNetwork.TESTNET);
        Maps stripped = new Maps(mixed);
        stripped.remove(stripped.in.get(0), Psbt.IN_NON_WITNESS_UTXO);
        assertRefused(stripped.parse(), BtcNetwork.TESTNET, "Input 1 is a Native SegWit coin without its previous transaction");
    }

    static Psbt withLockTime(Psbt p, long locktime, long sequence) {
        Maps m = new Maps(p);
        List<BtcTx.Input> ins = new ArrayList<>();
        for (BtcTx.Input in : p.tx.inputs) ins.add(new BtcTx.Input(in.prevTxid, in.vout, in.scriptSig, sequence));
        m.tx(new BtcTx(p.tx.version, ins, new ArrayList<>(p.tx.outputs), locktime, false));
        return m.parse();
    }

    @Test public void farFutureLockTimeIsWarned() throws Exception {
        Psbt p = psbt(fixture("p2wpkh-send-with-change"));
        long oct2026 = 1_791_900_000L; // 2026-10-13
        long tip = BtcPsbtReview.estimatedTip(BtcNetwork.BITCOIN, oct2026);
        // none, current height (anti fee sniping), a few days out: no warning
        for (long lock : new long[] {0, tip - 3000, tip, tip + 1008}) {
            assertNull(Long.toString(lock), BtcPsbtReview.lockTimeWarning(withLockTime(p, lock, 0xfffffffdL).tx, BtcNetwork.BITCOIN, oct2026));
        }
        String w = BtcPsbtReview.lockTimeWarning(withLockTime(p, tip + 1009, 0xfffffffdL).tx, BtcNetwork.BITCOIN, oct2026);
        assertNotNull(w);
        assertTrue(w, w.contains("locked until block") && w.contains("about 7 days away"));
        // not enforced when every input is final
        assertNull(BtcPsbtReview.lockTimeWarning(withLockTime(p, 5_000_000L, 0xffffffffL).tx, BtcNetwork.BITCOIN, oct2026));
        // times: a week is fine, more is not
        assertNull(BtcPsbtReview.lockTimeWarning(withLockTime(p, oct2026 + 7 * 86400, 0xfffffffdL).tx, BtcNetwork.BITCOIN, oct2026));
        String t = BtcPsbtReview.lockTimeWarning(withLockTime(p, oct2026 + 7 * 86400 + 1, 0xfffffffdL).tx, BtcNetwork.BITCOIN, oct2026);
        assertTrue(t, t.contains("more than a week from now"));
        assertNull("a time in the past", BtcPsbtReview.lockTimeWarning(withLockTime(p, 1_600_000_000L, 0xfffffffdL).tx, BtcNetwork.BITCOIN, oct2026));
        // a phone clock reset to 1970 is not trusted below the floor: a 2026 time lock is not "far future"
        assertNull(BtcPsbtReview.lockTimeWarning(withLockTime(p, BtcPsbtReview.CLOCK_FLOOR + 86400, 0xfffffffdL).tx, BtcNetwork.BITCOIN, 0));
        // testnet heights are not estimated; signet uses its own anchor
        assertNull(BtcPsbtReview.lockTimeWarning(withLockTime(p, 5_000_000L, 0xfffffffdL).tx, BtcNetwork.TESTNET, oct2026));
        assertNotNull(BtcPsbtReview.lockTimeWarning(withLockTime(p, 400_000L, 0xfffffffdL).tx, BtcNetwork.SIGNET, oct2026));
        assertNull(BtcPsbtReview.lockTimeWarning(withLockTime(p, 326_500L, 0xfffffffdL).tx, BtcNetwork.SIGNET, oct2026));
        // and it reaches the review (a lock in the year 2100 is far ahead of any clock)
        BtcPsbtReview r = review(withLockTime(p, 4_102_444_800L, 0xfffffffdL), BtcNetwork.BITCOIN);
        assertTrue(has(r, MessageReview.WARNING, "locked until 2100-01-01"));
        assertTrue(has(review(withLockTime(p, 50_000_000L, 0xfffffffdL), BtcNetwork.BITCOIN), MessageReview.WARNING, "locked until block 50,000,000"));
    }

    @Test public void feeWarnings() throws Exception {
        Psbt p = psbt(fixture("p2wpkh-send-with-change"));
        // drop the change output: the 263,000 sats left over become fee
        Maps m = new Maps(p);
        List<BtcTx.Output> outs = new ArrayList<>(p.tx.outputs.subList(0, 1));
        m.tx(new BtcTx(p.tx.version, new ArrayList<>(p.tx.inputs), outs, p.tx.locktime, false));
        m.out.remove(1);
        BtcPsbtReview r = review(m.parse(), BtcNetwork.BITCOIN);
        assertEquals(265_433, r.fee);
        assertTrue(has(r, MessageReview.DANGER, "of the amount sent"));
        assertTrue(has(r, MessageReview.WARNING, "sat/vB, above 500 sat/vB"));
        // a 0.25 BTC fee on a 0.012 BTC payment
        Maps big = new Maps(p);
        List<BtcTx.Output> o2 = new ArrayList<>();
        o2.add(new BtcTx.Output(1_234_567, p.tx.outputs.get(0).script));
        o2.add(new BtcTx.Output(263_000 - 250_000, p.tx.outputs.get(1).script));
        big.tx(new BtcTx(p.tx.version, new ArrayList<>(p.tx.inputs), o2, p.tx.locktime, false));
        assertTrue(has(review(big.parse(), BtcNetwork.BITCOIN), MessageReview.DANGER, "far more than a normal fee"));
        // a fee under 1 sat/vB
        Maps low = new Maps(p);
        List<BtcTx.Output> o3 = new ArrayList<>();
        o3.add(new BtcTx.Output(1_234_567, p.tx.outputs.get(0).script));
        o3.add(new BtcTx.Output(263_000 + 2_300, p.tx.outputs.get(1).script));
        low.tx(new BtcTx(p.tx.version, new ArrayList<>(p.tx.inputs), o3, p.tx.locktime, false));
        assertTrue(has(review(low.parse(), BtcNetwork.BITCOIN), MessageReview.WARNING, "below the usual 1 sat/vB"));
        assertEquals("12.3", BtcPsbtReview.rate(1230, 100));
        assertEquals("0.01234567 BTC", BtcPsbtReview.btc(1_234_567, BtcNetwork.BITCOIN));
        assertEquals("21000000.00000000 BTC", BtcPsbtReview.btc(BtcPsbtReview.MAX_MONEY, BtcNetwork.BITCOIN));
    }

    // ------------------------------------------------------------------ refusals

    @Test public void inputsThatAreNotOursAreRefused() throws Exception {
        Psbt p = psbt(fixture("p2wpkh-send-with-change"));
        byte[] fp = BtcKeysTest.wallet(BtcNetwork.BITCOIN).fingerprint();

        Maps foreign = new Maps(p);
        Psbt.Entry d = foreign.get(foreign.in.get(1), Psbt.IN_BIP32_DERIVATION);
        foreign.replace(foreign.in.get(1), Psbt.IN_BIP32_DERIVATION, Psbt.entry(Psbt.IN_BIP32_DERIVATION, d.keyData, origin(new byte[] {1, 2, 3, 4}, 84 | H, H, H, 0, 1)));
        assertRefused(foreign.parse(), BtcNetwork.BITCOIN, "Input 2 is not a coin of this wallet");

        Maps none = new Maps(p);
        none.remove(none.in.get(0), Psbt.IN_BIP32_DERIVATION);
        assertRefused(none.parse(), BtcNetwork.BITCOIN, "Input 1 is not a coin of this wallet");

        Maps account21 = new Maps(p);
        account21.replace(account21.in.get(0), Psbt.IN_BIP32_DERIVATION, Psbt.entry(Psbt.IN_BIP32_DERIVATION,
                Psbt.find(p.inputs.get(0), Psbt.IN_BIP32_DERIVATION).keyData, origin(fp, 84 | H, H, 20 | H, 0, 0)));
        assertRefused(account21.parse(), BtcNetwork.BITCOIN, "outside this wallet's Bitcoin accounts");

        Maps hardenedIndex = new Maps(p);
        hardenedIndex.replace(hardenedIndex.in.get(0), Psbt.IN_BIP32_DERIVATION, Psbt.entry(Psbt.IN_BIP32_DERIVATION,
                Psbt.find(p.inputs.get(0), Psbt.IN_BIP32_DERIVATION).keyData, origin(fp, 84 | H, H, H, 0, H)));
        assertRefused(hardenedIndex.parse(), BtcNetwork.BITCOIN, "outside");

        // right path, but the key in the PSBT is another one (index 1's key named as index 0)
        Maps wrongKey = new Maps(p);
        wrongKey.in.get(0).removeIf(e -> e.type == Psbt.IN_BIP32_DERIVATION);
        wrongKey.in.get(0).add(Psbt.entry(Psbt.IN_BIP32_DERIVATION, BtcKeysTest.wallet(BtcNetwork.BITCOIN).publicKey(BtcWallet.Type.P2WPKH, 0, 0, 1),
                origin(fp, 84 | H, H, H, 0, 0)));
        assertRefused(wrongKey.parse(), BtcNetwork.BITCOIN, "a different key");

        // right key and path, but the coin's script pays someone else
        // (a consistent previous transaction for that other script, so the coin data itself agrees)
        assertRefused(withCoin(p, 1, 500_000, BtcScript.p2wpkh(new byte[20]), true), BtcNetwork.BITCOIN, "script does not belong to that key");

        // a legacy coin
        Maps legacy = new Maps(p);
        legacy.remove(legacy.in.get(1), Psbt.IN_WITNESS_UTXO);
        legacy.in.get(1).add(Psbt.entry(Psbt.IN_WITNESS_UTXO, new byte[0], witnessUtxo(500_000, BtcScript.p2pkhScript(new byte[20]))));
        assertRefused(legacy.parse(), BtcNetwork.BITCOIN, "Legacy (P2PKH) coin");
    }

    @Test public void missingOrInconsistentUtxoDataIsRefused() throws Exception {
        Psbt p = psbt(fixture("p2wpkh-send-with-change"));
        Maps noUtxo = new Maps(p);
        noUtxo.remove(noUtxo.in.get(1), Psbt.IN_WITNESS_UTXO);
        assertRefused(noUtxo.parse(), BtcNetwork.BITCOIN, "has no witness UTXO");

        // input 1 carries a non-witness UTXO (the previous transaction): a lie in the witness UTXO is caught
        Maps lie = new Maps(p);
        BtcTx.Output real = Psbt.witnessUtxo(Psbt.find(p.inputs.get(0), Psbt.IN_WITNESS_UTXO).value);
        lie.replace(lie.in.get(0), Psbt.IN_WITNESS_UTXO, Psbt.entry(Psbt.IN_WITNESS_UTXO, new byte[0], witnessUtxo(real.value - 1, real.script)));
        assertRefused(lie.parse(), BtcNetwork.BITCOIN, "disagree about the coin");

        // outputs worth more than the inputs
        BtcTx.Output small = Psbt.witnessUtxo(Psbt.find(p.inputs.get(1), Psbt.IN_WITNESS_UTXO).value);
        assertRefused(withCoin(p, 1, 1_000, small.script, true), BtcNetwork.BITCOIN, "are worth more than the coins spent");
    }

    @Test public void onlySighashAllOrDefault() throws Exception {
        Psbt p = psbt(fixture("p2wpkh-send-with-change"));
        for (int t : new int[] {0x00, 0x02, 0x03, 0x81, 0x82, 0x83}) {
            Maps m = new Maps(p);
            m.in.get(0).add(Psbt.entry(Psbt.IN_SIGHASH_TYPE, new byte[0], new byte[] {(byte) t, 0, 0, 0}));
            assertRefused(m.parse(), BtcNetwork.BITCOIN, "signature hash type 0x" + Integer.toHexString(t));
        }
        Maps all = new Maps(p);
        all.in.get(0).add(Psbt.entry(Psbt.IN_SIGHASH_TYPE, new byte[0], new byte[] {1, 0, 0, 0}));
        review(all.parse(), BtcNetwork.BITCOIN);

        // Taproot: DEFAULT (64-byte signature) or explicit ALL (65 bytes, last byte 0x01)
        Psbt tr = psbt(fixture("p2tr-send-with-change"));
        Maps trAll = new Maps(tr);
        trAll.in.get(0).add(Psbt.entry(Psbt.IN_SIGHASH_TYPE, new byte[0], new byte[] {1, 0, 0, 0}));
        BtcPsbtReview r = review(trAll.parse(), BtcNetwork.BITCOIN);
        byte[] sig = Psbt.find(Psbt.parse(BtcPsbtSigner.sign(r, BtcKeysTest.seed(), new SecureRandom())).inputs.get(0), Psbt.IN_TAP_KEY_SIG).value;
        assertEquals(65, sig.length);
        assertEquals(1, sig[64]);
        Maps trNone = new Maps(tr);
        trNone.in.get(0).add(Psbt.entry(Psbt.IN_SIGHASH_TYPE, new byte[0], new byte[] {2, 0, 0, 0}));
        assertRefused(trNone.parse(), BtcNetwork.BITCOIN, "signature hash type 0x2");
    }

    @Test public void fieldsThePhoneDoesNotUnderstandAreRefused() throws Exception {
        Psbt p = psbt(fixture("p2wpkh-send-with-change"));
        Object[][] cases = {
                {Psbt.entry(0x30, new byte[0], new byte[] {1}), "an unknown field (type 0x30)"},
                {Psbt.entry(Psbt.PROPRIETARY, new byte[] {3, 'a', 'b', 'c', 0}, new byte[] {1}), "a proprietary field"},
                {Psbt.entry(Psbt.IN_REDEEM_SCRIPT, new byte[0], new byte[] {0x51}), "a redeem script"},
                {Psbt.entry(Psbt.IN_WITNESS_SCRIPT, new byte[0], new byte[] {0x51}), "a witness script"},
                {Psbt.entry(Psbt.IN_FINAL_SCRIPTWITNESS, new byte[0], new byte[] {0}), "already finalized data"},
                {Psbt.entry(Psbt.IN_SHA256, new byte[32], new byte[] {1}), "a hash preimage"},
                {Psbt.entry(Psbt.IN_TAP_MERKLE_ROOT, new byte[0], new byte[32]), "Taproot script-path data"},
        };
        for (Object[] c : cases) {
            Maps m = new Maps(p);
            m.in.get(0).add((Psbt.Entry) c[0]);
            assertRefused(m.parse(), BtcNetwork.BITCOIN, (String) c[1]);
        }
        // Taproot derivation with leaf hashes = a script-path key
        Psbt tr = psbt(fixture("p2tr-send-with-change"));
        Maps leaf = new Maps(tr);
        Psbt.Entry d = Psbt.find(tr.inputs.get(0), Psbt.IN_TAP_BIP32_DERIVATION);
        byte[] v = new byte[1 + 32 + d.value.length - 1];
        v[0] = 1;
        System.arraycopy(d.value, 1, v, 33, d.value.length - 1);
        leaf.replace(leaf.in.get(0), Psbt.IN_TAP_BIP32_DERIVATION, Psbt.entry(Psbt.IN_TAP_BIP32_DERIVATION, d.keyData, v));
        assertRefused(leaf.parse(), BtcNetwork.BITCOIN, "Taproot script path");
        // a different Taproot internal key
        Maps internal = new Maps(tr);
        internal.replace(internal.in.get(0), Psbt.IN_TAP_INTERNAL_KEY, Psbt.entry(Psbt.IN_TAP_INTERNAL_KEY, new byte[0], BtcCrypto.unhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")));
        assertRefused(internal.parse(), BtcNetwork.BITCOIN, "different Taproot internal key");
    }

    @Test public void outputsThePhoneCannotShowAreRefused() throws Exception {
        Psbt p = psbt(fixture("p2wpkh-send-with-change"));
        Maps bare = new Maps(p);
        List<BtcTx.Output> outs = new ArrayList<>(p.tx.outputs);
        outs.set(0, new BtcTx.Output(1_234_567, BtcCrypto.unhex("5121" + "02" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" + "51ae")));
        bare.tx(new BtcTx(p.tx.version, new ArrayList<>(p.tx.inputs), outs, p.tx.locktime, false));
        assertRefused(bare.parse(), BtcNetwork.BITCOIN, "Output 1 pays to a script the phone can't show as an address");

        Maps future = new Maps(p);
        List<BtcTx.Output> o2 = new ArrayList<>(p.tx.outputs);
        o2.set(0, new BtcTx.Output(1_234_567, BtcCrypto.unhex("5210751e76e8199196d454941c45d1b3a323")));
        future.tx(new BtcTx(p.tx.version, new ArrayList<>(p.tx.inputs), o2, p.tx.locktime, false));
        assertRefused(future.parse(), BtcNetwork.BITCOIN, "can't show as an address");

        // burning value in OP_RETURN: allowed, but DANGER
        Maps burn = new Maps(p);
        List<BtcTx.Output> o3 = new ArrayList<>(p.tx.outputs);
        o3.set(0, new BtcTx.Output(1_234_567, BtcCrypto.unhex("6a0401020304")));
        burn.tx(new BtcTx(p.tx.version, new ArrayList<>(p.tx.inputs), o3, p.tx.locktime, false));
        assertTrue(has(review(burn.parse(), BtcNetwork.BITCOIN), MessageReview.DANGER, "destroyed forever"));
    }

    @Test public void falseChangeClaimsAreRefused() throws Exception {
        Psbt p = psbt(fixture("p2wpkh-send-with-change"));
        byte[] fp = BtcKeysTest.wallet(BtcNetwork.BITCOIN).fingerprint();
        byte[] changeKey = Psbt.find(p.outputs.get(1), Psbt.OUT_BIP32_DERIVATION).keyData;
        // the RECIPIENT output claims to be change at m/84'/0'/0'/1/0: the script is not that key's
        Maps lie = new Maps(p);
        lie.out.get(0).add(Psbt.entry(Psbt.OUT_BIP32_DERIVATION, changeKey, origin(fp, 84 | H, H, H, 1, 0)));
        assertRefused(lie.parse(), BtcNetwork.BITCOIN, "Output 1 claims key path m/84'/0'/0'/1/0 but its script does not belong to that key");
        // a P2SH output claiming to be this wallet's
        Maps sh = new Maps(psbt(fixture("p2wpkh-account-2-legacy-recipients")));
        sh.out.get(1).add(Psbt.entry(Psbt.OUT_BIP32_DERIVATION, changeKey, origin(fp, 84 | H, H, H, 1, 0)));
        assertRefused(sh.parse(), BtcNetwork.BITCOIN, "claims to be this wallet's");
        // change without its derivation is just a recipient (no ✓)
        Maps plain = new Maps(p);
        plain.out.get(1).clear();
        BtcPsbtReview r = review(plain.parse(), BtcNetwork.BITCOIN);
        assertFalse(r.outputs.get(1).change);
        assertNull(value(r, "Change back to your wallet ✓"));
        assertEquals("Send 0.01497567 BTC", r.title);
    }

    @Test public void conflictingAmountsForTheSameCoinAreRefused() throws Exception {
        Psbt p = psbt(fixture("p2tr-send-with-change"));
        BtcAmountMemory memory = new BtcAmountMemory();
        BtcPsbtReview r = BtcPsbtReview.build(p, BtcNetwork.BITCOIN, BtcKeysTest.wallet(BtcNetwork.BITCOIN), null, memory);
        for (BtcPsbtReview.SignInput in : r.inputs) memory.record(p.tx.inputs.get(in.index).outpoint(), in.amount, in.script);
        BtcPsbtReview.build(p, BtcNetwork.BITCOIN, BtcKeysTest.wallet(BtcNetwork.BITCOIN), null, memory); // same claim again: fine
        Maps lie = new Maps(p);
        BtcTx.Output real = Psbt.witnessUtxo(Psbt.find(p.inputs.get(0), Psbt.IN_WITNESS_UTXO).value);
        lie.replace(lie.in.get(0), Psbt.IN_WITNESS_UTXO, Psbt.entry(Psbt.IN_WITNESS_UTXO, new byte[0], witnessUtxo(real.value + 1_000_000, real.script)));
        try {
            BtcPsbtReview.build(lie.parse(), BtcNetwork.BITCOIN, BtcKeysTest.wallet(BtcNetwork.BITCOIN), null, memory);
            fail();
        } catch (RequestRefusal e) {
            assertTrue(e.getMessage(), e.getMessage().contains("signed earlier as worth 2,000,000 sats, now it is claimed as 3,000,000 sats"));
        }
    }

    @Test public void structuralLimits() throws Exception {
        Psbt p = psbt(fixture("p2wpkh-send-with-change"));
        // PSBT version 2
        Maps v2 = new Maps(p);
        v2.global.add(Psbt.entry(Psbt.GLOBAL_VERSION, new byte[0], new byte[] {2, 0, 0, 0}));
        try { v2.parse(); fail(); } catch (Psbt.InvalidPsbt e) { assertTrue(e.getMessage().contains("version 2 is not supported")); }
        Maps v2field = new Maps(p);
        v2field.global.add(Psbt.entry(0x04, new byte[0], new byte[] {1}));
        try { v2field.parse(); fail(); } catch (Psbt.InvalidPsbt e) { assertTrue(e.getMessage().contains("version 2")); }
        // duplicate key
        Maps dup = new Maps(p);
        dup.in.get(0).add(Psbt.find(p.inputs.get(0), Psbt.IN_WITNESS_UTXO));
        try { dup.parse(); fail(); } catch (Psbt.InvalidPsbt e) { assertTrue(e.getMessage().contains("Duplicate")); }
        // 101 outputs
        List<BtcTx.Output> many = new ArrayList<>();
        for (int i = 0; i < 101; i++) many.add(new BtcTx.Output(1000, p.tx.outputs.get(0).script));
        Maps tooMany = new Maps(p);
        tooMany.tx(new BtcTx(2, new ArrayList<>(p.tx.inputs), many, 0, false));
        try { tooMany.parse(); fail(); } catch (Psbt.InvalidPsbt e) { assertTrue(e.getMessage().contains("at most 100")); }
        // size cap
        byte[] huge = Arrays.copyOf(p.serialize(), Psbt.MAX_BYTES + 1);
        try { Psbt.parse(huge); fail(); } catch (Psbt.InvalidPsbt e) { assertTrue(e.getMessage().contains("200 KiB")); }
        // trailing data
        byte[] trailing = Arrays.copyOf(p.serialize(), p.serialize().length + 1);
        try { Psbt.parse(trailing); fail(); } catch (Psbt.InvalidPsbt e) { assertTrue(e.getMessage().contains("Trailing")); }
    }

    // ------------------------------------------------------------------ USB requests

    @Test public void requestsAreSchemaExact() throws Exception {
        JSONObject ok = new JSONObject().put("id", "a-1").put("method", "btcGetAccount").put("network", "bitcoin").put("type", "p2wpkh").put("account", "1");
        BtcRequest r = BtcRequest.parse(ok);
        assertEquals(BtcRequest.Kind.GET_ACCOUNT, r.kind);
        assertEquals(0, r.account);
        for (String bad : new String[] {"0", "21", "01", "1.0", " 1", "x"}) {
            try { BtcRequest.parse(new JSONObject(ok.toString()).put("account", bad)); fail(bad); } catch (JSONException expected) { }
        }
        assertEquals(19, BtcRequest.parse(new JSONObject(ok.toString()).put("account", "20")).account);
        for (String[] bad : new String[][] {{"network", "regtest"}, {"network", "mainnet"}, {"type", "p2sh"}, {"type", "P2WPKH"}}) {
            try { BtcRequest.parse(new JSONObject(ok.toString()).put(bad[0], bad[1])); fail(bad[1]); } catch (JSONException expected) { }
        }
        try { BtcRequest.parse(new JSONObject(ok.toString()).put("extra", "1")); fail(); } catch (JSONException expected) { }
        try { BtcRequest.parse(new JSONObject(ok.toString()).put("change", "0")); fail(); } catch (JSONException expected) { }

        JSONObject show = new JSONObject(ok.toString()).put("method", "btcShowAddress").put("change", "1").put("index", "9999");
        BtcRequest s = BtcRequest.parse(show);
        assertEquals(1, s.change);
        assertEquals(9999, s.index);
        for (String[] bad : new String[][] {{"change", "2"}, {"index", "10000"}, {"index", "-1"}, {"index", "007"}}) {
            try { BtcRequest.parse(new JSONObject(show.toString()).put(bad[0], bad[1])); fail(bad[1]); } catch (JSONException expected) { }
        }

        String b64 = fixture("p2wpkh-send-with-change").getString("psbt");
        JSONObject sign = new JSONObject().put("id", "s-1").put("method", "btcSignPsbt").put("network", "bitcoin").put("psbt", b64);
        assertEquals(BtcRequest.Kind.SIGN_PSBT, BtcRequest.parse(sign).kind);
        try { BtcRequest.parse(new JSONObject(sign.toString()).put("psbt", b64 + " ")); fail(); } catch (JSONException expected) { }
        try { BtcRequest.parse(new JSONObject(sign.toString()).put("psbt", b64.substring(0, b64.length() - 4))); fail(); } catch (JSONException expected) { }
        try { BtcRequest.parse(new JSONObject(sign.toString()).put("psbt", "cHNidP8=" + "x")); fail(); } catch (JSONException expected) { }
        try { BtcRequest.parse(new JSONObject(sign.toString()).put("type", "p2tr")); fail(); } catch (JSONException expected) { }
        try {
            BtcRequest.parse(new JSONObject(sign.toString()).put("psbt", Base64.getEncoder().encodeToString("not a psbt".getBytes())));
            fail();
        } catch (RequestRefusal expected) {
            assertTrue(expected.getMessage().contains("not a valid PSBT"));
        }
        char[] big = new char[(Psbt.MAX_BYTES + 3) / 3 * 4 + 4];
        Arrays.fill(big, 'A');
        try { BtcRequest.parse(new JSONObject(sign.toString()).put("psbt", new String(big))); fail(); } catch (RequestRefusal expected) { }
        assertTrue(BtcRequest.lockedSummary(sign).startsWith("A Bitcoin transaction (2 inputs, 2 outputs)"));
    }

    @Test public void accountAndAddressResponses() throws Exception {
        BtcWallet w = BtcKeysTest.wallet(BtcNetwork.BITCOIN);
        JSONObject a = BtcRequest.accountResponse("a-1", w, BtcWallet.Type.P2TR, 0);
        assertEquals(6, a.length());
        assertEquals("ok", a.getString("status"));
        assertEquals("73c5da0a", a.getString("fingerprint"));
        assertEquals("m/86'/0'/0'", a.getString("path"));
        assertEquals("xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ", a.getString("xpub"));
        assertEquals("tr([73c5da0a/86h/0h/0h]xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/<0;1>/*)#xf07c0qd", a.getString("descriptor"));
        JSONObject addr = BtcRequest.addressResponse("b-1", w.address(BtcWallet.Type.P2WPKH, 0, 0, 0));
        assertEquals(3, addr.length());
        assertEquals("b-1", addr.getString("id"));
        assertEquals("ok", addr.getString("status"));
        assertEquals("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", addr.getString("address"));
    }

    @Test public void sharingChoicesAreBoundToTheWallet() {
        String wallet = "0x9858effd232b4033e47d90003d41ec34ecaeda94";
        BtcSharing s = BtcSharing.load(null, wallet);
        assertFalse(s.isShared(BtcNetwork.BITCOIN, BtcWallet.Type.P2WPKH, 0));
        s.share(BtcNetwork.BITCOIN, BtcWallet.Type.P2WPKH, 0);
        String saved = s.encode();
        assertTrue(BtcSharing.load(saved, wallet).isShared(BtcNetwork.BITCOIN, BtcWallet.Type.P2WPKH, 0));
        assertFalse("per network", BtcSharing.load(saved, wallet).isShared(BtcNetwork.TESTNET, BtcWallet.Type.P2WPKH, 0));
        assertFalse("per type", BtcSharing.load(saved, wallet).isShared(BtcNetwork.BITCOIN, BtcWallet.Type.P2TR, 0));
        assertFalse("per account", BtcSharing.load(saved, wallet).isShared(BtcNetwork.BITCOIN, BtcWallet.Type.P2WPKH, 1));
        assertFalse("another wallet", BtcSharing.load(saved, "0x" + "11".repeat(20)).isShared(BtcNetwork.BITCOIN, BtcWallet.Type.P2WPKH, 0));
        assertFalse("corrupt", BtcSharing.load("{", wallet).isShared(BtcNetwork.BITCOIN, BtcWallet.Type.P2WPKH, 0));
    }

    @Test public void sharingCanBeRevoked() {
        String wallet = "0x9858effd232b4033e47d90003d41ec34ecaeda94";
        BtcSharing s = BtcSharing.load(null, wallet);
        s.share(BtcNetwork.TESTNET, BtcWallet.Type.P2WPKH, 0);
        s.share(BtcNetwork.SIGNET, BtcWallet.Type.P2TR, 4);
        assertEquals(java.util.Arrays.asList("signet/p2tr/5", "testnet/p2wpkh/1"), s.keys());
        assertEquals("Bitcoin TESTNET · Account 1 · Native SegWit", BtcSharing.label("testnet/p2wpkh/1"));
        assertTrue(s.revoke("testnet/p2wpkh/1"));
        assertFalse(s.revoke("testnet/p2wpkh/1"));
        BtcSharing reloaded = BtcSharing.load(s.encode(), wallet);
        assertFalse(reloaded.isShared(BtcNetwork.TESTNET, BtcWallet.Type.P2WPKH, 0));
        assertTrue(reloaded.isShared(BtcNetwork.SIGNET, BtcWallet.Type.P2TR, 4));
        reloaded.revokeAll();
        assertTrue(BtcSharing.load(reloaded.encode(), wallet).keys().isEmpty());
    }
}
