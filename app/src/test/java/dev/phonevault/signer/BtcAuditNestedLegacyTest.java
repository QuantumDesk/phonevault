package dev.phonevault.signer;

import static dev.phonevault.signer.BtcPsbtTest.H;
import static dev.phonevault.signer.BtcPsbtTest.Maps;
import static dev.phonevault.signer.BtcPsbtTest.assertRefused;
import static dev.phonevault.signer.BtcPsbtTest.origin;
import static dev.phonevault.signer.BtcPsbtTest.review;
import static dev.phonevault.signer.BtcPsbtTest.witnessUtxo;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Adversarial audit of the BIP-49 (P2SH-P2WPKH) and BIP-44 (P2PKH) signing support. Each test is
 * an attack attempt (or an independent cross-check) and asserts what the phone actually does.
 *
 * <p>Fixtures {@code audit-legacy-mixed.json} were generated with embit 0.8.0 (sdist sha256
 * 8bf4b100…d770, verified) through tools/btc_fixtures.py's own {@code build()}: a Legacy input at
 * index 2 of four mixed-type inputs, and a testnet version-1 transaction with the Legacy input last.
 */
public final class BtcAuditNestedLegacyTest {
    private static final byte[] ZERO_AUX = new byte[32];
    private static final BtcWallet.Type NESTED = BtcWallet.Type.P2SH_P2WPKH, LEGACY = BtcWallet.Type.P2PKH;

    private static JSONObject audit(String name) throws Exception {
        JSONArray cases = new JSONObject(BtcSignatureVectorsTest.resource("audit-legacy-mixed.json")).getJSONArray("cases");
        for (int i = 0; i < cases.length(); i++) if (cases.getJSONObject(i).getString("name").equals(name)) return cases.getJSONObject(i);
        throw new AssertionError(name);
    }

    private static Psbt psbt(JSONObject f) throws Exception { return Psbt.parse(Base64.getDecoder().decode(f.getString("psbt"))); }

    // ------------------------------------------------------------------ independent cross-check

    /**
     * The legacy sighash with the P2PKH input NOT first, among SegWit v0 / nested / Taproot inputs,
     * version 1 and a non-RBF sequence: the phone's signatures are byte-for-byte embit's, the
     * addresses it shows (1… / 3… / m… / 2…) are embit's, and the fee and final txid match.
     */
    @Test public void legacyInputAnywhereInAMixedTransactionMatchesEmbit() throws Exception {
        for (String name : new String[] {"audit-mainnet-legacy-third-of-four", "audit-testnet-v1-legacy-last"}) {
            JSONObject f = audit(name);
            BtcNetwork n = BtcNetwork.fromWire(f.getString("network"));
            BtcPsbtReview r = review(psbt(f), n);
            assertEquals(name, f.getLong("fee"), r.fee);
            JSONArray outs = f.getJSONArray("outputs");
            for (int i = 0; i < outs.length(); i++) {
                assertEquals(name, outs.getJSONObject(i).getString("address"), r.outputs.get(i).address);
                assertEquals(name + " change " + i, outs.getJSONObject(i).getBoolean("change"), r.outputs.get(i).change);
            }
            byte[] signed = BtcPsbtSigner.sign(r, BtcKeysTest.seed(), new SecureRandom(), ZERO_AUX);
            Psbt out = Psbt.parse(signed);
            JSONArray sigs = f.getJSONArray("signatures");
            for (int k = 0; k < sigs.length(); k++) {
                JSONObject s = sigs.getJSONObject(k);
                int idx = s.getInt("input");
                Psbt.Entry e = Psbt.find(out.inputs.get(idx), s.getString("type").equals("partial_sig") ? Psbt.IN_PARTIAL_SIG : Psbt.IN_TAP_KEY_SIG);
                assertNotNull(name + " " + idx, e);
                assertEquals(name + " input " + idx + " (" + r.inputs.get(idx).type + ")", s.getString("sig"), BtcCrypto.hex(e.value));
            }
            assertEquals(name, f.getString("txid"), BtcCrypto.hex(BtcCrypto.reversed(BtcPsbtSigner.finalTxid(r, signed))));
        }
    }

    // ------------------------------------------------------------------ fee / amount

    /**
     * Mixed Legacy + Taproot, Taproot coin WITHOUT its previous transaction (allowed) and with a
     * lied (smaller) amount: the review shows a fee of 1 sat while the real fee is 2,999 sat more,
     * and the fee row says that one coin's amount is stated by the Mac (honest or not: the phone
     * can't tell). The lie is not exploitable: the Legacy and SegWit v0 signatures are valid either way, but the
     * Taproot signature commits to every amount, so it verifies only for the lie and the
     * transaction can never be completed; and the lied amount is not remembered.
     */
    @Test public void unprovenTaprootAmountIsLabelledOnTheFeeAndCannotYieldAValidTransaction() throws Exception {
        Psbt p = psbt(audit("audit-mainnet-legacy-third-of-four"));
        BtcPsbtReview honest = review(p, BtcNetwork.BITCOIN);
        assertEquals(3_000, honest.fee);
        String label = "Network fee (amount of 1 coin stated by your Mac)";
        assertTrue(BtcPsbtTest.has(honest, label, "0.00003000 BTC"));
        assertNull(BtcPsbtTest.value(honest, "Network fee"));
        BtcTx.Output real = Psbt.witnessUtxo(Psbt.find(p.inputs.get(3), Psbt.IN_WITNESS_UTXO).value);
        assertNull(Psbt.find(p.inputs.get(3), Psbt.IN_NON_WITNESS_UTXO));
        Maps m = new Maps(p);
        m.replace(m.in.get(3), Psbt.IN_WITNESS_UTXO, Psbt.entry(Psbt.IN_WITNESS_UTXO, new byte[0], witnessUtxo(real.value - 2_999, real.script)));
        BtcAmountMemory mem = new BtcAmountMemory();
        BtcPsbtReview lie = BtcPsbtReview.build(m.parse(), BtcNetwork.BITCOIN, BtcKeysTest.wallet(BtcNetwork.BITCOIN), null, mem);
        assertEquals("the phone shows the host's (unproven) Taproot amount", 1, lie.fee);
        assertFalse(lie.inputs.get(3).amountProven);
        assertTrue(BtcPsbtTest.has(lie, label, "0.00000001 BTC"));
        for (int i = 0; i < 3; i++) assertTrue(lie.inputs.get(i).amountProven);

        Psbt signed = Psbt.parse(BtcPsbtSigner.sign(lie, BtcKeysTest.seed(), new SecureRandom(), ZERO_AUX));
        BtcTx tx = signed.tx;
        // Legacy (index 2): no amount in the sighash, valid for the real transaction
        BtcPsbtReview.SignInput leg = lie.inputs.get(2);
        assertEquals(LEGACY, leg.type);
        byte[] legSig = Psbt.find(signed.inputs.get(2), Psbt.IN_PARTIAL_SIG).value;
        assertTrue(BtcCrypto.verifyEcdsa(leg.pubkey, tx.sighashLegacy(2, leg.script, BtcTx.SIGHASH_ALL), Arrays.copyOf(legSig, legSig.length - 1)));
        // Taproot (index 3): valid only under the lied amount
        long[] realAmounts = new long[4], liedAmounts = new long[4];
        byte[][] scripts = new byte[4][];
        for (BtcPsbtReview.SignInput in : honest.inputs) { realAmounts[in.index] = in.amount; scripts[in.index] = in.script; }
        for (BtcPsbtReview.SignInput in : lie.inputs) liedAmounts[in.index] = in.amount;
        byte[] tapSig = Psbt.find(signed.inputs.get(3), Psbt.IN_TAP_KEY_SIG).value;
        byte[] outputKey = Arrays.copyOfRange(scripts[3], 2, 34);
        assertTrue(BtcCrypto.verifySchnorr(outputKey, tx.sighashTaproot(3, liedAmounts, scripts, BtcTx.SIGHASH_DEFAULT), tapSig));
        assertFalse("the real transaction can't be completed", BtcCrypto.verifySchnorr(outputKey, tx.sighashTaproot(3, realAmounts, scripts, BtcTx.SIGHASH_DEFAULT), tapSig));
        // the lie is not recorded (only proven inputs are), so the honest PSBT is not blocked later
        for (BtcPsbtReview.SignInput in : lie.inputs) if (in.amountProven) mem.record(tx.inputs.get(in.index).outpoint(), in.amount, in.script);
        assertEquals(3_000, BtcPsbtReview.build(p, BtcNetwork.BITCOIN, BtcKeysTest.wallet(BtcNetwork.BITCOIN), null, mem).fee);
    }

    // ------------------------------------------------------------------ redeem-script substitution

    /** P2SH-P2WSH (a 1-of-1 multisig of this wallet's BIP-49 key) dressed as a Nested SegWit coin: refused. */
    @Test public void p2shP2wshOrBareP2shOfOurKeyIsRefused() throws Exception {
        Psbt p = psbt(audit("audit-mainnet-legacy-third-of-four")); // input 1 is m/49'/0'/1'/0/4
        BtcWallet w = BtcKeysTest.wallet(BtcNetwork.BITCOIN);
        byte[] pub = w.publicKey(NESTED, 1, 0, 4);
        byte[] ws = BtcPsbtTest.concat(BtcPsbtTest.concat(new byte[] {0x51, 0x21}, pub), new byte[] {0x51, (byte) 0xae});
        byte[] wsh = BtcPsbtTest.concat(new byte[] {0x00, 0x20}, BtcCrypto.sha256(ws));
        byte[] shwsh = BtcScript.p2sh(BtcCrypto.hash160(wsh));
        Maps a = new Maps(BtcPsbtTest.withCoin(p, 1, 220_000, shwsh, true));
        a.replace(a.in.get(1), Psbt.IN_REDEEM_SCRIPT, Psbt.entry(Psbt.IN_REDEEM_SCRIPT, new byte[0], wsh));
        assertRefused(a.parse(), BtcNetwork.BITCOIN, "Input 2 claims key path m/49'/0'/1'/0/4 but its script does not belong to that key");
        a.in.get(1).add(Psbt.entry(Psbt.IN_WITNESS_SCRIPT, new byte[0], ws));
        assertRefused(a.parse(), BtcNetwork.BITCOIN, "a witness script (P2WSH)");
        // bare P2SH of "<key> OP_CHECKSIG" (legacy-sighash P2SH): refused the same way
        byte[] pk = BtcPsbtTest.concat(BtcPsbtTest.concat(new byte[] {0x21}, pub), new byte[] {(byte) 0xac});
        Maps b = new Maps(BtcPsbtTest.withCoin(p, 1, 220_000, BtcScript.p2sh(BtcCrypto.hash160(pk)), true));
        b.replace(b.in.get(1), Psbt.IN_REDEEM_SCRIPT, Psbt.entry(Psbt.IN_REDEEM_SCRIPT, new byte[0], pk));
        assertRefused(b.parse(), BtcNetwork.BITCOIN, "script does not belong to that key");
    }

    // ------------------------------------------------------------------ keys, paths, flags

    /** The P2PKH address of this wallet's key in UNCOMPRESSED form, with a 65-byte derivation key: refused. */
    @Test public void uncompressedLegacyKeyIsRefused() throws Exception {
        Psbt p = psbt(audit("audit-mainnet-legacy-third-of-four"));
        BtcWallet w = BtcKeysTest.wallet(BtcNetwork.BITCOIN);
        byte[] unc = BtcCrypto.decodePoint(w.publicKey(LEGACY, 0, 0, 5)).getEncoded(false);
        Maps m = new Maps(BtcPsbtTest.withCoin(p, 2, 230_000, BtcScript.p2pkhScript(BtcCrypto.hash160(unc)), true));
        m.remove(m.in.get(2), Psbt.IN_WITNESS_UTXO);
        m.remove(m.in.get(2), Psbt.IN_BIP32_DERIVATION);
        m.in.get(2).add(Psbt.entry(Psbt.IN_BIP32_DERIVATION, unc, origin(w.fingerprint(), 44 | H, H, H, 0, 5)));
        assertRefused(m.parse(), BtcNetwork.BITCOIN, "but a different key than this wallet's");
    }

    @Test public void legacyAndNestedPathBoundsAndNetwork() throws Exception {
        Psbt p = psbt(audit("audit-testnet-v1-legacy-last")); // input 2: m/44'/1'/19'/1/7 (account 20)
        review(p, BtcNetwork.TESTNET);
        review(p, BtcNetwork.SIGNET); // same coin type and encodings: the host's claim, shown in amber
        assertRefused(p, BtcNetwork.BITCOIN, "outside this wallet's Bitcoin accounts");
        byte[] fp = BtcKeysTest.wallet(BtcNetwork.TESTNET).fingerprint();
        Psbt.Entry d = Psbt.find(p.inputs.get(1), Psbt.IN_BIP32_DERIVATION);
        int[][] bad = {
            {44 | H, 1 | H, 20 | H, 1, 7},      // account 21
            {44 | H, 1 | H, 19, 1, 7},          // unhardened account
            {44 | H, 1 | H, 19 | H, 2, 7},      // chain 2
            {44 | H, 1 | H, 19 | H, 1, 7 | H},  // hardened index
            {44 | H, 0 | H, 19 | H, 1, 7},      // mainnet coin type on testnet
            {44 | H, 1 | H, 19 | H, 1},         // short path
        };
        for (int[] path : bad) {
            Maps m = new Maps(p);
            m.replace(m.in.get(1), Psbt.IN_BIP32_DERIVATION, Psbt.entry(Psbt.IN_BIP32_DERIVATION, d.keyData, origin(fp, path)));
            assertRefused(m.parse(), BtcNetwork.TESTNET, "Input 2");
        }
    }

    @Test public void legacySighashFlagsOtherThanAllAndDuplicateCoinsAreRefused() throws Exception {
        Psbt p = psbt(audit("audit-mainnet-legacy-third-of-four"));
        for (byte[] t : new byte[][] {{0x41, 0, 0, 0}, {0x01, 0x01, 0, 0}, {(byte) 0x81, 0, 0, 0}, {0x01, 0, 0, 0x01}}) {
            Maps m = new Maps(p);
            m.in.get(2).add(Psbt.entry(Psbt.IN_SIGHASH_TYPE, new byte[0], t));
            assertRefused(m.parse(), BtcNetwork.BITCOIN, "Input 3 asks for signature hash type");
        }
        // the same Legacy coin twice (input 3 copied over input 4)
        Maps dup = new Maps(p);
        List<BtcTx.Input> ins = new ArrayList<>(p.tx.inputs);
        ins.set(3, ins.get(2));
        dup.tx(new BtcTx(p.tx.version, ins, new ArrayList<>(p.tx.outputs), p.tx.locktime, false));
        dup.in.set(3, new ArrayList<>(p.inputs.get(2)));
        assertRefused(dup.parse(), BtcNetwork.BITCOIN, "Input 4 spends the same coin twice");
    }

    /** A Legacy input whose host-supplied witness UTXO names a Nested SegWit script of the same key: refused (disagrees with the previous transaction). */
    @Test public void legacyCoinCannotBeRetypedThroughTheWitnessUtxo() throws Exception {
        Psbt p = psbt(audit("audit-mainnet-legacy-third-of-four"));
        BtcWallet w = BtcKeysTest.wallet(BtcNetwork.BITCOIN);
        Maps m = new Maps(p);
        m.in.get(2).add(Psbt.entry(Psbt.IN_WITNESS_UTXO, new byte[0], witnessUtxo(230_000, BtcWallet.scriptFor(NESTED, w.publicKey(LEGACY, 0, 0, 5)))));
        assertRefused(m.parse(), BtcNetwork.BITCOIN, "Input 3: the previous transaction and the witness UTXO disagree about the coin");
        assertArrayEquals(BtcWallet.scriptFor(LEGACY, w.publicKey(LEGACY, 0, 0, 5)), review(p, BtcNetwork.BITCOIN).inputs.get(2).script);
    }
}
