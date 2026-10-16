package dev.phonevault.signer;

import static dev.phonevault.signer.BtcPsbtTest.H;
import static dev.phonevault.signer.BtcPsbtTest.Maps;
import static dev.phonevault.signer.BtcPsbtTest.assertRefused;
import static dev.phonevault.signer.BtcPsbtTest.fixture;
import static dev.phonevault.signer.BtcPsbtTest.has;
import static dev.phonevault.signer.BtcPsbtTest.origin;
import static dev.phonevault.signer.BtcPsbtTest.psbt;
import static dev.phonevault.signer.BtcPsbtTest.review;
import static dev.phonevault.signer.BtcPsbtTest.value;
import static dev.phonevault.signer.BtcPsbtTest.witnessUtxo;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Migration support for coins of a restored Ledger/Trezor-era wallet: BIP-49 Nested SegWit
 * (P2SH-P2WPKH, 3… / 2…) and BIP-44 Legacy (P2PKH, 1… / m…, n…) accounts. Published vectors (BIP-49's
 * own test vector; the well-known BIP-44 addresses of "abandon … about", cross-checked with embit
 * 0.8.0), descriptors, and every signing rule specific to these types. The signing cross-check
 * against embit is BtcPsbtTest#signaturesMatchAnIndependentImplementation (fixtures
 * p2sh-p2wpkh-send-with-change, p2pkh-send-with-change, testnet-sweep-all-types).
 */
public final class BtcNestedAndLegacyTest {
    private static final BtcWallet.Type NESTED = BtcWallet.Type.P2SH_P2WPKH, LEGACY = BtcWallet.Type.P2PKH;

    // ------------------------------------------------------------------ keys and addresses

    /** BIP-49 "Test vectors" (testnet, account 0, first receiving address). */
    @Test public void bip49SpecVector() {
        BtcWallet t = BtcKeysTest.wallet(BtcNetwork.TESTNET);
        assertEquals("m/49'/1'/0'", t.accountPathString(NESTED, 0));
        // account0Xpriv tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY
        byte[] tprv = Base58.decodeCheck("tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY");
        Bip32.Key account = Bip32.derive(Bip32.master(BtcKeysTest.seed()), 49 | H, 1 | H, H);
        assertArrayEquals(Arrays.copyOfRange(tprv, 46, 78), account.privateKey());
        assertArrayEquals(Arrays.copyOfRange(tprv, 13, 45), account.chainCode);
        account.destroy();
        assertEquals("tpubDD7tXK8KeQ3YY83yWq755fHY2JW8Ha8Q765tknUM5rSvjPcGWfUppDFMpQ1ScziKfW3ZNtZvAD7M3u7bSs7HofjTD3KP3YxPK7X6hwV8Rk2", t.xpub(NESTED, 0));
        // account0recvPrivateKey cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ
        Bip32.Key k = BtcWallet.derivePrivate(BtcKeysTest.seed(), BtcNetwork.TESTNET, NESTED, 0, 0, 0);
        assertArrayEquals(Arrays.copyOfRange(Base58.decodeCheck("cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ"), 1, 33), k.privateKey());
        k.destroy();
        byte[] pub = t.publicKey(NESTED, 0, 0, 0);
        assertEquals("03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f", BtcCrypto.hex(pub));
        assertEquals("38971f73930f6c141d977ac4fd4a727c854935b3", BtcCrypto.hex(BtcCrypto.hash160(pub)));
        assertEquals("001438971f73930f6c141d977ac4fd4a727c854935b3", BtcCrypto.hex(BtcWallet.redeemScript(pub)));
        assertEquals("a914336caa13e08b96080a32b5d818d59b4ab3b3674287", BtcCrypto.hex(t.scriptPubKey(NESTED, 0, 0, 0)));
        assertEquals("2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", t.address(NESTED, 0, 0, 0));
        // signet shares testnet's encodings
        assertEquals("2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", BtcKeysTest.wallet(BtcNetwork.SIGNET).address(NESTED, 0, 0, 0));
    }

    /** Mainnet BIP-49 and BIP-44 for "abandon … about" (as Ledger, Trezor, Electrum and embit 0.8.0 derive them). */
    @Test public void mainnetVectors() {
        BtcWallet w = BtcKeysTest.wallet(BtcNetwork.BITCOIN);
        assertEquals("xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAet9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7", w.xpub(NESTED, 0));
        assertEquals("039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24", BtcCrypto.hex(w.publicKey(NESTED, 0, 0, 0)));
        assertEquals("37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf", w.address(NESTED, 0, 0, 0));
        assertEquals("34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7", w.address(NESTED, 0, 1, 0));

        assertEquals("m/44'/0'/0'", w.accountPathString(LEGACY, 0));
        assertEquals("xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj", w.xpub(LEGACY, 0));
        assertEquals("03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e", BtcCrypto.hex(w.publicKey(LEGACY, 0, 0, 0)));
        assertEquals("1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", w.address(LEGACY, 0, 0, 0));
        assertEquals("1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP", w.address(LEGACY, 0, 0, 1));
        assertEquals("1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH", w.address(LEGACY, 0, 1, 0));
        assertEquals("76a914" + BtcCrypto.hex(BtcCrypto.hash160(w.publicKey(LEGACY, 0, 0, 0))) + "88ac", BtcCrypto.hex(w.scriptPubKey(LEGACY, 0, 0, 0)));
        // m/44'/0'/0'/0/0 WIF L4p2b9VAf8k5aUahF1JCJUzZkgNEAqLfq8DDdQiyAprQAKSbu8hf (embit)
        Bip32.Key k = BtcWallet.derivePrivate(BtcKeysTest.seed(), BtcNetwork.BITCOIN, LEGACY, 0, 0, 0);
        assertArrayEquals(Arrays.copyOfRange(Base58.decodeCheck("L4p2b9VAf8k5aUahF1JCJUzZkgNEAqLfq8DDdQiyAprQAKSbu8hf"), 1, 33), k.privateKey());
        k.destroy();

        BtcWallet t = BtcKeysTest.wallet(BtcNetwork.TESTNET);
        assertEquals("tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba", t.xpub(LEGACY, 0));
        assertEquals("mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV", t.address(LEGACY, 0, 0, 0));
    }

    /** Descriptors exactly as embit 0.8.0 writes them (checksum included); always xpub/tpub, never ypub. */
    @Test public void descriptors() {
        BtcWallet m = BtcKeysTest.wallet(BtcNetwork.BITCOIN), t = BtcKeysTest.wallet(BtcNetwork.TESTNET);
        assertEquals("sh(wpkh([73c5da0a/49h/0h/0h]xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAet9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7/<0;1>/*))#zmygnj3e",
                m.descriptor(NESTED, 0));
        assertEquals("pkh([73c5da0a/44h/0h/0h]xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/<0;1>/*)#kw28l7md",
                m.descriptor(LEGACY, 0));
        assertEquals("sh(wpkh([73c5da0a/49h/1h/3h]tpubDD7tXK8KeQ3YfwUyWrMttexrCTzsUN9bNGy6RDjvQUabHYaChowSzvMREw75uTP4F4n2HJMmJquTnYMvJfpQzbmjZ3E4212sZP4ZwzJqVjG/<0;1>/*))#hvqwwafw",
                t.descriptor(NESTED, 3));
        assertEquals("pkh([73c5da0a/44h/1h/19h]tpubDC5FSnBiZDMnZ89hrY5HJ7DsRtTwmJnoCfKtHwmEMDz1wA29TkdJyQuwXzKPEYFBqFpM3xWLFDarNZcjR2exnDXhZ9HXHr6BuVQX8zozEpq/<0;1>/*)#edm9s4r6",
                t.descriptor(LEGACY, 19));
        // embit derives these from the descriptors above
        assertEquals("2NBhvigX5FwR1ydAdUGFh9jq37t2TJoorNw", t.address(NESTED, 3, 0, 0));
        assertEquals("n3ZmDbZJwavxkXZZD19avq3qhdvirEuYzx", t.address(LEGACY, 19, 0, 0));
        // the existing types are unchanged
        assertTrue(m.descriptor(BtcWallet.Type.P2WPKH, 0).startsWith("wpkh([73c5da0a/84h/0h/0h]xpub"));
        assertTrue(m.descriptor(BtcWallet.Type.P2TR, 0).startsWith("tr([73c5da0a/86h/0h/0h]xpub"));
    }

    // ------------------------------------------------------------------ USB requests

    @Test public void requestsAndSharingAcceptTheNewTypes() throws Exception {
        JSONObject get = new JSONObject().put("id", "a-1").put("method", "btcGetAccount").put("network", "bitcoin").put("type", "p2sh-p2wpkh").put("account", "2");
        BtcRequest r = BtcRequest.parse(get);
        assertEquals(NESTED, r.type);
        assertEquals(1, r.account);
        assertEquals(LEGACY, BtcRequest.parse(new JSONObject(get.toString()).put("type", "p2pkh")).type);
        for (String bad : new String[] {"p2sh", "p2sh_p2wpkh", "P2PKH", "p2wpkh-p2sh", "pkh", "sh-wpkh"}) {
            try { BtcRequest.parse(new JSONObject(get.toString()).put("type", bad)); fail(bad); } catch (JSONException expected) { }
        }
        assertTrue(BtcRequest.lockedSummary(get).contains("Account 2 · Nested SegWit"));
        JSONObject a = BtcRequest.accountResponse("a-1", BtcKeysTest.wallet(BtcNetwork.BITCOIN), LEGACY, 0);
        assertEquals("m/44'/0'/0'", a.getString("path"));
        assertTrue(a.getString("descriptor").startsWith("pkh([73c5da0a/44h/0h/0h]xpub6BosfCni"));
        JSONObject show = new JSONObject(get.toString()).put("method", "btcShowAddress").put("change", "0").put("index", "0");
        assertEquals(NESTED, BtcRequest.parse(show).type);

        String wallet = "0x9858effd232b4033e47d90003d41ec34ecaeda94";
        BtcSharing s = BtcSharing.load(null, wallet);
        s.share(BtcNetwork.BITCOIN, NESTED, 0);
        s.share(BtcNetwork.TESTNET, LEGACY, 19);
        BtcSharing reloaded = BtcSharing.load(s.encode(), wallet);
        assertTrue(reloaded.isShared(BtcNetwork.BITCOIN, NESTED, 0));
        assertTrue(reloaded.isShared(BtcNetwork.TESTNET, LEGACY, 19));
        assertFalse(reloaded.isShared(BtcNetwork.BITCOIN, LEGACY, 0));
        assertEquals("Bitcoin · Account 1 · Nested SegWit", BtcSharing.label("bitcoin/p2sh-p2wpkh/1"));
        assertEquals("Bitcoin TESTNET · Account 20 · Legacy", BtcSharing.label("testnet/p2pkh/20"));
    }

    // ------------------------------------------------------------------ review

    @Test public void nestedSegwitReview() throws Exception {
        BtcPsbtReview r = review(psbt(fixture("p2sh-p2wpkh-send-with-change")), BtcNetwork.BITCOIN);
        assertEquals("Account 1 · Nested SegWit (m/49'/0'/0')\n2 coins, 0.01000000 BTC", value(r, "Spending from"));
        assertTrue(value(r, "Send"), value(r, "Send").endsWith("\nNative SegWit (P2WPKH) address"));
        assertEquals("0.00348000 BTC · " + AddressKeys.shortBtc("34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7") + " · m/49'/0'/0'/1/0",
                value(r, "Change back to your wallet ✓"));
        assertTrue(r.outputs.get(1).change);
        assertEquals(2_000, r.fee);
        for (BtcPsbtReview.SignInput in : r.inputs) {
            assertEquals(NESTED, in.type);
            assertTrue("the previous transaction proves the amount", in.amountProven);
            assertEquals(BtcTx.SIGHASH_ALL, in.hashType);
        }
        assertTrue(has(r, "Network fee", "0.00002000 BTC"));
        boolean detail = false;
        for (MessageReview.Row row : r.details) if (row.label.equals("Input 1") && row.value.contains("Nested SegWit · SIGHASH_ALL")) detail = true;
        assertTrue(detail);
        assertNull(value(r, MessageReview.WARNING));
        assertNull(value(r, MessageReview.DANGER));
    }

    @Test public void legacyReview() throws Exception {
        BtcPsbtReview r = review(psbt(fixture("p2pkh-send-with-change")), BtcNetwork.BITCOIN);
        assertTrue(has(r, "Spending from", "Account 1 · Legacy (m/44'/0'/0')\n1 coin, 0.00400000 BTC"));
        assertTrue(has(r, "Spending from", "Account 3 · Legacy (m/44'/0'/2')\n1 coin, 0.00250000 BTC"));
        assertTrue(value(r, "Send"), value(r, "Send").endsWith("\nLegacy (P2PKH) address"));
        assertTrue(r.outputs.get(1).change);
        assertEquals("1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH", r.outputs.get(1).address);
        for (BtcPsbtReview.SignInput in : r.inputs) assertTrue(in.amountProven);
        // no witness: no SegWit marker, two 148 vB inputs
        assertEquals(10 + 2 * 148 + 2 * 34, r.vsize);
        assertNull(Psbt.find(r.psbt.inputs.get(0), Psbt.IN_WITNESS_UTXO));
    }

    @Test public void sweepOfEveryTypeOnTestnet() throws Exception {
        BtcPsbtReview r = review(psbt(fixture("testnet-sweep-all-types")), BtcNetwork.TESTNET);
        assertEquals(4, r.inputs.size());
        assertEquals(LEGACY, r.inputs.get(0).type);
        assertEquals(NESTED, r.inputs.get(1).type);
        assertEquals(BtcWallet.Type.P2WPKH, r.inputs.get(2).type);
        assertEquals(BtcWallet.Type.P2TR, r.inputs.get(3).type);
        assertTrue(value(r, "Send"), value(r, "Send").contains("\n2") && value(r, "Send").endsWith("Script hash (P2SH) address"));
        assertTrue(r.outputs.get(1).change);
        assertEquals(2_000, r.fee);
    }

    // ------------------------------------------------------------------ refusals

    @Test public void everyNonTaprootInputMustCarryItsPreviousTransaction() throws Exception {
        for (String name : new String[] {"p2sh-p2wpkh-send-with-change", "p2pkh-send-with-change", "testnet-sweep-all-types"}) {
            JSONObject f = fixture(name);
            BtcNetwork n = BtcNetwork.fromWire(f.getString("network"));
            Psbt p = psbt(f);
            for (int i = 0; i < p.inputs.size(); i++) {
                Maps m = new Maps(p);
                m.remove(m.in.get(i), Psbt.IN_NON_WITNESS_UTXO);
                if (Psbt.find(p.inputs.get(i), Psbt.IN_TAP_BIP32_DERIVATION) != null) {
                    review(m.parse(), n); // Taproot: none needed
                } else if (Psbt.find(p.inputs.get(i), Psbt.IN_WITNESS_UTXO) == null) {
                    // a legacy coin then has nothing that says what it is
                    assertRefused(m.parse(), n, "Input " + (i + 1) + " has no witness UTXO");
                } else {
                    assertRefused(m.parse(), n, "Input " + (i + 1) + " is a ");
                    assertRefused(m.parse(), n, "coin without its previous transaction");
                }
            }
        }
        // the exact wording per type
        Maps nested = new Maps(psbt(fixture("p2sh-p2wpkh-send-with-change")));
        nested.remove(nested.in.get(0), Psbt.IN_NON_WITNESS_UTXO);
        assertRefused(nested.parse(), BtcNetwork.BITCOIN, "Input 1 is a Nested SegWit coin without its previous transaction");
        // a legacy input that carries a witness UTXO but no previous transaction: still refused
        Psbt legacy = psbt(fixture("p2pkh-send-with-change"));
        Maps lw = new Maps(legacy);
        BtcTx.Output real = prevOut(legacy, 0);
        lw.in.get(0).add(Psbt.entry(Psbt.IN_WITNESS_UTXO, new byte[0], witnessUtxo(real.value, real.script)));
        review(lw.parse(), BtcNetwork.BITCOIN); // consistent with the previous transaction: fine
        lw.remove(lw.in.get(0), Psbt.IN_NON_WITNESS_UTXO);
        assertRefused(lw.parse(), BtcNetwork.BITCOIN, "Input 1 is a Legacy coin without its previous transaction");
        // ... and a witness UTXO that lies about the legacy coin's amount
        Maps lie = new Maps(legacy);
        lie.in.get(0).add(Psbt.entry(Psbt.IN_WITNESS_UTXO, new byte[0], witnessUtxo(real.value + 100_000, real.script)));
        assertRefused(lie.parse(), BtcNetwork.BITCOIN, "disagree about the coin");
    }

    static BtcTx.Output prevOut(Psbt p, int i) {
        BtcTx prev = BtcTx.parse(Psbt.find(p.inputs.get(i), Psbt.IN_NON_WITNESS_UTXO).value, BtcTx.MAX_PREV_IO);
        return prev.outputs.get((int) p.tx.inputs.get(i).vout);
    }

    @Test public void redeemScriptMustBeTheDerivedKeys() throws Exception {
        Psbt p = psbt(fixture("p2sh-p2wpkh-send-with-change"));
        BtcWallet w = BtcKeysTest.wallet(BtcNetwork.BITCOIN);
        assertArrayEquals(BtcWallet.redeemScript(w.publicKey(NESTED, 0, 0, 0)), Psbt.find(p.inputs.get(0), Psbt.IN_REDEEM_SCRIPT).value);
        Maps missing = new Maps(p);
        missing.remove(missing.in.get(1), Psbt.IN_REDEEM_SCRIPT);
        assertRefused(missing.parse(), BtcNetwork.BITCOIN, "Input 2 is a Nested SegWit (P2SH) coin without its redeem script");
        // the other input's redeem script (another key of this wallet)
        Maps swapped = new Maps(p);
        swapped.replace(swapped.in.get(1), Psbt.IN_REDEEM_SCRIPT, Psbt.find(p.inputs.get(0), Psbt.IN_REDEEM_SCRIPT));
        assertRefused(swapped.parse(), BtcNetwork.BITCOIN, "Input 2 names a redeem script that is not this wallet's key's");
        // a P2SH multisig-looking redeem script
        Maps multisig = new Maps(p);
        multisig.replace(multisig.in.get(0), Psbt.IN_REDEEM_SCRIPT, Psbt.entry(Psbt.IN_REDEEM_SCRIPT, new byte[0],
                Hex.bytes("5121" + BtcCrypto.hex(w.publicKey(NESTED, 0, 0, 0)) + "51ae")));
        assertRefused(multisig.parse(), BtcNetwork.BITCOIN, "Input 1 names a redeem script");
        // a redeem script on a legacy input, a witness script on a nested one
        Psbt legacy = psbt(fixture("p2pkh-send-with-change"));
        Maps lr = new Maps(legacy);
        lr.in.get(0).add(Psbt.entry(Psbt.IN_REDEEM_SCRIPT, new byte[0], BtcWallet.redeemScript(w.publicKey(LEGACY, 0, 0, 0))));
        assertRefused(lr.parse(), BtcNetwork.BITCOIN, "Input 1 carries a redeem script (P2SH)");
        Maps ws = new Maps(p);
        ws.in.get(0).add(Psbt.entry(Psbt.IN_WITNESS_SCRIPT, new byte[0], new byte[] {0x51}));
        assertRefused(ws.parse(), BtcNetwork.BITCOIN, "a witness script (P2WSH)");
        // an already finalized scriptSig
        Maps fin = new Maps(legacy);
        fin.in.get(0).add(Psbt.entry(Psbt.IN_FINAL_SCRIPTSIG, new byte[0], new byte[] {0x51}));
        assertRefused(fin.parse(), BtcNetwork.BITCOIN, "already finalized data");
        // an own Nested SegWit output naming another redeem script
        Maps out = new Maps(p);
        out.replace(out.out.get(1), Psbt.OUT_REDEEM_SCRIPT, Psbt.entry(Psbt.OUT_REDEEM_SCRIPT, new byte[0], BtcWallet.redeemScript(w.publicKey(NESTED, 0, 0, 0))));
        assertRefused(out.parse(), BtcNetwork.BITCOIN, "Output 2 names a redeem script");
    }

    @Test public void derivationPurposeMustMatchTheScriptType() throws Exception {
        Psbt p = psbt(fixture("p2pkh-send-with-change"));
        BtcWallet w = BtcKeysTest.wallet(BtcNetwork.BITCOIN);
        byte[] fp = w.fingerprint();
        // the legacy coin's key named under BIP-49 / BIP-84 paths
        for (int purpose : new int[] {49, 84}) {
            Maps m = new Maps(p);
            Psbt.Entry d = Psbt.find(p.inputs.get(0), Psbt.IN_BIP32_DERIVATION);
            m.replace(m.in.get(0), Psbt.IN_BIP32_DERIVATION, Psbt.entry(Psbt.IN_BIP32_DERIVATION, d.keyData, origin(fp, purpose | H, H, H, 0, 0)));
            assertRefused(m.parse(), BtcNetwork.BITCOIN, "which does not fit its script type (Legacy)");
        }
        // the SAME key as a P2SH-P2WPKH coin under its BIP-44 path: refused (the script is not the path's type)
        byte[] legacyKey = w.publicKey(LEGACY, 0, 0, 0);
        Psbt asNested = BtcPsbtTest.withCoin(p, 0, 400_000, BtcWallet.scriptFor(NESTED, legacyKey), true);
        Maps m = new Maps(asNested);
        m.remove(m.in.get(0), Psbt.IN_WITNESS_UTXO);
        m.in.get(0).add(Psbt.entry(Psbt.IN_WITNESS_UTXO, new byte[0], witnessUtxo(400_000, BtcWallet.scriptFor(NESTED, legacyKey))));
        m.in.get(0).add(Psbt.entry(Psbt.IN_REDEEM_SCRIPT, new byte[0], BtcWallet.redeemScript(legacyKey)));
        assertRefused(m.parse(), BtcNetwork.BITCOIN, "m/44'/0'/0'/0/0 (Legacy), which does not fit its script type (Nested SegWit)");
        // a legacy coin paying someone else, with this wallet's path and key
        assertRefused(BtcPsbtTest.withCoin(p, 0, 400_000, BtcScript.p2pkhScript(new byte[20]), true), BtcNetwork.BITCOIN,
                "script does not belong to that key");
        // the testnet key on mainnet
        assertRefused(psbt(fixture("testnet-sweep-all-types")), BtcNetwork.BITCOIN, "outside this wallet's Bitcoin accounts");
    }

    @Test public void onlySighashAll() throws Exception {
        for (String name : new String[] {"p2sh-p2wpkh-send-with-change", "p2pkh-send-with-change"}) {
            Psbt p = psbt(fixture(name));
            for (int t : new int[] {0x00, 0x02, 0x03, 0x81, 0x82, 0x83}) {
                Maps m = new Maps(p);
                m.in.get(0).add(Psbt.entry(Psbt.IN_SIGHASH_TYPE, new byte[0], new byte[] {(byte) t, 0, 0, 0}));
                assertRefused(m.parse(), BtcNetwork.BITCOIN, "signature hash type 0x" + Integer.toHexString(t));
            }
            Maps all = new Maps(p);
            all.in.get(0).add(Psbt.entry(Psbt.IN_SIGHASH_TYPE, new byte[0], new byte[] {1, 0, 0, 0}));
            review(all.parse(), BtcNetwork.BITCOIN);
        }
        try {
            psbt(fixture("p2pkh-send-with-change")).tx.sighashLegacy(0, BtcScript.p2pkhScript(new byte[20]), BtcTx.SIGHASH_NONE);
            fail();
        } catch (IllegalArgumentException expected) { }
        try {
            psbt(fixture("p2pkh-send-with-change")).tx.sighashLegacy(0, new byte[] {(byte) 0xab, (byte) 0xac}, BtcTx.SIGHASH_ALL);
            fail("OP_CODESEPARATOR script code");
        } catch (IllegalArgumentException expected) { }
    }

    /** Change only on the spent account AND type; a Legacy or Nested own output elsewhere is a WARNING. */
    @Test public void changeToAnotherTypeIsNotChange() throws Exception {
        Psbt p = psbt(fixture("p2pkh-send-with-change")); // spends m/44'/0'/0'/0/0 and m/44'/0'/2'/0/3
        BtcWallet w = BtcKeysTest.wallet(BtcNetwork.BITCOIN);
        // change to the Nested SegWit account 1 (same account number, other type)
        BtcPsbtReview nested = review(ownOutput(p, 1, NESTED, 0, 1, 0, w), BtcNetwork.BITCOIN);
        assertFalse(nested.outputs.get(1).change);
        assertTrue(nested.outputs.get(1).ownElsewhere);
        assertTrue(has(nested, MessageReview.WARNING, "To your wallet: Account 1 · Nested SegWit, path m/49'/0'/0'/1/0, which your wallet app may not show"
                + " (it is change for a different account or address type than the coins spent)"));
        // to Native SegWit change of the same account number
        BtcPsbtReview segwit = review(ownOutput(p, 1, BtcWallet.Type.P2WPKH, 0, 1, 0, w), BtcNetwork.BITCOIN);
        assertFalse(segwit.outputs.get(1).change);
        assertTrue(has(segwit, MessageReview.WARNING, "Account 1 · Native SegWit, path m/84'/0'/0'/1/0"));
        // Legacy change of the other spent account (3), within the window: change
        assertTrue(review(ownOutput(p, 1, LEGACY, 2, 1, 23, w), BtcNetwork.BITCOIN).outputs.get(1).change);
        assertFalse(review(ownOutput(p, 1, LEGACY, 2, 1, 24, w), BtcNetwork.BITCOIN).outputs.get(1).change);
        // an own Nested SegWit receive address (another type than spent) within the first 20: own ✓
        BtcPsbtReview recv = review(ownOutput(p, 1, NESTED, 0, 0, 5, w), BtcNetwork.BITCOIN);
        assertTrue(recv.outputs.get(1).ownReceive);
        assertTrue(has(recv, "Your own address ✓", "m/49'/0'/0'/0/5"));
    }

    /** A copy of {@code p} whose output {@code index} pays this wallet's key of {@code type}, with its derivation. */
    static Psbt ownOutput(Psbt p, int index, BtcWallet.Type type, int account, int change, int i, BtcWallet w) {
        byte[] pub = w.publicKey(type, account, change, i);
        Maps m = new Maps(p);
        List<BtcTx.Output> outs = new ArrayList<>(p.tx.outputs);
        outs.set(index, new BtcTx.Output(p.tx.outputs.get(index).value, BtcWallet.scriptFor(type, pub)));
        m.tx(new BtcTx(p.tx.version, new ArrayList<>(p.tx.inputs), outs, p.tx.locktime, false));
        m.out.get(index).clear();
        m.out.get(index).add(Psbt.entry(Psbt.OUT_BIP32_DERIVATION, pub, origin(w.fingerprint(), type.purpose | H, H, account | H, change, i)));
        if (type == NESTED) m.out.get(index).add(Psbt.entry(Psbt.OUT_REDEEM_SCRIPT, new byte[0], BtcWallet.redeemScript(pub)));
        return m.parse();
    }

    // ------------------------------------------------------------------ signing

    @Test public void signaturesVerifyAndTheFinalTxidIsKnown() throws Exception {
        for (String name : new String[] {"p2sh-p2wpkh-send-with-change", "p2pkh-send-with-change", "testnet-sweep-all-types"}) {
            JSONObject f = fixture(name);
            BtcNetwork n = BtcNetwork.fromWire(f.getString("network"));
            BtcPsbtReview r = review(psbt(f), n);
            byte[] signed = BtcPsbtSigner.sign(r, BtcKeysTest.seed(), new SecureRandom());
            Psbt out = Psbt.parse(signed);
            for (BtcPsbtReview.SignInput in : r.inputs) {
                if (!in.type.ecdsa()) continue;
                Psbt.Entry e = Psbt.find(out.inputs.get(in.index), Psbt.IN_PARTIAL_SIG);
                assertArrayEquals(in.pubkey, e.keyData);
                assertEquals(BtcTx.SIGHASH_ALL, e.value[e.value.length - 1]);
                byte[] der = Arrays.copyOf(e.value, e.value.length - 1);
                byte[] digest = in.type == LEGACY ? out.tx.sighashLegacy(in.index, in.script, BtcTx.SIGHASH_ALL)
                        : out.tx.sighashSegwitV0(in.index, BtcScript.p2pkhScript(BtcCrypto.hash160(in.pubkey)), in.amount, BtcTx.SIGHASH_ALL);
                assertTrue(name + " " + in.index, BtcCrypto.verifyEcdsa(in.pubkey, digest, der));
                // nothing finalized: the host builds scriptSig and witness
                assertNull(Psbt.find(out.inputs.get(in.index), Psbt.IN_FINAL_SCRIPTSIG));
                assertNull(Psbt.find(out.inputs.get(in.index), Psbt.IN_FINAL_SCRIPTWITNESS));
            }
            assertEquals(name, f.getString("txid"), BtcCrypto.hex(BtcCrypto.reversed(BtcPsbtSigner.finalTxid(r, signed))));
        }
        // SegWit-only: the final txid is the unsigned transaction's
        BtcPsbtReview segwit = review(psbt(fixture("p2wpkh-send-with-change")), BtcNetwork.BITCOIN);
        byte[] s = BtcPsbtSigner.sign(segwit, BtcKeysTest.seed(), new SecureRandom());
        assertArrayEquals(segwit.psbt.tx.txid(), BtcPsbtSigner.finalTxid(segwit, s));
    }

    @Test public void legacySighashCommitsToNoAmount() throws Exception {
        // which is why the previous transaction is mandatory for P2PKH inputs
        Psbt p = psbt(fixture("p2pkh-send-with-change"));
        byte[] spk = prevOut(p, 0).script;
        byte[] a = p.tx.sighashLegacy(0, spk, BtcTx.SIGHASH_ALL);
        assertArrayEquals(a, p.tx.sighashLegacy(0, spk, BtcTx.SIGHASH_ALL));
        assertFalse(Arrays.equals(a, p.tx.sighashLegacy(1, prevOut(p, 1).script, BtcTx.SIGHASH_ALL)));
        // and the response round-trips through BtcRequest
        BtcPsbtReview r = review(p, BtcNetwork.BITCOIN);
        JSONObject resp = BtcRequest.signedResponse("x", BtcPsbtSigner.sign(r, BtcKeysTest.seed(), new SecureRandom()));
        assertNotNull(Psbt.parse(Base64.getDecoder().decode(resp.getString("psbt"))));
    }

    @Test public void signingWithAnotherSeedFails() throws Exception {
        for (String name : new String[] {"p2sh-p2wpkh-send-with-change", "p2pkh-send-with-change"}) {
            BtcPsbtReview r = review(psbt(fixture(name)), BtcNetwork.BITCOIN);
            try {
                BtcPsbtSigner.sign(r, SeedVault.bip39Seed(BtcKeysTest.MNEMONIC, "x"), new SecureRandom());
                fail(name);
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("differs from the reviewed key"));
            }
        }
    }
}
