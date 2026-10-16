package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.web3j.crypto.Bip32ECKeyPair;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Multiple accounts (m/44'/60'/0'/0/i) and the BIP-39 passphrase ("25th word") wallet: published
 * BIP-39 / BIP-32 vectors (the "TREZOR" passphrase set), the standard Ethereum derivation vectors,
 * the account list rules, and the request {@code from} refusal. Test vectors only — no real keys.
 */
public final class AccountsTest {
    /** BIP-39 vector: entropy 00…00 (128 bits), passphrase "TREZOR". */
    static final String ABOUT = TestKeys.ABANDON_12;
    /** BIP-39 vector: entropy 00…00 (256 bits), passphrase "TREZOR" (24 words, the length this phone uses). */
    static final String ART = TestKeys.ABANDON_24;
    /** The Hardhat / Foundry development mnemonic: its first accounts are the best-known ETH derivation vectors. */
    static final String JUNK = "test test test test test test test test test test test junk";

    // ------------------------------------------------------------------ BIP-39 / BIP-32 vectors

    @Test public void bip39TrezorSeedsMatchThePublishedVectors() {
        assertEquals("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                Numeric.toHexStringNoPrefix(SeedVault.bip39Seed(ABOUT, "TREZOR")));
        assertEquals("bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
                Numeric.toHexStringNoPrefix(SeedVault.bip39Seed(ART, "TREZOR")));
    }

    @Test public void bip39TrezorMasterKeysMatchThePublishedXprv() {
        assertMaster(ABOUT, "TREZOR", "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF");
        assertMaster(ART, "TREZOR", "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM");
    }

    /** BIP-32 test vector 1 (seed 000102…0f): master fingerprint 3442193e. */
    @Test public void masterFingerprintMatchesBip32Vector1() {
        byte[] seed = Numeric.hexStringToByteArray("000102030405060708090a0b0c0d0e0f");
        assertEquals("3442193E", SeedVault.masterFingerprint(seed));
    }

    @Test public void standardEthereumDerivationVectors() {
        // m/44'/60'/0'/0/i of the development mnemonic (Hardhat/Foundry default accounts 0-3)
        String[] expected = {
                "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
                "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
                "0x90f79bf6eb2c4f870365e785982e1f101e93b906"};
        for (int i = 0; i < expected.length; i++) {
            SeedVault.Derived d = SeedVault.deriveAccount(JUNK, null, i);
            assertEquals("account " + i, expected[i], d.credentials.getAddress());
            assertEquals(i, d.index);
            assertEquals(expected[0], d.account0Address); // the wallet's identity, from any account
            assertEquals(SeedVault.deriveEvm(JUNK, "", i).getAddress(), d.credentials.getAddress());
        }
        // The vector MetaMask documents for "abandon … about" (no passphrase).
        assertEquals("0x9858effd232b4033e47d90003d41ec34ecaeda94", SeedVault.deriveAccount(ABOUT, "", 0).credentials.getAddress());
    }

    @Test public void passphraseOpensADifferentDeterministicWallet() {
        SeedVault.Derived plain = SeedVault.deriveAccount(ART, null, 0);
        SeedVault.Derived trezor = SeedVault.deriveAccount(ART, "TREZOR", 0);
        SeedVault.Derived again = SeedVault.deriveAccount(ART, "TREZOR", 0);
        SeedVault.Derived typo = SeedVault.deriveAccount(ART, "TREZOr", 0);
        assertNotEquals(plain.credentials.getAddress(), trezor.credentials.getAddress());
        assertNotEquals(plain.fingerprint, trezor.fingerprint);
        assertEquals(trezor.credentials.getAddress(), again.credentials.getAddress());
        assertEquals(trezor.fingerprint, again.fingerprint);
        // a wrong passphrase is not an error: it is simply another wallet (by design)
        assertNotEquals(trezor.credentials.getAddress(), typo.credentials.getAddress());
        assertNotEquals(trezor.fingerprint, typo.fingerprint);
        // fingerprint = BIP-32 master fingerprint of the passphrase seed
        assertEquals(SeedVault.masterFingerprint(SeedVault.bip39Seed(ART, "TREZOR")), trezor.fingerprint);
        // empty and null both mean the standard wallet
        assertEquals(plain.credentials.getAddress(), SeedVault.deriveAccount(ART, "", 0).credentials.getAddress());
        // accounts work under a passphrase too, and name the same wallet
        SeedVault.Derived third = SeedVault.deriveAccount(ART, "TREZOR", 2);
        assertEquals(trezor.credentials.getAddress(), third.account0Address);
        assertEquals(trezor.fingerprint, third.fingerprint);
        assertEquals(SeedVault.deriveEvm(ART, "TREZOR", 2).getAddress(), third.credentials.getAddress());
    }

    @Test public void passphraseIsNfkdNormalised() {
        // BIP-39: the passphrase is NFKD-normalised. Composed é (U+00E9) == e + combining acute.
        assertEquals(Numeric.toHexString(SeedVault.bip39Seed(ART, "café")),
                Numeric.toHexString(SeedVault.bip39Seed(ART, "café")));
    }

    @Test public void accountIndexIsBounded() {
        try { SeedVault.deriveAccount(ART, null, SeedVault.MAX_ACCOUNT_INDEX + 1); fail(); } catch (IllegalArgumentException expected) { }
        try { SeedVault.deriveAccount(ART, null, -1); fail(); } catch (IllegalArgumentException expected) { }
        try { SeedVault.deriveAccount("abandon abandon", null, 0); fail(); } catch (IllegalArgumentException expected) { }
    }

    @Test public void passphraseRulesMatchTheKeyboard() {
        assertEquals("Type a passphrase first", SeedVault.passphraseProblem(""));
        assertNull(SeedVault.passphraseProblem("TREZOR"));
        assertNull(SeedVault.passphraseProblem(" correct horse ~!@#$%^&*()_+{}|:\"<>?`-=[]\\;',./ "));
        assertTrue(SeedVault.passphraseProblem("café").contains("keyboard"));
        assertTrue(SeedVault.passphraseProblem("a\nb").contains("keyboard"));
        char[] longest = new char[SeedVault.MAX_PASSPHRASE_LENGTH + 1];
        Arrays.fill(longest, 'x');
        assertTrue(SeedVault.passphraseProblem(new String(longest)).contains("longer"));
        // every printable ASCII character can be typed on the phone's keyboard
        Set<String> keys = new HashSet<>(AccountScreens.allKeys());
        for (char c = '!'; c <= '~'; c++) {
            String k = String.valueOf(c);
            assertTrue("keyboard lacks " + k, keys.contains(k) || keys.contains(k.toLowerCase(java.util.Locale.ROOT)));
        }
    }

    // ------------------------------------------------------------------ account list

    private static String addr(int i) { return SeedVault.deriveAccount(JUNK, null, i).credentials.getAddress(); }

    @Test public void freshBookHasAccountOneActive() {
        AccountBook book = AccountBook.fresh(addr(0));
        assertEquals(0, book.activeIndex());
        assertEquals("Account 1", book.active().name());
        assertEquals(1, book.nextIndex());
        assertEquals(1, book.visible().size());
    }

    @Test public void addSwitchRenameHideAndPersist() {
        AccountBook book = AccountBook.fresh(addr(0));
        book.add(1, addr(1));
        book.add(2, addr(2));
        book.select(1, addr(1));
        assertEquals(1, book.activeIndex());
        assertEquals("Account 2", book.active().name());
        book.rename(1, "  Savings\u0007 ");
        assertEquals("Savings", book.active().name());
        book.rename(1, "   ");
        assertEquals("Account 2", book.active().name());
        book.rename(2, "Trading account with a very long name indeed");
        assertEquals(AccountBook.MAX_LABEL, book.get(2).name().length());
        try { book.hide(1); fail("the active account cannot be hidden"); } catch (IllegalStateException expected) { }
        book.hide(2);
        assertEquals(2, book.visible().size());
        assertEquals(1, book.hiddenCount());
        assertEquals("hidden accounts keep their index", 3, book.nextIndex());
        try { book.add(2, addr(2)); fail("indices are never reused"); } catch (IllegalArgumentException expected) { }

        String stored = book.encode();
        assertFalse("no key material in the stored list", stored.contains("priv") || stored.contains("passphrase"));
        assertEquals(1, AccountBook.storedActiveIndex(stored));
        AccountBook loaded = AccountBook.load(stored, addr(0));
        assertEquals(1, loaded.activeIndex());
        assertEquals("Account 2", loaded.active().name());
        assertTrue(loaded.get(2).hidden);
        assertEquals(addr(2), loaded.get(2).address);
        // selecting a hidden account shows it again
        loaded.select(2, addr(2));
        assertFalse(loaded.get(2).hidden);
    }

    @Test public void selectRequiresTheAddressTheSeedProduced() {
        AccountBook book = AccountBook.fresh(addr(0));
        book.add(1, addr(1));
        try { book.select(1, addr(2)); fail(); } catch (IllegalStateException expected) { }
        try { book.select(5, addr(5)); fail(); } catch (IllegalArgumentException expected) { }
        assertEquals(0, book.activeIndex());
    }

    @Test public void accountCapIsTwenty() {
        AccountBook book = AccountBook.fresh(addr(0));
        for (int i = 1; i < AccountBook.MAX_ACCOUNTS; i++) book.add(i, "0x" + String.format("%040x", i));
        assertEquals(20, book.all().size());
        assertEquals(-1, book.nextIndex());
        try { book.add(20, "0x" + String.format("%040x", 20)); fail(); } catch (IllegalArgumentException expected) { }
    }

    @Test public void storedListIsBoundToItsWallet() {
        AccountBook book = AccountBook.fresh(addr(0));
        book.add(1, addr(1));
        book.select(1, addr(1));
        String stored = book.encode();
        // After a replace/restore the account-0 address differs: the old list is discarded.
        String otherWallet = SeedVault.deriveAccount(ART, null, 0).credentials.getAddress();
        AccountBook other = AccountBook.load(stored, otherWallet);
        assertEquals(0, other.activeIndex());
        assertEquals(1, other.all().size());
        assertEquals(otherWallet, other.walletId);
        // absent / corrupt / duplicated / wrong version → a fresh list, never an exception
        for (String bad : new String[] {null, "", "{", "[]", "{\"v\":2}",
                stored.replace("\"i\":1", "\"i\":0"), stored.replace("\"v\":1", "\"v\":9"),
                stored.replace(addr(0).substring(2), "zz")}) {
            AccountBook b = AccountBook.load(bad, addr(0));
            assertEquals(0, b.activeIndex());
            assertEquals(1, b.all().size());
        }
        assertEquals(0, AccountBook.storedActiveIndex("{\"active\":99}"));
        assertEquals(0, AccountBook.storedActiveIndex("nonsense"));
    }

    @Test public void signingAccountDescribesTheActiveKey() {
        SigningAccount standard = new SigningAccount(1, "Account 2", false, "AAAAAAAA", addr(1));
        assertEquals("Account 2", standard.headline());
        assertEquals("Account 2\n0x70997970C51812dc3A010C7d01b50e0d17dc79C8", standard.signingWith());
        assertEquals("2", standard.accountNumber());
        assertEquals("standard", standard.walletKind());
        assertEquals("m/44'/60'/0'/0/1", standard.path());
        SeedVault.Derived d = SeedVault.deriveAccount(ART, "TREZOR", 1);
        SigningAccount hidden = new SigningAccount(1, "Account 2", true, d.fingerprint, d.credentials.getAddress());
        assertTrue(hidden.signingWith().startsWith("Account 2 (passphrase wallet) · fingerprint " + d.fingerprint + "\n0x"));
        assertEquals("passphrase", hidden.walletKind());
    }

    // ------------------------------------------------------------------ requests name their account

    private static JSONObject tx() throws JSONException {
        return new JSONObject().put("id", "acct-1").put("method", "signEip1559").put("chainId", "0x1")
                .put("nonce", "0x0").put("maxPriorityFeePerGas", "0x3b9aca00").put("maxFeePerGas", "0x77359400")
                .put("gasLimit", "0x5208").put("to", "0x00000000000000000000000000000000000000aa").put("value", "0x1").put("data", "0x");
    }

    @Test public void transactionFromIsOptionalAndStrict() throws Exception {
        assertNull(Eip1559Request.parse(tx()).from);
        String a1 = Credentials.create(SeedVault.deriveEvm(JUNK, "", 1).getEcKeyPair()).getAddress();
        Eip1559Request named = Eip1559Request.parse(AccessoryTransport.parseStrictRequest(
                tx().put("from", org.web3j.crypto.Keys.toChecksumAddress(a1)).toString()));
        assertEquals(a1, named.from);
        for (String bad : new String[] {"0x1234", "me", "0xZZ97970c51812dc3a010c7d01b50e0d17dc79c8"}) {
            try { Eip1559Request.parse(tx().put("from", bad)); fail(bad); } catch (JSONException expected) { }
        }
        try { Eip1559Request.parse(tx().put("from", 5)); fail(); } catch (JSONException expected) { }
        try { Eip1559Request.parse(tx().put("sender", a1)); fail("unknown fields stay refused"); } catch (JSONException expected) { }
    }

    @Test public void requestForAnotherAccountIsRefused() throws Exception {
        Credentials account1 = SeedVault.deriveEvm(JUNK, "", 0);
        Credentials account2 = SeedVault.deriveEvm(JUNK, "", 1);
        Eip1559Request forAccount2 = Eip1559Request.parse(tx().put("from", account2.getAddress()));
        // active = Account 1: refused with the switch-accounts message
        try {
            RequestRefusal.requireFrom(forAccount2.from, "Account 1", account1.getAddress());
            fail("a request for another account must be refused");
        } catch (RequestRefusal refusal) {
            assertEquals(RequestRefusal.WRONG_ACCOUNT_TITLE, refusal.title);
            assertTrue(refusal.getMessage().contains("Switch to the right account on the phone"));
            assertTrue(refusal.getMessage().contains(org.web3j.crypto.Keys.toChecksumAddress(account2.getAddress())));
            assertTrue(refusal.getMessage().contains("Account 1"));
        }
        // active = Account 2: allowed; and no "from" at all is always allowed
        RequestRefusal.requireFrom(forAccount2.from, "Account 2", account2.getAddress());
        RequestRefusal.requireFrom(null, "Account 1", account1.getAddress());
        // even if a session were built for the wrong key, signing refuses it
        ApprovalSession wrong = new ApprovalSession(forAccount2, account1);
        try { wrong.signIfIdentityUnchanged(account1); fail(); } catch (IllegalStateException expected) { }
        JSONObject signed = new ApprovalSession(forAccount2, account2).signIfIdentityUnchanged(account2);
        assertEquals(account2.getAddress(), signed.getString("address"));
    }

    @Test public void messageFromIsCheckedToo() throws Exception {
        Credentials account1 = SeedVault.deriveEvm(JUNK, "", 0);
        Credentials account3 = SeedVault.deriveEvm(JUNK, "", 2);
        MessageRequest plain = MessageRequest.parse(MessageRequestTest.personal("0x68656c6c6f"));
        assertNull(plain.from);
        MessageRequest named = MessageRequest.parse(AccessoryTransport.parseStrictRequest(
                MessageRequestTest.personal("0x68656c6c6f").put("from", account3.getAddress()).toString()));
        assertEquals(account3.getAddress(), named.from);
        try {
            RequestRefusal.requireFrom(named.from, "Account 1", account1.getAddress());
            fail();
        } catch (RequestRefusal expected) {
            assertEquals(RequestRefusal.WRONG_ACCOUNT_TITLE, expected.title);
        }
        try { new MessageApprovalSession(named, account1).signIfIdentityUnchanged(account1); fail(); } catch (IllegalStateException expected) { }
        JSONObject ok = new MessageApprovalSession(named, account3).signIfIdentityUnchanged(account3);
        assertEquals(account3.getAddress(), ok.getString("address"));
        try { MessageRequest.parse(MessageRequestTest.personal("0x68").put("from", "0x12")); fail(); } catch (JSONException expected) { }
    }

    /** Switching accounts after a review was built: the reviewed identity no longer signs. */
    @Test public void switchingAccountsInvalidatesAnOpenReview() throws Exception {
        Credentials account1 = SeedVault.deriveEvm(JUNK, "", 0);
        Credentials account2 = SeedVault.deriveEvm(JUNK, "", 1);
        ApprovalSession reviewed = new ApprovalSession(Eip1559Request.parse(tx()), account1);
        try {
            reviewed.signIfIdentityUnchanged(account2);
            fail("signing must stop when the active account changed after review");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("reviewed again"));
        }
        assertEquals(account1.getAddress(), reviewed.signIfIdentityUnchanged(account1).getString("address"));
    }

    // ------------------------------------------------------------------ helpers

    private static final String B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /** Base58Check decode (test-only): checks the 4-byte double-SHA-256 checksum. */
    private static byte[] base58Check(String s) throws Exception {
        BigInteger n = BigInteger.ZERO;
        for (char c : s.toCharArray()) {
            int d = B58.indexOf(c);
            assertTrue("bad base58 character", d >= 0);
            n = n.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(d));
        }
        byte[] raw = n.toByteArray();
        if (raw.length > 82 && raw[0] == 0) raw = Arrays.copyOfRange(raw, 1, raw.length);
        assertEquals(82, raw.length);
        byte[] payload = Arrays.copyOf(raw, 78);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] check = sha.digest(sha.digest(payload));
        assertTrue("xprv checksum", Arrays.equals(Arrays.copyOf(check, 4), Arrays.copyOfRange(raw, 78, 82)));
        return payload;
    }

    static void assertMaster(String mnemonic, String passphrase, String xprv) {
        try {
            byte[] x = base58Check(xprv);
            byte[] chainCode = Arrays.copyOfRange(x, 13, 45);
            byte[] key = Arrays.copyOfRange(x, 46, 78);
            byte[] seed = SeedVault.bip39Seed(mnemonic, passphrase);
            Bip32ECKeyPair master = Bip32ECKeyPair.generateKeyPair(seed);
            assertEquals(Numeric.toHexStringNoPrefix(chainCode), Numeric.toHexStringNoPrefix(master.getChainCode()));
            assertEquals(new BigInteger(1, key), master.getPrivateKey());
            // and our fingerprint is HASH160 of that master public key
            byte[] id = Hash.sha256hash160(master.getPublicKeyPoint().getEncoded(true));
            assertEquals(Numeric.toHexStringNoPrefix(Arrays.copyOf(id, 4)).toUpperCase(java.util.Locale.ROOT), SeedVault.masterFingerprint(seed));
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    // ------------------------------------------------------------------ accounts + the Mac's simulation

    private static JSONObject simClaim(String asset, String delta) throws JSONException {
        return new JSONObject().put("changes", new org.json.JSONArray().put(new JSONObject().put("asset", asset).put("delta", delta)))
                .put("node", "ethereum-rpc.publicnode.com").put("block", "0x18f603b");
    }

    /** Both optional fields together keep the exact field set: anything else is still refused. */
    @Test public void fromAndHostSimulationTogether() throws Exception {
        String a2 = SeedVault.deriveEvm(JUNK, "", 1).getAddress();
        JSONObject both = tx().put("from", a2).put("hostSimulation", simClaim("native", "-1"));
        Eip1559Request parsed = Eip1559Request.parse(AccessoryTransport.parseStrictRequest(both.toString()));
        assertEquals(a2, parsed.from);
        assertTrue(parsed.hostSimulation != null);
        assertNull(Eip1559Request.parse(tx().put("from", a2)).hostSimulation);
        assertNull(Eip1559Request.parse(tx().put("hostSimulation", simClaim("native", "-1"))).from);
        try { Eip1559Request.parse(new JSONObject(both.toString()).put("extra", 1)); fail("unknown fields stay refused"); }
        catch (JSONException expected) { assertTrue(expected.getMessage().contains("unknown=[extra]")); }
        try { Eip1559Request.parse(new JSONObject(both.toString()).put("from", "0x12")); fail(); } catch (JSONException expected) { }
    }

    /** The simulation's "the wallet" is the ACTIVE account: a transferFrom out of Account 2 is its loss, not Account 1's. */
    @Test public void simulationIsCheckedAgainstTheActiveAccount() throws Exception {
        Credentials account1 = SeedVault.deriveEvm(JUNK, "", 0);
        Credentials account2 = SeedVault.deriveEvm(JUNK, "", 1);
        String usdc = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
        String other = "0x7f3a9c04e2b16d58a41c0f9e6b2d7a8c5e1f4b93";
        String data = "0x23b872dd" + Numeric.toHexStringNoPrefixZeroPadded(Numeric.toBigInt(account2.getAddress()), 64)
                + Numeric.toHexStringNoPrefixZeroPadded(Numeric.toBigInt(other), 64)
                + Numeric.toHexStringNoPrefixZeroPadded(BigInteger.valueOf(1_000_000), 64);
        JSONObject json = tx().put("to", usdc).put("value", "0x0").put("data", data)
                .put("from", account2.getAddress()).put("hostSimulation", simClaim(usdc, "-1000000"));
        Eip1559Request request = Eip1559Request.parse(json);
        RequestRefusal.requireFrom(request.from, "Account 2", account2.getAddress());
        ApprovalSession active = new ApprovalSession(request, account2, TokenListTest.bundled());
        assertFalse(active.hostSimulation.text(), active.hostSimulation.contradicts);
        ApprovalSession wrong = new ApprovalSession(request, account1, TokenListTest.bundled());
        assertTrue(wrong.hostSimulation.text(), wrong.hostSimulation.contradicts);
    }

    /** A send to your own other account is named; a look-alike of it is DANGER. */
    @Test public void ownAccountsCountAsOwnInTheReview() throws Exception {
        Credentials account1 = SeedVault.deriveEvm(JUNK, "", 0);
        String a2 = SeedVault.deriveEvm(JUNK, "", 1).getAddress().toLowerCase(java.util.Locale.ROOT);
        AddressSafety safety = new AddressSafety(new AddressBook(new AddressSafetyTest.MemoryStore()),
                new RecipientHistory(new AddressSafetyTest.MemoryStore()));
        java.util.Map<String, String> own = new java.util.LinkedHashMap<>();
        own.put(account1.getAddress(), "Account 1");
        own.put(a2, "Savings");
        safety.setOwnAccounts(own);
        String toOwn = new ApprovalSession(Eip1559Request.parse(tx().put("to", a2)), account1, TokenList.empty(), safety).review.text();
        assertTrue(toOwn, toOwn.contains("Savings on this phone"));
        // same first 6 and last 4 hex characters, different middle
        String poison = a2.substring(0, 8) + "f".repeat(28) + a2.substring(36);
        if (poison.equals(a2)) poison = a2.substring(0, 8) + "e".repeat(28) + a2.substring(36);
        String toPoison = new ApprovalSession(Eip1559Request.parse(tx().put("to", poison)), account1, TokenList.empty(), safety).review.text();
        assertTrue(toPoison, toPoison.contains("your Savings on this phone"));
        assertTrue(toPoison, toPoison.contains("DIFFERENT address"));
    }
}
