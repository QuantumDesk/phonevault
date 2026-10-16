package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.web3j.crypto.Bip32ECKeyPair;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.MnemonicUtils;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Account numbering (Standard m/44'/60'/0'/0/i, Ledger Live m/44'/60'/i'/0/0): derivation vectors,
 * the per-wallet setting in AccountBook, what getAddress and the review say, and USB listAddresses.
 *
 * <p>Vectors for the "abandon … about" phrase (TestKeys.ABANDON_12), computed independently with
 * bip_utils 2.9.3 (pip bip_utils==2.9.3: Bip39SeedGenerator, Bip32Slip10Secp256k1.DerivePath,
 * EthAddr.EncodeKey), and cross-checked here with web3j's own BIP-32 at the explicit paths. The
 * Standard column's first entries are the widely published MetaMask / iancoleman values
 * (0x9858EfFD…, 0x6Fac4D18…, 0xb6716976…), which also anchor the independent implementation.
 */
public final class AccountNumberingTest {
    private static final String ABOUT = TestKeys.ABANDON_12;
    private static final String ART = TestKeys.ABANDON_24;

    static final String[] STANDARD_ABOUT = {
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
            "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A",
            "0xF3f50213C1d2e255e4B2bAD430F8A38EEF8D718E",
            "0x51cA8ff9f1C0a99f88E86B8112eA3237F55374cA",
    };
    static final String[] LEDGER_LIVE_ABOUT = {
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "0x78839F6054d7ed13918bAe0473BA31b1Ca9D7265",
            "0x07B5FdfEB4E11826D233403Fe8Db0611CCF4c231",
            "0x8559A4270Db933caC30830f2be9D099fD477A51D",
            "0xB9506F020318c2ECA294e0557222511f1e5333CB",
    };
    /** "abandon … art" (24 words), Ledger Live accounts 1-3 (bip_utils 2.9.3). */
    static final String[] LEDGER_LIVE_ART = {
            "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb",
            "0x94142B4f665316D3304C3a595ec83aC9C8046598",
            "0xe93E76dFCc3Bb3A6A3A36Bcd9df68cb7C0AD46AA",
    };
    /** "abandon … about" + passphrase "TREZOR", Ledger Live accounts 1-3 (bip_utils 2.9.3). */
    static final String[] LEDGER_LIVE_ABOUT_TREZOR = {
            "0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6",
            "0x16F92C9Ac08F4A3f7CB3D4C889B954d390572F65",
            "0x05d578b6B31310414a12Cb3a89d009c3b539F196",
    };

    private static final int H = Bip32ECKeyPair.HARDENED_BIT;

    /** web3j BIP-32 at an explicit path: the second implementation the vectors are checked with. */
    private static String web3jAddress(String mnemonic, String passphrase, int... path) {
        Bip32ECKeyPair master = Bip32ECKeyPair.generateKeyPair(MnemonicUtils.generateSeed(mnemonic, passphrase));
        return Keys.toChecksumAddress(Credentials.create(Bip32ECKeyPair.deriveKeyPair(master, path)).getAddress());
    }

    @Test public void ledgerLiveAndStandardVectors() {
        for (int i = 0; i < 5; i++) {
            assertEquals(STANDARD_ABOUT[i], web3jAddress(ABOUT, "", 44 | H, 60 | H, 0 | H, 0, i));
            assertEquals(LEDGER_LIVE_ABOUT[i], web3jAddress(ABOUT, "", 44 | H, 60 | H, i | H, 0, 0));
            assertEquals(STANDARD_ABOUT[i], Keys.toChecksumAddress(SeedVault.deriveAccount(ABOUT, "", i, AccountScheme.STANDARD).credentials.getAddress()));
            assertEquals(LEDGER_LIVE_ABOUT[i], Keys.toChecksumAddress(SeedVault.deriveAccount(ABOUT, "", i, AccountScheme.LEDGER_LIVE).credentials.getAddress()));
        }
        assertEquals(java.util.Arrays.asList(STANDARD_ABOUT), SeedVault.addresses(ABOUT, "", AccountScheme.STANDARD, 5));
        assertEquals(java.util.Arrays.asList(LEDGER_LIVE_ABOUT), SeedVault.addresses(ABOUT, "", AccountScheme.LEDGER_LIVE, 5));
        for (int i = 0; i < 3; i++) {
            assertEquals(LEDGER_LIVE_ART[i], Keys.toChecksumAddress(SeedVault.deriveAccount(ART, null, i, AccountScheme.LEDGER_LIVE).credentials.getAddress()));
            assertEquals(LEDGER_LIVE_ABOUT_TREZOR[i], Keys.toChecksumAddress(SeedVault.deriveAccount(ABOUT, "TREZOR", i, AccountScheme.LEDGER_LIVE).credentials.getAddress()));
        }
        // the 3-argument form is Standard numbering, unchanged
        assertEquals(STANDARD_ABOUT[3], Keys.toChecksumAddress(SeedVault.deriveAccount(ABOUT, "", 3).credentials.getAddress()));
    }

    @Test public void identityIsTheSameUnderBothNumberings() {
        SeedVault.Derived std = SeedVault.deriveAccount(ABOUT, "", 2, AccountScheme.STANDARD);
        SeedVault.Derived ll = SeedVault.deriveAccount(ABOUT, "", 2, AccountScheme.LEDGER_LIVE);
        assertEquals("account-0 address names the wallet under both", std.account0Address, ll.account0Address);
        assertEquals(STANDARD_ABOUT[0].toLowerCase(java.util.Locale.ROOT), ll.account0Address);
        assertEquals(std.fingerprint, ll.fingerprint);
        assertNotEquals(std.credentials.getAddress(), ll.credentials.getAddress());
        try { SeedVault.addresses(ABOUT, "", AccountScheme.STANDARD, 0); fail(); } catch (IllegalArgumentException expected) { }
        try { SeedVault.addresses(ABOUT, "", AccountScheme.STANDARD, 11); fail(); } catch (IllegalArgumentException expected) { }
        try { SeedVault.deriveAccount(ABOUT, "", 20, AccountScheme.LEDGER_LIVE); fail(); } catch (IllegalArgumentException expected) { }
    }

    @Test public void schemeWireNamesAndPaths() {
        assertSame(AccountScheme.STANDARD, AccountScheme.fromWire("standard"));
        assertSame(AccountScheme.LEDGER_LIVE, AccountScheme.fromWire("ledger-live"));
        for (String bad : new String[] {"Standard", "ledger_live", "ledger", "", " standard", "LEDGER-LIVE", null}) {
            try { AccountScheme.fromWire(bad); fail(bad); } catch (IllegalArgumentException expected) { }
        }
        assertEquals("m/44'/60'/0'/0/4", AccountScheme.STANDARD.pathString(4));
        assertEquals("m/44'/60'/4'/0/0", AccountScheme.LEDGER_LIVE.pathString(4));
        assertEquals("m/44'/60'/0'/0/0", AccountScheme.LEDGER_LIVE.pathString(0));
        try { AccountScheme.LEDGER_LIVE.pathString(20); fail(); } catch (IllegalArgumentException expected) { }
    }

    // ------------------------------------------------------------------ the setting in AccountBook

    private static String std(int i) { return SeedVault.deriveAccount(ABOUT, "", i, AccountScheme.STANDARD).credentials.getAddress(); }
    private static String ll(int i) { return SeedVault.deriveAccount(ABOUT, "", i, AccountScheme.LEDGER_LIVE).credentials.getAddress(); }

    @Test public void switchingParksTheListAndSwitchingBackRestoresIt() {
        AccountBook standard = AccountBook.fresh(std(0));
        assertSame(AccountScheme.STANDARD, standard.scheme);
        standard.add(1, std(1));
        standard.rename(1, "Savings");
        standard.select(1, std(1));
        String v1 = standard.encode();
        assertTrue("a plain Standard book stays v1 (earlier apps read it)", v1.contains("\"v\":1") && !v1.contains("scheme"));

        AccountBook ledger = standard.withScheme(AccountScheme.LEDGER_LIVE);
        assertSame(AccountScheme.LEDGER_LIVE, ledger.scheme);
        assertEquals("first time: Account 1", 0, ledger.activeIndex());
        assertEquals(1, ledger.all().size());
        assertEquals(standard.walletId, ledger.walletId);
        assertEquals("the old book is not changed", 1, standard.activeIndex());
        ledger.add(1, ll(1));
        ledger.select(1, ll(1));
        try { ledger.select(1, std(1)); fail("a Standard address for a Ledger Live account"); } catch (IllegalStateException expected) { }

        String stored = ledger.encode();
        assertTrue(stored, stored.contains("\"v\":2") && stored.contains("\"scheme\":\"ledger-live\""));
        assertSame(AccountScheme.LEDGER_LIVE, AccountBook.storedScheme(stored));
        assertEquals(1, AccountBook.storedActiveIndex(stored));
        AccountBook reloaded = AccountBook.load(stored, std(0));
        assertSame("survives relock/reboot", AccountScheme.LEDGER_LIVE, reloaded.scheme);
        assertEquals(ll(1).toLowerCase(java.util.Locale.ROOT), reloaded.active().address);
        assertSame(AccountScheme.STANDARD, reloaded.parked().scheme);

        AccountBook back = reloaded.withScheme(AccountScheme.STANDARD);
        assertSame(AccountScheme.STANDARD, back.scheme);
        assertEquals("labels and the active account come back", "Savings", back.active().name());
        assertEquals(1, back.activeIndex());
        AccountBook again = back.withScheme(AccountScheme.LEDGER_LIVE);
        assertEquals(1, again.activeIndex());
        assertEquals(ll(1).toLowerCase(java.util.Locale.ROOT), again.active().address);
        assertSame(again, again.withScheme(AccountScheme.LEDGER_LIVE));
        AccountBook restart = back.withScheme(AccountScheme.LEDGER_LIVE, false);
        assertEquals("a parked list that did not match the seed is not reused", 0, restart.activeIndex());
        assertEquals(1, restart.all().size());
    }

    @Test public void storedNumberingIsBoundAndStrict() throws Exception {
        AccountBook ledger = AccountBook.fresh(std(0)).withScheme(AccountScheme.LEDGER_LIVE);
        String stored = ledger.encode();
        String otherWallet = SeedVault.deriveAccount(ART, null, 0).credentials.getAddress();
        AccountBook other = AccountBook.load(stored, otherWallet);
        assertSame("another wallet's book (and its numbering) is discarded", AccountScheme.STANDARD, other.scheme);
        for (String bad : new String[] {
                stored.replace("\"scheme\":\"ledger-live\"", "\"scheme\":\"ledger\""),
                stored.replace("\"v\":2", "\"v\":3"),
                stored.replace("\"scheme\":\"ledger-live\",", "")}) {
            AccountBook b = AccountBook.load(bad, std(0));
            assertSame(bad, AccountScheme.STANDARD, b.scheme);
            assertEquals(1, b.all().size());
        }
        // a corrupt parked list is dropped, the book itself kept
        JSONObject j = new JSONObject(stored);
        j.getJSONObject("parked").put("accounts", "nonsense");
        AccountBook noParked = AccountBook.load(j.toString(), std(0));
        assertSame(AccountScheme.LEDGER_LIVE, noParked.scheme);
        assertNull(noParked.parked());
        assertSame(AccountScheme.STANDARD, AccountBook.storedScheme("{\"v\":1,\"scheme\":\"ledger-live\"}"));
        assertSame(AccountScheme.STANDARD, AccountBook.storedScheme("garbage"));
        assertSame(AccountScheme.STANDARD, AccountBook.storedScheme(null));
    }

    @Test public void signingAccountNamesItsPath() {
        SigningAccount standard = new SigningAccount(1, "Account 2", false, null, std(1));
        assertEquals("m/44'/60'/0'/0/1", standard.path());
        assertEquals("Account 2\n" + Keys.toChecksumAddress(std(1)), standard.signingWith());
        SigningAccount ledger = new SigningAccount(1, "Account 2", false, null, ll(1), AccountScheme.LEDGER_LIVE);
        assertEquals("m/44'/60'/1'/0/0", ledger.path());
        assertEquals("Account 2 · Ledger Live numbering m/44'/60'/1'/0/0\n" + LEDGER_LIVE_ABOUT[1], ledger.signingWith());
    }

    // ------------------------------------------------------------------ getAddress says the numbering

    private static Set<String> keys(JSONObject o) {
        Set<String> k = new HashSet<>();
        for (Iterator<String> it = o.keys(); it.hasNext(); ) k.add(it.next());
        return k;
    }

    @Test public void getAddressReportsLedgerLiveNumbering() throws Exception {
        Credentials key = SeedVault.deriveAccount(ABOUT, "", 1, AccountScheme.LEDGER_LIVE).credentials;
        JSONObject r = RequestRouter.addressAnswer("a-1", key, new SigningAccount(1, "Account 2", false, null, key.getAddress(), AccountScheme.LEDGER_LIVE));
        assertEquals(Set.of("id", "status", "address", "account", "wallet", "scheme"), keys(r));
        assertEquals("ledger-live", r.getString("scheme"));
        assertEquals("2", r.getString("account"));
        Credentials s = SeedVault.deriveAccount(ABOUT, "", 1).credentials;
        JSONObject plain = RequestRouter.addressAnswer("a-2", s, new SigningAccount(1, "Account 2", false, null, s.getAddress()));
        assertEquals("Standard: unchanged answer (older companions refuse unknown fields)",
                Set.of("id", "status", "address", "account", "wallet"), keys(plain));
    }

    // ------------------------------------------------------------------ USB listAddresses

    private static JSONObject list(String scheme, Object count) throws JSONException {
        return new JSONObject().put("id", "l-1").put("method", "listAddresses").put("scheme", scheme).put("count", count);
    }

    @Test public void listAddressesParsesStrictly() throws Exception {
        AddressListRequest r = AddressListRequest.parse(AccessoryTransport.parseStrictRequest(list("ledger-live", "5").toString()));
        assertEquals("l-1", r.id);
        assertSame(AccountScheme.LEDGER_LIVE, r.scheme);
        assertEquals(5, r.count);
        assertEquals(10, AddressListRequest.parse(list("standard", "10")).count);
        assertEquals(1, AddressListRequest.parse(list("standard", "1")).count);
        Object[][] bad = {
                {"standard", "0"}, {"standard", "11"}, {"standard", "01"}, {"standard", "-1"}, {"standard", "1.0"},
                {"standard", " 1"}, {"standard", "5 "}, {"standard", "999999999999"}, {"standard", 5},
                {"Standard", "5"}, {"ledger_live", "5"}, {"", "5"}, {"bip44", "5"},
        };
        for (Object[] b : bad) {
            try { AddressListRequest.parse(list((String) b[0], b[1])); fail("accepted " + b[0] + " / " + b[1]); } catch (JSONException expected) { }
        }
        for (JSONObject b : new JSONObject[] {
                list("standard", "5").put("extra", "x"),
                new JSONObject().put("id", "l-1").put("method", "listAddresses").put("scheme", "standard"),
                new JSONObject().put("id", "l-1").put("method", "listAddresses").put("count", "5"),
                list("standard", "5").put("id", "bad id"),
                list("standard", "5").put("method", "getAddress"),
        }) {
            try { AddressListRequest.parse(b); fail("accepted " + b); } catch (JSONException expected) { }
        }
        try {
            AccessoryTransport.parseStrictRequest("{\"id\":\"l-1\",\"method\":\"listAddresses\",\"scheme\":\"standard\",\"count\":5}");
            fail("numbers are refused by the transport");
        } catch (JSONException expected) { }
        try {
            AccessoryTransport.parseStrictRequest("{\"id\":\"l-1\",\"method\":\"listAddresses\",\"scheme\":\"standard\",\"scheme\":\"ledger-live\",\"count\":\"5\"}");
            fail("duplicate keys are refused by the transport");
        } catch (JSONException expected) { }
    }

    @Test public void listAddressesAnswerIsPublicAddressesOnly() throws Exception {
        AddressListRequest r = AddressListRequest.parse(list("ledger-live", "3"));
        List<String> three = SeedVault.addresses(ABOUT, "", AccountScheme.LEDGER_LIVE, 3);
        JSONObject a = r.response(three);
        assertEquals(Set.of("id", "status", "scheme", "addresses"), keys(a));
        assertEquals("ok", a.getString("status"));
        assertEquals("ledger-live", a.getString("scheme"));
        assertEquals(LEDGER_LIVE_ABOUT[0] + "," + LEDGER_LIVE_ABOUT[1] + "," + LEDGER_LIVE_ABOUT[2], a.getString("addresses"));
        try { r.response(three.subList(0, 2)); fail("count must match"); } catch (IllegalStateException expected) { }
        try { r.response(java.util.Arrays.asList("0x1", "0x2", "0x3")); fail(); } catch (IllegalStateException expected) { }
    }

    @Test public void lockedGateDescribesListAddresses() throws Exception {
        Supplier<TokenList> none = () -> TokenList.unavailable("test");
        assertEquals("Your Mac asks for 5 addresses of your wallet (Ledger Live account numbering). Unlock to review.",
                RequestRouter.lockedSummary(list("ledger-live", "5"), none));
        assertEquals("Your Mac asks for 1 address of your wallet (Standard account numbering). Unlock to review.",
                RequestRouter.lockedSummary(list("standard", "1"), none));
        assertTrue(RequestRouter.lockedSummary(list("standard", "11"), none).endsWith("It will be refused after you unlock."));
    }

    /** Routing and the share screen: readiness first, one approval slot, answers only under stateLock after the ownership re-check. */
    @Test public void listAddressesRoutingAndShareScreen() throws Exception {
        String route = SourceGuard.definition("\n    void onRequest(AccessoryTransport source, JSONObject json) {");
        int ready = route.indexOf("String refusal = notReady(");
        int dispatch = route.indexOf("addresses.handle(source, json, id, s);");
        assertTrue("listAddresses is dispatched after the readiness check", ready > 0 && dispatch > ready);
        assertTrue("and before the signing slot is claimed elsewhere", dispatch < route.indexOf("final ApprovalDecision decision = host.claimApproval(source, id);"));
        String handle = SourceGuard.definition("    void handle(AccessoryTransport source, JSONObject json, String fallbackId, int s) {");
        assertTrue("one request at a time", handle.contains("final ApprovalDecision decision = host.claimApproval(source, fallbackId);"));
        assertTrue("refused while a passphrase wallet is open", handle.contains("if (host.passphraseWalletOpen()) throw new RequestRefusal("));
        String screens = SourceGuard.source("AddressShareScreens.java");
        String code = SourceGuard.code(screens);
        int send = code.indexOf("source.send(reply);");
        assertTrue(send > 0);
        assertTrue("the approved answer is sent under stateLock", ScreenSplitTest.insideStateLock(code, send));
        assertTrue("after the ownership re-check", code.substring(code.lastIndexOf("synchronized (stateLock)", send), send)
                .contains("if (!host.owns(source, s, decision, RequestOwnership.ADDRESSES_UNDECIDED) || !decision.beginSigning()) return;"));
        assertEquals("the reply is sent at one place only", 1, code.split("source\\.send\\(reply\\)", -1).length - 1);
        assertTrue("the screen is drawn only while the request owns its slot",
                code.contains("if (host.abandonUnlessOwned(source, s, decision, RequestOwnership.ADDRESSES_SHOW)) return;"));
        assertTrue("addresses come from the standard wallet only", code.contains("host.vault().standardAddresses(r.scheme, r.count)"));
        assertTrue("Account 1 must be this wallet", code.contains("!addresses.get(0).equalsIgnoreCase(owner)"));
        assertFalse("nothing is remembered", code.contains("SharedPreferences") || code.contains("getSharedPreferences"));
    }

    /** Switching numbering publishes under stateLock and saves only the standard wallet's book. */
    @Test public void numberingSwitchCallSites() throws Exception {
        String worker = SourceGuard.definition("    private void switchNumberingWorker(AccountScheme next, boolean retried) {");
        assertTrue(worker.contains("app.vault().deriveAccount(switched.activeIndex(), pass, next)"));
        assertTrue("the derived address must match the list before it is published", worker.contains("switched.select(switched.activeIndex(), address);"));
        assertTrue(worker.contains("if (!app.requestPending() && app.approvalDecision() == null) {"));
        assertTrue(worker.contains("if (done && fingerprint == null) saveStandardBook(switched);"));
        String load = SourceGuard.definition("    private void loadKey() {");
        assertTrue("unlock derives the active account under the saved numbering",
                load.contains("store.deriveAccount(AccountBook.storedActiveIndex(savedBook), null, savedScheme)"));
        assertTrue(load.contains("loadedBook.scheme);"));
    }
}
