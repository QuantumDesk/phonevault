package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Adversarial audit proofs for account numbering (AccountScheme / AccountBook) and USB
 * listAddresses. Each test documents what it proves; tests named "finding…" pin current behaviour
 * that the audit reports as a weakness (they pass today and should be flipped when fixed).
 */
public final class AccountNumberingAuditTest {
    private static final String ABOUT = TestKeys.ABANDON_12;
    private static final String[] STD = AccountNumberingTest.STANDARD_ABOUT;
    private static final String[] LL = AccountNumberingTest.LEDGER_LIVE_ABOUT;
    private static final String WALLET = STD[0].toLowerCase(java.util.Locale.ROOT);
    private static final String ATTACKER = "0x00000000000000000000000000000000deadbeef";

    // ---------------------------------------------------------------- listAddresses parser

    private static JSONObject req(Object scheme, Object count) throws JSONException {
        return new JSONObject().put("id", "l1").put("method", "listAddresses").put("scheme", scheme).put("count", count);
    }

    @Test public void listAddressesRefusesEveryNonCanonicalField() throws Exception {
        Object[][] bad = {
                {"standard", "0"}, {"standard", "11"}, {"standard", "01"}, {"standard", "+5"}, {"standard", "5 "},
                {"standard", " 5"}, {"standard", "5.0"}, {"standard", "٥"}, {"standard", "１"}, {"standard", "-1"},
                {"standard", "2147483648"}, {"standard", 5}, {"standard", true}, {"standard", JSONObject.NULL},
                {"Standard", "5"}, {"ledger_live", "5"}, {"ledger-live ", "5"}, {"ledger-live\u0000", "5"},
                {"LEDGER-LIVE", "5"}, {"ledger", "5"}, {"", "5"}, {1, "5"},
        };
        for (Object[] b : bad) {
            try {
                AddressListRequest.parse(req(b[0], b[1]));
                fail("accepted scheme=" + b[0] + " count=" + b[1]);
            } catch (JSONException expected) { /* refused */ }
        }
        // extra / missing fields
        try { AddressListRequest.parse(req("standard", "5").put("passphrase", "x")); fail("extra field"); } catch (JSONException expected) { }
        JSONObject missing = req("standard", "5"); missing.remove("count");
        try { AddressListRequest.parse(missing); fail("missing field"); } catch (JSONException expected) { }
        // bounds that are accepted
        assertEquals(1, AddressListRequest.parse(req("standard", "1")).count);
        assertEquals(10, AddressListRequest.parse(req("ledger-live", "10")).count);
        assertEquals(SeedVault.MAX_LISTED_ADDRESSES, 10);
    }

    @Test public void listAddressesAnswerCarriesExactlyTheReviewedList() throws Exception {
        AddressListRequest r = AddressListRequest.parse(req("ledger-live", "3"));
        List<String> shown = SeedVault.addresses(ABOUT, "", AccountScheme.LEDGER_LIVE, 3);
        JSONObject answer = r.response(shown);
        assertEquals(String.join(",", shown), answer.getString("addresses"));
        assertEquals(Arrays.asList(LL[0], LL[1], LL[2]), shown);
        // Exactly the four fields, nothing else (no xpub, no passphrase-wallet data).
        assertEquals(4, answer.length());
        // Wrong size is refused, never padded or truncated.
        try { r.response(shown.subList(0, 2)); fail(); } catch (IllegalStateException expected) { }
    }

    @Test public void indexBoundsAndHardenedBit() {
        // i' never reaches 2^31: the index is capped at 19 before the hardened bit is ORed in.
        for (AccountScheme s : AccountScheme.values()) {
            for (int bad : new int[] {-1, 20, Integer.MAX_VALUE, Integer.MIN_VALUE, 0x80000000 | 3}) {
                try { s.path(bad); fail(s + " accepted " + bad); } catch (IllegalArgumentException expected) { }
            }
        }
        int[] p = AccountScheme.LEDGER_LIVE.path(19);
        assertEquals(19 | 0x80000000, p[2]);
        assertEquals(0, p[3]);
        assertEquals(0, p[4]);
        try { SeedVault.deriveAccount(ABOUT, null, 20, AccountScheme.LEDGER_LIVE); fail(); } catch (IllegalArgumentException expected) { }
    }

    // ---------------------------------------------------------------- AccountBook persistence

    /** Signing safety holds under tamper: the stored address of the account being selected is re-checked. */
    @Test public void tamperedActiveAccountNeverBecomesTheSigningKey() throws Exception {
        String stored = "{\"v\":2,\"wallet\":\"" + WALLET + "\",\"scheme\":\"ledger-live\",\"active\":1,\"accounts\":["
                + "{\"i\":0,\"a\":\"" + WALLET + "\"},{\"i\":1,\"a\":\"" + ATTACKER + "\"}]}";
        AccountBook book = AccountBook.load(stored, WALLET);
        assertSame(AccountScheme.LEDGER_LIVE, book.scheme);
        assertEquals(1, book.activeIndex());
        // MainActivity.loadKey compares book.active().address with the key derived under book.scheme:
        SeedVault.Derived d = SeedVault.deriveAccount(ABOUT, null, book.activeIndex(), book.scheme);
        assertTrue("loadKey would reset to Account 1", !book.active().address.equalsIgnoreCase(d.credentials.getAddress()));
        try { book.select(1, d.credentials.getAddress()); fail(); } catch (IllegalStateException expected) { }
    }

    /**
     * FINDING (low, local-tamper only): a stored NON-active account's address is never re-derived.
     * AccountBook.load trusts it, AccountScreens lists it as "Account 2", and ownAccountNames feeds it
     * to AddressSafety, so a review of a send to that (foreign) address says "Your account: Account 2
     * on this phone". The same holds for the parked list after a numbering switch.
     */
    @Test public void findingNonActiveStoredAddressIsTrustedAsOwnAccount() throws Exception {
        String stored = "{\"v\":2,\"wallet\":\"" + WALLET + "\",\"scheme\":\"standard\",\"active\":0,\"accounts\":["
                + "{\"i\":0,\"a\":\"" + WALLET + "\"},{\"i\":1,\"a\":\"" + ATTACKER + "\"}],"
                + "\"parked\":{\"scheme\":\"ledger-live\",\"active\":0,\"accounts\":[{\"i\":0,\"a\":\"" + WALLET + "\"},"
                + "{\"i\":2,\"a\":\"" + ATTACKER.replace("deadbeef", "cafebabe") + "\"}]}}";
        AccountBook book = AccountBook.load(stored, WALLET);
        assertEquals(ATTACKER, book.get(1).address);              // not STD[1]
        assertEquals(0, book.activeIndex());
        // loadKey's only check (active account) passes: account 0 is genuine.
        SeedVault.Derived d = SeedVault.deriveAccount(ABOUT, null, book.activeIndex(), book.scheme);
        assertTrue(book.active().address.equalsIgnoreCase(d.credentials.getAddress()));
        // What ownAccountNames builds from book.all():
        Map<String, String> own = new java.util.LinkedHashMap<>();
        for (AccountBook.Account a : book.all()) own.put(a.address, a.name());
        AddressSafety safety = new AddressSafety(null, null);
        safety.setOwnAccounts(own);
        List<MessageReview.Row> rows = safety.rows(WALLET, ATTACKER, RecipientHistory.Role.SEND);
        boolean namedOwn = false;
        for (MessageReview.Row r : rows) if (AddressSafety.OWN_ACCOUNT.equals(r.label) && r.value.startsWith("Account 2")) namedOwn = true;
        assertTrue("a foreign address is presented as the user's own Account 2", namedOwn);
        // The parked Ledger Live list is equally unchecked and comes back on switch.
        AccountBook ll = book.withScheme(AccountScheme.LEDGER_LIVE);
        assertNotNull(ll.get(2));
        assertTrue(!ll.get(2).address.equalsIgnoreCase(LL[2]));
    }

    /**
     * FINDING (low, local-corruption only): a v2 book whose active list is unreadable falls back to a
     * fresh STANDARD book even though the stored numbering is Ledger Live; storedScheme and load
     * disagree, and loadKey silently re-derives under Standard. Signing stays consistent with the
     * display (both Standard), but the numbering changed without the user.
     */
    @Test public void findingCorruptLedgerLiveBookRevertsToStandard() {
        String stored = "{\"v\":2,\"wallet\":\"" + WALLET + "\",\"scheme\":\"ledger-live\",\"active\":0,\"accounts\":[{\"i\":0,\"a\":\"0xnot\"}]}";
        assertSame(AccountScheme.LEDGER_LIVE, AccountBook.storedScheme(stored));
        assertSame(AccountScheme.STANDARD, AccountBook.load(stored, WALLET).scheme);
    }

    /** Wrong-wallet / same-scheme parked / swapped-scheme tamper is dropped. */
    @Test public void bookBindingRefusesCrossWalletAndSameSchemeParked() {
        String other = STD[1].toLowerCase(java.util.Locale.ROOT);
        String foreign = "{\"v\":2,\"wallet\":\"" + other + "\",\"scheme\":\"ledger-live\",\"active\":0,\"accounts\":[{\"i\":0,\"a\":\"" + other + "\"}]}";
        AccountBook b = AccountBook.load(foreign, WALLET);
        assertSame(AccountScheme.STANDARD, b.scheme);
        assertEquals(WALLET, b.walletId);
        String sameParked = "{\"v\":2,\"wallet\":\"" + WALLET + "\",\"scheme\":\"ledger-live\",\"active\":0,\"accounts\":[{\"i\":0,\"a\":\"" + WALLET + "\"}],"
                + "\"parked\":{\"scheme\":\"ledger-live\",\"active\":0,\"accounts\":[{\"i\":0,\"a\":\"" + WALLET + "\"}]}}";
        AccountBook c = AccountBook.load(sameParked, WALLET);
        assertSame(AccountScheme.LEDGER_LIVE, c.scheme);
        assertEquals(null, c.parked());
        // Out-of-range / duplicate indexes reject the list.
        String dup = "{\"v\":1,\"wallet\":\"" + WALLET + "\",\"active\":0,\"accounts\":[{\"i\":0,\"a\":\"" + WALLET + "\"},{\"i\":0,\"a\":\"" + WALLET + "\"}]}";
        assertEquals(1, AccountBook.load(dup, WALLET).all().size());
        String big = "{\"v\":1,\"wallet\":\"" + WALLET + "\",\"active\":20,\"accounts\":[{\"i\":0,\"a\":\"" + WALLET + "\"},{\"i\":20,\"a\":\"" + WALLET + "\"}]}";
        assertEquals(1, AccountBook.load(big, WALLET).all().size());
        assertEquals(0, AccountBook.storedActiveIndex(big));
    }

    /** Account 1 is genuinely identical under both numberings, with and without a passphrase. */
    @Test public void account1IdenticalUnderBothSchemes() {
        for (String pass : new String[] {null, "TREZOR"}) {
            SeedVault.Derived s = SeedVault.deriveAccount(ABOUT, pass, 0, AccountScheme.STANDARD);
            SeedVault.Derived l = SeedVault.deriveAccount(ABOUT, pass, 0, AccountScheme.LEDGER_LIVE);
            assertEquals(s.credentials.getAddress(), l.credentials.getAddress());
            assertEquals(s.account0Address, l.account0Address);
            // index>0 under Ledger Live still names the wallet by its Standard/LL-shared account 0
            assertEquals(s.account0Address, SeedVault.deriveAccount(ABOUT, pass, 3, AccountScheme.LEDGER_LIVE).account0Address);
        }
    }

    /** getAddress reports exactly the scheme the published SigningAccount carries; key mismatch is refused. */
    @Test public void getAddressSchemeTracksTheKey() throws Exception {
        SeedVault.Derived d = SeedVault.deriveAccount(ABOUT, null, 1, AccountScheme.LEDGER_LIVE);
        SigningAccount ll = new SigningAccount(1, "Account 2", false, d.fingerprint, d.credentials.getAddress(), AccountScheme.LEDGER_LIVE);
        JSONObject a = RequestRouter.addressAnswer("x", d.credentials, ll);
        assertEquals("ledger-live", a.getString("scheme"));
        assertTrue(LL[1].equalsIgnoreCase(a.getString("address")));
        // A SigningAccount for Standard Account 2 cannot be paired with the LL key.
        SigningAccount std = new SigningAccount(1, "Account 2", false, d.fingerprint, STD[1], AccountScheme.STANDARD);
        try { RequestRouter.addressAnswer("x", d.credentials, std); fail(); } catch (IllegalStateException expected) { }
    }
}
