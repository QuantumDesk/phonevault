package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
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
 * listAddresses. Each test documents what it proves (the audit's findings are fixed and asserted as such).
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
     * A stored NON-active account's address is re-derived before it is trusted. AccountBook.load
     * returns an unverified book; unlock (MainActivity.loadKey) and a numbering switch run
     * dropUnverified with the seed, which drops every listed account (both numberings) whose saved
     * address the seed does not give, so the list never shows it and ownAccountNames never feeds it to
     * AddressSafety: a send to that foreign address is not called "Your account". Genuine accounts
     * keep their labels, and the dropped index can be opened again (with its real address).
     */
    @Test public void nonActiveStoredAddressIsReDerivedAndDropped() throws Exception {
        String std1 = STD[1].toLowerCase(java.util.Locale.ROOT);
        String stored = "{\"v\":2,\"wallet\":\"" + WALLET + "\",\"scheme\":\"standard\",\"active\":0,\"accounts\":["
                + "{\"i\":0,\"a\":\"" + WALLET + "\"},{\"i\":1,\"a\":\"" + ATTACKER + "\"},{\"i\":2,\"a\":\"" + STD[2] + "\",\"l\":\"Savings\"}],"
                + "\"parked\":{\"scheme\":\"ledger-live\",\"active\":0,\"accounts\":[{\"i\":0,\"a\":\"" + WALLET + "\"},"
                + "{\"i\":1,\"a\":\"" + LL[1] + "\"},{\"i\":2,\"a\":\"" + ATTACKER.replace("deadbeef", "cafebabe") + "\"}]}}";
        AccountBook book = AccountBook.load(stored, WALLET);
        assertFalse("a stored list is untrusted until checked", book.verified());
        assertEquals(ATTACKER, book.get(1).address);

        int dropped = SeedVault.withWallet(ABOUT, null, w -> book.dropUnverified(w::address));
        assertEquals("the foreign Standard entry and the foreign parked Ledger Live entry", 2, dropped);
        assertTrue(book.verified());
        assertNull(book.get(1));
        assertEquals("a genuine account keeps its label", "Savings", book.get(2).name());
        assertEquals("the dropped index opens again", 1, book.nextIndex());
        book.add(1, STD[1]);
        assertEquals(std1, book.get(1).address);
        assertEquals("listed by index", Arrays.asList(0, 1, 2), indexes(book));

        // What ownAccountNames builds from the verified book: the foreign address is not "your account".
        Map<String, String> own = new java.util.LinkedHashMap<>();
        for (AccountBook.Account a : book.all()) own.put(a.address, a.name());
        assertFalse(own.containsKey(ATTACKER));
        AddressSafety safety = new AddressSafety(null, null);
        safety.setOwnAccounts(own);
        for (MessageReview.Row r : safety.rows(WALLET, ATTACKER, RecipientHistory.Role.SEND)) {
            assertFalse("a foreign address is never named as your account", AddressSafety.OWN_ACCOUNT.equals(r.label));
        }
        // The parked Ledger Live list was checked too: switching brings back only genuine accounts.
        AccountBook ll = book.withScheme(AccountScheme.LEDGER_LIVE);
        assertTrue(ll.verified());
        assertNull(ll.get(2));
        assertTrue(ll.get(1).address.equalsIgnoreCase(LL[1]));
        // Only a verified list names own accounts, and both the unlock and the switch re-derive the list.
        String names = SourceGuard.definition("    Map<String, String> ownAccountNames() {");
        assertTrue(names.contains("if (standard != null && !standard.verified()) standard = null;"));
        assertTrue(names.contains("if (passphraseAccounts != null && !passphraseAccounts.verified()) passphraseAccounts = null;"));
        assertTrue(SourceGuard.definition("    private void loadKey() {").contains("b.dropUnverified(w::address);"));
        assertTrue(SourceGuard.definition("    private void switchNumberingWorker(AccountScheme next, boolean retried) {").contains("b.dropUnverified(w::address);"));
    }

    /** A tampered ACTIVE account is dropped too: Account 1 becomes active, the signing key is Account 1's. */
    @Test public void tamperedActiveAccountFallsBackToAccount1() throws Exception {
        String stored = "{\"v\":2,\"wallet\":\"" + WALLET + "\",\"scheme\":\"ledger-live\",\"active\":1,\"accounts\":["
                + "{\"i\":0,\"a\":\"" + WALLET + "\"},{\"i\":1,\"a\":\"" + ATTACKER + "\"}]}";
        AccountBook book = AccountBook.load(stored, WALLET);
        SeedVault.Derived d = SeedVault.withWallet(ABOUT, null, w -> {
            assertEquals(1, book.dropUnverified(w::address));
            return w.account(book.activeIndex(), book.scheme);
        });
        assertEquals(0, book.activeIndex());
        assertSame(AccountScheme.LEDGER_LIVE, book.scheme);
        assertTrue(WALLET.equalsIgnoreCase(d.credentials.getAddress()));
        book.select(0, d.credentials.getAddress());
        // A list of another wallet is refused outright.
        AccountBook other = AccountBook.fresh(STD[1]);
        try { SeedVault.withWallet(ABOUT, null, w -> other.dropUnverified(w::address)); fail(); } catch (IllegalStateException expected) { }
    }

    /** The one-wallet derivation agrees with the per-account one (keys, identity, both numberings). */
    @Test public void walletDerivationMatchesPerAccountDerivation() throws Exception {
        for (String pass : new String[] {null, "TREZOR"}) {
            SeedVault.withWallet(ABOUT, pass, w -> {
                for (AccountScheme scheme : AccountScheme.values()) {
                    for (int i : new int[] {0, 1, 7, SeedVault.MAX_ACCOUNT_INDEX}) {
                        SeedVault.Derived one = SeedVault.deriveAccount(ABOUT, pass, i, scheme);
                        SeedVault.Derived many = w.account(i, scheme);
                        assertEquals(one.credentials.getEcKeyPair().getPrivateKey(), many.credentials.getEcKeyPair().getPrivateKey());
                        assertEquals(one.account0Address, many.account0Address);
                        assertEquals(one.fingerprint, many.fingerprint);
                        assertEquals(i, many.index);
                        assertEquals(one.credentials.getAddress().toLowerCase(java.util.Locale.ROOT), w.address(scheme, i));
                    }
                }
                return null;
            });
        }
        assertEquals(LL[2].toLowerCase(java.util.Locale.ROOT), SeedVault.withWallet(ABOUT, null, w -> w.address(AccountScheme.LEDGER_LIVE, 2)));
    }

    private static List<Integer> indexes(AccountBook book) {
        List<Integer> out = new java.util.ArrayList<>();
        for (AccountBook.Account a : book.all()) out.add(a.index);
        return out;
    }

    /**
     * A v2 book whose active list is unreadable starts over at Account 1 under its SAVED numbering
     * (Ledger Live stays Ledger Live; storedScheme and load agree) and carries a one-time notice,
     * shown on the home screen after unlock. A list that is saved again reads back without it.
     */
    @Test public void corruptLedgerLiveBookKeepsItsNumberingAndSaysSo() {
        String stored = "{\"v\":2,\"wallet\":\"" + WALLET + "\",\"scheme\":\"ledger-live\",\"active\":0,\"accounts\":[{\"i\":0,\"a\":\"0xnot\"}]}";
        assertSame(AccountScheme.LEDGER_LIVE, AccountBook.storedScheme(stored));
        AccountBook book = AccountBook.load(stored, WALLET);
        assertSame(AccountScheme.LEDGER_LIVE, book.scheme);
        assertEquals(1, book.all().size());
        assertEquals("Your account list was reset; account numbering is still Ledger Live.", book.resetNotice());
        assertEquals(book.resetNotice(), AccountBook.listNotice(book.resetNotice(), 0));
        AccountBook again = AccountBook.load(book.encode(), WALLET);
        assertSame(AccountScheme.LEDGER_LIVE, again.scheme);
        assertNull("one time only", again.resetNotice());
        // Not even the numbering readable: Standard, and the notice says how to switch back.
        AccountBook garbage = AccountBook.load("{\"v\":2,\"wallet\":", WALLET);
        assertSame(AccountScheme.STANDARD, garbage.scheme);
        assertEquals(AccountBook.RESET_UNREADABLE_NOTICE, garbage.resetNotice());
        // Another wallet's book or a newer format: a fresh list, no notice.
        assertNull(AccountBook.load(stored.replace(WALLET, STD[1].toLowerCase(java.util.Locale.ROOT)), WALLET).resetNotice());
        assertNull(AccountBook.load(stored.replace("\"v\":2", "\"v\":3"), WALLET).resetNotice());
        assertNull(AccountBook.listNotice(null, 0));
        assertEquals("2 saved accounts did not match your recovery phrase and were removed from your account list. "
                + "Add accounts again in ☰ → Accounts; each address is derived from your phrase.", AccountBook.listNotice(null, 2));
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
