package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONObject;
import org.junit.Test;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Address book, recipient history and address-poisoning (look-alike) detection. */
public final class AddressSafetyTest {
    private static final Credentials KEY = Credentials.create("4c0883a69102937d6231471b5dbb6204fe51296170827966f278a5e6f4f4f5f");
    private static final String ME = KEY.getAddress().toLowerCase();
    private static final String ALICE = "0xabcd7f3a9c04e2b16d58a41c0f9e6b2d7a8c1234";
    /** A poisoned look-alike of ALICE: same first 4 and last 4 hex characters, different middle. */
    private static final String POISON = addr("abcd", "1234");
    private static final String USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    private static final long DAY1 = 1_790_000_000_000L;

    /** prefix + zeros + suffix, 40 hex characters. */
    static String addr(String prefix, String suffix) {
        StringBuilder b = new StringBuilder("0x").append(prefix);
        while (b.length() < 42 - suffix.length()) b.append('0');
        return b.append(suffix).toString();
    }

    static final class MemoryStore implements AddressBook.Store {
        final Map<String, byte[]> files = new HashMap<>();
        boolean failWrites;

        @Override public byte[] read(String name) { return files.get(name); }

        @Override public void write(String name, byte[] bytes) throws IOException {
            if (failWrites) throw new IOException("disk full");
            files.put(name, bytes.clone());
        }
    }

    private static AddressSafety safety(MemoryStore store) {
        return new AddressSafety(new AddressBook(store), new RecipientHistory(store));
    }

    private static TransactionReview review(AddressSafety safety, String to, String value, String data) throws Exception {
        return new ApprovalSession(Eip1559Request.parse(SwapReviewTest.request("0x1", to, value, data)), KEY,
                TokenListTest.bundled(), safety).review;
    }

    private static TransactionReview send(AddressSafety safety, String to) throws Exception {
        return review(safety, to, "0xde0b6b3a7640000", "0x");
    }

    private static String value(TransactionReview r, String label) { return SwapReviewTest.value(r, label); }

    // ------------------------------------------------------------------ look-alike rule

    @Test public void lookAlikeMatchesPoisoningPatternsOnly() {
        assertEquals(42, POISON.length());
        assertTrue(LookAlike.similar(ALICE, POISON));                                        // first 4 + last 4
        assertTrue(LookAlike.similar(ALICE, POISON.toUpperCase().replace("0X", "0x")));      // case-insensitive
        assertFalse("identical is not a look-alike", LookAlike.similar(ALICE, ALICE.toUpperCase().replace("0X", "0x")));
        assertTrue(LookAlike.similar(ALICE, addr("abc", "1234")));                // 3 + 4 = 7
        assertTrue(LookAlike.similar(ALICE, addr("abcd7", "c234")));              // 5 + 3 = 8
        assertTrue("one edit at each end", LookAlike.similar(ALICE, addr("abcd7e", "8c1235")));
        assertFalse(LookAlike.similar(ALICE, addr("abcd", "9999")));               // ends differ
        assertFalse(LookAlike.similar(ALICE, addr("1111", "1234")));               // starts differ
        assertFalse(LookAlike.similar(ALICE, addr("ab", "1234")));                 // 2 + 4
        // random addresses essentially never collide
        SecureRandom random = new SecureRandom(new byte[] {1});
        int hits = 0;
        for (int i = 0; i < 20000; i++) {
            byte[] b = new byte[20];
            random.nextBytes(b);
            if (LookAlike.similar(ALICE, "0x" + Abi.toHex(b))) hits++;
        }
        assertEquals(0, hits);
    }

    @Test public void gridAlignsChunksAndMarksDifferences() {
        String grid = LookAlike.grid(ALICE, POISON);
        String[] lines = grid.split("\n");
        assertEquals(12, lines.length);
        String k = Keys.toChecksumAddress(ALICE).substring(2), p = Keys.toChecksumAddress(POISON).substring(2);
        assertEquals(" 1   " + k.substring(0, 4) + "    " + p.substring(0, 4), lines[2]);           // same chunk: no mark
        assertTrue(lines[3].endsWith(LookAlike.DIFFERENT_MARK));                                        // chunk 2 differs
        assertEquals("10   " + k.substring(36) + "    " + p.substring(36), lines[11]);
        assertEquals(8, LookAlike.differingChunks(ALICE, POISON));
        assertEquals("0xABcD…1234".toLowerCase(), LookAlike.shortForm(ALICE).toLowerCase());
    }

    @Test public void levenshtein() {
        assertEquals(0, LookAlike.levenshtein("abcdef", "abcdef"));
        assertEquals(1, LookAlike.levenshtein("abcdef", "abcdxf"));
        assertEquals(1, LookAlike.levenshtein("abcdef", "abcdf"));
        assertEquals(2, LookAlike.levenshtein("abcdef", "abcfed"));
    }

    // ------------------------------------------------------------------ history on the review

    @Test public void firstTimeThenCountedHistory() throws Exception {
        MemoryStore store = new MemoryStore();
        AddressSafety s = safety(store);
        TransactionReview first = send(s, ALICE);
        assertTrue(SwapReviewTest.has(first, "WARNING", "First time sending to this address"));
        assertNull(value(first, "History"));
        assertNull(s.record(ME, first.parties, DAY1));
        assertNull(s.record(ME, first.parties, DAY1 + 86_400_000L));
        TransactionReview third = send(s, ALICE);
        assertEquals("Sent here 2 times before (first on " + AddressSafety.day(DAY1) + ")", value(third, "History"));
        assertFalse(SwapReviewTest.has(third, "WARNING", "First time"));
        // persisted: a fresh object over the same storage sees it; another wallet does not
        assertEquals(2, new RecipientHistory(store).lookup(ME, ALICE).sends);
        assertNull(new RecipientHistory(store).lookup("0x9999999999999999999999999999999999999999", ALICE));
    }

    @Test public void lookAlikeOfAPastRecipientIsDangerWithTheComparison() throws Exception {
        MemoryStore store = new MemoryStore();
        AddressSafety s = safety(store);
        s.record(ME, send(s, ALICE).parties, DAY1);
        TransactionReview r = send(s, POISON);
        String danger = value(r, "DANGER");
        assertTrue(danger, danger.startsWith("Looks like " + LookAlike.shortForm(ALICE) + " you sent to before, but it is a DIFFERENT address"));
        assertEquals(LookAlike.grid(ALICE, POISON), value(r, AddressSafety.COMPARE));
        assertEquals(Keys.toChecksumAddress(ALICE), value(r, "Known address"));
        assertEquals(Keys.toChecksumAddress(POISON), value(r, "This address"));
        assertTrue(SwapReviewTest.has(r, "WARNING", "First time sending"));
        // ERC-20 recipients get the same check
        TransactionReview token = review(s, USDC, "0x0", Erc20ReviewTest.transfer(POISON, BigInteger.valueOf(50_000_000)));
        assertTrue(value(token, "DANGER").startsWith("Looks like"));
        // and the known address itself is clean
        assertNull(value(send(s, ALICE), "DANGER"));
    }

    @Test public void lookAlikeOfThisWalletItselfIsDanger() throws Exception {
        String fake = addr(ME.substring(2, 6), ME.substring(38));
        TransactionReview r = send(safety(new MemoryStore()), fake);
        assertTrue(value(r, "DANGER"), value(r, "DANGER").contains("(this wallet's own address), but it is a DIFFERENT address"));
    }

    @Test public void spendersHaveTheirOwnHistory() throws Exception {
        MemoryStore store = new MemoryStore();
        AddressSafety s = safety(store);
        TransactionReview approve = review(s, USDC, "0x0", Erc20ReviewTest.approve(ALICE, BigInteger.valueOf(5)));
        assertTrue(SwapReviewTest.has(approve, "WARNING", "First time approving this spender"));
        s.record(ME, approve.parties, DAY1);
        TransactionReview again = review(s, USDC, "0x0", Erc20ReviewTest.approve(ALICE, BigInteger.valueOf(5)));
        assertEquals("Approved this spender once before (first on " + AddressSafety.day(DAY1) + ")", value(again, "History"));
        // a revoke is not counted as an approval
        assertTrue(review(s, USDC, "0x0", Erc20ReviewTest.approve(ALICE, BigInteger.ZERO)).parties.isEmpty());
        // sending to an address you only approved is still a first send
        assertTrue(SwapReviewTest.has(send(s, ALICE), "WARNING", "You approved it as a spender before"));
    }

    @Test public void historyProblemsAreShownNotHidden() throws Exception {
        MemoryStore store = new MemoryStore();
        store.files.put(RecipientHistory.FILE, "{not json".getBytes(StandardCharsets.UTF_8));
        AddressSafety s = safety(store);
        assertTrue(SwapReviewTest.has(send(s, ALICE), "WARNING", "could not be read"));
        assertNotNull(s.record(ME, send(s, ALICE).parties, DAY1));
        assertEquals("the unreadable file is not overwritten", "{not json", new String(store.files.get(RecipientHistory.FILE), StandardCharsets.UTF_8));
        // a failed write is reported, never thrown (the signature already exists)
        MemoryStore full = new MemoryStore();
        AddressSafety f = safety(full);
        full.failWrites = true;
        assertTrue(f.record(ME, send(f, ALICE).parties, DAY1).contains("disk full"));
    }

    // ------------------------------------------------------------------ address book

    @Test public void contactNamesComeOnlyFromThePhone() throws Exception {
        MemoryStore store = new MemoryStore();
        AddressSafety s = safety(store);
        s.book.put(ALICE, "Alice", DAY1);
        TransactionReview r = send(s, ALICE);
        assertEquals("Alice (named on this phone)", value(r, AddressSafety.CONTACT));
        // a look-alike of a CONTACT is flagged with the contact's name even without history
        TransactionReview p = send(s, POISON);
        assertTrue(value(p, "DANGER").contains("(\"Alice\") saved in your address book, but it is a DIFFERENT address"));
        assertNull(value(p, AddressSafety.CONTACT));
        // the host has no field that could carry a name: an extra field is a schema error
        try {
            Eip1559Request.parse(SwapReviewTest.request("0x1", ALICE, "0x1", "0x").put("label", "Alice"));
            fail("accepted a host-supplied label");
        } catch (org.json.JSONException expected) {
            assertTrue(expected.getMessage().contains("unknown=[label]"));
        }
    }

    @Test public void addRenameDeleteAndPersist() throws Exception {
        MemoryStore store = new MemoryStore();
        AddressBook book = new AddressBook(store);
        book.put(ALICE, "  Alice  ", DAY1);
        assertEquals("Alice", book.name(ALICE.toUpperCase().replace("0X", "0x")));
        book.put(ALICE, "Alice Cold", DAY1 + 5);
        assertEquals("Alice Cold", new AddressBook(store).name(ALICE));
        assertEquals(DAY1, new AddressBook(store).list().get(0).added);
        book.put(USDC, "Bob's shop", DAY1);
        List<AddressBook.Contact> list = new AddressBook(store).list();
        assertEquals("Alice Cold", list.get(0).name);
        assertEquals("Bob's shop", list.get(1).name);
        book.remove(ALICE);
        assertNull(new AddressBook(store).name(ALICE));
        assertEquals(1, new AddressBook(store).size());
        JSONObject saved = new JSONObject(new String(store.files.get(AddressBook.FILE), StandardCharsets.UTF_8));
        assertEquals(1, saved.getInt("version"));
    }

    @Test public void namesAreShortPlainAndUnique() throws Exception {
        AddressBook book = new AddressBook(new MemoryStore());
        String[] bad = {"", "   ", "A very long name that exceeds", "Alice‮ecila", "Al\nice", "Bob  Smith", "-Alice", "0xabcd", "Ålice", "Alice​"};
        for (String name : bad) {
            try {
                book.put(ALICE, name, DAY1);
                fail("accepted name [" + name + "]");
            } catch (AddressBook.InvalidNameException expected) {
                // refused
            }
        }
        book.put(ALICE, "Alice", DAY1);
        try {
            book.put(POISON, "alice", DAY1);
            fail("two addresses with the same name");
        } catch (AddressBook.InvalidNameException expected) {
            assertTrue(expected.getMessage().contains("already saved"));
        }
        // a failed write leaves the book as it was
        MemoryStore store = new MemoryStore();
        AddressBook b2 = new AddressBook(store);
        store.failWrites = true;
        try {
            b2.put(ALICE, "Alice", DAY1);
            fail("write failure not reported");
        } catch (IOException expected) {
            assertNull(b2.name(ALICE));
        }
    }

    @Test public void corruptBookIsReportedAndNotOverwritten() throws Exception {
        MemoryStore store = new MemoryStore();
        store.files.put(AddressBook.FILE, "{\"version\":1,\"contacts\":[{\"address\":\"nope\"}]}".getBytes(StandardCharsets.UTF_8));
        AddressBook book = new AddressBook(store);
        assertNotNull(book.problem());
        try {
            book.put(ALICE, "Alice", DAY1);
            fail("changed an unreadable book");
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains("could not be read"));
        }
    }

    @Test public void swapToAnotherAddressAndNftRecipientsUseTheSameChecks() throws Exception {
        MemoryStore store = new MemoryStore();
        AddressSafety s = safety(store);
        s.record(ME, send(s, ALICE).parties, DAY1);
        String nft = NftReviewTest.safeTransfer721(ME, POISON, 1);
        TransactionReview r = review(s, "0x5555555555555555555555555555555555555555", "0x0", nft);
        assertTrue(value(r, "DANGER").startsWith("Looks like"));
        String setAll = NftReviewTest.setApprovalForAll(POISON, true);
        TransactionReview all = review(s, "0x5555555555555555555555555555555555555555", "0x0", setAll);
        assertTrue(SwapReviewTest.has(all, "DANGER", "Looks like"));
        assertTrue(SwapReviewTest.has(all, "WARNING", "First time approving"));
    }
}
