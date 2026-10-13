package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Bitcoin addresses in the phone's address book and recipient history (keyed by network),
 * address-poisoning detection for them, and the USB line limit for btcSignPsbt.
 */
public final class BtcSafetyAndTransportTest {
    private static final String ALICE = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    /** Same first 4 (after bc1q) and last 4 characters as ALICE, different middle: a poisoning attempt. */
    private static final String POISON = "bc1qcr8tqqqqqqqqqqqqqqqqqqqqqqqqqqqq306fyu";

    private static AddressSafety safety(AddressSafetyTest.MemoryStore store) {
        return new AddressSafety(new AddressBook(store), new RecipientHistory(store));
    }

    private static String value(List<MessageReview.Row> rows, String label) {
        for (MessageReview.Row r : rows) if (r.label.equals(label)) return r.value;
        return null;
    }

    @Test public void addressKeys() {
        String k = AddressKeys.btc(BtcNetwork.BITCOIN, ALICE);
        assertEquals("btc:bitcoin:" + ALICE, k);
        assertTrue(AddressKeys.isBtc(k));
        assertEquals(ALICE, AddressKeys.address(k));
        assertEquals("bitcoin", AddressKeys.network(k));
        assertEquals("bc1qcr8t…306fyu", AddressKeys.shortForm(k));
        assertEquals("btc:testnet:3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", AddressKeys.normalize("btc:testnet:3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
        assertEquals("0xabcd7f3a9c04e2b16d58a41c0f9e6b2d7a8c1234", AddressKeys.normalize("0xABCD7f3a9c04e2b16d58a41c0f9e6b2d7a8c1234"));
        for (String bad : new String[] {"btc:regtest:" + ALICE, "btc:bitcoin:BC1Q" + ALICE.substring(4).toUpperCase(), "btc:bitcoin:", "bitcoin:" + ALICE, ALICE}) {
            try { AddressKeys.normalize(bad); fail(bad); } catch (IllegalArgumentException expected) { }
        }
        assertEquals("btc-wallet:signet:73c5da0a", AddressKeys.walletKey("btc-wallet:signet:73c5da0a"));
    }

    @Test public void lookAlikeBitcoinAddresses() {
        String a = AddressKeys.btc(BtcNetwork.BITCOIN, ALICE), p = AddressKeys.btc(BtcNetwork.BITCOIN, POISON);
        assertTrue(LookAlike.similar(a, p));
        assertFalse("identical", LookAlike.similar(a, a));
        assertFalse("other network", LookAlike.similar(a, AddressKeys.btc(BtcNetwork.TESTNET, POISON)));
        assertFalse("never against EVM", LookAlike.similar(a, "0xabcd7f3a9c04e2b16d58a41c0f9e6b2d7a8c1234"));
        assertFalse("unrelated", LookAlike.similar(a, AddressKeys.btc(BtcNetwork.BITCOIN, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")));
        String grid = LookAlike.grid(a, p);
        assertTrue(grid, grid.contains(LookAlike.DIFFERENT_MARK));
        assertEquals(11, LookAlike.chunkCount(a, p));
        assertTrue(LookAlike.differingChunks(a, p) >= 6);
        // random bech32 bodies essentially never collide
        java.util.Random rnd = new java.util.Random(7);
        int hits = 0;
        for (int i = 0; i < 20_000; i++) {
            StringBuilder s = new StringBuilder("bc1q");
            for (int j = 0; j < 38; j++) s.append(Bech32.CHARSET.charAt(rnd.nextInt(32)));
            if (LookAlike.similar(a, AddressKeys.btc(BtcNetwork.BITCOIN, s.toString()))) hits++;
        }
        assertEquals(0, hits);
    }

    @Test public void historyAndPoisoningRowsForBitcoin() {
        AddressSafetyTest.MemoryStore store = new AddressSafetyTest.MemoryStore();
        AddressSafety s = safety(store);
        String wallet = "btc-wallet:bitcoin:73c5da0a";
        String alice = AddressKeys.btc(BtcNetwork.BITCOIN, ALICE);
        List<MessageReview.Row> first = s.rows(wallet, alice, RecipientHistory.Role.SEND);
        assertTrue(value(first, MessageReview.WARNING).startsWith("First time sending to this address"));
        List<TransactionReview.Party> parties = new ArrayList<>();
        parties.add(new TransactionReview.Party(alice, RecipientHistory.Role.SEND));
        assertNull(s.record(wallet, parties, 1_790_000_000_000L));
        assertTrue(value(s.rows(wallet, alice, RecipientHistory.Role.SEND), "History").startsWith("Sent here once before"));
        // the same address on testnet is a different entry
        assertNotNull(value(s.rows("btc-wallet:testnet:73c5da0a", AddressKeys.btc(BtcNetwork.TESTNET, ALICE), RecipientHistory.Role.SEND), MessageReview.WARNING));
        // poisoning
        List<MessageReview.Row> poisoned = s.rows(wallet, AddressKeys.btc(BtcNetwork.BITCOIN, POISON), RecipientHistory.Role.SEND);
        String danger = value(poisoned, MessageReview.DANGER);
        assertTrue(danger, danger.startsWith("Looks like bc1qcr8t…306fyu you sent to before, but it is a DIFFERENT address"));
        assertTrue(danger, danger.contains("of 11 chunks differ"));
        assertEquals(ALICE, value(poisoned, "Known address"));
        assertEquals(POISON, value(poisoned, "This address"));
        // a saved contact name, and it survives a reload
        new AddressBook(store);
        try {
            s.book.put(alice, "Alice cold", 1L);
        } catch (Exception e) { throw new AssertionError(e); }
        assertEquals("Alice cold", new AddressBook(store).name(alice));
        assertEquals("Alice cold (named on this phone)", value(s.rows(wallet, alice, RecipientHistory.Role.SEND), AddressSafety.CONTACT));
        assertEquals(1, new RecipientHistory(store).entries(wallet).size());
        assertNull(new RecipientHistory(store).problem());
    }

    // ------------------------------------------------------------------ USB line limit

    private static final class Recorder implements AccessoryTransport.Listener {
        final List<String> disconnects = new ArrayList<>();
        final List<JSONObject> requests = new ArrayList<>();
        final CountDownLatch done = new CountDownLatch(1);
        @Override public void onConnected(AccessoryTransport s) { }
        @Override public synchronized void onRequest(AccessoryTransport s, JSONObject r) { requests.add(r); }
        @Override public synchronized void onDisconnected(AccessoryTransport s, String reason) { disconnects.add(reason); done.countDown(); }
    }

    private static Recorder run(String lines) throws Exception {
        Recorder r = new Recorder();
        Closeable fd = () -> { };
        AccessoryTransport.openForTest(fd, new ByteArrayInputStream(lines.getBytes(StandardCharsets.UTF_8)), new ByteArrayOutputStream(), r).start();
        assertTrue(r.done.await(10, TimeUnit.SECONDS));
        return r;
    }

    private static String psbtLine(int psbtBytes, boolean methodFirst) {
        byte[] raw = new byte[psbtBytes];
        Arrays.fill(raw, (byte) 7);
        String b64 = Base64.getEncoder().encodeToString(raw);
        return methodFirst
                ? "{\"id\":\"p-1\",\"method\":\"btcSignPsbt\",\"network\":\"bitcoin\",\"psbt\":\"" + b64 + "\"}\n"
                : "{\"id\":\"p-1\",\"network\":\"bitcoin\",\"psbt\":\"" + b64 + "\",\"method\":\"btcSignPsbt\"}\n";
    }

    @Test public void largePsbtRequestsPassTheTransport() throws Exception {
        Recorder r = run(psbtLine(Psbt.MAX_BYTES, true));
        assertEquals(1, r.requests.size());
        assertEquals("btcSignPsbt", r.requests.get(0).getString("method"));
        assertEquals("USB cable disconnected", r.disconnects.get(0));
    }

    @Test public void psbtFieldMustComeAfterTheMethod() throws Exception {
        Recorder r = run(psbtLine(40_000, false));
        assertEquals(0, r.requests.size());
        assertTrue(r.disconnects.get(0).contains("32 KiB"));
    }

    @Test public void otherMethodsStayAt32KiB() throws Exception {
        // names btcSignPsbt inside the one nested object to get the larger buffer, but is another method
        char[] pad = new char[40_000];
        Arrays.fill(pad, 'a');
        Recorder r = run("{\"id\":\"x\",\"hostSimulation\":{\"method\":\"btcSignPsbt\"},\"method\":\"signEip1559\",\"pad\":\"" + new String(pad) + "\"}\n");
        assertEquals(0, r.requests.size());
        assertTrue(r.disconnects.get(0), r.disconnects.get(0).contains("32 KiB"));
    }

    @Test public void psbtLinesAreStillBounded() throws Exception {
        Recorder r = run(psbtLine(AccessoryTransport.MAX_PSBT_REQUEST_BYTES, true));
        assertEquals(0, r.requests.size());
        assertTrue(r.disconnects.get(0), r.disconnects.get(0).contains("288 KiB"));
    }
}
