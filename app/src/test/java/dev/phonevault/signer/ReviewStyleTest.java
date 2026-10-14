package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.json.JSONObject;
import org.junit.Test;
import org.web3j.crypto.Credentials;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Presentation of review rows: levels, topics, danger summary/acknowledgement, grouped addresses, colors. */
public final class ReviewStyleTest {
    private static final Credentials KEY = TestKeys.EVM_KEY;
    private static final String USDC_ETH = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    private static final String SPENDER = "0x3333333333333333333333333333333333333333";
    private static final BigInteger MAX = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);

    private static MessageReview.Row row(String label, String value) { return new MessageReview.Row(label, value); }

    // ------------------------------------------------------------------ levels and headings

    @Test public void warningIsACheckAndDangerStaysDanger() {
        assertEquals(ReviewStyle.Level.DANGER, ReviewStyle.level(MessageReview.DANGER));
        assertEquals(ReviewStyle.Level.CHECK, ReviewStyle.level(MessageReview.WARNING));
        assertEquals(ReviewStyle.Level.NONE, ReviewStyle.level("Recipient"));
        assertEquals("RECIPIENT", ReviewStyle.heading(row("Recipient", "0x…")));
    }

    @Test public void headingsCarryATopic() {
        assertEquals("DANGER · UNLIMITED PERMISSION", ReviewStyle.heading(row(MessageReview.DANGER,
                "UNLIMITED allowance: 0x3333 will be able to take ALL of this wallet's USDC, now and in the future.")));
        assertEquals("CHECK · NEW RECIPIENT", ReviewStyle.heading(row(MessageReview.WARNING,
                "First time sending to this address from this wallet. Check the whole address with the recipient.")));
        assertEquals("DANGER · FEE", ReviewStyle.heading(row(MessageReview.DANGER,
                "The network fee is 0.001 BTC, 40% of the amount sent.")));
        assertEquals("DANGER · UNREADABLE DATA", ReviewStyle.heading(row(MessageReview.DANGER,
                "Unreadable data: these bytes are not plain text. They could be the hash of a transaction or permission.")));
        assertEquals("DANGER · NETWORK", ReviewStyle.heading(row(MessageReview.DANGER,
                "The message is for Base, but your host is on Ethereum. Do not sign unless you meant to act on that network.")));
        assertEquals("DANGER · ALL YOUR NFTS", ReviewStyle.heading(row(MessageReview.DANGER,
                "Lets 0x33 move EVERY NFT in this collection, now and in future")));
        assertEquals("CHECK · UNKNOWN TOKEN", ReviewStyle.heading(row(MessageReview.WARNING,
                "Unknown token contract 0x22. It is not in the token list built into this phone, so its fee… ")));
        // an explicit topic wins over the text
        assertEquals("CHECK · NEW SPENDER", ReviewStyle.heading(new MessageReview.Row(MessageReview.WARNING, "anything", "New spender")));
        // no recognisable topic: the level word alone
        assertEquals("CHECK", ReviewStyle.heading(row(MessageReview.WARNING, "Something unusual.")));
    }

    @Test public void feeIsMatchedAsAWordOnly() {
        assertNull(ReviewStyle.topicOf("A coffee shop."));
        assertEquals("FEE", ReviewStyle.topicOf("Fees that high are rarely needed."));
    }

    @Test public void addressSafetyRowsNameTheirTopic() {
        AddressSafetyTest.MemoryStore store = new AddressSafetyTest.MemoryStore();
        AddressSafety s = new AddressSafety(new AddressBook(store), new RecipientHistory(store));
        String me = KEY.getAddress().toLowerCase();
        List<MessageReview.Row> send = s.rows(me, SPENDER, RecipientHistory.Role.SEND);
        List<MessageReview.Row> approve = s.rows(me, SPENDER, RecipientHistory.Role.APPROVE);
        assertEquals("CHECK · NEW RECIPIENT", ReviewStyle.heading(send.get(send.size() - 1)));
        assertEquals("CHECK · NEW SPENDER", ReviewStyle.heading(approve.get(approve.size() - 1)));
    }

    // ------------------------------------------------------------------ the danger summary and the second checkbox

    @Test public void unlimitedApprovalNeedsTheDangerAcknowledgement() throws Exception {
        JSONObject req = new JSONObject().put("id", "t").put("method", "signEip1559").put("chainId", "0x1")
                .put("nonce", "0x7").put("maxPriorityFeePerGas", "0x3b9aca00").put("maxFeePerGas", "0x77359400")
                .put("gasLimit", "0xfde8").put("to", USDC_ETH).put("value", "0x0")
                .put("data", Erc20ReviewTest.approve(SPENDER, MAX));
        TransactionReview r = new ApprovalSession(Eip1559Request.parse(req), KEY, TokenListTest.bundled()).review;
        List<MessageReview.Row> dangers = ReviewStyle.dangers(r.summary, r.details);
        assertEquals(1, dangers.size());
        assertEquals("DANGER · UNLIMITED PERMISSION", ReviewStyle.heading(dangers.get(0)));
        assertEquals("1 danger below — read before signing", ReviewStyle.dangerSummary(dangers.size()));
        assertEquals("I understand: UNLIMITED allowance: 0x3333…3333 will be able to take ALL of this wallet's USDC, "
                + "now and in the future, until you revoke it.", ReviewStyle.dangerAcknowledgement(dangers));
    }

    @Test public void severalDangersAreCountedAndNamed() {
        List<MessageReview.Row> d = ReviewStyle.dangers(
                Arrays.asList(row("Action", "x"), row(MessageReview.DANGER, "No minimum: you may get nothing back."),
                        row(MessageReview.WARNING, "First time sending to this address.")),
                null,
                Collections.singletonList(row(MessageReview.DANGER, "The Mac's simulation does not match.")));
        assertEquals(2, d.size());
        assertEquals("2 dangers below — read before signing", ReviewStyle.dangerSummary(2));
        assertEquals("I understand: No minimum: you may get nothing back. (and 1 more danger shown above)",
                ReviewStyle.dangerAcknowledgement(d));
        assertNull(ReviewStyle.dangerAcknowledgement(Collections.emptyList()));
    }

    @Test public void firstSentenceKeepsDecimalsAndShortAddresses() {
        assertEquals("Send 1.5 ETH to 0x12…34 now.", ReviewStyle.firstSentence("Send 1.5 ETH to 0x12…34 now. Then more."));
        assertEquals("No full stop", ReviewStyle.firstSentence("No full stop"));
        String longOne = new String(new char[400]).replace('\0', 'a');
        assertTrue(ReviewStyle.firstSentence(longOne).length() <= 220);
    }

    // ------------------------------------------------------------------ approval gate

    @Test public void approveNeedsReviewedAndTheEnd() {
        ApprovalGate g = new ApprovalGate(false);
        assertFalse(g.mayApprove());
        g.setReviewed(true);
        assertFalse("not scrolled to the end yet", g.mayApprove());
        g.reachedEnd();
        assertTrue(g.mayApprove());
        g.setReviewed(false);
        assertFalse(g.mayApprove());
    }

    @Test public void aDangerNeedsTheSecondCheckbox() {
        ApprovalGate g = new ApprovalGate(true);
        g.setReviewed(true);
        g.reachedEnd();
        assertFalse(g.mayApprove());
        g.setDangerAcknowledged(true);
        assertTrue(g.mayApprove());
        g.setDangerAcknowledged(false);
        assertFalse(g.mayApprove());
    }

    @Test public void endOfScrollIsMeasuredWithSlop() {
        assertTrue("content fits", ApprovalGate.atEnd(1000, 0, 1000, 24));
        assertFalse(ApprovalGate.atEnd(3000, 0, 1000, 24));
        assertFalse(ApprovalGate.atEnd(3000, 1900, 1000, 24));
        assertTrue(ApprovalGate.atEnd(3000, 1980, 1000, 24));
    }

    // ------------------------------------------------------------------ addresses

    @Test public void evmAddressesAreGroupedInFours() {
        String a = "0x51dd9Afd5f32aBcD1234567890abCDef12345678";
        assertEquals("0x51dd 9Afd 5f32 aBcD 1234 5678 90ab CDef 1234 5678", ReviewStyle.groupEvm(a));
        assertEquals("0x51dd 9Afd 5f32 aBcD 1234\n5678 90ab CDef 1234 5678", ReviewStyle.groupEvmTwoLines(a));
        assertEquals("Send 1 ETH to 0x51dd 9Afd 5f32 aBcD 1234 5678 90ab CDef 1234 5678.",
                ReviewStyle.groupEvmIn("Send 1 ETH to " + a + "."));
        // not addresses: short forms, hashes and calldata stay as they are
        String hash = "0x" + new String(new char[64]).replace('\0', 'a');
        assertEquals(hash, ReviewStyle.groupEvmIn(hash));
        assertEquals("0x51dd…5678", ReviewStyle.groupEvmIn("0x51dd…5678"));
        assertEquals("not an address", ReviewStyle.groupEvm("not an address"));
        assertEquals("to 0x51dd…5678 now", ReviewStyle.shortenEvm("to " + a + " now"));
        assertTrue(Addresses.isEvm(a));
        assertFalse(Addresses.isEvm(a + "0"));
    }

    @Test public void signedTextIsNeverRegrouped() {
        String a = "0x51dd9Afd5f32aBcD1234567890abCDef12345678";
        assertEquals("Pay " + a, ReviewStyle.displayValue("Message", "Pay " + a));
        assertEquals("\"" + a + "\"", ReviewStyle.displayValue("message.note · string", "\"" + a + "\""));
        assertEquals(a, ReviewStyle.displayValue("message.salt · bytes20", a));
        assertEquals(a, ReviewStyle.displayValue("Data (hex)", a));
        assertEquals(ReviewStyle.groupEvm(a), ReviewStyle.displayValue("message.to · address", a));
        assertEquals(ReviewStyle.groupEvm(a), ReviewStyle.displayValue("Signing address · Account 1", a));
        assertEquals(ReviewStyle.groupEvm(a), ReviewStyle.displayValue("Recipient", a));
    }

    @Test public void groupingKeepsEveryCharacter() {
        String a = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01";
        assertEquals(a, ReviewStyle.groupEvm(a).replace(" ", ""));
    }

    // ------------------------------------------------------------------ colors

    @Test public void inksAreLegibleOnTheDarkGround() {
        assertTrue(ReviewStyle.contrast(ReviewStyle.WARNING_INK, ReviewStyle.GROUND) >= 4.5);
        assertTrue(ReviewStyle.contrast(ReviewStyle.WARNING_INK, ReviewStyle.SURFACE) >= 4.5);
        assertTrue(ReviewStyle.contrast(ReviewStyle.DANGER_INK, ReviewStyle.GROUND) >= 4.5);
        assertTrue(ReviewStyle.contrast(ReviewStyle.DANGER_INK, ReviewStyle.SURFACE) >= 4.5);
        assertFalse("amber and red must differ", ReviewStyle.WARNING_INK == ReviewStyle.DANGER_INK);
    }
}
