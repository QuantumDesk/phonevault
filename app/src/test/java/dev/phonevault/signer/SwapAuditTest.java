package dev.phonevault.signer;

import static dev.phonevault.signer.Calldata.ADDRESS_THIS;
import static dev.phonevault.signer.Calldata.CONTRACT_BALANCE;
import static dev.phonevault.signer.Calldata.ETH;
import static dev.phonevault.signer.Calldata.MSG_SENDER;
import static dev.phonevault.signer.SwapReviewTest.DEADLINE;
import static dev.phonevault.signer.SwapReviewTest.E18;
import static dev.phonevault.signer.SwapReviewTest.E6;
import static dev.phonevault.signer.SwapReviewTest.FEE_COLLECTOR;
import static dev.phonevault.signer.SwapReviewTest.OTHER;
import static dev.phonevault.signer.SwapReviewTest.UR_ETH;
import static dev.phonevault.signer.SwapReviewTest.USDC;
import static dev.phonevault.signer.SwapReviewTest.WETH;
import static dev.phonevault.signer.SwapReviewTest.cmds;
import static dev.phonevault.signer.SwapReviewTest.count;
import static dev.phonevault.signer.SwapReviewTest.has;
import static dev.phonevault.signer.SwapReviewTest.refused;
import static dev.phonevault.signer.SwapReviewTest.request;
import static dev.phonevault.signer.SwapReviewTest.review;
import static dev.phonevault.signer.SwapReviewTest.synthetic;
import static dev.phonevault.signer.SwapReviewTest.value;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.web3j.crypto.Credentials;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Adversarial-audit PROOFS (2026-10-13). Each test demonstrates a review that understates a loss
 * or misses an alarm for calldata an untrusted host can send; it asserts the CURRENT (misleading)
 * behaviour, so it passes today and must be inverted when the finding is fixed.
 */
public final class SwapAuditTest {
    private static final Credentials KEY = Credentials.create("4c0883a69102937d6231471b5dbb6204fe51296170827966f278a5e6f4f4f5f");
    private static final String FEE_COLLECTOR_2 = "0x000000fee23a103a10d593b9ae06b3e05f2e7e2d";

    private static TransactionReview vector(String name) throws Exception {
        JSONObject v = synthetic(name);
        return TransactionReview.build(Eip1559Request.parse(request(v.getString("chainId"), v.getString("to"),
                v.getString("value"), v.getString("data"))), v.getString("from"), TokenListTest.bundled());
    }

    private static BigDecimal ethAmount(String shown) {
        return new BigDecimal(shown.replace(" ETH", "").replace(" WETH", "").replace(",", ""));
    }

    // ------------------------------------------------------------------ F1: split fees

    /**
     * F1 (fixed). The ">3% fee = DANGER + OTHER ADDRESS" rule applies to all portions of the same
     * output together: fourteen 3% portions (~34.7% of the output, to two other addresses) are one
     * DANGER total, "Recipient: OTHER ADDRESS ✗", the other-address title and sign label, and both
     * collectors are recorded parties.
     */
    @Test public void splitPortionsAreAddedUpIntoOneDanger() throws Exception {
        TransactionReview r = vector("audit-split-fees-under-three-percent");
        assertTrue(r.text(), has(r, "DANGER", "OTHER ADDRESS ✗ 14 separate fees together take 34.71% of the WETH output"));
        assertEquals(r.text(), 15, count(r, "DANGER")); // the total, plus each portion as an OTHER ADDRESS payout
        assertTrue(value(r, "Summary"), value(r, "Summary").contains("Recipient: OTHER ADDRESS ✗"));
        assertEquals("Swap to other address & sign", r.signLabel);
        assertEquals("Swap to OTHER ADDRESS", r.title);
        assertEquals(r.text(), 0, count(r, "WARNING"));
        assertEquals(2, r.parties.size()); // each collector once
        // what the wallet is left with is still shown: 0.0312 × 0.97^14 ≈ 0.02037 — a third gone
        BigDecimal left = ethAmount(value(r, "You get at least"));
        assertTrue(left.toPlainString(), left.compareTo(new BigDecimal("0.0204")) < 0);
        assertTrue(left.compareTo(new BigDecimal("0.0203")) > 0);
    }

    /** F1 (fixed): portions adding up to 1–3% are one WARNING; each portion stays a plain "Fee" row. */
    @Test public void splitPortionsBetweenOneAndThreePercentAreOneWarning() throws Exception {
        byte[] usdcForWeth = Calldata.v3Swap(ADDRESS_THIS, BigInteger.valueOf(100).multiply(E6), new BigInteger("31200000000000000"),
                Calldata.v3Path(USDC, 500, WETH), true);
        String data = Calldata.execute(cmds(0x00, 0x06, 0x06, 0x0c), Arrays.asList(usdcForWeth,
                Calldata.payPortion(WETH, FEE_COLLECTOR, 100), Calldata.payPortion(WETH, FEE_COLLECTOR_2, 100),
                Calldata.unwrap(MSG_SENDER, BigInteger.ZERO)), BigInteger.valueOf(DEADLINE));
        TransactionReview r = review("0x1", UR_ETH, "0x0", data);
        assertTrue(r.text(), has(r, "WARNING", "2 separate fees together take 1.99% of the WETH output"));
        assertEquals(r.text(), 1, count(r, "WARNING"));
        assertEquals(2, count(r, "Fee"));
        assertTrue(value(r, "Summary").contains("Recipient: this wallet ✓"));
        assertTrue(r.parties.isEmpty());
    }

    /** F1 in V4 (fixed): twelve 3% TAKE_PORTIONs (~30.6% of the USDC output) are a DANGER. */
    @Test public void splitV4TakePortionsAreADanger() throws Exception {
        BigInteger in = new BigInteger("500000000000000000");
        List<byte[]> params = new ArrayList<>();
        params.add(Calldata.v4ExactInSingle(Calldata.poolKey(ETH, USDC, 500, 10, ETH), true, in, BigInteger.valueOf(1200).multiply(E6)));
        params.add(Calldata.currencyAmount(ETH, in));
        int[] actions = new int[15];
        actions[0] = 0x06;
        actions[1] = 0x0c;
        for (int i = 0; i < 12; i++) {
            actions[2 + i] = 0x10;
            params.add(Calldata.take(USDC, i % 2 == 0 ? FEE_COLLECTOR : FEE_COLLECTOR_2, BigInteger.valueOf(300)));
        }
        actions[14] = 0x0f;
        params.add(Calldata.currencyAmount(USDC, BigInteger.ZERO));
        byte[] v4 = Calldata.v4(cmds(actions), params.toArray(new byte[0][]));
        TransactionReview r = review("0x1", UR_ETH, "0x6f05b59d3b20000",
                Calldata.execute(cmds(0x10), Collections.singletonList(v4), BigInteger.valueOf(DEADLINE)));
        assertTrue(r.text(), has(r, "DANGER", "OTHER ADDRESS ✗ 12 separate fees together take 30.61% of the USDC output"));
        assertTrue(value(r, "Summary").contains("Recipient: OTHER ADDRESS ✗"));
        assertEquals("Swap to other address & sign", r.signLabel);
        assertEquals(2, r.parties.size());
        // 1200 × 0.97^12 ≈ 832.9 USDC left of a 1200 USDC minimum
        String got = value(r, "You get at least");
        assertTrue(got, new BigDecimal(got.replace(" USDC", "").replace(",", "")).compareTo(new BigDecimal("833")) < 0);
    }

    // ------------------------------------------------------------------ F2: abandoned input

    /**
     * F2 (fixed). Unused native value is refused ("does not use"), and so is the same ETH wrapped
     * first and left in the router as an exactly known 1 WETH (anyone — the host's own bot — could
     * SWEEP it in the next block).
     */
    @Test public void wrappedNativeLeftInTheRouterIsRefused() throws Exception {
        JSONObject v = synthetic("audit-wrapped-eth-left-in-router");
        String why = refused(v.getString("chainId"), v.getString("to"), v.getString("value"), v.getString("data"));
        assertTrue(why, why.contains("it leaves 1000000000000000000 of this wallet's own " + WETH.toLowerCase() + " in the router"));
        // ... like the unwrapped twin of exactly this call
        String unwrapped = Calldata.execute(cmds(0x0b, 0x00), Arrays.asList(
                Calldata.wrap(ADDRESS_THIS, E18),
                Calldata.v3Swap(MSG_SENDER, E18, BigInteger.valueOf(1200).multiply(E6), Calldata.v3Path(WETH, 500, USDC), false)),
                BigInteger.valueOf(DEADLINE));
        assertTrue(refused("0x1", UR_ETH, "0x1bc16d674ec80000", unwrapped).contains("does not use"));
    }

    /** F2 with tokens (fixed): 1000 USDC pulled by Permit2, 100 swapped, exactly 900 USDC abandoned — refused. */
    @Test public void permit2PulledTokensLeftInTheRouterAreRefused() throws Exception {
        byte[] pull = Calldata.args(Calldata.a(USDC), Calldata.a(ADDRESS_THIS),
                new org.web3j.abi.datatypes.generated.Uint160(BigInteger.valueOf(1000).multiply(E6)));
        String data = Calldata.execute(cmds(0x02, 0x00), Arrays.asList(pull,
                Calldata.v3Swap(MSG_SENDER, BigInteger.valueOf(100).multiply(E6), new BigInteger("31200000000000000"),
                        Calldata.v3Path(USDC, 500, WETH), false)), BigInteger.valueOf(DEADLINE));
        String why = refused("0x1", UR_ETH, "0x0", data);
        assertTrue(why, why.contains("it leaves 900000000 of this wallet's own " + USDC.toLowerCase() + " in the router"));
        // pulling exactly what is swapped is still fine
        byte[] exact = Calldata.args(Calldata.a(USDC), Calldata.a(ADDRESS_THIS),
                new org.web3j.abi.datatypes.generated.Uint160(BigInteger.valueOf(100).multiply(E6)));
        TransactionReview ok = review("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x02, 0x00), Arrays.asList(exact,
                Calldata.v3Swap(MSG_SENDER, BigInteger.valueOf(100).multiply(E6), new BigInteger("31200000000000000"),
                        Calldata.v3Path(USDC, 500, WETH), false)), BigInteger.valueOf(DEADLINE)));
        assertEquals(ok.text(), 0, count(ok, "DANGER"));
        assertFalse(ok.text().contains("may be left"));
    }

    // ------------------------------------------------------------------ F3: 1-wei minimum

    /**
     * F3 (fixed). A 1-wei minimum is just as unprotected as 0 (sandwichable to nothing) and gets the
     * No-minimum DANGER. (A host simulation claiming a fair 0.3 WETH output does not contradict a
     * 1-wei minimum, so the DANGER row is what warns.)
     */
    @Test public void oneWeiMinimumIsFlaggedAsNoMinimum() throws Exception {
        TransactionReview r = vector("audit-one-wei-minimum");
        assertEquals("0.000000000000000001 WETH", value(r, "You get at least"));
        assertTrue(r.text(), has(r, "DANGER", "No minimum: this swap accepts getting next to nothing back (0.000000000000000001 WETH)"));
        assertEquals(1, count(r, "DANGER"));
        assertEquals(0, count(r, "WARNING"));
        // no real transaction trips the dust rule: only the one with a literal 0 minimum shows "No minimum"
        JSONArray real = SwapReviewTest.vectors();
        for (int i = 0; i < real.length(); i++) {
            JSONObject t = real.getJSONObject(i);
            TransactionReview tr;
            try {
                tr = TransactionReview.build(Eip1559Request.parse(request(t.getString("chainId"), t.getString("to"),
                        t.getString("value"), t.getString("data"))), t.getString("from"), TokenListTest.bundled());
            } catch (RequestRefusal refusedVector) {
                continue;
            }
            assertEquals(t.getString("tx"), t.getString("tx").startsWith("0x4d2a784f"), has(tr, "DANGER", "No minimum"));
        }

        JSONObject v = synthetic("audit-one-wei-minimum");
        JSONObject claim = new JSONObject().put("node", "ethereum-rpc.publicnode.com").put("block", "0x18f603b")
                .put("changes", new JSONArray()
                        .put(new JSONObject().put("asset", USDC.toLowerCase()).put("delta", "-1000000000"))
                        .put(new JSONObject().put("asset", WETH.toLowerCase()).put("delta", "300000000000000000")));
        ApprovalSession s = new ApprovalSession(Eip1559Request.parse(request(v.getString("chainId"), v.getString("to"),
                v.getString("value"), v.getString("data")).put("hostSimulation", claim)), KEY, TokenListTest.bundled());
        assertNotNull(s.hostSimulation);
        assertFalse(s.hostSimulation.text(), s.hostSimulation.contradicts);

        // the same swap with minimum 0 does get the DANGER
        String zero = Calldata.execute(cmds(0x00), Collections.singletonList(
                Calldata.v3Swap(MSG_SENDER, BigInteger.valueOf(1000).multiply(E6), BigInteger.ZERO, Calldata.v3Path(USDC, 500, WETH), true)),
                BigInteger.valueOf(DEADLINE));
        assertTrue(has(review("0x1", UR_ETH, "0x0", zero), "DANGER", "No minimum"));
    }

    // ------------------------------------------------------------------ F4: unused input paid away

    /**
     * F4. The wallet's own unused input (here up to ~10 ETH) unwrapped to ANOTHER address is shown
     * as "at least 0 ETH goes to …": the payout's known upper bound (everything sent minus what the
     * exact-output swap used) is not stated.
     */
    @Test public void unusedInputPaidToAnotherAddressReadsAsAtLeastZero() throws Exception {
        String data = Calldata.execute(cmds(0x0b, 0x01, 0x0c), Arrays.asList(
                Calldata.wrap(ADDRESS_THIS, CONTRACT_BALANCE),
                Calldata.v3Swap(MSG_SENDER, E6, BigInteger.TEN.multiply(E18), Calldata.v3Path(USDC, 500, WETH), false),
                Calldata.unwrap(OTHER, BigInteger.ZERO)), BigInteger.valueOf(DEADLINE));
        TransactionReview r = review("0x1", UR_ETH, "0x8ac7230489e80000", data);
        assertTrue(r.text(), has(r, "DANGER", "OTHER ADDRESS ✗ at least 0 ETH goes to"));
        assertEquals("1 USDC", value(r, "You get exactly"));
    }

    // ------------------------------------------------------------------ F5: max deadline

    /** F5. "No deadline" is a WARNING, but deadline = 2^256−1 (never expires) is a plain row. */
    @Test public void maximumDeadlineIsNotWarned() throws Exception {
        byte[] swap = Calldata.v3Swap(MSG_SENDER, BigInteger.valueOf(100).multiply(E6), new BigInteger("31200000000000000"),
                Calldata.v3Path(USDC, 500, WETH), true);
        BigInteger max = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
        TransactionReview never = review("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x00), Collections.singletonList(swap), max));
        assertTrue(value(never, "Expires"), value(never, "Expires").startsWith("No expiry"));
        assertEquals(never.text(), 0, count(never, "WARNING"));
        assertEquals(0, count(never, "DANGER"));
        TransactionReview none = review("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x00), Collections.singletonList(swap), null));
        assertTrue(has(none, "WARNING", "No deadline"));
    }

    // ------------------------------------------------------------------ F6: simulation refund bound

    /**
     * F6. On an exact-output swap paid in ETH, the refund is bounded by what was sent, yet the
     * simulation check treats it as unbounded: a host claim of a NET +1 ETH gain is not a mismatch.
     */
    @Test public void simulationClaimOfNetEthGainOnARefundIsNotAMismatch() throws Exception {
        String data = Calldata.execute(cmds(0x0b, 0x01, 0x0c), Arrays.asList(
                Calldata.wrap(ADDRESS_THIS, CONTRACT_BALANCE),
                Calldata.v3Swap(MSG_SENDER, BigInteger.valueOf(100).multiply(E6), new BigInteger("50000000000000000"),
                        Calldata.v3Path(USDC, 500, WETH), false),
                Calldata.unwrap(MSG_SENDER, BigInteger.ZERO)), BigInteger.valueOf(DEADLINE));
        JSONObject claim = new JSONObject().put("node", "ethereum-rpc.publicnode.com").put("block", "0x18f603b")
                .put("changes", new JSONArray()
                        .put(new JSONObject().put("asset", "native").put("delta", E18.toString()))
                        .put(new JSONObject().put("asset", USDC.toLowerCase()).put("delta", "100000000")));
        ApprovalSession s = new ApprovalSession(Eip1559Request.parse(request("0x1", UR_ETH, "0xb1a2bc2ec50000", data)
                .put("hostSimulation", claim)), KEY, TokenListTest.bundled());
        assertNotNull(s.review.text(), value(s.review, "Unused input"));
        assertFalse(s.hostSimulation.text(), s.hostSimulation.contradicts);
    }

    // ------------------------------------------------------------------ F7: asymmetric look-alikes

    /**
     * F7. Look-alike detection needs ≥3 matching characters at EACH end. A poisoned address that
     * copies the last 8 (or first 8) hex characters of a saved contact is not flagged.
     */
    @Test public void asymmetricLookAlikesAreMissed() throws Exception {
        String alice = "0xabcd7f3a9c04e2b16d58a41c0f9e6b2d7a8c1234";
        String suffix8 = AddressSafetyTest.addr("ab", "7a8c1234");   // 0xab…7a8c1234: 2 + 8 matching
        String prefix8 = AddressSafetyTest.addr("abcd7f3a", "5");    // 0xabcd7f3a…: 8 + 0 matching
        assertFalse(LookAlike.similar(alice, suffix8));
        assertFalse(LookAlike.similar(alice, prefix8));

        AddressSafetyTest.MemoryStore store = new AddressSafetyTest.MemoryStore();
        AddressSafety safety = new AddressSafety(new AddressBook(store), new RecipientHistory(store));
        safety.book.put(alice, "Alice", 1_790_000_000_000L);
        for (String poison : new String[] {suffix8, prefix8}) {
            TransactionReview r = new ApprovalSession(Eip1559Request.parse(request("0x1", poison, "0xde0b6b3a7640000", "0x")),
                    KEY, TokenListTest.bundled(), safety).review;
            assertEquals(r.text(), 0, count(r, "DANGER"));
        }
    }
}
