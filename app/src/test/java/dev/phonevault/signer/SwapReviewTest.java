package dev.phonevault.signer;

import static dev.phonevault.signer.Calldata.ADDRESS_THIS;
import static dev.phonevault.signer.Calldata.CONTRACT_BALANCE;
import static dev.phonevault.signer.Calldata.ETH;
import static dev.phonevault.signer.Calldata.MSG_SENDER;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionDecoder;
import org.web3j.utils.Numeric;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Uniswap router review: real mainnet/Base transactions (swap-vectors.json, each with its explorer
 * link) and hand-built calldata encoded with web3j's independent ABI encoder.
 */
public final class SwapReviewTest {
    private static final Credentials KEY = Credentials.create("4c0883a69102937d6231471b5dbb6204fe51296170827966f278a5e6f4f4f5f");
    static final String UR_ETH = "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af";      // Universal Router 2.0, Ethereum
    static final String UR21_ETH = "0x23617e59A5925b2A4Bf75d73ff6711cD0b29De85";    // Universal Router 2.1.2, Ethereum
    static final String SR02_ETH = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45";    // SwapRouter02, Ethereum
    static final String USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    static final String WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    static final String UNKNOWN = "0x2222222222222222222222222222222222222222";
    static final String OTHER = "0x7f3a9c04e2b16d58a41c0f9e6b2d7a8c5e1f4b93";
    static final String FEE_COLLECTOR = "0x000000fee13a103a10d593b9ae06b3e05f2e7e1c";
    static final BigInteger E6 = BigInteger.TEN.pow(6), E18 = BigInteger.TEN.pow(18);
    static final long DEADLINE = Instant.parse("2026-10-11T14:32:00Z").getEpochSecond();

    // ------------------------------------------------------------------ helpers

    static JSONObject request(String chainHex, String to, String value, String data) throws JSONException {
        return new JSONObject().put("id", "swap-1").put("method", "signEip1559").put("chainId", chainHex)
                .put("nonce", "0x0").put("maxPriorityFeePerGas", "0x3b9aca00").put("maxFeePerGas", "0x77359400")
                .put("gasLimit", "0x493e0").put("to", to).put("value", value).put("data", data);
    }

    static TransactionReview review(String chain, String to, String value, String data) throws Exception {
        return new ApprovalSession(Eip1559Request.parse(request(chain, to, value, data)), KEY, TokenListTest.bundled()).review;
    }

    static String value(TransactionReview r, String label) {
        for (MessageReview.Row row : r.summary) if (row.label.equals(label)) return row.value;
        for (MessageReview.Row row : r.details) if (row.label.equals(label)) return row.value;
        return null;
    }

    static boolean has(TransactionReview r, String label, String fragment) {
        for (MessageReview.Row row : r.summary) if (row.label.equals(label) && row.value.contains(fragment)) return true;
        return false;
    }

    static String refused(String chain, String to, String value, String data) {
        try {
            Eip1559Request.parse(request(chain, to, value, data));
            fail("accepted " + data);
            return null;
        } catch (RequestRefusal expected) {
            return expected.getMessage();
        } catch (JSONException other) {
            throw new AssertionError("refused, but not as a RequestRefusal: " + other.getMessage());
        }
    }

    static byte[] cmds(int... c) {
        byte[] out = new byte[c.length];
        for (int i = 0; i < c.length; i++) out[i] = (byte) c[i];
        return out;
    }

    // ------------------------------------------------------------------ the headline example

    @Test public void usdcForEthReadsAsGiveGetRecipientExpiry() throws Exception {
        String data = Calldata.execute(cmds(0x00, 0x0c), Arrays.asList(
                Calldata.v3Swap(ADDRESS_THIS, BigInteger.valueOf(100).multiply(E6), new BigInteger("31200000000000000"),
                        Calldata.v3Path(USDC, 500, WETH), true),
                Calldata.unwrap(MSG_SENDER, new BigInteger("31200000000000000"))), BigInteger.valueOf(DEADLINE));
        TransactionReview r = review("0x1", UR_ETH, "0x0", data);
        assertEquals("You give 100 USDC · You get at least 0.0312 ETH · Recipient: this wallet ✓ · Expires 2026-10-11 14:32 UTC",
                value(r, "Summary"));
        assertEquals("Swap USDC → ETH", r.title);
        assertEquals("Swap on Uniswap (Universal Router 2.0)", value(r, "Action"));
        assertEquals("100 USDC", value(r, "You give"));
        assertEquals("0.0312 ETH", value(r, "You get at least"));
        assertEquals(SwapReview.THIS_WALLET, value(r, "Recipient"));
        assertTrue(value(r, "Expires").startsWith("2026-10-11 14:32:00 UTC"));
        assertTrue(value(r, "Paid through").contains("Permit2"));
        assertTrue(value(r, "Router").contains(UR_ETH));
        assertEquals(0, count(r, "DANGER"));
        assertEquals(0, count(r, "WARNING"));
        assertEquals("Approve swap & sign", r.signLabel);
        assertTrue(r.lockedSummary.startsWith("You give 100 USDC"));
        assertTrue(r.parties.isEmpty());
        // details: the steps, readable
        assertTrue(value(r, "Step 1").contains("USDC → WETH"));
        assertTrue(value(r, "Step 2").contains("Unwrap all of the router's WETH"));
    }

    static int count(TransactionReview r, String label) {
        int n = 0;
        for (MessageReview.Row row : r.summary) if (row.label.equals(label)) n++;
        return n;
    }

    @Test public void interfaceFeeIsShownAndAboveOnePercentWarned() throws Exception {
        BigInteger min = new BigInteger("31200000000000000");
        String data = Calldata.execute(cmds(0x00, 0x06, 0x0c), Arrays.asList(
                Calldata.v3Swap(ADDRESS_THIS, BigInteger.valueOf(100).multiply(E6), min, Calldata.v3Path(USDC, 500, WETH), true),
                Calldata.payPortion(WETH, FEE_COLLECTOR, 25),
                Calldata.unwrap(MSG_SENDER, BigInteger.ZERO)), BigInteger.valueOf(DEADLINE));
        TransactionReview r = review("0x1", UR_ETH, "0x0", data);
        assertTrue(value(r, "Fee").startsWith("Fee: 0.25% of the WETH output"));
        assertTrue(value(r, "Fee").contains(Keys.toChecksumAddress(FEE_COLLECTOR)));
        // what is left after the 0.25% portion is still a guaranteed minimum
        assertEquals("0.031122 ETH", value(r, "You get at least"));
        assertTrue(value(r, "Summary").contains("Recipient: this wallet ✓"));

        String high = Calldata.execute(cmds(0x00, 0x06, 0x0c), Arrays.asList(
                Calldata.v3Swap(ADDRESS_THIS, BigInteger.valueOf(100).multiply(E6), min, Calldata.v3Path(USDC, 500, WETH), true),
                Calldata.payPortion(WETH, FEE_COLLECTOR, 300),
                Calldata.unwrap(MSG_SENDER, BigInteger.ZERO)), BigInteger.valueOf(DEADLINE));
        TransactionReview three = review("0x1", UR_ETH, "0x0", high);
        assertTrue(has(three, "WARNING", "more than 1%"));
        assertEquals("exactly 3% is still a (high) fee", 0, count(three, "DANGER"));
        assertTrue(value(three, "Summary").contains("Recipient: this wallet ✓"));
    }

    @Test public void feeAboveThreePercentIsAnOtherAddressDanger() throws Exception {
        BigInteger min = new BigInteger("31200000000000000");
        for (int command : new int[] {0x06, 0x07}) {
            // PAY_PORTION in basis points; PAY_PORTION_FULL_PRECISION (2.1) in 1e18 units, same (address,address,uint256) layout
            byte[] fee = command == 0x06 ? Calldata.payPortion(WETH, FEE_COLLECTOR, 301)
                    : Calldata.transfer(WETH, FEE_COLLECTOR, new BigInteger("30100000000000000"));
            String data = Calldata.execute(cmds(0x00, command, 0x0c), Arrays.asList(
                    Calldata.v3Swap21(ADDRESS_THIS, BigInteger.valueOf(100).multiply(E6), min, Calldata.v3Path(USDC, 500, WETH), true),
                    fee, Calldata.unwrap(MSG_SENDER, BigInteger.ZERO)), BigInteger.valueOf(DEADLINE));
            TransactionReview r = review("0x1", UR21_ETH, "0x0", data);
            assertTrue(Integer.toHexString(command), value(r, "Summary").contains("Recipient: OTHER ADDRESS ✗"));
            assertTrue(has(r, "DANGER", "OTHER ADDRESS ✗ 3.01% of the WETH output"));
            assertTrue(has(r, "DANGER", "more than 3%"));
            assertNull("not shown as an ordinary fee", value(r, "Fee"));
            assertEquals("Swap to OTHER ADDRESS", r.title);
            assertEquals("Swap to other address & sign", r.signLabel);
            assertEquals(1, r.parties.size());
            assertEquals(FEE_COLLECTOR, r.parties.get(0).address);
        }
        // 100% (the decoder's upper bound) is the same DANGER, never a "Fee" row
        String all = Calldata.execute(cmds(0x00, 0x06), Arrays.asList(
                Calldata.v3Swap(ADDRESS_THIS, BigInteger.valueOf(100).multiply(E6), min, Calldata.v3Path(USDC, 500, WETH), true),
                Calldata.payPortion(WETH, FEE_COLLECTOR, 10_000)), BigInteger.valueOf(DEADLINE));
        assertTrue(has(review("0x1", UR_ETH, "0x0", all), "DANGER", "OTHER ADDRESS ✗ 100% of the WETH output"));
    }

    @Test public void feeToTheZeroAddressIsRefused() {
        BigInteger min = new BigInteger("31200000000000000");
        String data = Calldata.execute(cmds(0x00, 0x06, 0x0c), Arrays.asList(
                Calldata.v3Swap(ADDRESS_THIS, BigInteger.valueOf(100).multiply(E6), min, Calldata.v3Path(USDC, 500, WETH), true),
                Calldata.payPortion(WETH, ETH, 25),
                Calldata.unwrap(MSG_SENDER, BigInteger.ZERO)), BigInteger.valueOf(DEADLINE));
        String why = refused("0x1", UR_ETH, "0x0", data);
        assertTrue(why, why.startsWith(SwapPlan.CANNOT_EXPLAIN) && why.contains("a fee paid to the zero address"));
    }

    @Test public void outputToAnotherAddressIsDanger() throws Exception {
        String data = Calldata.execute(cmds(0x00), Collections.singletonList(
                Calldata.v3Swap(OTHER, BigInteger.valueOf(100).multiply(E6), E18, Calldata.v3Path(USDC, 500, WETH), true)),
                BigInteger.valueOf(DEADLINE));
        TransactionReview r = review("0x1", UR_ETH, "0x0", data);
        assertTrue(value(r, "Summary").contains("Recipient: OTHER ADDRESS ✗"));
        assertTrue(value(r, "DANGER").startsWith("OTHER ADDRESS ✗ at least 1 WETH goes to " + Keys.toChecksumAddress(OTHER)));
        assertEquals("Swap to OTHER ADDRESS", r.title);
        assertEquals("Swap to other address & sign", r.signLabel);
        assertEquals(1, r.parties.size());
        assertEquals(OTHER, r.parties.get(0).address);
        // a literal recipient that IS this wallet is "this wallet"
        String self = Calldata.execute(cmds(0x00), Collections.singletonList(
                Calldata.v3Swap(KEY.getAddress(), BigInteger.valueOf(100).multiply(E6), E18, Calldata.v3Path(USDC, 500, WETH), true)),
                BigInteger.valueOf(DEADLINE));
        assertTrue(value(review("0x1", UR_ETH, "0x0", self), "Summary").contains("Recipient: this wallet ✓"));
    }

    @Test public void ethInputIsWrappedAndAccounted() throws Exception {
        String data = Calldata.execute(cmds(0x0b, 0x00), Arrays.asList(
                Calldata.wrap(ADDRESS_THIS, CONTRACT_BALANCE),
                Calldata.v3Swap(MSG_SENDER, CONTRACT_BALANCE, BigInteger.valueOf(2500).multiply(E6), Calldata.v3Path(WETH, 500, USDC), false)),
                BigInteger.valueOf(DEADLINE));
        TransactionReview r = review("0x1", UR_ETH, "0xde0b6b3a7640000", data);
        assertEquals("You give 1 ETH · You get at least 2,500 USDC · Recipient: this wallet ✓ · Expires 2026-10-11 14:32 UTC", value(r, "Summary"));
        assertEquals("1 ETH (used by the swap)", value(r, "Native value sent"));
        assertNull("no Permit2 when only ETH is paid", value(r, "Paid through"));
    }

    @Test public void unusedNativeValueIsRefused() {
        String data = Calldata.execute(cmds(0x0b, 0x00), Arrays.asList(
                Calldata.wrap(ADDRESS_THIS, E18),
                Calldata.v3Swap(MSG_SENDER, E18, BigInteger.ONE, Calldata.v3Path(WETH, 500, USDC), false)),
                BigInteger.valueOf(DEADLINE));
        String why = refused("0x1", UR_ETH, "0x1bc16d674ec80000", data); // 2 ETH sent, 1 ETH used
        assertTrue(why.startsWith(SwapPlan.CANNOT_EXPLAIN));
        assertTrue(why.contains("does not use"));
        // and ETH sent along a token-only swap
        String tokenOnly = Calldata.execute(cmds(0x00), Collections.singletonList(
                Calldata.v3Swap(MSG_SENDER, E6, BigInteger.ONE, Calldata.v3Path(USDC, 500, WETH), true)), BigInteger.valueOf(DEADLINE));
        assertTrue(refused("0x1", UR_ETH, "0x1", tokenOnly).contains("does not use"));
    }

    @Test public void exactOutputWithEthRefundsTheRest() throws Exception {
        // wrap all, buy exactly 100 USDC for at most 0.05 WETH, return unused WETH as ETH
        String data = Calldata.execute(cmds(0x0b, 0x01, 0x0c), Arrays.asList(
                Calldata.wrap(ADDRESS_THIS, CONTRACT_BALANCE),
                Calldata.v3Swap(MSG_SENDER, BigInteger.valueOf(100).multiply(E6), new BigInteger("50000000000000000"),
                        Calldata.v3Path(USDC, 500, WETH), false), // exact-output paths are output-first
                Calldata.unwrap(MSG_SENDER, BigInteger.ZERO)), BigInteger.valueOf(DEADLINE));
        TransactionReview r = review("0x1", UR_ETH, "0xb1a2bc2ec50000", data);
        assertEquals("100 USDC", value(r, "You get exactly"));
        assertTrue(value(r, "Summary").startsWith("You give at most 0.05 ETH · You get 100 USDC · Recipient: this wallet ✓"));
        assertTrue(value(r, "Unused input").contains("ETH the swap does not need comes back"));
        assertEquals(0, count(r, "DANGER"));
    }

    @Test public void v2SwapAndPermit2Permit() throws Exception {
        String data = Calldata.execute(cmds(0x0a, 0x08), Arrays.asList(
                Calldata.permit2Permit(USDC, UniversalRouter.UINT160_MAX, UniversalRouter.UINT48_MAX.longValue(), 0, UR_ETH, DEADLINE),
                Calldata.v2Swap(MSG_SENDER, BigInteger.valueOf(50).multiply(E6), BigInteger.TEN.pow(16), Arrays.asList(USDC, WETH), true)),
                BigInteger.valueOf(DEADLINE));
        TransactionReview r = review("0x1", UR_ETH, "0x0", data);
        assertEquals("You give 50 USDC · You get at least 0.01 WETH · Recipient: this wallet ✓ · Expires 2026-10-11 14:32 UTC", value(r, "Summary"));
        assertTrue(has(r, "WARNING", "may spend UNLIMITED USDC from this wallet with NO expiry"));
        // a permit naming another spender is refused
        String evil = Calldata.execute(cmds(0x0a, 0x08), Arrays.asList(
                Calldata.permit2Permit(USDC, UniversalRouter.UINT160_MAX, 0, 0, OTHER, DEADLINE),
                Calldata.v2Swap(MSG_SENDER, BigInteger.valueOf(50).multiply(E6), BigInteger.ONE, Arrays.asList(USDC, WETH), true)),
                BigInteger.valueOf(DEADLINE));
        assertTrue(refused("0x1", UR_ETH, "0x0", evil).contains("spender other than this router"));
    }

    @Test public void unknownTokensAreRawWithAWarning() throws Exception {
        String data = Calldata.execute(cmds(0x00), Collections.singletonList(
                Calldata.v3Swap(MSG_SENDER, BigInteger.valueOf(100).multiply(E6), BigInteger.valueOf(123456789), Calldata.v3Path(USDC, 3000, UNKNOWN), true)),
                BigInteger.valueOf(DEADLINE));
        TransactionReview r = review("0x1", UR_ETH, "0x0", data);
        assertEquals("123,456,789 base units of unknown token " + UNKNOWN, value(r, "You get at least"));
        assertTrue(has(r, "WARNING", "Unknown token " + UNKNOWN));
        assertEquals("Swap USDC → 0x2222…2222", r.title);
    }

    @Test public void noMinimumIsDanger() throws Exception {
        String data = Calldata.execute(cmds(0x00), Collections.singletonList(
                Calldata.v3Swap(MSG_SENDER, BigInteger.valueOf(100).multiply(E6), BigInteger.ZERO, Calldata.v3Path(USDC, 500, WETH), true)),
                BigInteger.valueOf(DEADLINE));
        assertTrue(has(review("0x1", UR_ETH, "0x0", data), "DANGER", "No minimum"));
    }

    @Test public void executeWithoutDeadlineWarns() throws Exception {
        String data = Calldata.execute(cmds(0x00), Collections.singletonList(
                Calldata.v3Swap(MSG_SENDER, E6, BigInteger.ONE, Calldata.v3Path(USDC, 500, WETH), true)), null);
        TransactionReview r = review("0x1", UR_ETH, "0x0", data);
        assertTrue(value(r, "Summary").endsWith("· No deadline"));
        assertTrue(has(r, "WARNING", "No deadline"));
    }

    // ------------------------------------------------------------------ V4

    @Test public void v4EthForUsdcSingleHop() throws Exception {
        BigInteger in = new BigInteger("500000000000000000");
        byte[] v4 = Calldata.v4(cmds(0x06, 0x0c, 0x0f),
                Calldata.v4ExactInSingle(Calldata.poolKey(ETH, USDC, 500, 10, ETH), true, in, BigInteger.valueOf(1200).multiply(E6)),
                Calldata.currencyAmount(ETH, in),
                Calldata.currencyAmount(USDC, BigInteger.ZERO));
        TransactionReview r = review("0x1", UR_ETH, "0x6f05b59d3b20000", Calldata.execute(cmds(0x10), Collections.singletonList(v4), BigInteger.valueOf(DEADLINE)));
        assertEquals("You give 0.5 ETH · You get at least 1,200 USDC · Recipient: this wallet ✓ · Expires 2026-10-11 14:32 UTC", value(r, "Summary"));
        assertEquals(0, count(r, "WARNING"));

        // the same on a 2.1 router with the 2.1 struct (minHopPriceX36)
        byte[] v421 = Calldata.v4(cmds(0x06, 0x0c, 0x0f),
                Calldata.v4ExactInSingle21(Calldata.poolKey(ETH, USDC, 500, 10, ETH), true, in, BigInteger.valueOf(1200).multiply(E6)),
                Calldata.currencyAmount(ETH, in),
                Calldata.currencyAmount(USDC, BigInteger.ZERO));
        TransactionReview r21 = review("0x1", UR21_ETH, "0x6f05b59d3b20000", Calldata.execute(cmds(0x10), Collections.singletonList(v421), BigInteger.valueOf(DEADLINE)));
        assertEquals(value(r, "Summary"), value(r21, "Summary"));
        // a 2.0-shaped struct sent to a 2.1 router is not what that router reads: refused
        assertTrue(refused("0x1", UR21_ETH, "0x6f05b59d3b20000", Calldata.execute(cmds(0x10), Collections.singletonList(v4), BigInteger.valueOf(DEADLINE)))
                .startsWith(SwapPlan.CANNOT_EXPLAIN));
    }

    @Test public void v4HookIsWarnedAndUnsupportedActionsRefused() throws Exception {
        BigInteger in = BigInteger.valueOf(100).multiply(E6);
        String hook = "0x0000000000000000000000000000000000004444";
        byte[] hooked = Calldata.v4(cmds(0x06, 0x0c, 0x0f),
                Calldata.v4ExactInSingle(Calldata.poolKey(ETH, USDC, 500, 10, hook), false, in, BigInteger.ONE),
                Calldata.currencyAmount(USDC, in),
                Calldata.currencyAmount(ETH, BigInteger.ZERO));
        TransactionReview r = review("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x10), Collections.singletonList(hooked), BigInteger.valueOf(DEADLINE)));
        assertTrue(has(r, "WARNING", "hook " + Keys.toChecksumAddress(hook)));
        assertEquals("100 USDC", value(r, "You give"));

        for (int action : new int[] {0x00, 0x02, 0x0a, 0x0d, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x19}) {
            byte[] bad = Calldata.v4(cmds(0x06, action, 0x0c, 0x0f),
                    Calldata.v4ExactInSingle(Calldata.poolKey(ETH, USDC, 500, 10, ETH), false, in, BigInteger.ONE),
                    Calldata.currencyAmount(USDC, in), Calldata.currencyAmount(USDC, in), Calldata.currencyAmount(ETH, BigInteger.ZERO));
            String why = refused("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x10), Collections.singletonList(bad), BigInteger.valueOf(DEADLINE)));
            assertTrue(action + ": " + why, why.startsWith(SwapPlan.CANNOT_EXPLAIN));
        }
        // a swap whose output is never taken leaves value in the pool manager: refused
        byte[] untaken = Calldata.v4(cmds(0x06, 0x0c),
                Calldata.v4ExactInSingle(Calldata.poolKey(ETH, USDC, 500, 10, ETH), false, in, BigInteger.ONE),
                Calldata.currencyAmount(USDC, in));
        assertTrue(refused("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x10), Collections.singletonList(untaken), BigInteger.valueOf(DEADLINE)))
                .contains("untaken"));
    }

    // ------------------------------------------------------------------ refusals

    @Test public void unsupportedCommandsFlagsAndRoutersAreRefused() {
        byte[] swap = Calldata.v3Swap(MSG_SENDER, E6, BigInteger.ONE, Calldata.v3Path(USDC, 500, WETH), true);
        for (int c : new int[] {0x03, 0x07, 0x0d, 0x0e, 0x11, 0x12, 0x13, 0x14, 0x21, 0x40, 0x3f}) {
            String data = Calldata.execute(cmds(c, 0x00), Arrays.asList(swap, swap), BigInteger.valueOf(DEADLINE));
            String why = refused("0x1", UR_ETH, "0x0", data);
            assertTrue(Integer.toHexString(c) + ": " + why, why.startsWith(SwapPlan.CANNOT_EXPLAIN));
        }
        // allow-revert flag on an otherwise fine swap; the 0x40 bit that 2.0's 0x3f mask ignores
        assertTrue(refused("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x80), Collections.singletonList(swap), BigInteger.valueOf(DEADLINE))).contains("allow-revert"));
        assertTrue(refused("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x40), Collections.singletonList(swap), BigInteger.valueOf(DEADLINE))).startsWith(SwapPlan.CANNOT_EXPLAIN));
        // the same calldata to a contract that is not a pinned router: an unknown contract call
        String ok = Calldata.execute(cmds(0x00), Collections.singletonList(swap), BigInteger.valueOf(DEADLINE));
        assertTrue(refused("0x1", UNKNOWN, "0x0", ok).contains("can't be explained"));
        // a pinned router address on a chain where it is not pinned (UR 2.0 Ethereum address on Polygon)
        assertTrue(refused("0x89", UR_ETH, "0x0", ok).contains("can't be explained"));
        // Sepolia's 2.0 router is deliberately not pinned
        assertNull(UniswapRouters.lookup(11155111, "0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b"));
    }

    @Test public void nonCanonicalInputsAreRefused() {
        String ok = Calldata.execute(cmds(0x00), Collections.singletonList(
                Calldata.v3Swap(MSG_SENDER, E6, BigInteger.ONE, Calldata.v3Path(USDC, 500, WETH), true)), BigInteger.valueOf(DEADLINE));
        assertNotNull(parseOk(ok));
        // dirty padding on the recipient word inside the command input
        byte[] dirty = Calldata.v3Swap(MSG_SENDER, E6, BigInteger.ONE, Calldata.v3Path(USDC, 500, WETH), true);
        dirty[0] = 1;
        assertTrue(refused("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x00), Collections.singletonList(dirty), BigInteger.valueOf(DEADLINE)))
                .contains("not canonically encoded"));
        // bool that is 2
        byte[] two = Calldata.v3Swap(MSG_SENDER, E6, BigInteger.ONE, Calldata.v3Path(USDC, 500, WETH), true);
        two[32 * 4 + 31] = 2;
        assertTrue(refused("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x00), Collections.singletonList(two), BigInteger.valueOf(DEADLINE)))
                .startsWith(SwapPlan.CANNOT_EXPLAIN));
        // trailing bytes inside a command input (the router would ignore them; the phone refuses)
        byte[] plain = Calldata.v3Swap(MSG_SENDER, E6, BigInteger.ONE, Calldata.v3Path(USDC, 500, WETH), true);
        byte[] longer = Arrays.copyOf(plain, plain.length + 32);
        assertTrue(refused("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x00), Collections.singletonList(longer), BigInteger.valueOf(DEADLINE)))
                .startsWith(SwapPlan.CANNOT_EXPLAIN));
        // more than 64 bytes appended to execute(): refused; up to 64 shown as extra data
        StringBuilder pad = new StringBuilder();
        for (int i = 0; i < 65; i++) pad.append("ab");
        assertTrue(refused("0x1", UR_ETH, "0x0", ok + pad).startsWith(SwapPlan.CANNOT_EXPLAIN));
        // malformed v3 path
        byte[] badPath = Calldata.v3Swap(MSG_SENDER, E6, BigInteger.ONE, Arrays.copyOf(Calldata.v3Path(USDC, 500, WETH), 42), true);
        assertTrue(refused("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x00), Collections.singletonList(badPath), BigInteger.valueOf(DEADLINE)))
                .contains("malformed v3 path"));
        // commands and inputs differ in number
        assertTrue(refused("0x1", UR_ETH, "0x0", Calldata.execute(cmds(0x00, 0x00), Collections.singletonList(dirty), BigInteger.valueOf(DEADLINE)))
                .startsWith(SwapPlan.CANNOT_EXPLAIN));
    }

    private static Eip1559Request parseOk(String data) {
        try {
            return Eip1559Request.parse(request("0x1", UR_ETH, "0x0", data));
        } catch (JSONException e) {
            throw new AssertionError(e.getMessage());
        }
    }

    // ------------------------------------------------------------------ SwapRouter02

    @Test public void swapRouter02EthForUsdcWithRefund() throws Exception {
        String data = Calldata.multicall(BigInteger.valueOf(DEADLINE),
                Calldata.exactInputSingle(WETH, USDC, 500, MSG_SENDER, E18, BigInteger.valueOf(2400).multiply(E6)),
                "0x12210e8a");
        TransactionReview r = review("0x1", SR02_ETH, "0xde0b6b3a7640000", data);
        assertEquals("You give 1 ETH · You get at least 2,400 USDC · Recipient: this wallet ✓ · Expires 2026-10-11 14:32 UTC", value(r, "Summary"));
        assertEquals("Swap on Uniswap (SwapRouter02)", value(r, "Action"));
        // an unsupported inner call is refused
        String bad = Calldata.multicall(BigInteger.valueOf(DEADLINE),
                Calldata.exactInputSingle(WETH, USDC, 500, MSG_SENDER, E18, BigInteger.ONE), "0x472b43f3");
        assertTrue(refused("0x1", SR02_ETH, "0xde0b6b3a7640000", bad).startsWith(SwapPlan.CANNOT_EXPLAIN));
    }

    // ------------------------------------------------------------------ real transactions

    /** Expected outcome per real transaction: a summary fragment, or "REFUSED:" + reason fragment. */
    private static final Map<String, String[]> EXPECT = new HashMap<>();

    static {
        EXPECT.put("0xdc99815e", new String[] {"You give 43.01961 USDT", "Recipient: this wallet ✓", "Expires 2026-10-12 02:09 UTC"});
        EXPECT.put("0x7fee711e", new String[] {"You get at least 1,191.917451 USDT", "Recipient: this wallet ✓"});
        EXPECT.put("0xd14b8860", new String[] {"REFUSED:WRAP_ETH to another address"});
        EXPECT.put("0x65b058dd", new String[] {"You get at least 227.107032 USDC", "Recipient: this wallet ✓"});
        EXPECT.put("0x5e6b73ce", new String[] {"You give 0.041691939906325635 ETH", "Recipient: this wallet ✓"});
        EXPECT.put("0xc13029f4", new String[] {"You get at least 85.517548 USDC", "Expires 2026-10-12 02:26 UTC"});
        EXPECT.put("0x29638840", new String[] {"Recipient: this wallet ✓"});
        EXPECT.put("0x1e989ed5", new String[] {"You get at least 100.280419 USDT"});
        EXPECT.put("0x4d2a784f", new String[] {"You get at least 0 ETH", "No deadline"});
        EXPECT.put("0xbb1be55f", new String[] {"You give at most 1,533.18333 USDT", "Recipient: OTHER ADDRESS ✗"});
        EXPECT.put("0xf27a541d", new String[] {"You give 122.198333 USDC"});
        EXPECT.put("0xc109dc1d", new String[] {"You give 0.0785 ETH", "Recipient: this wallet ✓"});
        EXPECT.put("0x6e776a4a", new String[] {"You give 0.183594372651034427 ETH"});
        EXPECT.put("0x8b618e06", new String[] {"You give 0.1 ETH", "Recipient: this wallet ✓"});
        EXPECT.put("0x8a1923bb", new String[] {"You give 0.15 WETH"});
        EXPECT.put("0x5191f1a1", new String[] {"You give 0.007613378178552002 ETH"});
        EXPECT.put("0x3cb4537e", new String[] {"You give 0.008716207907100552 ETH"});
        EXPECT.put("0xebcf8fa1", new String[] {"REFUSED:price-limited"});
        EXPECT.put("0x1be390ad", new String[] {"You give 13.75 ETH", "Recipient: this wallet ✓"});
        EXPECT.put("0x8a504950", new String[] {"You give 107.03395 USDC · You get at least 106.980433 USDC"});
        EXPECT.put("0x35b206bf", new String[] {"You give 20.501299 USDC · You get at least 0.007861969515657016 ETH"});
        EXPECT.put("0x7baf23f1", new String[] {"You get at least 0.975783 USDC"});
        EXPECT.put("0x15d8cf08", new String[] {"You give 0.001969116378716215 ETH"});
    }

    /** The real on-chain transactions of swap-vectors.json (synthetic entries excluded). */
    static JSONArray vectors() throws Exception { return vectors(false); }

    /** The hand-built entries of swap-vectors.json ("tx": "synthetic-…"). */
    static JSONArray syntheticVectors() throws Exception { return vectors(true); }

    private static JSONArray vectors(boolean synthetic) throws Exception {
        File f = new File("src/test/resources/swap-vectors.json");
        if (!f.isFile()) f = new File("app/src/test/resources/swap-vectors.json");
        JSONArray all = new JSONObject(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8)).getJSONArray("vectors");
        JSONArray out = new JSONArray();
        for (int i = 0; i < all.length(); i++) {
            JSONObject v = all.getJSONObject(i);
            boolean s = v.getString("tx").startsWith("synthetic-");
            assertEquals(v.getString("tx"), s, v.has("synthetic"));
            if (s == synthetic) out.put(v);
        }
        return out;
    }

    static JSONObject synthetic(String name) throws Exception {
        JSONArray vs = syntheticVectors();
        for (int i = 0; i < vs.length(); i++) if (vs.getJSONObject(i).getString("tx").equals("synthetic-" + name)) return vs.getJSONObject(i);
        throw new AssertionError("no synthetic vector " + name);
    }

    static final String DAI = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
    static final BigInteger HALF_ETH = new BigInteger("500000000000000000");

    /** The synthetic vectors' calldata, re-encoded here with web3j: the JSON (independent Python encoder) must match. */
    @Test public void syntheticVectorsMatchAnIndependentEncoder() throws Exception {
        BigInteger dl = BigInteger.valueOf(DEADLINE);
        BigInteger m = BigInteger.valueOf(1200).multiply(E18);
        Map<String, String> expect = new HashMap<>();
        expect.put("sr02-zero-min-weth-unwrapped-as-refund", Calldata.multicall(dl,
                Calldata.exactInputSingle(WETH, DAI, 500, MSG_SENDER, HALF_ETH, m),
                Calldata.exactInputSingle(USDC, WETH, 500, ADDRESS_THIS, BigInteger.valueOf(1000).multiply(E6), BigInteger.ZERO),
                "0x49616997" + Numeric.toHexStringNoPrefixZeroPadded(BigInteger.ZERO, 64)));
        byte[] swapIn = Calldata.v3Swap(MSG_SENDER, HALF_ETH, m, Calldata.v3Path(WETH, 500, DAI), false);
        byte[] hidden = Calldata.v3Swap(ADDRESS_THIS, BigInteger.valueOf(1000).multiply(E6), BigInteger.ZERO, Calldata.v3Path(USDC, 500, WETH), true);
        expect.put("ur-zero-min-weth-unwrapped-as-refund", Calldata.execute(cmds(0x0b, 0x00, 0x00, 0x0c), Arrays.asList(
                Calldata.wrap(ADDRESS_THIS, HALF_ETH), swapIn, hidden, Calldata.unwrap(MSG_SENDER, BigInteger.ZERO)), dl));
        expect.put("ur-zero-min-weth-swept-as-refund", Calldata.execute(cmds(0x0b, 0x00, 0x00, 0x04), Arrays.asList(
                Calldata.wrap(ADDRESS_THIS, HALF_ETH), swapIn, hidden, Calldata.sweep(WETH, MSG_SENDER, BigInteger.ZERO)), dl));
        byte[] usdcForWeth = Calldata.v3Swap(ADDRESS_THIS, BigInteger.valueOf(100).multiply(E6), new BigInteger("31200000000000000"),
                Calldata.v3Path(USDC, 500, WETH), true);
        expect.put("ur-five-percent-fee", Calldata.execute(cmds(0x00, 0x06, 0x0c), Arrays.asList(usdcForWeth,
                Calldata.payPortion(WETH, FEE_COLLECTOR, 500), Calldata.unwrap(MSG_SENDER, new BigInteger("29600000000000000"))), dl));
        expect.put("ur-fee-to-zero-address", Calldata.execute(cmds(0x00, 0x06, 0x0c), Arrays.asList(usdcForWeth,
                Calldata.payPortion(WETH, ETH, 25), Calldata.unwrap(MSG_SENDER, BigInteger.ZERO)), dl));
        JSONArray vs = syntheticVectors();
        assertEquals(expect.size(), vs.length());
        for (int i = 0; i < vs.length(); i++) {
            JSONObject v = vs.getJSONObject(i);
            String data = expect.get(v.getString("tx").substring("synthetic-".length()));
            assertNotNull(v.getString("tx"), data);
            assertEquals(v.getString("tx"), data.toLowerCase(), v.getString("data"));
        }
    }

    /**
     * The zero-minimum output of a swap, paid out in a coin this wallet also gave (ETH ≡ WETH),
     * must never pass for "unused input": SwapRouter02 and Universal Router (unwrap and sweep).
     */
    @Test public void zeroMinimumOutputIsNeverShownAsARefund() throws Exception {
        for (String name : new String[] {"sr02-zero-min-weth-unwrapped-as-refund", "ur-zero-min-weth-unwrapped-as-refund",
                "ur-zero-min-weth-swept-as-refund"}) {
            JSONObject v = synthetic(name);
            TransactionReview r = TransactionReview.build(Eip1559Request.parse(request(v.getString("chainId"), v.getString("to"),
                    v.getString("value"), v.getString("data"))), v.getString("from"), TokenListTest.bundled());
            assertNull(name, value(r, "Unused input"));
            assertTrue(name + ": " + r.text(), has(r, "DANGER", "No minimum"));
            assertTrue(name, has(r, "You get at least", name.contains("swept") ? "0 WETH" : "0 ETH"));
            assertTrue(name, has(r, "You get at least", "1,200 DAI"));
            assertTrue(name + ": " + value(r, "Summary"), value(r, "Summary").contains("You give 0.5 ETH + 1,000 USDC"));
        }
        // the honest exact-output refund (only the unused part of the ETH sent) is still a refund
        String honest = Calldata.execute(cmds(0x0b, 0x01, 0x0c), Arrays.asList(
                Calldata.wrap(ADDRESS_THIS, CONTRACT_BALANCE),
                Calldata.v3Swap(MSG_SENDER, BigInteger.valueOf(100).multiply(E6), new BigInteger("50000000000000000"),
                        Calldata.v3Path(USDC, 500, WETH), false),
                Calldata.unwrap(MSG_SENDER, BigInteger.ZERO)), BigInteger.valueOf(DEADLINE));
        TransactionReview ok = review("0x1", UR_ETH, "0xb1a2bc2ec50000", honest);
        assertNotNull(value(ok, "Unused input"));
        assertEquals(0, count(ok, "DANGER"));
        // ... but mixing a zero-minimum swap output into that refund makes the whole payout a DANGER
        String mixed = Calldata.execute(cmds(0x0b, 0x01, 0x00, 0x0c), Arrays.asList(
                Calldata.wrap(ADDRESS_THIS, CONTRACT_BALANCE),
                Calldata.v3Swap(MSG_SENDER, BigInteger.valueOf(100).multiply(E6), new BigInteger("50000000000000000"),
                        Calldata.v3Path(USDC, 500, WETH), false),
                Calldata.v3Swap(ADDRESS_THIS, BigInteger.valueOf(1000).multiply(E6), BigInteger.ZERO, Calldata.v3Path(USDC, 500, WETH), true),
                Calldata.unwrap(MSG_SENDER, BigInteger.ZERO)), BigInteger.valueOf(DEADLINE));
        TransactionReview bad = review("0x1", UR_ETH, "0xb1a2bc2ec50000", mixed);
        assertNull(value(bad, "Unused input"));
        assertTrue(has(bad, "DANGER", "No minimum"));
        // SwapRouter02's own exact-output + refundETH stays a refund
        String sr02 = Calldata.multicall(BigInteger.valueOf(DEADLINE),
                Calldata.call("5023b4df", new org.web3j.abi.datatypes.StaticStruct(Calldata.a(WETH), Calldata.a(USDC),
                        new org.web3j.abi.datatypes.generated.Uint24(BigInteger.valueOf(500)), Calldata.a(MSG_SENDER),
                        Calldata.u(BigInteger.valueOf(100).multiply(E6)), Calldata.u(new BigInteger("50000000000000000")),
                        new org.web3j.abi.datatypes.generated.Uint160(BigInteger.ZERO))),
                "0x12210e8a");
        TransactionReview sr = review("0x1", SR02_ETH, "0xb1a2bc2ec50000", sr02);
        assertNotNull(sr.text(), value(sr, "Unused input"));
        assertEquals(0, count(sr, "DANGER"));
    }

    @Test public void syntheticFeeVectors() throws Exception {
        JSONObject five = synthetic("ur-five-percent-fee");
        TransactionReview r = TransactionReview.build(Eip1559Request.parse(request(five.getString("chainId"), five.getString("to"),
                five.getString("value"), five.getString("data"))), five.getString("from"), TokenListTest.bundled());
        assertTrue(value(r, "Summary").contains("Recipient: OTHER ADDRESS ✗"));
        assertTrue(has(r, "DANGER", "OTHER ADDRESS ✗ 5% of the WETH output"));
        JSONObject zero = synthetic("ur-fee-to-zero-address");
        assertTrue(refused(zero.getString("chainId"), zero.getString("to"), zero.getString("value"), zero.getString("data"))
                .contains("a fee paid to the zero address"));
    }

    @Test public void v4TakePortionAboveThreePercentAndToZeroAddress() throws Exception {
        BigInteger in = new BigInteger("500000000000000000");
        for (String to : new String[] {FEE_COLLECTOR, ETH}) {
            byte[] v4 = Calldata.v4(cmds(0x06, 0x0c, 0x10, 0x0f),
                    Calldata.v4ExactInSingle(Calldata.poolKey(ETH, USDC, 500, 10, ETH), true, in, BigInteger.valueOf(1200).multiply(E6)),
                    Calldata.currencyAmount(ETH, in),
                    Calldata.take(USDC, to, BigInteger.valueOf(400)),
                    Calldata.currencyAmount(USDC, BigInteger.ZERO));
            String data = Calldata.execute(cmds(0x10), Collections.singletonList(v4), BigInteger.valueOf(DEADLINE));
            if (to.equals(ETH)) {
                assertTrue(refused("0x1", UR_ETH, "0x6f05b59d3b20000", data).contains("a fee paid to the zero address"));
            } else {
                TransactionReview r = review("0x1", UR_ETH, "0x6f05b59d3b20000", data);
                assertTrue(has(r, "DANGER", "OTHER ADDRESS ✗ 4% of the USDC output"));
                assertTrue(value(r, "Summary").contains("Recipient: OTHER ADDRESS ✗"));
            }
        }
    }

    @Test public void realRouterTransactionsDecodeAsExpected() throws Exception {
        JSONArray vs = vectors();
        assertEquals(EXPECT.size(), vs.length());
        int accepted = 0;
        for (int i = 0; i < vs.length(); i++) {
            JSONObject v = vs.getJSONObject(i);
            String[] expect = EXPECT.get(v.getString("tx").substring(0, 10));
            assertNotNull("no expectation for " + v.getString("tx"), expect);
            assertTrue(v.getString("explorer").endsWith(v.getString("tx")));
            JSONObject req = request(v.getString("chainId"), v.getString("to"), v.getString("value"), v.getString("data"));
            if (expect[0].startsWith("REFUSED:")) {
                try {
                    Eip1559Request.parse(req);
                    fail(v.getString("tx") + " was accepted");
                } catch (RequestRefusal e) {
                    assertTrue(v.getString("tx") + ": " + e.getMessage(), e.getMessage().startsWith(SwapPlan.CANNOT_EXPLAIN));
                    assertTrue(v.getString("tx") + ": " + e.getMessage(), e.getMessage().contains(expect[0].substring(8)));
                }
                continue;
            }
            Eip1559Request r = Eip1559Request.parse(req);
            assertEquals(Eip1559Request.Kind.SWAP, r.kind);
            // reviewed as the wallet that actually sent it (recipient checks are relative to the signer)
            TransactionReview review = TransactionReview.build(r, v.getString("from"), TokenListTest.bundled());
            String summary = value(review, "Summary");
            for (String fragment : expect) assertTrue(v.getString("tx") + ": " + summary, summary.contains(fragment));
            accepted++;
        }
        assertEquals(21, accepted);
    }

    @Test public void realTransactionsCarryTheirTagAndHooksAndNoMinimumVisibly() throws Exception {
        JSONArray vs = vectors();
        for (int i = 0; i < vs.length(); i++) {
            JSONObject v = vs.getJSONObject(i);
            String tx = v.getString("tx");
            if (!tx.startsWith("0xc109dc1d") && !tx.startsWith("0x4d2a784f") && !tx.startsWith("0x15d8cf08")) continue;
            TransactionReview r = TransactionReview.build(Eip1559Request.parse(request(v.getString("chainId"), v.getString("to"),
                    v.getString("value"), v.getString("data"))), v.getString("from"), TokenListTest.bundled());
            if (tx.startsWith("0xc109dc1d")) {
                assertTrue(value(r, "Extra data").startsWith("22 bytes are appended"));
                assertTrue(value(r, "Appended bytes (ignored by the router)").startsWith("0x756e6978")); // "unix"
            } else if (tx.startsWith("0x4d2a784f")) {
                assertTrue(has(r, "DANGER", "No minimum"));
            } else {
                assertTrue(has(r, "WARNING", "hook 0xBDF938149ac6a781F94FAa0ed45E6A0e984c6544"));
            }
        }
    }

    @Test public void signedSwapCarriesExactlyTheReviewedCall() throws Exception {
        JSONArray vs = vectors();
        int signed = 0;
        for (int i = 0; i < vs.length(); i++) {
            JSONObject v = vs.getJSONObject(i);
            Eip1559Request r;
            try {
                r = Eip1559Request.parse(request(v.getString("chainId"), v.getString("to"), v.getString("value"), v.getString("data")));
            } catch (RequestRefusal refused) {
                continue;
            }
            ApprovalSession session = new ApprovalSession(r, KEY, TokenListTest.bundled());
            RawTransaction decoded = TransactionDecoder.decode(session.signIfIdentityUnchanged(KEY).getString("signedTransaction"));
            assertEquals(v.getString("to").toLowerCase(), decoded.getTo());
            assertEquals(Numeric.toBigInt(v.getString("value")), decoded.getValue());
            assertEquals(Numeric.cleanHexPrefix(v.getString("data")).toLowerCase(), Numeric.cleanHexPrefix(decoded.getData()).toLowerCase());
            // and the review was decoded from that same data
            assertEquals(SwapDecoder.decode(r.swap.router, "0x" + Numeric.cleanHexPrefix(decoded.getData()), decoded.getValue()).gives.size(),
                    r.swap.gives.size());
            signed++;
        }
        assertEquals(21, signed);
    }

    @Test public void routerPinsAreChecksummedAndOnAllowListedChains() {
        for (String[] e : UniswapRouters.ENTRIES) {
            assertEquals(e[1], Keys.toChecksumAddress(e[1]));
            assertTrue(Eip1559Request.supportedChain(Long.parseLong(e[0])));
            assertNotNull(UniswapRouters.lookup(Long.parseLong(e[0]), e[1].toLowerCase()));
        }
        for (long chain : new long[] {1, 10, 137, 8453, 42161, 11155111}) {
            String w = UniswapRouters.wrappedNative(chain);
            assertEquals(w, Keys.toChecksumAddress(w));
        }
        // where the token list has the wrapped native token, it is the same contract
        try {
            TokenList list = TokenListTest.bundled();
            for (long chain : new long[] {1, 10, 8453, 42161, 11155111}) {
                assertEquals("WETH", list.lookup(chain, UniswapRouters.wrappedNative(chain)).symbol);
            }
            assertNull("WPOL is not in the token list; the router pin names it", list.lookup(137, UniswapRouters.WPOL_137));
        } catch (Exception ex) {
            throw new AssertionError(ex);
        }
        assertFalse(UniswapRouters.isRouterOnAnyChain(UNKNOWN));
    }
}
