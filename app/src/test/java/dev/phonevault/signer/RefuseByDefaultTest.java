package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONException;
import org.junit.Test;

/**
 * Non-empty calldata the phone cannot fully decode is refused — never shown raw for a blind
 * approval — with a reason the phone also shows on screen. Plain native transfers stay allowed.
 */
public final class RefuseByDefaultTest {
    private static final String CONTRACT = "0x2222222222222222222222222222222222222222";
    private static final String USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

    private static RequestRefusal refusal(String to, String value, String data) {
        try {
            Eip1559Request.parse(SwapReviewTest.request("0x1", to, value, data));
            fail("accepted " + data);
            return null;
        } catch (RequestRefusal r) {
            return r;
        } catch (JSONException other) {
            throw new AssertionError("not a RequestRefusal: " + other.getMessage());
        }
    }

    @Test public void unknownSelectorsAreRefusedWithAReason() {
        String[] calls = {
                "0xdeadbeef",                                                           // selector only
                "0x" + "d0e30db0",                                                       // WETH deposit()
                "0x" + "2e1a7d4d" + "0000000000000000000000000000000000000000000000000de0b6b3a7640000", // withdraw(uint256)
                "0x" + "ac9650d8" + "00".repeat(64),                                     // multicall(bytes[]) to a non-router
                "0x" + "1249c58b",                                                       // mint()
        };
        for (String data : calls) {
            RequestRefusal r = refusal(CONTRACT, "0x0", data);
            assertEquals(RequestRefusal.UNKNOWN_CALL_TITLE, r.title);
            assertTrue(r.getMessage(), r.getMessage().startsWith("This contract call can't be explained by the phone, so it was refused and nothing was signed"));
            assertTrue(r.getMessage().contains("selector 0x" + data.substring(2, 10)));
            assertTrue(r.getMessage().contains(CONTRACT));
        }
        // with native value too (e.g. a payable mint): still refused, not reviewed raw
        assertEquals(RequestRefusal.UNKNOWN_CALL_TITLE, refusal(CONTRACT, "0xde0b6b3a7640000", "0x1249c58b").title);
    }

    @Test public void plainNativeTransfersToContractsStayAllowedWithAWarning() throws Exception {
        TransactionReview usdc = SwapReviewTest.review("0x1", USDC, "0xde0b6b3a7640000", "0x");
        assertTrue(SwapReviewTest.has(usdc, "WARNING", "This address is the USDC token contract"));
        TransactionReview router = SwapReviewTest.review("0x1", SwapReviewTest.UR_ETH, "0x1", "0x");
        assertTrue(SwapReviewTest.has(router, "WARNING", "a Uniswap router contract"));
        TransactionReview plain = SwapReviewTest.review("0x1", CONTRACT, "0x1", "0x");
        assertEquals("The offline phone can't tell whether this address is a wallet or a contract.", SwapReviewTest.value(plain, "Contract check"));
    }
}
