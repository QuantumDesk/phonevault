package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.math.BigDecimal;
import java.math.BigInteger;

/** The one amount formatter: exact, never rounded, zero always "0". */
public final class UnitsTest {
    private static final BigInteger ETH = BigInteger.TEN.pow(18);

    @Test public void zeroIsZeroAtEveryScale() {
        for (int decimals : new int[] {0, 6, 9, 18}) {
            assertEquals("0", Units.format(BigInteger.ZERO, decimals, false));
            assertEquals("0", Units.format(BigInteger.ZERO, decimals, true));
        }
    }

    @Test public void ungroupedEtherAmounts() {
        assertEquals("0.000000000000000001", Units.format(BigInteger.ONE, 18, false));
        assertEquals("1", Units.format(ETH, 18, false));
        assertEquals("1.5", Units.format(ETH.multiply(BigInteger.valueOf(3)).shiftRight(1), 18, false));
        assertEquals("123456789.000000000000000005",
                Units.format(ETH.multiply(BigInteger.valueOf(123_456_789)).add(BigInteger.valueOf(5)), 18, false));
        assertEquals("115792089237316195423570985008687907853269984665640564039457.584007913129639935",
                Units.format(BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE), 18, false));
        assertEquals("2", Units.format(BigInteger.valueOf(2_000_000_000), 9, false));
        assertEquals("0.000000001", Units.format(BigInteger.ONE, 9, false));
    }

    @Test public void groupedSplitsTheWholePartOnly() {
        assertEquals("123,456,789.000000000000000005",
                Units.format(ETH.multiply(BigInteger.valueOf(123_456_789)).add(BigInteger.valueOf(5)), 18, true));
        assertEquals("1,000", Units.format(BigInteger.valueOf(1000), 0, true));
        assertEquals("999", Units.format(BigInteger.valueOf(999), 0, true));
    }

    /** Non-zero values: byte for byte what the screens printed before (movePointLeft/strip/plain). */
    @Test public void ungroupedMatchesThePreviousFormattingForNonZero() {
        BigInteger[] values = {BigInteger.ONE, BigInteger.TEN, ETH, ETH.subtract(BigInteger.ONE), ETH.multiply(BigInteger.valueOf(1000)),
                new BigInteger("42000000000000"), new BigInteger("1234567890123456789012345"), BigInteger.ONE.shiftLeft(255)};
        for (BigInteger v : values) {
            for (int decimals : new int[] {9, 18}) {
                assertEquals(new BigDecimal(v).movePointLeft(decimals).stripTrailingZeros().toPlainString(),
                        Units.format(v, decimals, false));
            }
        }
    }

    @Test public void refusesNegatives() {
        try { Units.format(BigInteger.ONE.negate(), 18, false); fail("negative amount"); } catch (IllegalArgumentException expected) { }
        try { Units.format(BigInteger.ONE, -1, false); fail("negative decimals"); } catch (IllegalArgumentException expected) { }
    }

    /** The transaction review's own labels for a zero value and a zero priority fee. */
    @Test public void zeroValueAndZeroTipOnTheReview() throws Exception {
        Eip1559Request r = Eip1559Request.parse(SwapReviewTest.request("0x1", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "0x0", "0x")
                .put("maxPriorityFeePerGas", "0x0"));
        assertEquals("0 ETH", r.valueEth());
        assertEquals("0 gwei (0 wei, 0x0)", r.maxPriorityFeePerGasLabel());
        assertEquals("up to 0.0006 ETH", r.maximumFeeEth());
    }
}
