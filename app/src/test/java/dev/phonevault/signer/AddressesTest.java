package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.regex.Matcher;

/** The one EVM address check, and the short form every screen shows. */
public final class AddressesTest {
    private static final String USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // EIP-55 casing
    private static final String USDC_LOWER = USDC.toLowerCase();

    @Test public void acceptsExactlyZeroXAndFortyHexDigits() {
        assertTrue(Addresses.isEvm(USDC));
        assertTrue(Addresses.isEvm(USDC_LOWER));
        assertTrue(Addresses.isEvm(USDC.toUpperCase().replace("0X", "0x")));
        assertFalse(Addresses.isEvm(null));
        assertFalse(Addresses.isEvm(""));
        assertFalse("capital X", Addresses.isEvm("0X" + USDC.substring(2)));
        assertFalse("no prefix", Addresses.isEvm(USDC.substring(2)));
        assertFalse("39 digits", Addresses.isEvm(USDC.substring(0, 41)));
        assertFalse("41 digits", Addresses.isEvm(USDC + "0"));
        assertFalse("leading space", Addresses.isEvm(" " + USDC));
        assertFalse("trailing newline", Addresses.isEvm(USDC + "\n"));
        assertFalse("non-hex", Addresses.isEvm("0x" + USDC.substring(3) + "g"));
    }

    @Test public void lowercaseVariantRefusesAnyCapital() {
        assertTrue(Addresses.isEvmLowercase(USDC_LOWER));
        assertFalse(Addresses.isEvmLowercase(USDC));
        assertFalse(Addresses.isEvmLowercase(null));
        assertEquals(USDC_LOWER, Addresses.lowercase(USDC));
    }

    @Test public void zeroAddressIsExact() {
        assertTrue(Addresses.isZero("0x" + new String(new char[40]).replace('\0', '0')));
        assertFalse(Addresses.isZero("0x" + new String(new char[39]).replace('\0', '0') + "1"));
        assertFalse(Addresses.isZero(null));
    }

    @Test public void checksumHelpers() {
        assertTrue(Addresses.isChecksummed(USDC));
        assertFalse(Addresses.isChecksummed(USDC_LOWER));
        assertFalse(Addresses.isChecksummed(USDC.replace('A', 'a')));
        assertTrue(Addresses.hasMixedCase(USDC));
        assertFalse(Addresses.hasMixedCase(USDC_LOWER));
        assertFalse(Addresses.hasMixedCase(USDC.toUpperCase().replace("0X", "0x")));
    }

    /** Inside text only whole addresses match: not the head of a hash or the tail of a word. */
    @Test public void inTextMatchesWholeAddressesOnly() {
        Matcher m = Addresses.EVM_IN_TEXT.matcher("to " + USDC + ".");
        assertTrue(m.find());
        assertEquals(USDC, m.group());
        assertFalse(Addresses.EVM_IN_TEXT.matcher(USDC + "ab").find());
        assertFalse(Addresses.EVM_IN_TEXT.matcher("a" + USDC).find());
    }

    // ------------------------------------------------------------------ short forms, per call site

    /** Account list, contacts, swap assets, look-alike danger: EIP-55 casing, 6 + 4. */
    @Test public void addressKeysShortFormIsChecksummedSixAndFour() {
        assertEquals("0xA0b8…eB48", AddressKeys.shortForm(USDC_LOWER));
        assertEquals("0xA0b8…eB48", AddressKeys.shortForm(USDC));
        assertEquals("0xA0b8…eB48", Addresses.shortEvm(USDC_LOWER));
    }

    /** Bitcoin: 8 + 6, but anything up to 16 characters whole. */
    @Test public void bitcoinShortFormKeepsShortAddressesWhole() {
        assertEquals("1234567890abcdef", AddressKeys.shortBtc("1234567890abcdef"));
        assertEquals("12345678…bcdefg", AddressKeys.shortBtc("1234567890abcdefg"));
        assertEquals("bc1qcr8t…306fyu", AddressKeys.shortBtc("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"));
    }

    /** The locked-screen summary of a native transfer: EIP-55 casing, 8 + 6. */
    @Test public void lockedTransferSummaryIsEightAndSix() throws Exception {
        TransactionReview r = SwapReviewTest.review("0x1", USDC_LOWER, "0xde0b6b3a7640000", "0x");
        assertTrue(r.lockedSummary, r.lockedSummary.startsWith("Native token transfer · 1 ETH to 0xA0b869…06eB48 · "));
    }

    /** The danger checkbox and blind-sign topics: case exactly as written, 6 + 4. */
    @Test public void reviewStyleShortensInTextKeepingCase() {
        assertEquals("to 0xA0b8…eB48 now", ReviewStyle.shortenEvm("to " + USDC + " now"));
        assertEquals("to 0xa0b8…eb48 now", ReviewStyle.shortenEvm("to " + USDC_LOWER + " now"));
        String hash = "0x" + new String(new char[64]).replace('\0', 'a');
        assertEquals(hash, ReviewStyle.shortenEvm(hash));
    }

    @Test public void shortenReturnsShortTextWhole() {
        assertEquals("0123456789", Addresses.shorten("0123456789", 6, 4));
        assertEquals("012345…7890", Addresses.shorten("01234567890", 6, 4));
        assertEquals("0123456789ab", Addresses.shorten("0123456789ab", 6, 4, 12));
    }
}
