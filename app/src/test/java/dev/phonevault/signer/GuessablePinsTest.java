package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/** PINs a thief tries first are refused when a PIN is chosen, never at unlock. */
public class GuessablePinsTest {
    private static boolean refused(String pin) { return GuessablePins.guessable(pin.toCharArray()); }

    @Test public void sameDigit() {
        for (char d = '0'; d <= '9'; d++) assertTrue(refused(String.valueOf(new char[] {d, d, d, d, d, d})));
    }

    @Test public void straightRunsBothWaysAndAcrossNine() {
        for (String p : new String[] {"123456", "234567", "345678", "456789", "567890", "678901", "789012", "890123",
                "901234", "012345", "654321", "987654", "876543", "210987", "109876", "098765", "321098"}) {
            assertTrue(p, refused(p));
        }
    }

    @Test public void repeatedGroupsAndDoubledDigits() {
        for (String p : new String[] {"121212", "909090", "123123", "580580", "112233", "998877", "447700", "002299"}) {
            assertTrue(p, refused(p));
        }
    }

    @Test public void theStudysCommonList() {
        assertEquals(20, GuessablePins.COMMON.size());
        for (String p : GuessablePins.COMMON) {
            assertEquals(6, p.length());
            assertTrue(p, refused(p));
        }
        for (String p : new String[] {"159753", "147258", "696969", "520520", "101010", "789456", "147852", "123321"}) {
            assertTrue(p, refused(p));
        }
    }

    @Test public void ordinaryPinsPass() {
        for (String p : new String[] {"004217", "381947", "750263", "120934", "122334", "123457", "135791", "246802",
                "112234", "121213", "123124", "135792"}) {
            assertFalse(p, refused(p));
        }
    }

    @Test public void notThisChecksJob() {
        assertFalse("length is the PIN screen's rule", GuessablePins.guessable("12345".toCharArray()));
        assertFalse(GuessablePins.guessable(null));
        assertFalse(GuessablePins.guessable("12345a".toCharArray()));
    }

    @Test public void theMessage() {
        assertEquals("That PIN is one of the first a thief would try. Choose six digits that aren't a pattern.", GuessablePins.MESSAGE);
    }

    /** storeNewPin refuses one too (any path that stores a PIN), zeroing both copies, before the chip sees it. */
    @Test public void storeNewPinRefusesAGuessablePin() throws Exception {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        VaultPin pin = new VaultPin(prefs, 1000);
        char[] chosen = "123456".toCharArray(), forSystem = chosen.clone();
        try {
            CredentialGate.storeNewPin(chosen, forSystem, p -> { fail("the chip never sees it"); return true; }, pin);
            fail();
        } catch (IllegalArgumentException expected) {
            assertEquals(GuessablePins.MESSAGE, expected.getMessage());
        }
        assertEquals("000000", new String(chosen));
        assertEquals("000000", new String(forSystem));
        assertFalse(pin.isSet());
    }

    /** Where it applies: choosing a PIN (first entry of SET PIN), and never unlock. */
    @Test public void appliedWhereAPinIsChosenOnly() throws Exception {
        String create = SourceGuard.definition("private void onCreatePinEntry(");
        int check = create.indexOf("if (GuessablePins.guessable(entered)) {");
        assertTrue(check > 0);
        assertTrue("before the first entry is kept", check < create.indexOf("firstEntry[0] = entered.clone();"));
        assertTrue(create.contains("pinScreen.showError(GuessablePins.MESSAGE);"));
        assertFalse("never at unlock", SourceGuard.definition("private void onUnlockEntry(").contains("GuessablePins"));
        assertEquals("one check site in the activity, plus storeNewPin", 1,
                SourceGuard.mainActivity().split("GuessablePins\\.guessable\\(", -1).length - 1);
    }
}
