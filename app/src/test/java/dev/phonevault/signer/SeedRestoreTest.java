package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/** BIP39 restore validation: count, wordlist membership, checksum, normalization, derivation. */
public class SeedRestoreTest {
    // A standard BIP39 test vector (all-zero entropy) → known 24-word phrase and m/44'/60'/0'/0/0.
    private static final String VALID =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
            + "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
            + "abandon abandon abandon art";

    @Test public void validPhrasePassesAndDerivesDeterministically() throws Exception {
        String m = SeedRestore.validate(VALID);
        assertEquals(VALID, m);
        String address = SeedRestore.deriveAddress(m, 0);
        assertTrue(address.matches("0x[0-9a-fA-F]{40}"));
        // Re-deriving the same phrase gives the same account (that IS recoverability).
        assertEquals(address, SeedRestore.deriveAddress(m, 0));
        // Matches the app's own generator path for the same words.
        assertEquals(address, SeedVault.deriveEvm(m, "", 0).getAddress());
    }

    @Test public void normalizationHandlesCaseAndWhitespace() throws Exception {
        String messy = "  ABANDON  abandon\tabandon abandon abandon abandon abandon abandon "
                + "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                + "abandon abandon abandon abandon abandon ART ";
        assertEquals(VALID, SeedRestore.validate(messy));
    }

    @Test public void wrongWordCountIsRejected() {
        try {
            SeedRestore.validate("abandon abandon abandon art");
            fail("12/short phrase must be rejected");
        } catch (SeedRestore.RestoreException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("Expected 24"));
        }
    }

    @Test public void unknownWordIsRejectedByPosition() {
        String bad = VALID.replaceFirst("art$", "zzzzznotaword");
        try {
            SeedRestore.validate(bad);
            fail("a non-BIP39 word must be rejected");
        } catch (SeedRestore.RestoreException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("Word 24"));
        }
        assertEquals(java.util.Collections.singletonList(24), SeedRestore.unknownWordPositions(bad));
    }

    @Test public void badChecksumIsRejected() {
        // All 24 words are valid BIP39 words, but the checksum word is wrong (art → abandon).
        String badChecksum = VALID.replaceFirst("art$", "abandon");
        assertTrue(SeedRestore.unknownWordPositions(badChecksum).isEmpty());
        try {
            SeedRestore.validate(badChecksum);
            fail("bad checksum must be rejected");
        } catch (SeedRestore.RestoreException e) {
            assertTrue(e.getMessage(), e.getMessage().toLowerCase().contains("checksum"));
        }
    }

    @Test public void emptyInputGivesAGuidingMessage() {
        try {
            SeedRestore.validate("   ");
            fail("empty must be rejected");
        } catch (SeedRestore.RestoreException e) {
            assertTrue(e.getMessage().contains("24-word"));
        }
    }

    @Test public void suggestionsAutocompleteFromTheBip39List() {
        assertTrue(SeedRestore.suggestions("aban", 5).contains("abandon"));
        assertTrue(SeedRestore.suggestions("zo", 5).contains("zoo"));
        assertTrue(SeedRestore.suggestions("", 5).isEmpty());
        assertTrue(SeedRestore.suggestions("xqz", 5).isEmpty());
        assertTrue(SeedRestore.suggestions("a", 3).size() <= 3);
        assertTrue(SeedRestore.isWord("art"));
        assertFalse(SeedRestore.isWord("notaword"));
        assertEquals(2048, SeedRestore.wordList().size());
    }
}
