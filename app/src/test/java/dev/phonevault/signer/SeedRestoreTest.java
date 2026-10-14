package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/** BIP39 restore validation: count, wordlist membership, checksum, normalization, derivation. */
public class SeedRestoreTest {
    // Standard BIP39 all-zero-entropy 24-word phrase (what Phone Vault generates the length of).
    private static final String VALID = TestKeys.ABANDON_24;
    // EXTERNAL, independently-published reference vectors (iancoleman / ethers.js / Trezor), so
    // these tests prove our derivation matches the wider ecosystem — not that it agrees with
    // itself. m/44'/60'/0'/0/0, lowercased.
    // Canonical 12-word "abandon×11 about" — one of the most-cited Ethereum test vectors.
    private static final String KNOWN_12 = TestKeys.ABANDON_12;
    private static final String KNOWN_12_ADDR = "0x9858effd232b4033e47d90003d41ec34ecaeda94";
    // 24-word all-zero entropy → its published account-0 address.
    private static final String KNOWN_24_ADDR = "0xf278cf59f82edcf871d630f28ecc8056f25c1cdb";

    @Test public void derivationMatchesExternalReferenceVectors() {
        // Independent compatibility: a standard wallet importing these phrases lands on the same
        // address. This is the anchor that makes the other assertions meaningful.
        assertEquals(KNOWN_12_ADDR, SeedVault.deriveEvm(KNOWN_12, "", 0).getAddress().toLowerCase());
        assertEquals(KNOWN_24_ADDR, SeedVault.deriveEvm(VALID, "", 0).getAddress().toLowerCase());
    }

    @Test public void restoredPhraseYieldsTheExternallyKnownAddress() throws Exception {
        String m = SeedRestore.validate(VALID);
        assertEquals(VALID, m);
        // The restore path must reproduce the SAME externally-known account, not merely a stable one.
        assertEquals(KNOWN_24_ADDR, SeedRestore.deriveAddress(m, 0).toLowerCase());
        // A different account index is a different address (BIP44 path is honoured).
        assertFalse(KNOWN_24_ADDR.equalsIgnoreCase(SeedRestore.deriveAddress(m, 1)));
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
