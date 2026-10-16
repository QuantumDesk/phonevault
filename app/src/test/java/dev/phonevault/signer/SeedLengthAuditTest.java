package dev.phonevault.signer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.DecoderResult;
import com.google.zxing.qrcode.decoder.Decoder;

import org.junit.Test;
import org.web3j.crypto.MnemonicUtils;
import org.web3j.utils.Numeric;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Security audit (variable-length restore): proof tests. Public test vectors and freshly generated
 * throwaway phrases only. Each test re-derives the expected value by a path independent of the code
 * under test (own PBKDF2, own BIP39 checksum, ZXing's decoder back to words).
 */
public final class SeedLengthAuditTest {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final List<String> LIST = MnemonicUtils.getWords();

    // ------------------------------------------------------------ independent BIP39 reference

    /** PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048, 64): written out, not web3j's. */
    private static byte[] pbkdf2(String mnemonic, String passphrase) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(mnemonic.getBytes(StandardCharsets.UTF_8), "HmacSHA512"));
        byte[] salt = ("mnemonic" + passphrase).getBytes(StandardCharsets.UTF_8);
        mac.update(salt);
        byte[] u = mac.doFinal(new byte[] {0, 0, 0, 1});
        byte[] t = u.clone();
        for (int i = 1; i < 2048; i++) {
            u = mac.doFinal(u);
            for (int j = 0; j < t.length; j++) t[j] ^= u[j];
        }
        return t;
    }

    /** True iff the words are a valid BIP39 English phrase of a length the phone restores (own checksum). */
    private static boolean referenceValid(String[] w) throws Exception {
        if (!SeedRestore.isWordCount(w.length)) return false;
        int total = w.length * 11, cs = w.length / 3, ent = total - cs;
        boolean[] bits = new boolean[total];
        for (int i = 0; i < w.length; i++) {
            int idx = LIST.indexOf(w[i]);
            if (idx < 0) return false;
            for (int b = 0; b < 11; b++) bits[i * 11 + b] = ((idx >> (10 - b)) & 1) == 1;
        }
        byte[] e = new byte[ent / 8];
        for (int b = 0; b < ent; b++) if (bits[b]) e[b / 8] |= (byte) (0x80 >> (b % 8));
        byte[] h = MessageDigest.getInstance("SHA-256").digest(e);
        for (int b = 0; b < cs; b++) if ((((h[0] >> (7 - b)) & 1) == 1) != bits[ent + b]) return false;
        return true;
    }

    private static String[] randomPhrase(int n) {
        byte[] entropy = new byte[n * 4 / 3];
        RANDOM.nextBytes(entropy);
        return MnemonicUtils.generateMnemonic(entropy).split(" ");
    }

    // ------------------------------------------------------------ restore derives the standard seed

    /** The stored-phrase → seed path equals an independent PBKDF2 on all 32 vectors (12/15/18/21/24). */
    @Test public void seedEqualsIndependentPbkdf2ForEveryVector() throws Exception {
        int checked = 0;
        for (String[] v : Bip39LengthsTest.vectors()) {
            String canonical = SeedRestore.validate(v[1].toUpperCase(Locale.ROOT).replace(" ", " \t "), v[1].split(" ").length);
            assertEquals(v[1], canonical);
            byte[] ours = SeedVault.bip39Seed(canonical, "TREZOR");
            assertArrayEquals(v[1], pbkdf2(v[1], "TREZOR"), ours);
            assertEquals(v[2], Numeric.toHexStringNoPrefix(ours));
            checked++;
        }
        assertEquals(32, checked);
    }

    /** Well-known cross-wallet vector: "abandon x11 about" → 0x9858…da94 at m/44'/60'/0'/0/0, no passphrase. */
    @Test public void restoreConfirmAddressIsTheCrossWalletStandard() {
        assertEquals("0x9858effd232b4033e47d90003d41ec34ecaeda94",
                SeedRestore.deriveAddress(TestKeys.ABANDON_12, 0).toLowerCase(Locale.ROOT));
    }

    // ------------------------------------------------------------ checksum at every position, every length

    /**
     * Every single-word substitution at every position, for every length: SeedRestore.validate
     * accepts exactly when an independent checksum says the result is a valid phrase, and
     * bip39Seed / SeedQR agree with that verdict.
     */
    @Test public void substitutionsAgreeWithIndependentChecksum() throws Exception {
        int refused = 0, accepted = 0;
        for (int n : SeedRestore.WORD_COUNTS) {
            for (int trial = 0; trial < 3; trial++) {
                String[] w = randomPhrase(n);
                for (int pos = 0; pos < n; pos++) {
                    for (int delta : new int[] {1, 7, 1024}) {
                        String[] m = w.clone();
                        m[pos] = LIST.get((LIST.indexOf(w[pos]) + delta) % 2048);
                        String joined = String.join(" ", m);
                        boolean ref = referenceValid(m);
                        boolean ok;
                        try { SeedRestore.validate(joined, n); ok = true; } catch (SeedRestore.RestoreException e) { ok = false; }
                        assertEquals(n + " words, position " + (pos + 1), ref, ok);
                        boolean seedOk;
                        try { SeedVault.bip39Seed(joined, ""); seedOk = true; } catch (IllegalArgumentException e) { seedOk = false; }
                        assertEquals(ref, seedOk);
                        if (SeedQr.supports(n)) {
                            boolean qrOk;
                            try { SeedQr.compactBytes(m); qrOk = true; } catch (IllegalArgumentException e) { qrOk = false; }
                            assertEquals("SeedQR checksum verdict, " + n + " words pos " + (pos + 1), ref, qrOk);
                        }
                        if (ok) accepted++; else refused++;
                    }
                }
            }
        }
        assertTrue(refused > 0 && accepted > 0); // both branches exercised (low-checksum 12-word cases collide)
    }

    // ------------------------------------------------------------ normalisation

    @Test public void onlyCanonicalAsciiPhrasesAreAccepted() throws Exception {
        String twelve = TestKeys.ABANDON_12;
        assertEquals(twelve, SeedRestore.validate("\n  " + twelve.toUpperCase(Locale.ROOT).replace(" ", "\t\t") + "  \r\n", 12));
        // Non-ASCII separators / letters and 4-letter abbreviations are refused, never reinterpreted.
        for (String bad : new String[] {
                twelve.replace(" ", " "),                                     // NBSP
                twelve.replaceFirst("abandon", "ａｂａｎｄｏｎ"), // fullwidth "abandon"
                twelve.replace("abandon", "aban"),                                  // 4-letter prefix
                twelve.replaceFirst("abandon", "abandoŃ"),                    // combining mark
        }) {
            try { SeedRestore.validate(bad, 12); fail("accepted: " + bad.length()); } catch (SeedRestore.RestoreException expected) { }
        }
        // The derivation path refuses any non-canonical string (stored records are canonical).
        for (String bad : new String[] {twelve + " ", " " + twelve, twelve.replaceFirst(" ", "  "), twelve.toUpperCase(Locale.ROOT)}) {
            try { SeedVault.bip39Seed(bad, ""); fail("derived from a non-canonical phrase"); } catch (IllegalArgumentException expected) { }
        }
        // Turkish default locale does not change lowercasing (ROOT is used).
        Locale saved = Locale.getDefault();
        try {
            Locale.setDefault(new Locale("tr", "TR"));
            assertEquals(twelve, SeedRestore.validate(twelve.toUpperCase(Locale.ROOT), 12));
            assertTrue(SeedRestore.isWord("DIGITAL"));
        } finally {
            Locale.setDefault(saved);
        }
    }

    /** A pre-upgrade record holds a 24-word canonical string with no length field: it still reads as 24 words. */
    @Test public void existing24WordRecordReadsAs24() throws Exception {
        for (int i = 0; i < 20; i++) {
            byte[] e = new byte[SeedVault.ENTROPY_BYTES];
            RANDOM.nextBytes(e);
            String stored = MnemonicUtils.generateMnemonic(e); // exactly what SeedVault.generate stores
            assertEquals(24, stored.split(" ").length);          // BackupScreens.openBackup split
            assertEquals(stored, SeedRestore.validate(stored));  // canonical, valid
            assertEquals(6, 24 / BackupScreens.wordsPerPage(24));
            assertArrayEquals(pbkdf2(stored, ""), SeedVault.bip39Seed(stored, ""));
        }
    }

    // ------------------------------------------------------------ spot check

    /** Answering with the word from any OTHER position (when it differs) fails the check, at every length. */
    @Test public void spotCheckRejectsWordsFromTheWrongPosition() {
        for (int n : SeedRestore.WORD_COUNTS) {
            Set<Integer> seen = new HashSet<>();
            for (int trial = 0; trial < 400; trial++) {
                String[] w = randomPhrase(n);
                BackupCheck.Challenge c = new BackupCheck.Challenge(w, RANDOM);
                Set<Integer> positions = new HashSet<>();
                int wrongAt = RANDOM.nextInt(c.total());
                for (int k = 0; k < c.total(); k++) {
                    int p = c.position();
                    assertTrue(p >= 0 && p < n);
                    assertTrue("positions are distinct", positions.add(p));
                    seen.add(p);
                    if (k == wrongAt) {
                        int other = (p + 1 + RANDOM.nextInt(n - 1)) % n;
                        if (w[other].equals(w[p])) break; // same word: not a wrong answer
                        assertFalse(c.answer(w[other]));
                        assertFalse(c.complete());
                        assertFalse("no recovery after a miss", c.answer(w[p]));
                        break;
                    }
                    assertTrue(c.answer(w[p]));
                }
            }
            assertEquals("every position can be asked, " + n + " words", n, seen.size());
        }
    }

    // ------------------------------------------------------------ phrase pages

    /** The page loop (BackupScreens.showPhrasePage) shows every word once, in order, for every length. */
    @Test public void phrasePagesShowEveryWordOnceInOrder() throws Exception {
        String src = SourceGuard.source("BackupScreens.java");
        assertTrue(src.contains("for (int i = backupPage * per; i < backupPage * per + per; i++) {"));
        assertTrue(src.contains("return n / wordsPerPage(n);"));
        for (int n : SeedRestore.WORD_COUNTS) {
            int per = BackupScreens.wordsPerPage(n), pages = n / per, next = 0;
            for (int page = 0; page < pages; page++)
                for (int i = page * per; i < page * per + per; i++) assertEquals(next++, i);
            assertEquals(n, next);
        }
    }

    // ------------------------------------------------------------ SeedQR

    private static BitMatrix bits(SeedQr.Modules m) {
        BitMatrix b = new BitMatrix(m.size);
        for (int r = 0; r < m.size; r++) for (int c = 0; c < m.size; c++) if (m.get(r, c)) b.set(c, r);
        return b;
    }

    /** Random 12 and 24-word phrases: scanning each symbol back yields exactly the same words. */
    @Test public void seedQrScansBackToTheSamePhrase() throws Exception {
        for (int n : new int[] {12, 24}) {
            for (int trial = 0; trial < 150; trial++) {
                String[] w = randomPhrase(n);
                DecoderResult compact = new Decoder().decode(bits(SeedQr.encode(w, SeedQr.Format.COMPACT)));
                byte[] entropy = compact.getByteSegments().get(0);
                assertEquals(n * 4 / 3, entropy.length);
                assertArrayEquals(w, MnemonicUtils.generateMnemonic(entropy).split(" "));
                String d = new Decoder().decode(bits(SeedQr.encode(w, SeedQr.Format.STANDARD))).getText();
                assertEquals(n * 4, d.length());
                String[] back = new String[n];
                for (int i = 0; i < n; i++) back[i] = LIST.get(Integer.parseInt(d.substring(4 * i, 4 * i + 4)));
                assertArrayEquals(w, back);
            }
        }
    }

    /** 15/18/21 words are refused by every SeedQR entry point, not only encode(). */
    @Test public void seedQrRefusesOtherLengthsAtEveryEntryPoint() {
        for (int n : new int[] {15, 18, 21}) {
            String[] w = randomPhrase(n);
            assertFalse(SeedQr.supports(n));
            try { SeedQr.indices(w); fail(); } catch (IllegalArgumentException expected) { }
            try { SeedQr.standardDigits(w); fail(); } catch (IllegalArgumentException expected) { }
            try { SeedQr.compactBytes(w); fail(); } catch (IllegalArgumentException expected) { }
            for (SeedQr.Format f : SeedQr.Format.values()) {
                try { SeedQr.version(n, f); fail(); } catch (IllegalArgumentException expected) { }
                try { SeedQr.encode(w, f); fail(); } catch (IllegalArgumentException expected) { }
            }
        }
    }

    /** The 12-word Standard SeedQR (version 2) fits the printed 25x25 card: its pre-printed modules match. */
    @Test public void twelveWordStandardMatchesThe25x25Card() {
        for (int trial = 0; trial < 50; trial++) {
            SeedQr.Modules m = SeedQr.encode(randomPhrase(12), SeedQr.Format.STANDARD);
            assertEquals(2, m.version);
            Boolean[][] fixed = SeedQrTest.functionPatterns(2);
            for (int r = 0; r < m.size; r++)
                for (int c = 0; c < m.size; c++)
                    if (fixed[r][c] != null) assertEquals(fixed[r][c], m.get(r, c));
        }
    }

    // ------------------------------------------------------------ FINDING (low): idle-hide page count

    /**
     * BackupScreens.tickSeedTimer calls host.hideBackup() (MainActivity.hideBackup → clearSensitiveUi
     * → backup.clear() → backupWords = null) BEFORE it builds "continue from page X of " + pageCount(),
     * and pageCount() falls back to CREATE_WORD_COUNT (24 → 6 pages) when backupWords is null. So a
     * 12/15/18/21-word phrase is always told "of 6". This test PASSES while the bug exists.
     */
    @Test public void idleHideMessageUses24WordPageCount_BUG() throws Exception {
        String backup = SourceGuard.source("BackupScreens.java");
        int tick = backup.indexOf("private void tickSeedTimer()");
        int hide = backup.indexOf("host.hideBackup();", tick);
        int msg = backup.indexOf("\" of \" + pageCount() + \".\"", tick);
        assertTrue(tick > 0 && hide > tick && msg > hide);
        assertTrue(backup.contains("int n = backupWords == null ? SeedRestore.CREATE_WORD_COUNT : backupWords.length;"));
        assertTrue(backup.contains("backupWords = null;"));
        String main = SourceGuard.mainActivity();
        int h = main.indexOf("private void hideBackup()");
        assertTrue(h > 0 && main.indexOf("clearSensitiveUi();", h) > h);
        assertTrue(main.contains("backup.clear();"));
        // What the user is told vs the truth, after an idle hide on the last page:
        int shownTotal = 24 / BackupScreens.wordsPerPage(24);
        assertEquals(6, 18 / BackupScreens.wordsPerPage(18)); // 18 words: 6 pages, right by coincidence
        for (int n : new int[] {12, 15, 21}) {
            int real = n / BackupScreens.wordsPerPage(n);
            assertNotEquals(n + " words", real, shownTotal);
        }
        assertEquals(7, 21 / BackupScreens.wordsPerPage(21)); // "page 7 of 6"
        assertEquals(3, 12 / BackupScreens.wordsPerPage(12)); // "page 3 of 6"
    }
}
