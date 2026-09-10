package dev.phonevault.signer;

import org.junit.Test;
import static org.junit.Assert.*;
import java.security.SecureRandom;
import org.web3j.crypto.MnemonicUtils;

public class BackupCheckTest {
    private static final String ADDRESS = "0x1111111111111111111111111111111111111111";
    @Test public void newOrDifferentWalletHasNoBackupProof() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        BackupCheck check = new BackupCheck(prefs);
        assertFalse(check.verified(ADDRESS));
        check.record(ADDRESS);
        assertTrue(new BackupCheck(prefs).verified(ADDRESS));
        assertFalse(check.verified("0x2222222222222222222222222222222222222222"));
        check.clear();
        assertFalse(new BackupCheck(prefs).verified(ADDRESS));
    }
    @Test public void failedCommitDoesNotUnlockReceiving() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        BackupCheck check = new BackupCheck(prefs);
        prefs.failAtCommit = 1;
        try { check.record(ADDRESS); fail("Expected persistence failure"); }
        catch (IllegalStateException expected) { assertFalse(check.verified(ADDRESS)); }
        prefs.failAtCommit = -1;
        check.record(ADDRESS);
        assertTrue(check.verified(ADDRESS));
    }
    @Test public void spotChecksARandomSubsetOfDistinctPositions() {
        String[] words = MnemonicUtils.generateMnemonic(new byte[32]).split(" ");
        BackupCheck.Challenge challenge = new BackupCheck.Challenge(words, new SecureRandom());
        assertEquals("default spot-check is a handful, not all 24", BackupCheck.SPOT_CHECK, challenge.total());
        assertTrue(challenge.total() >= 1 && challenge.total() < 24);
        boolean[] seen = new boolean[24];
        for (int i = 0; i < challenge.total(); i++) {
            assertFalse(challenge.complete());
            int position = challenge.position();
            assertFalse("each checked position is distinct", seen[position]);
            seen[position] = true;
            assertTrue(challenge.answer(words[position]));
        }
        assertTrue(challenge.complete());
        assertFalse(challenge.answer(words[0]));
        challenge.destroy();
        assertFalse(challenge.complete());
    }

    @Test public void checkCountIsConfigurableUpToAllPositions() {
        String[] words = MnemonicUtils.generateMnemonic(new byte[32]).split(" ");
        BackupCheck.Challenge full = new BackupCheck.Challenge(words, new SecureRandom(), 24);
        assertEquals(24, full.total());
        for (int i = 0; i < 24; i++) assertTrue(full.answer(words[full.position()]));
        assertTrue(full.complete());
    }
    @Test public void wrongWordInvalidatesWholeCheck() {
        String[] words = MnemonicUtils.generateMnemonic(new byte[32]).split(" ");
        BackupCheck.Challenge challenge = new BackupCheck.Challenge(words, new SecureRandom());
        assertFalse(challenge.answer("not-a-recovery-word"));
        for (String word : words) assertFalse(challenge.answer(word));
        assertFalse(challenge.complete());
    }
}
