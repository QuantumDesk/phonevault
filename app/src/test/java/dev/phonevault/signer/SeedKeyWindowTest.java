package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * The seed key's 30 s window, as seen from the app. Phone 2 (StrongBox) showed keystore2 accepting
 * {@code Cipher.init} ~30.4 s after the PIN while the Titan M refused the decrypt's update, so the
 * app must never rely on its own confirmation near the edge, the probe must reach the chip, and the
 * backup retry must stay inside the flow that owns the screen.
 */
public class SeedKeyWindowTest {
    private static final long T = 1_000_000L;

    @Test public void freshOwnConfirmationRunsWithoutAsking() {
        assertEquals(SeedKeyWindow.Decision.RUN, SeedKeyWindow.decide(T, T));
        assertEquals(SeedKeyWindow.Decision.RUN, SeedKeyWindow.decide(T, T + 21_999));
    }

    @Test public void ownConfirmationNearOrPastTheEdgeAsksInsteadOfProbing() {
        // 22 s .. 31 s is where an init-only probe succeeded and the chip then refused.
        for (long age : new long[] {22_000, 25_000, 29_600, 30_000, 30_400, 31_000, 60_000, 3_600_000}) {
            assertEquals("age " + age, SeedKeyWindow.Decision.ASK, SeedKeyWindow.decide(T, T + age));
        }
    }

    @Test public void noOwnConfirmationAsksTheChipFirst() {
        // Boot unlock or a PIN just installed: the app did not see the check, the chip decides.
        assertEquals(SeedKeyWindow.Decision.PROBE, SeedKeyWindow.decide(0, T));
    }

    @Test public void clockGoingBackwardsIsNotTrusted() {
        assertEquals(SeedKeyWindow.Decision.ASK, SeedKeyWindow.decide(T, T - 1));
    }

    @Test public void marginLeavesTimeForTheOperation() {
        assertTrue(SeedKeyWindow.USE_WITHOUT_ASKING_MS + SeedKeyWindow.SAFETY_MARGIN_MS
                == SystemCredential.AUTH_WINDOW_SECONDS * 1000L);
        assertTrue(SeedKeyWindow.SAFETY_MARGIN_MS >= 5_000);
    }

    // ---- source guards for the parts only the phone can exercise

    @Test public void probeCompletesARealOperation() throws Exception {
        String probe = SourceGuard.body(SourceGuard.source("VaultKeyStore.java"), "synchronized boolean seedKeyUsableNow() {");
        int init = probe.indexOf("cipher.init(");
        int fin = probe.indexOf("cipher.doFinal(");
        assertTrue("the probe must reach the chip's own check (update/finish), not stop at init",
                init >= 0 && fin > init && fin < probe.indexOf("return true;"));
    }

    @Test public void withSeedKeyUsesTheWindowDecision() throws Exception {
        String gate = SourceGuard.body(SourceGuard.source("MainActivity.java"), "private void withSeedKey(String why, Runnable op) {");
        assertTrue(gate.contains("SeedKeyWindow.decide("));
        assertTrue("an own, stale confirmation must prompt, not probe",
                gate.indexOf("Decision.ASK") < gate.indexOf("seedKeyUsableNow()"));
    }

    @Test public void backupRetryStaysInsideTheOwningFlow() throws Exception {
        String open = SourceGuard.body(SourceGuard.source("MainActivity.java"), "private void openBackup(int token, int s, boolean checkOnly, boolean retried) {");
        assertTrue(open.contains("!retried && authLapsed(e)"));
        assertTrue("retry re-opens with the same token", open.contains("openBackup(token, s, checkOnly, true)"));
        assertEquals("re-entering beginSensitive is refused while the flow is active",
                -1, open.indexOf("startBackupAccess("));
        assertEquals(-1, open.indexOf("beginSensitive("));
    }
}
