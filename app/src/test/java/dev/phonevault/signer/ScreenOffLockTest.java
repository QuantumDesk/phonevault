package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** "Lock after screen off": when the vault may wait, and what still always asks for the PIN. */
public class ScreenOffLockTest {
    private static final long T = 1_000_000L;

    @Test public void immediatelyIsTheDefaultAndLocksAtOnce() {
        ScreenOffLock l = new ScreenOffLock();
        assertEquals(ScreenOffLock.Action.LOCK_NOW, l.screenOff(0, true, true, false, T));
        assertFalse(l.running());
        assertFalse(l.pinRequiredForSensitive());
    }

    @Test public void aGraceKeepsTheVaultOpenOnlyForItsLength() {
        ScreenOffLock l = new ScreenOffLock();
        assertEquals(ScreenOffLock.Action.GRACE, l.screenOff(30, true, true, false, T));
        assertTrue(l.running());
        assertEquals(30_000L, l.remainingMs(T));
        assertFalse(l.timerMustLock(T + 29_999));
        assertTrue(l.timerMustLock(T + 30_000));
        // Woken inside the grace: no lock, the grace ends.
        assertFalse(l.wakeMustLock(T + 29_000));
        assertFalse(l.running());
        assertFalse("a later timer does nothing", l.timerMustLock(T + 60_000));
    }

    @Test public void aWakeAfterTheGraceLocks() {
        // The CPU may sleep through the timer: the wake itself checks the clock.
        ScreenOffLock l = new ScreenOffLock();
        assertEquals(ScreenOffLock.Action.GRACE, l.screenOff(60, true, true, false, T));
        assertTrue(l.wakeMustLock(T + 60_000));
        assertFalse(l.running());
        assertFalse("nothing running: a plain wake never locks", l.wakeMustLock(T + 61_000));
    }

    @Test public void neverLongerThanAMinute() {
        ScreenOffLock l = new ScreenOffLock();
        assertEquals("not a choice: at once", ScreenOffLock.Action.LOCK_NOW, l.screenOff(120, true, true, false, T));
        assertEquals(ScreenOffLock.Action.LOCK_NOW, l.screenOff(45, true, true, false, T));
        assertEquals(ScreenOffLock.Action.LOCK_NOW, l.screenOff(Integer.MAX_VALUE, true, true, false, T));
        assertEquals(ScreenOffLock.Action.GRACE, l.screenOff(60, true, true, false, T));
        assertEquals(60_000L, l.remainingMs(T));
    }

    @Test public void onlyWhenTheDisplayWentOffAndTheVaultIsUnlocked() {
        ScreenOffLock l = new ScreenOffLock();
        assertEquals("hidden for another reason (display still on)", ScreenOffLock.Action.LOCK_NOW, l.screenOff(60, false, true, false, T));
        assertEquals("already locked", ScreenOffLock.Action.LOCK_NOW, l.screenOff(60, true, false, false, T));
        assertEquals("a screen that never outlives the display (phrase, restore, PIN entry…)",
                ScreenOffLock.Action.LOCK_NOW, l.screenOff(60, true, true, true, T));
        assertFalse(l.running());
    }

    @Test public void sensitiveActionsAskForThePinAfterAGraceWake() {
        ScreenOffLock l = new ScreenOffLock();
        l.screenOff(30, true, true, false, T);
        assertFalse(l.wakeMustLock(T + 5_000));
        assertTrue("recovery phrase, restore, replace: always the PIN", l.pinRequiredForSensitive());
        l.sensitivePinConfirmed();
        assertFalse(l.pinRequiredForSensitive());
        l.screenOff(30, true, true, false, T + 10_000);
        assertTrue(l.pinRequiredForSensitive());
        l.locked();
        assertFalse("a lock ends it (the unlock asks for the PIN anyway)", l.pinRequiredForSensitive());
        assertFalse(l.running());
    }

    @Test public void aLockEndsTheGrace() {
        ScreenOffLock l = new ScreenOffLock();
        l.screenOff(60, true, true, false, T);
        l.locked();
        assertFalse(l.timerMustLock(T + 60_000));
        assertFalse(l.wakeMustLock(T + 1));
    }

    /** The activity wiring: what ScreenOffLock decides is what MainActivity does. */
    @Test public void mainActivityWiring() throws Exception {
        String stop = SourceGuard.definition("protected void onStop() {");
        assertTrue(stop.contains("screenOffLock.screenOff(display.screenOffGraceSeconds(), !displayInteractive(), unlocked,"));
        assertTrue(stop.contains("mustLockWithDisplay()"));
        assertTrue("every other case locks, as before", stop.contains("lock();"));
        assertTrue("the chip's window is not reused for a sensitive action", stop.contains("credentialGate.forgetConfirmation();"));
        assertTrue("the idle lock is off while the display is", stop.contains("ui.removeCallbacks(idleLock);"));

        String start = SourceGuard.definition("protected void onStart() {");
        assertTrue(start.contains("if (screenOffLock.wakeMustLock(SystemClock.elapsedRealtime())) {"));
        assertTrue(start.indexOf("lock();") > start.indexOf("wakeMustLock"));
        assertTrue("idle lock re-armed from the wake", start.contains("armIdleLock();"));

        String must = SourceGuard.definition("private boolean mustLockWithDisplay() {");
        for (String s : new String[] {"sensitive.active()", "backup.showingWords()", "passphraseEntry", "replacementActive()",
                "setup.replacing()", "!walletLoaded", "pinScreen != null", "credentialGate.promptOpen()"}) {
            assertTrue(s, must.contains(s));
        }

        String lock = SourceGuard.definition("private void lock() {");
        assertTrue(lock.contains("screenOffLock.locked();"));
        assertTrue(lock.contains("ui.removeCallbacks(graceLock);"));

        String sensitive = SourceGuard.definition("private void beginSensitive(String purpose, Runnable afterPin) {");
        int forced = sensitive.indexOf("if (screenOffLock.pinRequiredForSensitive()) {");
        assertTrue("a sensitive action after a grace wake asks for the PIN, never the chip's open window", forced > 0);
        assertTrue(sensitive.indexOf("confirmDevicePin(", forced) > forced);
        assertTrue(sensitive.indexOf("confirmDevicePin(", forced) < sensitive.indexOf("withSeedKey(", forced));

        assertTrue("power off / reboot from the power menu locks first",
                SourceGuard.mainActivity().contains("if (Intent.ACTION_SHUTDOWN.equals(intent.getAction())) lock();"));
        assertFalse("the grace is never persisted", SourceGuard.source("ScreenOffLock.java").contains("SharedPreferences"));
    }

    /** Restart: device owner only, confirmed, never while a request is held or reviewed, and it locks first. */
    @Test public void restartWiring() throws Exception {
        String restart = SourceGuard.definition("private void restart() {");
        assertTrue(restart.contains("if (!host.restartAvailable() || host.requestUnderReview() || !unlocked) return;"));
        assertTrue("locks before rebooting", restart.indexOf("lock();") < restart.indexOf(".reboot("));
        String review = SourceGuard.definition("public boolean requestUnderReview() {");
        assertTrue(review.contains("approvalDecision != null || requestPending.get() || heldRequest.summary() != null"));
        String power = SourceGuard.definition("void showPower() {");
        assertTrue(power.contains("hold the power button"));
        assertTrue(power.contains("if (!host.restartAvailable()) {"));
        assertTrue(power.contains("} else if (host.requestUnderReview()) {"));
        String confirm = SourceGuard.definition("private void confirmRestart() {");
        assertTrue("re-checked when confirmed", confirm.contains("if (host.restartAvailable() && !host.requestUnderReview()) host.restart();"));
    }
}
