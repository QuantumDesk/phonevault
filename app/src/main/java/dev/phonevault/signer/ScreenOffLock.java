package dev.phonevault.signer;

/**
 * "Lock after screen off" (Display &amp; auto-lock): the decisions, free of Android so they are
 * unit-tested (ScreenOffLockTest). MainActivity feeds it the screen-off and wake events.
 *
 * <ul>
 *   <li>Grace 0 (the default), the activity hidden for any reason other than the display going
 *       off, or a screen that must never outlive the display (a sensitive flow: recovery phrase,
 *       backup check, replace or restore; passphrase typing; first-run setup): lock at once.</li>
 *   <li>Otherwise the vault stays unlocked for at most the grace ({@link DisplaySettings#MAX_SCREEN_OFF_GRACE_SECONDS}
 *       at most). Waking inside it needs no PIN; waking after it (the CPU may sleep through the
 *       timer, so the wake checks the clock itself) locks before anything is drawn.</li>
 *   <li>After a grace wake, the next sensitive action asks for the PIN even if the security chip's
 *       own window from an earlier PIN is still open ({@link #pinRequiredForSensitive}).</li>
 *   <li>Nothing here answers a request: a held or open USB request still needs Approve on screen.
 *       A reboot or power-off ends the process, so it always locks (nothing is persisted).</li>
 * </ul>
 */
final class ScreenOffLock {
    enum Action { LOCK_NOW, GRACE }

    /** elapsedRealtime when the grace ends; 0: no grace running. */
    private long deadline;
    /** Set when a grace starts; cleared by a lock or by a PIN confirmed for a sensitive action. */
    private boolean pinRequiredForSensitive;

    /**
     * The activity was stopped.
     *
     * @param graceSeconds  the saved choice (validated again here)
     * @param displayOff    the display really went off (PowerManager#isInteractive false); a stop
     *                      for any other reason locks at once
     * @param unlocked      the vault is unlocked now
     * @param mustLockNow   a screen is up that never outlives the display (see the class comment)
     */
    Action screenOff(int graceSeconds, boolean displayOff, boolean unlocked, boolean mustLockNow, long now) {
        int grace = DisplaySettings.validGrace(graceSeconds);
        if (grace <= 0 || !displayOff || !unlocked || mustLockNow) {
            deadline = 0;
            return Action.LOCK_NOW;
        }
        // A second screen-off inside a running grace keeps the first deadline (never extended).
        if (deadline == 0) deadline = now + grace * 1000L;
        pinRequiredForSensitive = true;
        return Action.GRACE;
    }

    /** A grace is running (the display went off and the vault has not locked yet). */
    boolean running() { return deadline != 0; }

    /** Milliseconds left in the running grace (0 when none or past). */
    long remainingMs(long now) { return deadline == 0 ? 0 : Math.max(0, deadline - now); }

    /**
     * The activity is visible again. True: the grace ran out while the display was off, lock now
     * (before anything is drawn). False: no grace was running, or the wake came inside it (the
     * grace ends here; the idle lock takes over).
     */
    boolean wakeMustLock(long now) {
        if (deadline == 0) return false;
        boolean expired = now >= deadline;
        deadline = 0;
        return expired;
    }

    /** The grace timer fired: lock unless a wake already ended the grace. */
    boolean timerMustLock(long now) { return deadline != 0 && now >= deadline; }

    /** A sensitive action must ask for the PIN now, even inside the chip's window. */
    boolean pinRequiredForSensitive() { return pinRequiredForSensitive; }

    /** The PIN was confirmed for a sensitive action after the grace wake. */
    void sensitivePinConfirmed() { pinRequiredForSensitive = false; }

    /** The vault locked: no grace, and the next unlock asks for the PIN anyway. */
    void locked() {
        deadline = 0;
        pinRequiredForSensitive = false;
    }
}
