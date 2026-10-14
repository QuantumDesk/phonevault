package dev.phonevault.signer;

import java.util.Arrays;

/**
 * The credential-mode gate's decisions, free of Android so they are unit-tested
 * (CredentialGateTest): the locked gate with its once-per-boot silent unlock, the device-PIN
 * prompt, and "may the seed key be used now?" ({@link SeedKeyWindow}). MainActivity supplies the
 * screens, the system prompt and the keystore probe through {@link Env}. UI thread only.
 */
final class CredentialGate {
    /** What the gate needs from the activity. Every call is on the UI thread. */
    interface Env {
        /** The unlock session token (MainActivity's {@code session}). */
        int session();
        boolean unlocked();
        /** Between onStart and onStop. */
        boolean foreground();
        /** The vault PIN is the device credential (VaultPin's persisted marker). */
        boolean credentialMode();
        /** SystemClock.elapsedRealtime(). */
        long elapsedRealtime();
        /** Settings.Global.BOOT_COUNT, -1 when unknown. */
        int bootId();
        /** Persisted once-per-boot record of the silent unlock (null before the vault is operational). */
        BootUnlockGuard bootUnlock();
        /** Android's own lock screen still reports the device locked (false without a keyguard). */
        boolean deviceLocked();
        void post(Runnable r);
        void postDelayed(Runnable r, long delayMs);
        void showLoading(String title, String caption);
        /** Draw the locked page of session {@code s} (its Unlock button calls {@link #promptUnlock}). */
        void showLockedPage(int s);
        /** Unlock session {@code s}; refused (and {@link #unlocked()} stays false) if it is stale. */
        void unlock(int s);
        /** Show the system device-PIN prompt; {@code result} runs on the UI thread (possibly at once). */
        void systemConfirm(String why, Confirmed result);
        /** On the crypto thread: does the seed key work right now? {@code result} runs on the UI thread. */
        void probeSeedKey(Probed result);
    }

    interface Confirmed { void done(boolean ok); }

    interface Probed { void done(boolean ready); }

    /** Boot unlock is tried only this soon after boot (elapsedRealtime). */
    static final long FRESH_BOOT_MS = 10 * 60 * 1000L;
    /** How long the boot attempt waits for Android's lock screen to report the device unlocked. */
    static final long KEYGUARD_WAIT_MS = 4000;
    static final long KEYGUARD_POLL_MS = 250;

    private final Env env;
    /** elapsedRealtime of the last successful device-PIN check (credential mode); 0: none. */
    private long lastCredentialConfirm;
    /** True while a system PIN prompt is on screen, so a re-created gate does not stack another. */
    private boolean credentialPromptOpen;
    /** Session whose boot-time silent unlock attempt is still pending (-1: none). */
    private int bootAttemptSession = -1;
    /** The unlock in progress is the boot-time silent one (its failure is not the user's). */
    private boolean silentUnlockAttempt;

    CredentialGate(Env env) { this.env = env; }

    /**
     * The vault PIN is the Android lock credential; the seed key needs a fresh system check. Decided
     * by VaultPin's persisted credential-mode marker (set once SystemCredential.install succeeded),
     * never by whether an app PIN hash exists.
     */
    static boolean credentialMode(VaultPin pin) { return pin != null && pin.credentialHeld(); }

    /** Installs the PIN as the device credential (true) or not (false). Zeroes the array it is given. */
    interface ChipInstall { boolean install(char[] pin) throws Exception; }

    /**
     * SET PIN: the chip FIRST. Once it holds the PIN the app stores only the credential-mode marker,
     * never a PBKDF2 hash an offline guesser could search; the app hash is the no-chip fallback
     * only. {@code chosen} is zeroed either way, {@code forSystem} by the installer. A crash after
     * install but before the marker is repaired at startup (VaultPin.reconcile).
     *
     * @return true when the chip now holds the PIN
     */
    static boolean storeNewPin(char[] chosen, char[] forSystem, ChipInstall chip, VaultPin pin) throws Exception {
        boolean bound = chip.install(forSystem); // zeroes forSystem
        if (bound) {
            Arrays.fill(chosen, '0');
            pin.markCredentialHeld();
        } else {
            pin.set(chosen); // zeroes the array
        }
        return bound;
    }

    /** The current unlock is the boot-time silent attempt. */
    boolean silentUnlockAttempt() { return silentUnlockAttempt; }

    void endSilentUnlockAttempt() { silentUnlockAttempt = false; }

    /** Our own confirmation can no longer be relied on (the keystore said the window lapsed). */
    void forgetConfirmation() { lastCredentialConfirm = 0; }

    /**
     * Locked gate in credential mode: our screen, the system verifies the PIN.
     *
     * <p>Right after a boot the user has just entered the PIN on Android's lock screen (to unlock
     * encrypted storage), which also opens the seed key's window. The FIRST gate after a boot
     * therefore tries the key before prompting: once per BOOT (BootUnlockGuard, persisted against
     * the boot id, so re-creating the activity cannot re-arm it), and never once the vault has
     * locked since that boot. Any later gate always prompts.
     */
    void show(int s) {
        // The boot attempt below is still waiting for this session: onCreate and onResume both
        // show the gate on a cold start, and a second call would replace the attempt's loading
        // screen with the locked page AND queue the system prompt while the boot lock screen is
        // still animating away (the PIN would be asked a second time). The
        // attempt shows the gate itself if the keystore refuses; a new session (lock) passes.
        if (bootAttemptSession == s) return;
        boolean freshBoot = env.elapsedRealtime() < FRESH_BOOT_MS;
        if (freshBoot && env.bootUnlock().tryConsume(env.bootId())) {
            // The boot lock screen may still be animating away: give it up to 4 s to report the
            // device unlocked, then try the key; if the keystore refuses we come back and prompt.
            // tryConsume committed "used for this boot" before we got here.
            bootAttemptSession = s;
            final long deadline = env.elapsedRealtime() + KEYGUARD_WAIT_MS;
            Runnable attempt = new Runnable() {
                @Override public void run() {
                    if (s != env.session() || env.unlocked()) { bootAttemptSession = -1; return; }
                    if (env.deviceLocked() && env.elapsedRealtime() < deadline) {
                        env.postDelayed(this, KEYGUARD_POLL_MS);
                        return;
                    }
                    bootAttemptSession = -1;
                    silentUnlockAttempt = true;
                    env.unlock(s);
                    if (!env.unlocked()) { silentUnlockAttempt = false; show(env.session()); }
                }
            };
            env.showLoading("Opening your wallet", "Using the PIN you just entered…");
            env.post(attempt);
            return;
        }
        env.showLockedPage(s);
        env.post(() -> { if (!env.unlocked() && s == env.session() && env.foreground()) promptUnlock(s); });
    }

    /** The locked page's Unlock: the system prompt, then unlock if this gate is still current. */
    void promptUnlock(int s) {
        confirmDevicePin("Enter your PIN to unlock", () -> {
            if (s == env.session() && !env.unlocked()) env.unlock(s);
        }, null);
    }

    /** Ask the system to verify the device PIN; one prompt at a time. {@code onCancel} may be null. */
    void confirmDevicePin(String why, Runnable onOk, Runnable onCancel) {
        if (credentialPromptOpen) return;
        credentialPromptOpen = true;
        final int s = env.session();
        env.systemConfirm(why, ok -> {
            credentialPromptOpen = false;
            if (s != env.session() && env.unlocked()) return;
            if (ok) {
                lastCredentialConfirm = env.elapsedRealtime();
                onOk.run();
            } else if (onCancel != null) {
                onCancel.run();
            }
        });
    }

    /**
     * Run {@code op} with the seed key usable: in credential mode ask the system to verify the PIN
     * unless that happened moments ago (inside the key's window, with margin). Old mode: run now.
     * {@code onCancel} (may be null) runs if the PIN prompt is dismissed.
     */
    void withSeedKey(String why, Runnable op, Runnable onCancel) {
        if (!env.credentialMode()) { op.run(); return; }
        SeedKeyWindow.Decision decision = SeedKeyWindow.decide(lastCredentialConfirm, env.elapsedRealtime());
        if (decision == SeedKeyWindow.Decision.RUN) { op.run(); return; }
        // Our own confirmation is near or past the window's end: probing now could pass keystore2
        // and still fail on the chip a moment later (SeedKeyWindow), so ask.
        if (decision == SeedKeyWindow.Decision.ASK) { confirmDevicePin(why, op, onCancel); return; }
        // Ask the chip before asking the person: right after a PIN was set or entered on Android's
        // own screen the key may already be usable, and a second prompt would be pure friction.
        final int s = env.session();
        env.probeSeedKey(ready -> {
            if (s != env.session()) return;
            if (ready) { op.run(); return; }
            confirmDevicePin(why, op, onCancel);
        });
    }
}
