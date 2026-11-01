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
        void systemConfirm(PromptText text, Confirmed result);
        /** Dismiss the open system prompt; its {@code result} then reports a failure. */
        void cancelSystemConfirm();
        /** What the prompt may say about the request held behind the gate (null: none). Under stateLock. */
        HeldRequest.LockPrompt heldPrompt();
        /** On the crypto thread: does the seed key work right now? {@code result} runs on the UI thread. */
        void probeSeedKey(Probed result);
    }

    interface Confirmed { void done(boolean ok); }

    interface Probed { void done(boolean ready); }

    /** The system prompt's own text (BiometricPrompt title, subtitle, optional description). */
    static final class PromptText {
        final String title, subtitle, description;
        /** It tells of a held request (re-shown when that request changes or is dropped). */
        final boolean held;

        PromptText(String title, String subtitle, String description, boolean held) {
            this.title = title;
            this.subtitle = subtitle;
            this.description = description;
            this.held = held;
        }

        @Override public boolean equals(Object o) {
            if (!(o instanceof PromptText)) return false;
            PromptText t = (PromptText) o;
            return held == t.held && title.equals(t.title) && subtitle.equals(t.subtitle)
                    && java.util.Objects.equals(description, t.description);
        }

        @Override public int hashCode() { return java.util.Objects.hash(title, subtitle, description, held); }

        @Override public String toString() { return title + " | " + subtitle + (description == null ? "" : " | " + description); }
    }

    static final String UNLOCK_WHY = "Enter your PIN to unlock";

    /** The prompt of an action (a sensitive screen, the plain unlock): "Phone Vault", why. */
    static PromptText actionText(String why) { return new PromptText("Phone Vault", why, null, false); }

    /**
     * The unlock prompt. With a request held behind the gate it says so, since the prompt covers
     * the locked page and its "INCOMING REQUEST" card (Pixel 6a): who sent it (the validated site,
     * else "your Mac") and its kind only, never an amount, an address or any content.
     */
    static PromptText unlockText(HeldRequest.LockPrompt held) {
        if (held == null) return actionText(UNLOCK_WHY);
        String from = held.site != null ? "From " + held.site + ", via your Mac" : "From your Mac";
        String kind = held.kind == null ? "" : Character.toUpperCase(held.kind.charAt(0)) + held.kind.substring(1) + ". ";
        return new PromptText("Incoming request", from,
                kind + "Unlock to review it. Nothing is signed until you approve it.", true);
    }

    /** Wait after a cancelled prompt before showing its replacement (the old one is still closing). */
    static final long RESHOW_DELAY_MS = 300;
    /** A cancelled prompt that never reported back is treated as closed after this long. */
    static final long CANCEL_GIVE_UP_MS = 2000;

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
    /** The open prompt's text (null when none is open). */
    private PromptText openText;
    /** Counts prompts shown; a result for an older one (given up on after a cancel) is ignored. */
    private int promptGeneration;
    /** The open prompt was cancelled to show the unlock prompt again with the current held request. */
    private boolean reshowAfterCancel;
    /** Session whose boot-time silent unlock attempt is still pending (-1: none). */
    private int bootAttemptSession = -1;
    /** The unlock in progress is the boot-time silent one (its failure is not the user's). */
    private boolean silentUnlockAttempt;
    /** Session whose locked page {@link #show} drew last (-1: none). */
    private int lockedPageSession = -1;

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
        lockedPageSession = s;
        env.showLockedPage(s);
        env.post(() -> { if (!env.unlocked() && s == env.session() && env.foreground()) promptUnlock(s); });
    }

    /** The locked page's Unlock: the system prompt, then unlock if this gate is still current. */
    void promptUnlock(int s) {
        if (credentialPromptOpen) { heldRequestChanged(); return; } // never stacked; its text kept current
        confirm(unlockText(env.heldPrompt()), () -> {
            if (s == env.session() && !env.unlocked()) env.unlock(s);
        }, null);
    }

    /**
     * A request was held or dropped behind the gate (or the gate was drawn again): the open system
     * prompt covers the locked page and its "INCOMING REQUEST" card, so it must say the same
     * (Pixel 6a: only the PIN pad was visible, the request appeared only after unlock).
     * BiometricPrompt's text cannot change while it is up: cancel it and show the unlock prompt
     * again with {@link #unlockText} for what is held now. Only while locked, in the foreground,
     * with the current session's locked page on screen (the page a stale prompt's success unlocks),
     * and only when held-request text is involved: a prompt without one is left as it was. The
     * cancel arrives as a failed confirmation (nothing unlocks, a stale prompt's onCancel runs as
     * for Back); if it never reports back within {@link #CANCEL_GIVE_UP_MS} it is treated as closed
     * and its late result ignored. Nothing here answers or signs anything: the held request is
     * dispatched only by the unlock.
     */
    void heldRequestChanged() {
        if (!credentialPromptOpen || reshowAfterCancel || env.unlocked() || !env.foreground()) return;
        if (lockedPageSession != env.session()) return;
        PromptText want = unlockText(env.heldPrompt());
        if (want.equals(openText) || (!want.held && !openText.held)) return;
        reshowAfterCancel = true;
        final int cancelled = promptGeneration;
        env.cancelSystemConfirm();
        env.postDelayed(() -> {
            if (cancelled != promptGeneration || !credentialPromptOpen || !reshowAfterCancel) return; // it reported back
            promptGeneration++; // its late result, if any, is ignored
            credentialPromptOpen = false;
            openText = null;
            reshowAfterCancel = false;
            reshowUnlock();
        }, CANCEL_GIVE_UP_MS);
    }

    /** After a cancel for new text: the unlock prompt again, if its locked page is still the gate on screen. */
    private void reshowUnlock() {
        int now = env.session();
        if (env.unlocked() || lockedPageSession != now || !env.foreground()) return;
        promptUnlock(now);
    }

    /** The open prompt's text, or null (tests). */
    PromptText openPromptText() { return openText; }

    /** A system PIN prompt of ours is on screen (a second one would not be stacked). */
    boolean promptOpen() { return credentialPromptOpen; }

    /**
     * Ask the system to verify the device PIN; one prompt at a time. {@code onCancel} may be null.
     *
     * <p>A prompt can outlive the session that opened it: a lock while it is up (the screen went
     * off, the idle lock) starts a new session and draws a new locked page, whose own prompt is
     * not stacked on the one still open. A correct PIN in that older prompt was ignored ("stale")
     * and the vault stayed locked with no prompt left (Pixel 6a, a prompt open ~10 minutes). Its
     * own action ({@code onOk}: unlock an old gate, open an old sensitive flow) is still never run
     * for a newer session, but the system has just verified the PIN, so it unlocks the credential
     * locked page that is on screen now, and only that: never a hidden activity
     * (MainActivity#unlock checks), nor a session whose gate is not that page (the boot attempt, a
     * sealed vault's own screen), nor anything once a newer session is unlocked. A dismissed stale
     * prompt leaves that page and its Unlock button.
     */
    void confirmDevicePin(String why, Runnable onOk, Runnable onCancel) { confirm(actionText(why), onOk, onCancel); }

    private void confirm(PromptText text, Runnable onOk, Runnable onCancel) {
        if (credentialPromptOpen) return;
        credentialPromptOpen = true;
        openText = text;
        final int generation = ++promptGeneration;
        final int s = env.session();
        env.systemConfirm(text, ok -> {
            if (generation != promptGeneration || !credentialPromptOpen) return; // given up on after a cancel
            credentialPromptOpen = false;
            openText = null;
            boolean reshow = reshowAfterCancel;
            reshowAfterCancel = false;
            finish(s, ok, onOk, onCancel);
            // Cancelled for new text: show it once the old prompt has gone. A success that beat the
            // cancel has unlocked (or been ignored as stale) above; nothing is shown again then.
            if (reshow && !ok) env.postDelayed(this::reshowUnlock, RESHOW_DELAY_MS);
        });
    }

    /** A prompt of session {@code s} reported back: see {@link #confirmDevicePin}. */
    private void finish(int s, boolean ok, Runnable onOk, Runnable onCancel) {
        if (s != env.session() && env.unlocked()) return;
        if (ok) lastCredentialConfirm = env.elapsedRealtime();
        if (s != env.session()) {
            int now = env.session();
            if (ok && lockedPageSession == now) env.unlock(now);
            else if (!ok && onCancel != null) onCancel.run();
            return;
        }
        if (ok) {
            onOk.run();
        } else if (onCancel != null) {
            onCancel.run();
        }
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
