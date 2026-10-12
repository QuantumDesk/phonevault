package dev.phonevault.signer;

/**
 * When may the app use the credential-bound seed key without asking for the PIN first?
 *
 * <p>Two clocks decide whether the key works, and they disagree near the end of the window
 * (StrongBox, phone 2, 2026-10-11): keystore2 admits {@code Cipher.init} by how long ago it
 * <em>received</em> the auth token, in whole seconds (a token re-delivered when the prompt closes
 * makes it look ~0.4 s younger, and truncation adds up to 1 s more), while the Titan M refuses the
 * first update/finish from the token's <em>issue</em> time and the secure-clock timestamp, in
 * milliseconds. Between about 29.6 s and 31 s after the PIN the init succeeds and the decrypt then
 * fails with KEY_USER_NOT_AUTHENTICATED. So: when this app confirmed the PIN itself it knows how old
 * the window is and never probes it near the edge; it probes only when the PIN was entered
 * somewhere it cannot see (Android's boot lock screen, the first PIN install). The keystore stays
 * the authority either way; this only chooses between "go", "ask" and "ask the chip first".
 */
final class SeedKeyWindow {
    /** Use a confirmation only while this much of the window is left for the operation itself. */
    static final long SAFETY_MARGIN_MS = 8_000L;
    static final long USE_WITHOUT_ASKING_MS = SystemCredential.AUTH_WINDOW_SECONDS * 1000L - SAFETY_MARGIN_MS;

    enum Decision {
        /** This app confirmed the PIN moments ago: run the operation. */
        RUN,
        /** This app's own confirmation is too old to rely on: ask for the PIN. */
        ASK,
        /** No confirmation seen by this app (boot unlock, fresh PIN): ask the chip, then decide. */
        PROBE
    }

    private SeedKeyWindow() {}

    /**
     * @param lastConfirmMs elapsed-realtime of this app's last successful PIN confirmation, 0 if none
     * @param nowMs         elapsed-realtime now
     */
    static Decision decide(long lastConfirmMs, long nowMs) {
        if (lastConfirmMs <= 0) return Decision.PROBE;
        long age = nowMs - lastConfirmMs;
        return age >= 0 && age < USE_WITHOUT_ASKING_MS ? Decision.RUN : Decision.ASK;
    }
}
