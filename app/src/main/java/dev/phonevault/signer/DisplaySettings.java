package dev.phonevault.signer;

import android.content.SharedPreferences;

/**
 * Display &amp; comfort preferences (Display &amp; auto-lock): text size, screen timeout, idle lock,
 * haptics. Pure logic over SharedPreferences so the mapping and persistence are JVM-tested; the
 * Android side effects (system setting, theme scale, haptics flag) are applied by the callers.
 *
 * <p>Stored in MainActivity's own {@code getPreferences()} file (named after the activity), which
 * is where {@code large_text} and {@code idle_seconds} have always lived.
 */
final class DisplaySettings {
    /** File name Activity#getPreferences uses for MainActivity (its local class name). */
    static final String PREFS_FILE = "MainActivity";

    static final String KEY_LARGE_TEXT = "large_text";
    static final String KEY_IDLE_SECONDS = "idle_seconds";
    static final String KEY_SCREEN_TIMEOUT_SECONDS = "screen_timeout_seconds";
    static final String KEY_HAPTICS = "haptics";

    /** Screen-off timeout choices. 60 s is the appliance's long-standing default. */
    static final int[] SCREEN_TIMEOUT_CHOICES = {30, 60, 120, 300};
    static final int DEFAULT_SCREEN_TIMEOUT_SECONDS = 60;
    /** Idle-lock choices (no touch while the screen is kept on, e.g. during a review). */
    static final int[] IDLE_CHOICES = {30, 60, 120};
    static final int DEFAULT_IDLE_SECONDS = 120;

    /** One factor scales every text size in VaultTheme. */
    static final float STANDARD_TEXT_SCALE = 1f;
    static final float LARGE_TEXT_SCALE = 1.2f;

    private final SharedPreferences preferences;

    DisplaySettings(SharedPreferences preferences) { this.preferences = preferences; }

    // ---------------------------------------------------------------- text size

    boolean largeText() { return preferences.getBoolean(KEY_LARGE_TEXT, false); }

    boolean setLargeText(boolean large) { return preferences.edit().putBoolean(KEY_LARGE_TEXT, large).commit(); }

    static float textScale(boolean large) { return large ? LARGE_TEXT_SCALE : STANDARD_TEXT_SCALE; }

    /** A base size (sp, as written at the call site) under the given scale, rounded to 0.5 sp. */
    static float scaledSp(float baseSp, float scale) {
        if (!(baseSp > 0f)) return baseSp;
        return Math.round(baseSp * scale * 2f) / 2f;
    }

    // ---------------------------------------------------------------- screen timeout / idle lock

    int screenTimeoutSeconds() { return validScreenTimeout(preferences.getInt(KEY_SCREEN_TIMEOUT_SECONDS, DEFAULT_SCREEN_TIMEOUT_SECONDS)); }

    boolean setScreenTimeoutSeconds(int seconds) {
        if (!contains(SCREEN_TIMEOUT_CHOICES, seconds)) throw new IllegalArgumentException("Unsupported screen timeout");
        return preferences.edit().putInt(KEY_SCREEN_TIMEOUT_SECONDS, seconds).commit();
    }

    /** The value written to Settings.System.SCREEN_OFF_TIMEOUT (milliseconds). */
    int screenTimeoutMs() { return screenTimeoutSeconds() * 1000; }

    int idleSeconds() { return validIdle(preferences.getInt(KEY_IDLE_SECONDS, DEFAULT_IDLE_SECONDS)); }

    boolean setIdleSeconds(int seconds) {
        if (!contains(IDLE_CHOICES, seconds)) throw new IllegalArgumentException("Unsupported idle lock");
        return preferences.edit().putInt(KEY_IDLE_SECONDS, seconds).commit();
    }

    /**
     * The vault's own idle lock. Screen off always locks, so a longer idle lock than the screen
     * timeout would only ever apply on screens that keep the display on (a request review): the
     * effective idle lock is the shorter of the two, so the vault never stays open longer with the
     * screen held on than it would with the screen allowed to sleep.
     */
    long idleLockMs() { return effectiveIdleSeconds(idleSeconds(), screenTimeoutSeconds()) * 1000L; }

    static int effectiveIdleSeconds(int idleSeconds, int screenTimeoutSeconds) {
        return Math.min(validIdle(idleSeconds), validScreenTimeout(screenTimeoutSeconds));
    }

    static int validScreenTimeout(int seconds) {
        return contains(SCREEN_TIMEOUT_CHOICES, seconds) ? seconds : DEFAULT_SCREEN_TIMEOUT_SECONDS;
    }

    static int validIdle(int seconds) { return contains(IDLE_CHOICES, seconds) ? seconds : DEFAULT_IDLE_SECONDS; }

    /** "30 seconds", "1 minute", "2 minutes", "5 minutes". */
    static String durationLabel(int seconds) {
        if (seconds < 60 || seconds % 60 != 0) return seconds + " seconds";
        int minutes = seconds / 60;
        return minutes == 1 ? "1 minute" : minutes + " minutes";
    }

    // ---------------------------------------------------------------- haptics

    boolean haptics() { return preferences.getBoolean(KEY_HAPTICS, true); }

    boolean setHaptics(boolean on) { return preferences.edit().putBoolean(KEY_HAPTICS, on).commit(); }

    private static boolean contains(int[] choices, int value) {
        for (int c : choices) if (c == value) return true;
        return false;
    }
}
