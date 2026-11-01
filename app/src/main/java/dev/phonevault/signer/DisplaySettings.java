package dev.phonevault.signer;

import android.content.SharedPreferences;

/**
 * Display &amp; comfort preferences (Display &amp; auto-lock): text size, brightness, screen timeout,
 * idle lock, lock after screen off, haptics. Pure logic over SharedPreferences so the mapping and persistence are JVM-tested; the
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
    static final String KEY_SCREEN_OFF_GRACE_SECONDS = "screen_off_grace_seconds";
    static final String KEY_BRIGHTNESS_PERCENT = "brightness_percent";
    static final String KEY_BRIGHTNESS_AUTO = "brightness_auto";

    /**
     * Screen-off timeout choices. 2 minutes is the default from beta5 on (it was 60 s): a phone
     * whose owner saved a choice keeps it, since only an absent key falls back to the default.
     */
    static final int[] SCREEN_TIMEOUT_CHOICES = {30, 60, 120, 300, 600};
    static final int DEFAULT_SCREEN_TIMEOUT_SECONDS = 120;
    /** Idle-lock choices (no touch while the screen is on, e.g. kept on during a review). */
    static final int[] IDLE_CHOICES = {30, 60, 120, 300, 600};
    static final int DEFAULT_IDLE_SECONDS = 120;
    /**
     * Lock after screen off: at once (0, the default), 30 s or 1 minute, never longer. Inside that
     * window waking the phone does not ask for the PIN (ScreenOffLock has the rules).
     */
    static final int[] SCREEN_OFF_GRACE_CHOICES = {0, 30, 60};
    static final int DEFAULT_SCREEN_OFF_GRACE_SECONDS = 0;
    static final int MAX_SCREEN_OFF_GRACE_SECONDS = 60;
    /** What Display &amp; auto-lock shows while a grace window is chosen. */
    static final String GRACE_WARNING = "Anyone who picks up the phone in this time can open it without the PIN. "
            + "Signing still needs your approval on screen.";

    /** Brightness slider range (percent of the panel's range); 0 is never written (a black screen). */
    static final int MIN_BRIGHTNESS_PERCENT = 1;
    static final int MAX_BRIGHTNESS_PERCENT = 100;
    /** Settings.System.SCREEN_BRIGHTNESS range. */
    static final int MAX_SYSTEM_BRIGHTNESS = 255;
    /** Settings.System.SCREEN_BRIGHTNESS_MODE values (MANUAL, AUTOMATIC). */
    static final int BRIGHTNESS_MODE_MANUAL = 0;
    static final int BRIGHTNESS_MODE_AUTOMATIC = 1;

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
     * The vault's own idle lock (no touch while the screen is on). With "Lock after screen off" at
     * once, screen off locks, so a longer idle lock than the screen timeout only ever applies on
     * screens that keep the display on (a request review): the effective idle lock is the shorter
     * of the two, so the vault never stays open longer with the screen held on than it would with
     * the screen allowed to sleep. With a grace window the vault may stay open for the screen
     * timeout plus the grace when the screen sleeps, and the idle lock keeps that bound.
     *
     * @param screenHeldOn a screen keeps the display on (a review: the keep-screen-on window flag)
     */
    long idleLockMs(boolean screenHeldOn) {
        return effectiveIdleSeconds(idleSeconds(), screenTimeoutSeconds(), screenOffGraceSeconds(), screenHeldOn) * 1000L;
    }

    /** As {@link #idleLockMs(boolean)} with the display allowed to sleep. */
    long idleLockMs() { return idleLockMs(false); }

    static int effectiveIdleSeconds(int idleSeconds, int screenTimeoutSeconds) {
        return effectiveIdleSeconds(idleSeconds, screenTimeoutSeconds, 0, false);
    }

    /**
     * An idle lock shorter than the screen timeout always applies as chosen. Otherwise the screen
     * goes off first (its own lock path, after the grace, takes over), so the idle lock is the
     * bound the screen-off path would give: the screen timeout plus the grace, and never longer
     * than the chosen idle lock while a screen holds the display on. With no grace this is the
     * shorter of the two, as before.
     */
    static int effectiveIdleSeconds(int idleSeconds, int screenTimeoutSeconds, int graceSeconds, boolean screenHeldOn) {
        int idle = validIdle(idleSeconds);
        int screen = validScreenTimeout(screenTimeoutSeconds);
        int grace = validGrace(graceSeconds);
        if (idle < screen) return idle;
        return screenHeldOn ? Math.min(idle, screen + grace) : screen + grace;
    }

    // ---------------------------------------------------------------- lock after screen off

    int screenOffGraceSeconds() {
        return validGrace(preferences.getInt(KEY_SCREEN_OFF_GRACE_SECONDS, DEFAULT_SCREEN_OFF_GRACE_SECONDS));
    }

    boolean setScreenOffGraceSeconds(int seconds) {
        if (!contains(SCREEN_OFF_GRACE_CHOICES, seconds)) throw new IllegalArgumentException("Unsupported lock delay");
        return preferences.edit().putInt(KEY_SCREEN_OFF_GRACE_SECONDS, seconds).commit();
    }

    /** A stored value that is not a choice (corrupt, or from a later build) locks at once. */
    static int validGrace(int seconds) {
        return contains(SCREEN_OFF_GRACE_CHOICES, seconds) && seconds <= MAX_SCREEN_OFF_GRACE_SECONDS ? seconds : 0;
    }

    /** "Immediately", "30 seconds", "1 minute". */
    static String graceLabel(int seconds) { return seconds <= 0 ? "Immediately" : durationLabel(seconds); }

    // ---------------------------------------------------------------- brightness

    /** The owner chose a brightness here (until then the phone's own setting is left alone). */
    boolean brightnessChosen() {
        return preferences.contains(KEY_BRIGHTNESS_PERCENT) || preferences.contains(KEY_BRIGHTNESS_AUTO);
    }

    /** Slider position, 1..100 (default 50 until chosen). */
    int brightnessPercent() { return clampPercent(preferences.getInt(KEY_BRIGHTNESS_PERCENT, 50)); }

    boolean brightnessAuto() { return preferences.getBoolean(KEY_BRIGHTNESS_AUTO, false); }

    /** Save a manual level: Automatic goes off. */
    boolean setBrightnessPercent(int percent) {
        return preferences.edit().putInt(KEY_BRIGHTNESS_PERCENT, clampPercent(percent))
                .putBoolean(KEY_BRIGHTNESS_AUTO, false).commit();
    }

    boolean setBrightnessAuto(boolean auto) {
        return preferences.edit().putBoolean(KEY_BRIGHTNESS_AUTO, auto)
                .putInt(KEY_BRIGHTNESS_PERCENT, brightnessPercent()).commit();
    }

    static int clampPercent(int percent) {
        return Math.max(MIN_BRIGHTNESS_PERCENT, Math.min(MAX_BRIGHTNESS_PERCENT, percent));
    }

    /** Settings.System.SCREEN_BRIGHTNESS for a slider position: 1..100 % onto 1..255, never 0. */
    static int systemBrightness(int percent) {
        int p = clampPercent(percent);
        return Math.max(1, Math.round(p * MAX_SYSTEM_BRIGHTNESS / 100f));
    }

    /** The slider position a system value shows (the inverse of {@link #systemBrightness}). */
    static int percentForSystem(int value) {
        int v = Math.max(1, Math.min(MAX_SYSTEM_BRIGHTNESS, value));
        return clampPercent(Math.round(v * 100f / MAX_SYSTEM_BRIGHTNESS));
    }

    /** WindowManager.LayoutParams#screenBrightness for the fallback (not device owner): 0..1. */
    static float windowBrightness(int percent) { return systemBrightness(percent) / (float) MAX_SYSTEM_BRIGHTNESS; }

    /** Settings.System.SCREEN_BRIGHTNESS_MODE for the saved choice. */
    int systemBrightnessMode() { return brightnessAuto() ? BRIGHTNESS_MODE_AUTOMATIC : BRIGHTNESS_MODE_MANUAL; }

    static int validScreenTimeout(int seconds) {
        return contains(SCREEN_TIMEOUT_CHOICES, seconds) ? seconds : DEFAULT_SCREEN_TIMEOUT_SECONDS;
    }

    static int validIdle(int seconds) { return contains(IDLE_CHOICES, seconds) ? seconds : DEFAULT_IDLE_SECONDS; }

    /** "30 seconds", "1 minute", "2 minutes", "5 minutes", "10 minutes". */
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
