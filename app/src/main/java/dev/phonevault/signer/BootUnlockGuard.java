package dev.phonevault.signer;

import android.content.SharedPreferences;

/**
 * The credential-mode boot shortcut (no second PIN prompt right after Android's own boot lock
 * screen) may run AT MOST ONCE PER BOOT, and never after the vault has locked since that boot.
 * Both facts are persisted against the boot id ({@code Settings.Global.BOOT_COUNT}), so an
 * activity re-creation (keyboard attach, uiMode change, process restart) cannot re-arm it.
 *
 * <p>An unknown boot id (negative) never allows the shortcut: the user is simply prompted.
 */
final class BootUnlockGuard {
    static final String USED = "boot_silent_unlock_used_v1";
    static final String LOCKED = "boot_locked_since_v1";

    private final SharedPreferences preferences;

    BootUnlockGuard(SharedPreferences preferences) { this.preferences = preferences; }

    /**
     * True (and the attempt is recorded, committed BEFORE returning) if this boot's single silent
     * attempt is still available. A failed commit refuses the attempt.
     */
    synchronized boolean tryConsume(int bootId) {
        if (bootId < 0) return false;
        if (preferences.getInt(USED, -1) == bootId || preferences.getInt(LOCKED, -1) == bootId) return false;
        return preferences.edit().putInt(USED, bootId).commit();
    }

    /** Any lock of an operational vault disarms the shortcut for the rest of this boot. */
    synchronized void noteLock(int bootId) {
        if (bootId < 0 || preferences.getInt(LOCKED, -1) == bootId) return;
        preferences.edit().putInt(LOCKED, bootId).commit(); // best effort; USED still bounds it to one try
    }
}
