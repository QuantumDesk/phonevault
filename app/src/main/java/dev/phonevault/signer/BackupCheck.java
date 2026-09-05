package dev.phonevault.signer;

import android.content.SharedPreferences;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.security.SecureRandom;

/** Full 24-position backup challenge; its persisted completion is bound to the exact account. */
final class BackupCheck {
    private static final String KEY = "backup_checked_address_v1";
    private final SharedPreferences preferences;
    private boolean uncertain;
    BackupCheck(SharedPreferences preferences) { this.preferences = preferences; }
    boolean verified(String address) {
        return !uncertain && address != null && address.toLowerCase(Locale.ROOT).equals(preferences.getString(KEY, ""));
    }
    void record(String address) {
        if (address == null || !address.matches("0x[0-9a-fA-F]{40}"))
            throw new IllegalArgumentException("Invalid backup identity");
        String normalized = address.toLowerCase(Locale.ROOT);
        uncertain = true;
        if (!preferences.edit().putString(KEY, normalized).commit()
                || !normalized.equals(preferences.getString(KEY, "")))
            throw new IllegalStateException("Backup check could not be saved. Check again before receiving.");
        uncertain = false;
    }
    void clear() {
        uncertain = true;
        if (!preferences.edit().remove(KEY).commit() || preferences.getString(KEY, null) != null)
            throw new IllegalStateException("Backup status could not be cleared");
        uncertain = false;
    }

    static final class Challenge {
        private final String[] words;
        private final List<Integer> order = new ArrayList<>();
        private int progress;
        private boolean failed;
        Challenge(String[] words, SecureRandom random) {
            if (words.length != 24) throw new IllegalArgumentException("Expected 24 recovery words");
            this.words = words.clone();
            for (int i = 0; i < words.length; i++) order.add(i);
            Collections.shuffle(order, random);
        }
        int progress() { return progress; }
        int position() {
            if (complete() || failed) throw new IllegalStateException("Challenge is no longer active");
            return order.get(progress);
        }
        boolean answer(String word) {
            if (failed || complete()) return false;
            if (!words[position()].equals(word)) { failed = true; return false; }
            progress++;
            return true;
        }
        boolean complete() { return !failed && progress == 24; }
        void destroy() { Arrays.fill(words, null); failed = true; }
    }
}
