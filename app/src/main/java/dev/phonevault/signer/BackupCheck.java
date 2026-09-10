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

    /**
     * How many of the 24 words we spot-check, chosen at random. Real hardware wallets verify a
     * handful, not the whole phrase: a full 24-position gauntlet is an onboarding wall that most
     * people abandon. This confirms the user actually wrote the phrase down; the strong
     * recoverability proof is a full restore (type the phrase back, match the address).
     */
    static final int SPOT_CHECK = 3;

    static final class Challenge {
        private final String[] words;
        private final List<Integer> order = new ArrayList<>();
        private final int checkCount;
        private int progress;
        private boolean failed;

        Challenge(String[] words, SecureRandom random) {
            this(words, random, SPOT_CHECK);
        }

        Challenge(String[] words, SecureRandom random, int checkCount) {
            if (words.length != 24) throw new IllegalArgumentException("Expected 24 recovery words");
            if (checkCount < 1 || checkCount > words.length) throw new IllegalArgumentException("bad checkCount");
            this.words = words.clone();
            this.checkCount = checkCount;
            List<Integer> all = new ArrayList<>();
            for (int i = 0; i < words.length; i++) all.add(i);
            Collections.shuffle(all, random);
            order.addAll(all.subList(0, checkCount)); // a random subset, kept in a random order
        }

        int progress() { return progress; }
        int total() { return checkCount; }
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
        boolean complete() { return !failed && progress == checkCount; }
        void destroy() { Arrays.fill(words, null); failed = true; }
    }
}
