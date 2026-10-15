package dev.phonevault.signer;

import android.content.SharedPreferences;

/**
 * "Check your backup" reminder. Stores only non-secret metadata, in whole days since the epoch:
 * the day of the last successful backup check (written by {@link BackupCheck#record} in the same
 * commit that marks the backup verified), the reminder interval, and a snooze.
 *
 * <p>The vault is offline, so its clock may be wrong. A clock that runs backwards never makes the
 * reminder due (it waits until the clock passes the last check again); a clock that jumps forward
 * can only show the gentle card early, which a check or a snooze dismisses. Nothing here ever blocks
 * receiving or signing, and callers show it only on Home, never during a request.
 */
final class BackupReminder {
    static final String KEY_LAST_DAY = "backup_reminder_last_day_v1";
    static final String KEY_INTERVAL = "backup_reminder_interval_days_v1";
    static final String KEY_SNOOZE_UNTIL = "backup_reminder_snooze_until_day_v1";
    /** Offered on the phone; 0 = off. */
    static final int[] CHOICES = {0, 30, 90, 180};
    static final int DEFAULT_INTERVAL_DAYS = 90;
    static final int SNOOZE_DAYS = 14;
    private static final long DAY_MS = 24L * 60 * 60 * 1000;

    private final SharedPreferences preferences;

    BackupReminder(SharedPreferences preferences) { this.preferences = preferences; }

    static int day(long epochMillis) { return (int) Math.floorDiv(epochMillis, DAY_MS); }

    int intervalDays() {
        int saved = preferences.getInt(KEY_INTERVAL, DEFAULT_INTERVAL_DAYS);
        for (int choice : CHOICES) if (choice == saved) return saved;
        return DEFAULT_INTERVAL_DAYS;
    }

    boolean setIntervalDays(int days) {
        boolean allowed = false;
        for (int choice : CHOICES) allowed |= choice == days;
        if (!allowed) throw new IllegalArgumentException("Unsupported reminder interval");
        return preferences.edit().putInt(KEY_INTERVAL, days).commit();
    }

    /** Day of the last successful check, or -1 when unknown (checked before reminders existed). */
    int lastCheckDay() { return preferences.getInt(KEY_LAST_DAY, -1); }

    /**
     * Whether Home should show the reminder today, for a wallet whose backup is verified. A wallet
     * verified before reminders existed has no recorded day: today becomes its baseline (so an
     * update never greets the user with an immediate nag).
     */
    boolean due(long nowMillis) {
        int interval = intervalDays();
        if (interval == 0) return false;
        int today = day(nowMillis);
        int last = lastCheckDay();
        if (last < 0) {
            preferences.edit().putInt(KEY_LAST_DAY, today).apply();
            return false;
        }
        if (today < last) return false; // clock went backwards: wait, never nag
        if (today < preferences.getInt(KEY_SNOOZE_UNTIL, 0)) return false;
        return today - last >= interval;
    }

    /** "Not now": hide the card for {@link #SNOOZE_DAYS} days. */
    boolean snooze(long nowMillis) {
        return preferences.edit().putInt(KEY_SNOOZE_UNTIL, day(nowMillis) + SNOOZE_DAYS).commit();
    }

    /** Adds the "checked today" fields to an edit that records a successful backup check. */
    static SharedPreferences.Editor markChecked(SharedPreferences.Editor edit, long nowMillis) {
        return edit.putInt(KEY_LAST_DAY, day(nowMillis)).remove(KEY_SNOOZE_UNTIL);
    }

    /** Card headline, e.g. "It's been 3 months: check your backup (2 minutes)". */
    String headline(long nowMillis) {
        int days = Math.max(0, day(nowMillis) - lastCheckDay());
        String since = days >= 60 ? (days / 30) + " months"
                : days >= 28 ? "a month"
                : days >= 14 ? (days / 7) + " weeks"
                : days + (days == 1 ? " day" : " days");
        return "It's been " + since + ": check your backup (2 minutes)";
    }

    /** Settings label for an interval. */
    static String label(int days) {
        return days == 0 ? "Off" : days == 30 ? "Every month" : days == 90 ? "Every 3 months" : "Every 6 months";
    }
}
