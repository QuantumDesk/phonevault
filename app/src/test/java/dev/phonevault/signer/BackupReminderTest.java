package dev.phonevault.signer;

import static org.junit.Assert.*;

import org.junit.Test;

public class BackupReminderTest {
    private static final long DAY = 24L * 60 * 60 * 1000;
    private static final long T0 = 20_000L * DAY + 5 * 60 * 60 * 1000L; // an arbitrary day, 05:00 UTC
    private static final String ADDRESS = "0x1111111111111111111111111111111111111111";

    @Test public void dueEveryNinetyDaysByDefaultAfterACheck() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        BackupReminder reminder = new BackupReminder(prefs);
        assertEquals(90, reminder.intervalDays());
        BackupReminder.markChecked(prefs.edit(), T0).commit();
        assertFalse(reminder.due(T0));
        assertFalse(reminder.due(T0 + 89 * DAY));
        assertTrue(reminder.due(T0 + 90 * DAY));
        assertEquals("It's been 3 months: check your backup (2 minutes)", reminder.headline(T0 + 90 * DAY));
    }

    @Test public void aSuccessfulBackupCheckRestartsTheInterval() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        BackupReminder reminder = new BackupReminder(prefs);
        BackupReminder.markChecked(prefs.edit(), T0).commit();
        assertTrue(reminder.due(T0 + 100 * DAY));
        new BackupCheck(prefs).record(ADDRESS); // the real spot-check path, with today's clock
        assertEquals(BackupReminder.day(System.currentTimeMillis()), reminder.lastCheckDay());
        assertFalse(reminder.due(System.currentTimeMillis()));
    }

    @Test public void snoozeHidesForTwoWeeksAndACheckClearsIt() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        BackupReminder reminder = new BackupReminder(prefs);
        BackupReminder.markChecked(prefs.edit(), T0).commit();
        long dueAt = T0 + 95 * DAY;
        assertTrue(reminder.due(dueAt));
        assertTrue(reminder.snooze(dueAt));
        assertFalse(reminder.due(dueAt));
        assertFalse(reminder.due(dueAt + 13 * DAY));
        assertTrue(reminder.due(dueAt + 14 * DAY));
        reminder.snooze(dueAt + 14 * DAY);
        BackupReminder.markChecked(prefs.edit(), dueAt + 15 * DAY).commit();
        assertEquals(-1, prefs.getInt(BackupReminder.KEY_SNOOZE_UNTIL, -1));
        assertTrue(reminder.due(dueAt + 15 * DAY + 90 * DAY));
    }

    @Test public void intervalIsConfigurableAndOffNeverNags() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        BackupReminder reminder = new BackupReminder(prefs);
        BackupReminder.markChecked(prefs.edit(), T0).commit();
        assertTrue(reminder.setIntervalDays(30));
        assertTrue(reminder.due(T0 + 30 * DAY));
        assertEquals("It's been a month: check your backup (2 minutes)", reminder.headline(T0 + 30 * DAY));
        assertTrue(reminder.setIntervalDays(180));
        assertFalse(reminder.due(T0 + 179 * DAY));
        assertTrue(reminder.due(T0 + 180 * DAY));
        assertEquals("It's been 6 months: check your backup (2 minutes)", reminder.headline(T0 + 180 * DAY));
        assertTrue(reminder.setIntervalDays(0));
        assertFalse(reminder.due(T0 + 5000 * DAY));
        try { reminder.setIntervalDays(45); fail(); } catch (IllegalArgumentException expected) { }
        prefs.edit().putInt(BackupReminder.KEY_INTERVAL, 7).commit(); // corrupt value → default
        assertEquals(BackupReminder.DEFAULT_INTERVAL_DAYS, reminder.intervalDays());
    }

    @Test public void walletVerifiedBeforeRemindersGetsTodayAsBaseline() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        BackupReminder reminder = new BackupReminder(prefs);
        assertEquals(-1, reminder.lastCheckDay());
        assertFalse("no immediate nag after an update", reminder.due(T0));
        assertEquals(BackupReminder.day(T0), reminder.lastCheckDay());
        assertTrue(reminder.due(T0 + 90 * DAY));
    }

    @Test public void clockGoingBackwardsNeverNags() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        BackupReminder reminder = new BackupReminder(prefs);
        BackupReminder.markChecked(prefs.edit(), T0).commit();
        assertFalse(reminder.due(T0 - 400 * DAY));
        assertFalse(reminder.due(0));
        assertEquals(BackupReminder.day(T0), reminder.lastCheckDay());
    }
}
