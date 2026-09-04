package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.SharedPreferences;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/** Adversarial tests for the PIN gate: attempt limit, verified erase, fail-closed erase. */
public class VaultPinTest {
    private static final int FAST_ITERATIONS = 1000;

    private static char[] pin(String s) { return s.toCharArray(); }

    private static VaultPin fresh(SharedPreferences prefs) throws Exception {
        VaultPin p = new VaultPin(prefs, FAST_ITERATIONS);
        p.set(pin("123456"));
        return p;
    }

    @Test public void correctPinUnlocksAndResetsCounter() throws Exception {
        FakePrefs prefs = new FakePrefs();
        VaultPin p = fresh(prefs);
        assertEquals(VaultPin.Outcome.WRONG, p.verify(pin("000000"), null).outcome);
        assertEquals(VaultPin.MAX_ATTEMPTS - 1, p.attemptsRemaining());
        assertEquals(VaultPin.Outcome.OK, p.verify(pin("123456"), null).outcome);
        assertEquals(VaultPin.MAX_ATTEMPTS, p.attemptsRemaining());
    }

    @Test public void tenthWrongAttemptErasesAndClearsPin() throws Exception {
        FakePrefs prefs = new FakePrefs();
        VaultPin p = fresh(prefs);
        AtomicInteger erased = new AtomicInteger();
        VaultPin.Result last = null;
        for (int i = 0; i < VaultPin.MAX_ATTEMPTS; i++) {
            last = p.verify(pin("999999"), erased::incrementAndGet);
        }
        assertEquals(VaultPin.Outcome.WIPED, last.outcome);
        assertEquals(1, erased.get());
        assertFalse("PIN must be cleared after a verified erase", p.isSet());
        assertFalse(p.eraseOutstanding());
    }

    @Test public void failedEraseKeepsPinAndBlocksFurtherGuesses() throws Exception {
        FakePrefs prefs = new FakePrefs();
        VaultPin p = fresh(prefs);
        VaultPin.Eraser broken = () -> { throw new IllegalStateException("keystore unavailable"); };
        VaultPin.Result last = null;
        for (int i = 0; i < VaultPin.MAX_ATTEMPTS; i++) {
            last = p.verify(pin("999999"), broken);
        }
        assertEquals(VaultPin.Outcome.ERASE_FAILED, last.outcome);
        assertTrue("PIN must survive a failed erase (fail closed)", p.isSet());
        assertTrue(p.eraseOutstanding());
        // Even the CORRECT pin no longer unlocks: the only thing that can happen now is an erase.
        assertEquals(VaultPin.Outcome.ERASE_FAILED, p.verify(pin("123456"), broken).outcome);
        assertTrue(p.isSet());
        // Once the erase succeeds, the gate resets.
        AtomicInteger erased = new AtomicInteger();
        assertEquals(VaultPin.Outcome.WIPED, p.verify(pin("000000"), erased::incrementAndGet).outcome);
        assertEquals(1, erased.get());
        assertFalse(p.isSet());
    }

    @Test public void attemptIsCountedBeforeComparison() throws Exception {
        FakePrefs prefs = new FakePrefs();
        VaultPin p = fresh(prefs);
        prefs.failAtCommit = prefs.commits + 1; // the very next commit = the pre-check counter write
        try {
            p.verify(pin("123456"), null);
            throw new AssertionError("verify must refuse when the attempt cannot be recorded");
        } catch (IllegalStateException expected) {
            // ok
        }
    }

    @Test public void failedCounterResetIsNotReportedAsSuccess() throws Exception {
        FakePrefs prefs = new FakePrefs();
        VaultPin p = fresh(prefs);
        assertEquals(VaultPin.Outcome.WRONG, p.verify(pin("000000"), null).outcome);
        // verify() commits twice on a correct PIN: counter++ then counter=0. Fail the reset.
        prefs.failAtCommit = prefs.commits + 2;
        try {
            p.verify(pin("123456"), null);
            throw new AssertionError("a failed counter reset must not unlock");
        } catch (IllegalStateException expected) {
            // ok
        }
        assertEquals("counter stays elevated (2 wrong-equivalent attempts recorded)",
                VaultPin.MAX_ATTEMPTS - 2, p.attemptsRemaining());
        // With storage healthy again the correct PIN unlocks and resets.
        assertEquals(VaultPin.Outcome.OK, p.verify(pin("123456"), null).outcome);
        assertEquals(VaultPin.MAX_ATTEMPTS, p.attemptsRemaining());
    }

    @Test public void rejectsMalformedPins() throws Exception {
        VaultPin p = new VaultPin(new FakePrefs(), FAST_ITERATIONS);
        for (String bad : new String[] {"12345", "1234567", "12a456", ""}) {
            try {
                p.set(pin(bad));
                throw new AssertionError("accepted malformed PIN: " + bad);
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        assertFalse(p.isSet());
    }

    @Test public void verifyZeroesTheSuppliedPin() throws Exception {
        VaultPin p = fresh(new FakePrefs());
        char[] entered = pin("123456");
        p.verify(entered, null);
        for (char c : entered) assertEquals('0', c);
    }

    /** Minimal in-memory SharedPreferences (only what VaultPin touches). */
    static final class FakePrefs implements SharedPreferences {
        final Map<String, Object> map = new HashMap<>();
        int commits;          // commits attempted so far
        int failAtCommit = -1; // the Nth commit (1-based) returns false

        @Override public Map<String, ?> getAll() { return map; }
        @Override public String getString(String k, String d) { Object v = map.get(k); return v == null ? d : (String) v; }
        @Override public Set<String> getStringSet(String k, Set<String> d) { return d; }
        @Override public int getInt(String k, int d) { Object v = map.get(k); return v == null ? d : (Integer) v; }
        @Override public long getLong(String k, long d) { return d; }
        @Override public float getFloat(String k, float d) { return d; }
        @Override public boolean getBoolean(String k, boolean d) { return d; }
        @Override public boolean contains(String k) { return map.containsKey(k); }
        @Override public Editor edit() { return new FakeEditor(); }
        @Override public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener l) {}
        @Override public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener l) {}

        final class FakeEditor implements Editor {
            final Map<String, Object> puts = new HashMap<>();
            final Set<String> removes = new java.util.HashSet<>();
            boolean clearAll;
            @Override public Editor putString(String k, String v) { puts.put(k, v); return this; }
            @Override public Editor putStringSet(String k, Set<String> v) { return this; }
            @Override public Editor putInt(String k, int v) { puts.put(k, v); return this; }
            @Override public Editor putLong(String k, long v) { return this; }
            @Override public Editor putFloat(String k, float v) { return this; }
            @Override public Editor putBoolean(String k, boolean v) { return this; }
            @Override public Editor remove(String k) { removes.add(k); return this; }
            @Override public Editor clear() { clearAll = true; return this; }
            @Override public boolean commit() {
                commits++;
                if (commits == failAtCommit) return false;
                if (clearAll) map.clear();
                for (String k : removes) map.remove(k);
                map.putAll(puts);
                return true;
            }
            @Override public void apply() { commit(); }
        }
    }
}
