package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * The credential-mode gate (CredentialGate), driven through a fake activity. The phone-only race
 * it guards: on a cold start after the boot PIN, onCreate and onResume both show the credential
 * gate. A second call must not replace the boot attempt's loading screen with the locked page and
 * queue the system PIN prompt while Android's lock screen is still going away, or the vault asks
 * for the PIN a second time. Also: the boot shortcut is once per boot, the device-PIN prompt never
 * stacks, the seed-key window decision, and the held request's binding to its connection.
 */
public class CredentialGateTest {
    private static final long BOOT = 60_000L; // a minute after boot

    /** The activity side: records what the gate asked for; unlock succeeds when {@link #unlockWorks}. */
    static final class FakeEnv implements CredentialGate.Env {
        int session = 1;
        boolean unlocked, foreground = true, credentialMode = true, deviceLocked, unlockWorks = true;
        long now = BOOT;
        int bootId = 7;
        BootUnlockGuard guard = new BootUnlockGuard(new VaultPinTest.FakePrefs());
        final Deque<Runnable> posted = new ArrayDeque<>();
        final List<Long> delays = new ArrayList<>();
        final List<String> events = new ArrayList<>();
        final Deque<CredentialGate.Confirmed> prompts = new ArrayDeque<>();
        final Deque<CredentialGate.Probed> probes = new ArrayDeque<>();
        boolean silentDuringUnlock;
        CredentialGate gate;

        @Override public int session() { return session; }
        @Override public boolean unlocked() { return unlocked; }
        @Override public boolean foreground() { return foreground; }
        @Override public boolean credentialMode() { return credentialMode; }
        @Override public long elapsedRealtime() { return now; }
        @Override public int bootId() { return bootId; }
        @Override public BootUnlockGuard bootUnlock() { return guard; }
        @Override public boolean deviceLocked() { return deviceLocked; }
        @Override public void post(Runnable r) { posted.add(r); delays.add(0L); }
        @Override public void postDelayed(Runnable r, long delayMs) { posted.add(r); delays.add(delayMs); }
        @Override public void showLoading(String title, String caption) { events.add("loading"); }
        @Override public void showLockedPage(int s) { events.add("locked:" + s); }
        @Override public void unlock(int s) {
            events.add("unlock:" + s);
            silentDuringUnlock = gate.silentUnlockAttempt();
            if (unlockWorks && s == session) unlocked = true;
        }
        @Override public void systemConfirm(String why, CredentialGate.Confirmed result) { events.add("prompt:" + why); prompts.add(result); }
        @Override public void probeSeedKey(CredentialGate.Probed result) { events.add("probe"); probes.add(result); }

        /** Run everything posted so far (and what that posts), like the UI looper. */
        void drain() { while (!posted.isEmpty()) posted.poll().run(); }

        long count(String prefix) { return events.stream().filter(e -> e.startsWith(prefix)).count(); }
    }

    private static FakeEnv env() {
        FakeEnv e = new FakeEnv();
        e.gate = new CredentialGate(e);
        return e;
    }

    @Test public void pendingBootAttemptIsNotReplacedByASecondGate() {
        FakeEnv e = env();
        e.gate.show(1);                       // onCreate
        assertEquals(List.of("loading"), e.events);
        e.gate.show(1);                       // onResume, same session, attempt still pending
        assertEquals("no locked page, no prompt while the boot attempt is pending", List.of("loading"), e.events);
        e.drain();
        assertTrue(e.unlocked);
        assertTrue("the unlock knows it is the silent one", e.silentDuringUnlock);
        assertEquals(0, e.count("locked"));
        assertEquals(0, e.count("prompt"));
    }

    @Test public void failedBootAttemptReleasesTheGuardAndPromptsOnce() {
        FakeEnv e = env();
        e.unlockWorks = false;
        e.gate.show(1);
        e.drain();
        assertFalse(e.unlocked);
        assertFalse("released on failure", e.gate.silentUnlockAttempt());
        assertEquals(1, e.count("locked:1"));
        assertEquals("the locked page offers the system prompt once", 1, e.count("prompt:Enter your PIN to unlock"));
        e.gate.show(1); // a later gate of the same session is not blocked any more: the attempt ended
        assertEquals(2, e.count("locked:1"));
    }

    @Test public void bootAttemptWaitsForTheLockScreenThenTries() {
        FakeEnv e = env();
        e.deviceLocked = true;
        e.gate.show(1);
        e.posted.poll().run();                // first try: keyguard still up
        assertEquals("polled again", 1, e.posted.size());
        assertEquals(Long.valueOf(CredentialGate.KEYGUARD_POLL_MS), e.delays.get(e.delays.size() - 1));
        assertEquals(0, e.count("unlock"));
        e.now += CredentialGate.KEYGUARD_WAIT_MS; // deadline passed: try the key anyway
        e.drain();
        assertEquals(1, e.count("unlock:1"));
    }

    @Test public void lockBeforeTheAttemptRunsAbandonsIt() {
        FakeEnv e = env();
        e.gate.show(1);
        e.session = 2;                        // lock(): new session
        e.drain();
        assertEquals(0, e.count("unlock"));
        e.gate.show(2);                       // the boot shortcut is spent: the next gate prompts
        assertEquals(1, e.count("locked:2"));
    }

    @Test public void bootShortcutIsOncePerBootAndOnlyRightAfterBoot() {
        FakeEnv e = env();
        e.gate.show(1);
        e.drain();
        e.unlocked = false;
        e.session = 2;
        e.gate.show(2);
        assertEquals("a second gate this boot prompts", 1, e.count("locked:2"));

        FakeEnv late = env();
        late.now = CredentialGate.FRESH_BOOT_MS;
        late.gate.show(1);
        assertEquals(List.of("locked:1"), late.events);
        assertTrue("not consumed when too late after boot", late.guard.tryConsume(late.bootId));

        FakeEnv locked = env();
        locked.guard.noteLock(locked.bootId); // lock() this boot
        locked.gate.show(1);
        assertEquals(List.of("locked:1"), locked.events);

        FakeEnv unknownBoot = env();
        unknownBoot.bootId = -1;
        unknownBoot.gate.show(1);
        assertEquals(List.of("locked:1"), unknownBoot.events);
    }

    @Test public void lockedPagePromptsOnlyForTheVisibleCurrentGate() {
        FakeEnv e = env();
        e.now = CredentialGate.FRESH_BOOT_MS + 1;
        e.foreground = false;
        e.gate.show(1);
        e.drain();
        assertEquals(0, e.count("prompt"));
        e.foreground = true;
        e.gate.show(1);
        e.session = 2;
        e.drain();
        assertEquals("stale gate", 0, e.count("prompt"));
    }

    @Test public void devicePinPromptNeverStacksAndIgnoresStaleResults() {
        FakeEnv e = env();
        int[] ok = {0}, cancel = {0};
        e.gate.confirmDevicePin("why", () -> ok[0]++, () -> cancel[0]++);
        e.gate.confirmDevicePin("again", () -> ok[0]++, () -> cancel[0]++);
        assertEquals("one prompt at a time", 1, e.prompts.size());
        e.prompts.poll().done(false);
        assertEquals(1, cancel[0]);
        e.gate.confirmDevicePin("why", () -> ok[0]++, null);
        e.prompts.poll().done(true);
        assertEquals(1, ok[0]);

        // A prompt from an older session that finishes while a newer session is unlocked does nothing.
        e.gate.confirmDevicePin("why", () -> ok[0]++, () -> cancel[0]++);
        e.session = 5;
        e.unlocked = true;
        e.prompts.poll().done(true);
        assertEquals(1, ok[0]);
        assertEquals(1, cancel[0]);
    }

    @Test public void unlockPromptUnlocksOnlyTheCurrentLockedSession() {
        FakeEnv e = env();
        e.gate.promptUnlock(1);
        e.prompts.poll().done(true);
        assertEquals(1, e.count("unlock:1"));
        FakeEnv stale = env();
        stale.gate.promptUnlock(1);
        stale.session = 2;
        stale.prompts.poll().done(true);
        assertEquals(0, stale.count("unlock"));
    }

    // ---------------------------------------------------------------- seed-key window

    @Test public void withSeedKeyRunsAtOnceOutsideCredentialMode() {
        FakeEnv e = env();
        e.credentialMode = false;
        int[] ran = {0};
        e.gate.withSeedKey("why", () -> ran[0]++, null);
        assertEquals(1, ran[0]);
        assertTrue(e.events.isEmpty());
    }

    @Test public void withSeedKeyUsesTheWindowDecision() {
        FakeEnv e = env();
        int[] ran = {0};
        // No own confirmation yet: ask the chip first, prompt only if it refuses.
        e.gate.withSeedKey("why", () -> ran[0]++, null);
        assertEquals(List.of("probe"), e.events);
        e.probes.poll().done(false);
        assertEquals(1, e.count("prompt:why"));
        e.prompts.poll().done(true);       // own confirmation now
        assertEquals(1, ran[0]);

        // Fresh own confirmation: run without asking.
        e.now += 1_000;
        e.gate.withSeedKey("why", () -> ran[0]++, null);
        assertEquals(2, ran[0]);
        assertEquals(1, e.count("probe"));

        // An own, stale confirmation must prompt, not probe (the chip may refuse a moment later).
        e.now += SeedKeyWindow.USE_WITHOUT_ASKING_MS;
        e.gate.withSeedKey("why", () -> ran[0]++, null);
        assertEquals("never probes near the edge", 1, e.count("probe"));
        assertEquals(2, e.count("prompt:why"));

        // A lapsed window reported by the keystore forgets the confirmation: back to probing.
        e.prompts.poll().done(true);
        e.gate.forgetConfirmation();
        e.gate.withSeedKey("why", () -> ran[0]++, null);
        assertEquals(2, e.count("probe"));
    }

    @Test public void probeResultForAnOldSessionIsDropped() {
        FakeEnv e = env();
        int[] ran = {0};
        e.gate.withSeedKey("why", () -> ran[0]++, null);
        e.session = 2;
        e.probes.poll().done(true);
        assertEquals(0, ran[0]);
        assertEquals(0, e.count("prompt"));
    }

    // ---------------------------------------------------------------- held request

    private static AccessoryTransport transport() {
        return AccessoryTransport.openForTest(() -> { }, new ByteArrayInputStream(new byte[0]), new ByteArrayOutputStream(),
                new AccessoryTransport.Listener() {
                    @Override public void onConnected(AccessoryTransport source) { }
                    @Override public void onRequest(AccessoryTransport source, JSONObject request) { }
                    @Override public void onDisconnected(AccessoryTransport source, String reason) { }
                });
    }

    /**
     * A request held behind the lock is bound to the connection it arrived on: a new connection or
     * that connection's disconnect drops it, and unlock dispatches it only to that same live session.
     */
    @Test public void heldRequestIsBoundToItsConnection() throws Exception {
        AccessoryTransport a = transport(), b = transport();
        JSONObject json = new JSONObject().put("id", "1").put("method", "getAddress");
        HeldRequest held = new HeldRequest();
        assertFalse("never while unlocked", held.holdIfLocked(true, a, a, json, "s"));
        assertFalse("only from the live connection", held.holdIfLocked(false, b, a, json, "s"));
        assertNull(held.summary());

        assertTrue(held.holdIfLocked(false, a, a, json, "summary"));
        assertEquals("summary", held.summary());
        HeldRequest.Taken taken = held.take(a);
        assertNotNull(taken);
        assertSame(a, taken.source);
        assertSame(json, taken.request);
        assertNull("taken once", held.take(a));

        held.holdIfLocked(false, a, a, json, "summary");
        assertNull("never re-targeted at whatever transport is current", held.take(b));
        assertNull("and forgotten", held.summary());

        held.holdIfLocked(false, a, a, json, "summary");
        assertFalse(held.dropIfFrom(b));
        assertEquals("summary", held.summary());
        assertTrue("its own connection's disconnect drops it", held.dropIfFrom(a));
        assertNull(held.take(a));

        held.holdIfLocked(false, a, a, json, "summary");
        a.close();
        assertNull("a closed connection gets nothing", held.take(a));

        held.holdIfLocked(false, b, b, json, "summary");
        held.clear();
        assertNull(held.take(b));
    }

    /** The call sites: every hold, take, drop and new-connection clear goes through HeldRequest under stateLock. */
    @Test public void heldRequestCallSites() throws Exception {
        String dispatch = SourceGuard.definition("private void dispatchHeldRequest() {");
        assertTrue(dispatch.contains("held = heldRequest.take(transport);"));
        assertTrue(dispatch.contains("onRequest(held.source, held.request)"));
        assertEquals("held only from the live connection while locked, under stateLock", 1,
                SourceGuard.count("synchronized \\(stateLock\\) \\{ host\\.heldRequest\\(\\)\\.holdIfLocked\\(host\\.unlocked\\(\\), host\\.transport\\(\\), source, json, body\\); \\}"));
        assertEquals("no other hold site", 1, SourceGuard.count("\\.holdIfLocked\\("));
        String handle = SourceGuard.definition("private void handleIntent(Intent intent, boolean resumed) {");
        assertEquals("cleared on a new connection, locked and unlocked", 2,
                handle.split("synchronized \\(stateLock\\) \\{ heldRequest\\.clear\\(\\); \\}", -1).length - 1);
        String disc = SourceGuard.definition("public void onDisconnected(AccessoryTransport source, String reason) {");
        assertTrue(disc.contains("droppedHeld = heldRequest.dropIfFrom(source);"));
        assertTrue("lock() forgets it", SourceGuard.definition("private void lock() {").contains("heldRequest.clear();"));
    }
}
