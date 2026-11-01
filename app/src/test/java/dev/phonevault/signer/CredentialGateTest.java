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
        /** The request held behind the gate, as the prompt may describe it (null: none). */
        HeldRequest.LockPrompt held;
        /** Every prompt shown, in order. */
        final List<CredentialGate.PromptText> texts = new ArrayList<>();

        @Override public void systemConfirm(CredentialGate.PromptText text, CredentialGate.Confirmed result) {
            events.add("prompt:" + text.subtitle);
            texts.add(text);
            prompts.add(result);
        }
        /** The system reports a cancelled prompt through its own callback (the test delivers it). */
        @Override public void cancelSystemConfirm() { events.add("cancel"); }
        @Override public HeldRequest.LockPrompt heldPrompt() { return held; }

        CredentialGate.PromptText lastText() { return texts.get(texts.size() - 1); }
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

    /**
     * Pixel 6a: the unlock prompt stayed open across a lock (new session, new locked page, whose own
     * prompt is not stacked on the open one). A correct PIN in it must unlock the gate on screen,
     * not be dropped as stale with no prompt left.
     */
    @Test public void stalePromptSuccessUnlocksTheLockedPageOnScreen() {
        FakeEnv e = env();
        e.now = CredentialGate.FRESH_BOOT_MS + 1;
        e.gate.show(1);
        e.drain();
        assertEquals(1, e.prompts.size());
        e.session = 2;                       // lock() while the prompt is up
        e.gate.show(2);                      // the new gate
        e.drain();
        assertEquals("not stacked", 1, e.count("prompt"));
        e.prompts.poll().done(true);
        assertEquals(List.of("locked:1", "prompt:Enter your PIN to unlock", "locked:2", "unlock:2"), e.events);
        assertTrue(e.unlocked);

        // Dismissed instead: nothing unlocks, the new page's Unlock opens a prompt again.
        FakeEnv d = env();
        d.now = CredentialGate.FRESH_BOOT_MS + 1;
        d.gate.show(1);
        d.drain();
        d.session = 2;
        d.gate.show(2);
        d.drain();
        d.prompts.poll().done(false);
        assertEquals(0, d.count("unlock"));
        assertFalse(d.gate.promptOpen());
        d.gate.promptUnlock(2);
        assertEquals(2, d.count("prompt"));
        d.prompts.poll().done(true);
        assertEquals(1, d.count("unlock:2"));
    }

    /** A stale prompt's own action never runs for a newer session, and a stale success needs that session's locked page. */
    @Test public void stalePromptNeverRunsItsActionForANewerSession() {
        FakeEnv e = env();
        int[] ran = {0}, cancelled = {0};
        e.gate.confirmDevicePin("Enter your PIN to open the wallet", () -> ran[0]++, () -> cancelled[0]++);
        e.session = 2;                       // locked; no locked page drawn for session 2 (e.g. sealed)
        e.prompts.poll().done(true);
        assertEquals(0, ran[0]);
        assertEquals(0, e.count("unlock"));
        assertFalse(e.unlocked);
    }

    /**
     * Pixel 6a: Back on the system prompt of a sensitive action left its SensitiveFlow token taken,
     * so "Continue · verify PIN" and ☰ → Wallet did nothing until the next lock. Cancel, an error
     * and a timeout all arrive as a failed confirmation and must release it (MainActivity passes
     * releaseSensitive as onCancel); the next sensitive action then prompts again.
     */
    @Test public void dismissedSensitivePromptReleasesTheFlowAndTheNextOnePromptsAgain() throws Exception {
        FakeEnv e = env();
        e.unlocked = true;
        SensitiveFlow flow = new SensitiveFlow(new Object());
        int[] opened = {0};
        for (int attempt = 1; attempt <= 3; attempt++) {
            int token = flow.begin();
            assertTrue("attempt " + attempt + " may begin", token > 0);
            e.gate.withSeedKey("Enter your PIN to show the phrase", () -> { if (flow.owns(token)) opened[0]++; }, () -> flow.end(token));
            if (!e.probes.isEmpty()) e.probes.poll().done(false); // the key is not usable yet: ask
            assertEquals("attempt " + attempt + " prompts", attempt, e.count("prompt"));
            e.prompts.poll().done(false);    // Back / error / timeout
            assertFalse("released", flow.active());
            assertFalse(e.gate.promptOpen());
        }
        assertEquals(0, opened[0]);
        int token = flow.begin();
        e.gate.withSeedKey("Enter your PIN to show the phrase", () -> { if (flow.owns(token)) opened[0]++; }, () -> flow.end(token));
        if (!e.probes.isEmpty()) e.probes.poll().done(false);
        e.prompts.poll().done(true);
        assertEquals(1, opened[0]);

        String begin = SourceGuard.definition("private void beginSensitive(String purpose, Runnable afterPin) {");
        assertTrue("credential mode releases the token when the prompt is dismissed",
                begin.contains("() -> releaseSensitive(token));"));
        assertTrue("never takes a token while a prompt is already open (it would never be asked)",
                begin.contains("if (credentialMode() && credentialGate.promptOpen()) return;"));
        assertTrue(SourceGuard.definition("private void releaseSensitive(int token) {").contains("sensitive.end(token)"));
    }

    // ---------------------------------------------------------------- held request on the system prompt

    private static final String HELLO = "0x68656c6c6f";
    private static final String TO = "0x1111111111111111111111111111111111111111";

    /**
     * Pixel 6a: the system PIN prompt opens at once and covers the locked page, so the
     * "INCOMING REQUEST" card under it was invisible until after unlock. The prompt itself says a
     * request waits: who sent it (a validated site, else "your Mac") and its kind, nothing else.
     */
    @Test public void unlockPromptTextNamesTheHeldRequestOnlyByKindAndSite() throws Exception {
        CredentialGate.PromptText plain = CredentialGate.unlockText(null);
        assertEquals("Phone Vault", plain.title);
        assertEquals("Enter your PIN to unlock", plain.subtitle);
        assertNull(plain.description);
        assertFalse(plain.held);

        JSONObject fromSite = MessageRequestTest.personal(HELLO).put("origin", "https://app.uniswap.org");
        CredentialGate.PromptText site = CredentialGate.unlockText(HeldRequest.LockPrompt.of(fromSite));
        assertTrue(site.held);
        assertEquals("Incoming request", site.title);
        assertEquals("From app.uniswap.org, via your Mac", site.subtitle);
        assertEquals("Message signature. Unlock to review it. Nothing is signed until you approve it.", site.description);

        JSONObject local = MessageRequestTest.personal(HELLO).put("origin", "http://localhost:3000");
        assertEquals("From http://localhost:3000, via your Mac",
                CredentialGate.unlockText(HeldRequest.LockPrompt.of(local)).subtitle);

        // An origin that fails validation is never shown: the request is refused after unlock.
        for (String bad : new String[] {"http://app.uniswap.org", "https://App.Uniswap.org", "https://evil.example/path", "https://a b"}) {
            CredentialGate.PromptText t = CredentialGate.unlockText(
                    HeldRequest.LockPrompt.of(MessageRequestTest.personal(HELLO).put("origin", bad)));
            assertEquals(bad, "From your Mac", t.subtitle);
            assertFalse(bad, t.toString().contains("uniswap") || t.toString().contains("evil"));
        }
        // A request that does not parse names no site either, even with a well-formed origin.
        JSONObject extra = MessageRequestTest.personal(HELLO).put("origin", "https://app.uniswap.org").put("extra", "1");
        assertEquals("From your Mac", CredentialGate.unlockText(HeldRequest.LockPrompt.of(extra)).subtitle);
        // No origin: your Mac.
        assertEquals("From your Mac", CredentialGate.unlockText(HeldRequest.LockPrompt.of(MessageRequestTest.personal(HELLO))).subtitle);

        // Never an amount, an address or the message: the kind only.
        JSONObject tx = new JSONObject().put("id", "t").put("method", "signEip1559").put("chainId", "0x1")
                .put("to", TO).put("value", "0x6f05b59d3b20000").put("data", "0x");
        CredentialGate.PromptText txText = CredentialGate.unlockText(HeldRequest.LockPrompt.of(tx));
        assertEquals("From your Mac", txText.subtitle);
        assertEquals("Transaction. Unlock to review it. Nothing is signed until you approve it.", txText.description);
        for (CredentialGate.PromptText t : new CredentialGate.PromptText[] {site, txText}) {
            String all = t.toString().toLowerCase(java.util.Locale.ROOT);
            assertFalse(all.contains("0x"));
            assertFalse(all.contains("hello"));
            assertFalse(all.contains("eth"));
        }
        String[][] kinds = {
                {"eth_signTypedData_v4", "Typed-data signature. "}, {"btcSignPsbt", "Bitcoin transaction. "},
                {"btcGetAccount", "Bitcoin account request. "}, {"btcShowAddress", "Address request. "},
                {"getAddress", "Address request. "}, {"listAddresses", "Address request. "},
                {"attest", "Hardware check. "}, {"somethingElse", ""}};
        for (String[] k : kinds) {
            CredentialGate.PromptText t = CredentialGate.unlockText(
                    HeldRequest.LockPrompt.of(new JSONObject().put("id", "x").put("method", k[0])));
            assertEquals(k[0], k[1] + "Unlock to review it. Nothing is signed until you approve it.", t.description);
            assertEquals(k[0], "From your Mac", t.subtitle);
        }

        // HeldRequest keeps it with the request and forgets it with the request.
        HeldRequest held = new HeldRequest();
        AccessoryTransport a = transport();
        assertNull(held.lockPrompt());
        held.holdIfLocked(false, a, a, fromSite, "summary");
        assertEquals(new HeldRequest.LockPrompt("message signature", "app.uniswap.org"), held.lockPrompt());
        held.dropIfFrom(a);
        assertNull(held.lockPrompt());
        held.holdIfLocked(false, a, a, tx, "summary");
        held.take(a);
        assertNull(held.lockPrompt());
    }

    /** A request held before the gate prompts: the first prompt already says so. */
    @Test public void unlockPromptSaysARequestIsWaiting() {
        FakeEnv e = env();
        e.now = CredentialGate.FRESH_BOOT_MS + 1;
        e.held = new HeldRequest.LockPrompt("message signature", "app.uniswap.org");
        e.gate.show(1);
        e.drain();
        assertEquals(List.of("locked:1", "prompt:From app.uniswap.org, via your Mac"), e.events);
        assertTrue(e.lastText().held);
        e.prompts.poll().done(true);
        assertEquals("the PIN unlocks; the unlock dispatches the request, the gate never does", 1, e.count("unlock:1"));
    }

    /**
     * A request that arrives while the prompt is up: BiometricPrompt text cannot change in place, so
     * the prompt is cancelled and shown again with the new text. The cancel unlocks nothing.
     */
    @Test public void requestArrivingUnderAnOpenPromptReShowsIt() {
        FakeEnv e = env();
        e.now = CredentialGate.FRESH_BOOT_MS + 1;
        e.gate.show(1);
        e.drain();
        assertFalse(e.lastText().held);

        e.held = new HeldRequest.LockPrompt("transaction", null);
        e.gate.heldRequestChanged();
        assertEquals(1, e.count("cancel"));
        e.gate.heldRequestChanged();         // the page redrawn again before the cancel reported back
        assertEquals("cancelled once", 1, e.count("cancel"));
        e.gate.promptUnlock(1);              // nor does the Unlock button stack one
        assertEquals(1, e.count("prompt"));
        e.prompts.poll().done(false);        // the cancel arrives as a failure
        assertEquals(0, e.count("unlock"));
        assertFalse(e.unlocked);
        e.drain();                           // after a moment: the prompt again, with the request
        assertEquals(2, e.count("prompt"));
        assertEquals(CredentialGate.unlockText(e.held), e.lastText());
        assertEquals(e.lastText(), e.gate.openPromptText());

        // The same request again (the page is drawn again): nothing changes.
        e.gate.heldRequestChanged();
        e.gate.promptUnlock(1);
        assertEquals(1, e.count("cancel"));

        // Another request replaces it: shown again with its own text.
        e.held = new HeldRequest.LockPrompt("message signature", "app.uniswap.org");
        e.gate.heldRequestChanged();
        assertEquals(2, e.count("cancel"));
        e.prompts.poll().done(false);
        e.drain();
        assertEquals("prompt:From app.uniswap.org, via your Mac", e.events.get(e.events.size() - 1));

        e.prompts.poll().done(true);
        assertEquals(1, e.count("unlock:1"));
        assertTrue(e.unlocked);
    }

    /** A held request that is dropped (its host disconnected, a new connection): the plain prompt again. */
    @Test public void droppedRequestRestoresThePlainPrompt() {
        FakeEnv e = env();
        e.now = CredentialGate.FRESH_BOOT_MS + 1;
        e.held = new HeldRequest.LockPrompt("transaction", null);
        e.gate.show(1);
        e.drain();
        assertTrue(e.lastText().held);
        e.held = null;
        e.gate.heldRequestChanged();
        assertEquals(1, e.count("cancel"));
        e.prompts.poll().done(false);
        e.drain();
        assertEquals(CredentialGate.unlockText(null), e.lastText());
        assertEquals("prompt:Enter your PIN to unlock", e.events.get(e.events.size() - 1));

        // A screen-off dismisses the prompt itself; the next gate's prompt reads what is held then.
        FakeEnv off = env();
        off.now = CredentialGate.FRESH_BOOT_MS + 1;
        off.held = new HeldRequest.LockPrompt("transaction", null);
        off.gate.show(1);
        off.drain();
        off.prompts.poll().done(false);      // the system closed it
        off.held = null;                     // the session ended with it
        off.gate.heldRequestChanged();       // no prompt open: nothing to cancel
        assertEquals(0, off.count("cancel"));
        off.session = 2;
        off.gate.show(2);
        off.drain();
        assertEquals(CredentialGate.unlockText(null), off.lastText());
    }

    /** The PIN entered just before the cancel landed: it unlocks, and nothing is shown again. */
    @Test public void successBeatingTheCancelUnlocksWithoutReShowing() {
        FakeEnv e = env();
        e.now = CredentialGate.FRESH_BOOT_MS + 1;
        e.gate.show(1);
        e.drain();
        e.held = new HeldRequest.LockPrompt("transaction", null);
        e.gate.heldRequestChanged();
        e.prompts.poll().done(true);
        e.drain();
        assertEquals(1, e.count("unlock:1"));
        assertEquals(1, e.count("prompt"));
    }

    /** A cancelled prompt that never reports back cannot wedge the gate: given up on, its late result ignored. */
    @Test public void cancelThatNeverReportsBackIsGivenUpOn() {
        FakeEnv e = env();
        e.now = CredentialGate.FRESH_BOOT_MS + 1;
        e.gate.show(1);
        e.drain();
        CredentialGate.Confirmed lost = e.prompts.poll();
        e.held = new HeldRequest.LockPrompt("transaction", null);
        e.gate.heldRequestChanged();
        assertTrue(e.delays.contains(CredentialGate.CANCEL_GIVE_UP_MS));
        e.drain();                           // the give-up timer
        assertEquals(2, e.count("prompt"));
        assertTrue(e.lastText().held);
        lost.done(true);                     // the old prompt's late result
        assertEquals(0, e.count("unlock"));
        assertTrue("the new prompt is still the open one", e.gate.promptOpen());
        e.prompts.poll().done(true);
        assertEquals(1, e.count("unlock:1"));
    }

    /**
     * The prompt that outlived its session (Pixel 6a, stale-prompt fix): a request held on the new
     * locked page re-shows it as that page's unlock prompt, and the PIN unlocks that page.
     */
    @Test public void stalePromptIsReShownForTheNewLockedPage() {
        FakeEnv e = env();
        e.now = CredentialGate.FRESH_BOOT_MS + 1;
        e.gate.show(1);
        e.drain();
        e.session = 2;                       // lock() while the prompt is up
        e.gate.show(2);
        e.drain();
        assertEquals("not stacked", 1, e.count("prompt"));
        e.held = new HeldRequest.LockPrompt("message signature", null);
        e.gate.heldRequestChanged();
        e.prompts.poll().done(false);
        assertEquals(0, e.count("unlock"));
        e.drain();
        assertEquals(2, e.count("prompt"));
        assertTrue(e.lastText().held);
        e.prompts.poll().done(true);
        assertEquals(List.of("unlock:2"), e.events.stream().filter(x -> x.startsWith("unlock")).collect(java.util.stream.Collectors.toList()));
    }

    /** Only the locked, visible gate's prompt is re-shown; a prompt without held text is left alone. */
    @Test public void heldRequestChangeLeavesOtherPromptsAlone() {
        FakeEnv unlocked = env();
        unlocked.unlocked = true;
        unlocked.gate.confirmDevicePin("Enter your PIN to show the phrase", () -> { }, null);
        unlocked.held = new HeldRequest.LockPrompt("transaction", null);
        unlocked.gate.heldRequestChanged();
        assertEquals(0, unlocked.count("cancel"));

        FakeEnv hidden = env();
        hidden.now = CredentialGate.FRESH_BOOT_MS + 1;
        hidden.gate.show(1);
        hidden.drain();
        hidden.foreground = false;
        hidden.held = new HeldRequest.LockPrompt("transaction", null);
        hidden.gate.heldRequestChanged();
        assertEquals(0, hidden.count("cancel"));

        // No locked page of this session (a sealed vault's screen, the boot attempt): nothing to re-show onto.
        FakeEnv noPage = env();
        noPage.gate.confirmDevicePin("Enter your PIN to unlock", () -> { }, null);
        noPage.held = new HeldRequest.LockPrompt("transaction", null);
        noPage.gate.heldRequestChanged();
        assertEquals(0, noPage.count("cancel"));

        // Held text on neither side: a stale prompt of another kind is not cancelled by a redraw.
        FakeEnv plain = env();
        plain.now = CredentialGate.FRESH_BOOT_MS + 1;
        plain.gate.confirmDevicePin("Enter your PIN to open the wallet", () -> { }, null);
        plain.session = 2;
        plain.gate.show(2);
        plain.drain();
        plain.gate.heldRequestChanged();
        assertEquals(0, plain.count("cancel"));
    }

    /** The activity side: every held/dropped refresh reaches the prompt, and the prompt carries all its text. */
    @Test public void heldPromptCallSites() throws Exception {
        assertTrue(SourceGuard.definition("private void refreshGateRequest(String label, String body) {")
                .contains("credentialGate.heldRequestChanged();"));
        String confirm = SourceGuard.definition("public void systemConfirm(CredentialGate.PromptText text, CredentialGate.Confirmed result) {");
        assertTrue(confirm.contains("text.title, text.subtitle, text.description, cancel"));
        assertTrue(SourceGuard.definition("public HeldRequest.LockPrompt heldPrompt() {")
                .contains("synchronized (stateLock) { return heldRequest.lockPrompt(); }"));
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
        String lock = SourceGuard.definition("private void lock() {");
        assertTrue("only a relock while still locked keeps the gate session (and what it holds)",
                lock.contains("boolean keepGateSession = !wasUnlocked && transport != null && !transport.isClosed();"));
        assertTrue("a lock from unlocked forgets it", lock.contains("HeldRequest.Taken undispatched = heldRequest.take(staleTransport);"));
        assertTrue("and answers it with a refusal as the last frame, never anything else",
                lock.contains("if (undispatched != null) staleTransport.closeAfter(HeldRequest.lockedRefusal(undispatched.request));"));
        String show = SourceGuard.definition("public void showHeldOnGate(AccessoryTransport source, String label, String body) {");
        assertTrue("never while unlocked, only from the live session", show.contains("if (unlocked || source != transport) return;"));
        assertTrue("the credential-mode locked page shows it too", show.contains("refreshGateRequest(label, body);"));
        assertTrue(SourceGuard.definition("private void refreshGateRequest(String label, String body) {")
                .contains("if (lockedPageSession == session.get()) showLockedPage(lockedPageSession);"));
    }

    /** The refusal a lock gives a held request: an error for its own id, never a signature. */
    @Test public void lockedRefusalIsAnErrorForTheRequestId() throws Exception {
        JSONObject refusal = HeldRequest.lockedRefusal(new JSONObject().put("id", "req-7").put("method", "eth_signTransaction"));
        assertEquals("req-7", refusal.getString("id"));
        assertEquals("error", refusal.getString("status"));
        assertTrue(refusal.getString("error").contains("Nothing was signed"));
        assertEquals(3, refusal.length());
        assertEquals("an unusable id is not echoed", "unknown",
                HeldRequest.lockedRefusal(new JSONObject().put("id", "bad id\n")).getString("id"));
    }
}
