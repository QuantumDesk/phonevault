package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Source guard for a phone-only race: on a cold start after the boot PIN, onCreate and onResume
 * both show the credential gate. A second call must not replace the boot attempt's loading screen
 * with the locked page and queue the system PIN prompt while Android's lock screen is still going
 * away, or the vault asks for the PIN a second time.
 */
public class CredentialGateTest {
    private static String gate() throws Exception {
        return SourceGuard.body(SourceGuard.mainActivity(), "private void showCredentialGate(int s) {");
    }

    @Test public void pendingBootAttemptIsNotReplacedByASecondGate() throws Exception {
        String gate = gate();
        int guard = gate.indexOf("if (bootAttemptSession == s) return;");
        assertTrue("showCredentialGate must return while this session's boot attempt is pending", guard >= 0);
        assertTrue("the guard comes before any screen or prompt", guard < gate.indexOf("showLoading(")
                && guard < gate.indexOf("promptUnlock("));
        assertTrue(gate.contains("bootAttemptSession = s;"));
        // The attempt releases the guard on every exit, before it can fall back to the gate.
        int release = gate.indexOf("bootAttemptSession = -1;\n                    silentUnlockAttempt = true;");
        assertTrue(release >= 0 && release < gate.indexOf("showCredentialGate(session.get())"));
        assertTrue(gate.contains("if (s != session.get() || unlocked) { bootAttemptSession = -1; return; }"));
    }

    /**
     * A request held behind the lock is bound to the connection it arrived on: a new connection or
     * that connection's disconnect drops it, and unlock dispatches it only to that same live session.
     */
    @Test public void heldRequestIsBoundToItsConnection() throws Exception {
        String src = SourceGuard.mainActivity();
        String dispatch = SourceGuard.body(src, "private void dispatchHeldRequest() {");
        assertTrue(dispatch.contains("source = heldSource;"));
        assertTrue(dispatch.contains("source != null && source == transport && !source.isClosed()"));
        assertFalse("never re-targeted at whatever transport is current", dispatch.contains("source = transport;"));
        assertEquals("both hold sites record the source", 2,
                src.split("heldRequest = json; heldSummary = b; heldSource = source;", -1).length - 1);
        assertEquals("held only from the live connection", 2,
                src.split("if \\(!unlocked && source == transport\\) \\{ heldRequest = json;", -1).length - 1);
        String handle = SourceGuard.body(src, "private void handleIntent(Intent intent) {");
        assertEquals("cleared on a new connection, locked and unlocked", 2,
                handle.split("clearHeldRequest\\(\\);", -1).length - 1);
        String disc = SourceGuard.body(src, "public void onDisconnected(AccessoryTransport source, String reason) {");
        assertTrue(disc.contains("droppedHeld = heldSource == source;") && disc.contains("clearHeldRequest();"));
    }
}
