package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * Credential mode: once the PIN is the device credential (Titan M verifies it), the app keeps no
 * offline-guessable PIN record, and the one boot-time silent unlock is spent once per boot. No real
 * PINs or seeds: the PIN is a synthetic value.
 */
public class CredentialModeTest {

    /** Once the chip holds the PIN only a marker is stored: nothing to guess against offline. */
    @Test public void credentialModeStoresNoAppPinHash() throws Exception {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        VaultPin p = new VaultPin(prefs, 1000);
        p.markCredentialHeld();
        assertTrue(p.credentialHeld());
        assertTrue("the gate does not fall back to SET PIN", p.isSet());
        assertFalse(p.appPinSet());
        assertFalse(p.eraseOutstanding());
        for (String key : new String[] {"pin_hash_v1", "pin_salt_v1", "pin_iter_v1", "pin_attempts_v1"}) {
            assertFalse(key + " stored in credential mode", prefs.map.containsKey(key));
        }
        try {
            p.set("004217".toCharArray());
            fail("an app PIN must not be stored next to the device credential");
        } catch (IllegalStateException expected) { }
        assertFalse(prefs.map.containsKey("pin_hash_v1"));

        // SET PIN installs the chip credential FIRST and writes the hash only when that fails.
        String src = SourceGuard.mainActivity();
        int install = src.indexOf("boolean bound = SystemCredential.install(this, forSystem); // zeroes forSystem");
        int mark = src.indexOf("pin.markCredentialHeld();", install);
        int set = src.indexOf("pin.set(chosen);", install);
        assertTrue(install >= 0 && mark > install && set > mark);
        assertTrue(src.substring(install, set).contains("} else {"));
        assertTrue("mode switch reads the marker, not the hash",
                src.contains("private boolean credentialMode() { return pin != null && pin.credentialHeld(); }"));
        assertTrue("startup reconciliation runs before the first gate",
                src.indexOf("pin.reconcile(SystemCredential.isSet(this));") < src.indexOf("showPinGate(getIntent());"));
    }

    /**
     * A device credential with an app hash still stored (state from before the marker existed):
     * startup reconciliation writes the marker FIRST, then removes the record; a crash in between
     * (marker + hash) is finished on the next start; repeated runs change nothing.
     */
    @Test public void reconcileDropsTheAppHashOnceTheChipHoldsThePin() throws Exception {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        VaultPin p = new VaultPin(prefs, 1000);
        p.set("004217".toCharArray()); // hash stored, device credential present

        prefs.failAtCommit = prefs.commits + 2; // crash after the marker commit, before the removal
        try { p.reconcile(true); fail("removal commit was made to fail"); } catch (IllegalStateException expected) { }
        assertTrue("marker written before the hash is deleted", p.credentialHeld());
        assertTrue(prefs.map.containsKey("pin_hash_v1"));

        prefs.failAtCommit = -1;
        p.reconcile(false); // marker is authoritative even if the system check is unavailable
        assertTrue(p.credentialHeld());
        assertFalse(prefs.map.containsKey("pin_hash_v1"));
        assertFalse(prefs.map.containsKey("pin_salt_v1"));
        assertFalse(prefs.map.containsKey("pin_iter_v1"));
        int commits = prefs.commits;
        p.reconcile(true);
        assertEquals("idempotent", commits, prefs.commits);

        // Fallback mode (no device credential, no marker): the hash is kept and still verifies.
        VaultPinTest.FakePrefs fallback = new VaultPinTest.FakePrefs();
        VaultPin q = new VaultPin(fallback, 1000);
        q.set("004217".toCharArray());
        q.reconcile(false);
        assertFalse(q.credentialHeld());
        assertEquals(VaultPin.Outcome.OK, q.verify("004217".toCharArray(), () -> { }).outcome);
    }

    @Test public void bootSilentUnlockIsOncePerBootAndNeverAfterALock() throws Exception {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        assertTrue(new BootUnlockGuard(prefs).tryConsume(7));
        assertFalse("a re-created activity (new guard, same prefs) cannot re-arm it", new BootUnlockGuard(prefs).tryConsume(7));
        assertTrue("the next boot gets its own single attempt", new BootUnlockGuard(prefs).tryConsume(8));

        VaultPinTest.FakePrefs locked = new VaultPinTest.FakePrefs();
        new BootUnlockGuard(locked).noteLock(9);
        assertFalse("any lock this boot disarms it", new BootUnlockGuard(locked).tryConsume(9));
        assertFalse("unknown boot id: always prompt", new BootUnlockGuard(new VaultPinTest.FakePrefs()).tryConsume(-1));
        VaultPinTest.FakePrefs failing = new VaultPinTest.FakePrefs();
        failing.failAtCommit = 1;
        assertFalse("not recorded => not attempted", new BootUnlockGuard(failing).tryConsume(3));

        String src = SourceGuard.mainActivity();
        assertFalse("no per-instance flag", src.contains("bootUnlockEligible"));
        String gate = SourceGuard.body(src, "private void showCredentialGate(int s) {");
        assertTrue(gate.contains("if (freshBoot && bootUnlock.tryConsume(bootId())) {"));
        String lock = SourceGuard.body(src, "private void lock() {");
        assertTrue("lock() disarms the silent path for this boot", lock.contains("bootUnlock.noteLock(bootId());"));
        assertTrue(src.contains("Settings.Global.BOOT_COUNT"));
    }
}
