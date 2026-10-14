package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.os.UserManager;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Key-custody / lockdown audit (2026-10-13). The findings are fixed; these tests now assert the
 * fixed behaviour (credential mode stores no PIN hash, one boot silent unlock per boot, wireless
 * adb refused, Bitcoin replies gated on adb). No real PINs or seeds: the PIN is a synthetic value.
 */
public class KeyCustodyAuditTest {

    private static String read(String rel) throws Exception {
        for (String prefix : new String[] {"", "app/"}) {
            Path p = Paths.get(prefix + rel);
            if (Files.exists(p)) return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
        }
        fail(rel + " not found from " + Paths.get("").toAbsolutePath());
        return null;
    }

    private static String mainActivity() throws Exception {
        return read("src/main/java/dev/phonevault/signer/MainActivity.java");
    }

    private static byte[] pbkdf2(char[] pin, byte[] salt, int iterations) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(pin, salt, iterations, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    // ------------------------------------------------------------------ F1: no PIN hash in credential mode (fixed)

    /**
     * The app-level PBKDF2 record is everything an offline guesser needs (hash + salt + work factor,
     * no attempt counter, no Titan M). It still exists in the no-chip FALLBACK mode — shown here
     * with a reduced work factor and a 10^4 slice — which is why credential mode must not keep it.
     */
    @Test public void fallbackModePinRecordIsOfflineGuessable() throws Exception {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        VaultPin p = new VaultPin(prefs, 1000);
        p.set("004217".toCharArray()); // synthetic test PIN

        String hash = (String) prefs.map.get("pin_hash_v1");
        String salt = (String) prefs.map.get("pin_salt_v1");
        Integer iter = (Integer) prefs.map.get("pin_iter_v1");
        assertNotNull(hash);
        assertNotNull(salt);
        assertNotNull(iter);

        byte[] expected = hex(hash), saltBytes = hex(salt);
        String recovered = null;
        for (int i = 0; i < 10_000 && recovered == null; i++) {
            char[] guess = String.format("%06d", i).toCharArray();
            if (MessageDigest.isEqual(expected, pbkdf2(guess, saltBytes, iter))) recovered = new String(guess);
        }
        assertEquals("offline search recovers the PIN from prefs alone", "004217", recovered);
    }

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
        String src = mainActivity();
        int install = src.indexOf("boolean bound = SystemCredential.install(this, forSystem); // zeroes forSystem");
        int mark = src.indexOf("pin.markCredentialHeld();", install);
        int set = src.indexOf("pin.set(chosen);", install);
        assertTrue(install >= 0 && mark > install && set > mark);
        assertTrue(src.substring(install, set).contains("} else {"));
        assertTrue("mode switch reads the marker, not the hash",
                src.contains("private boolean credentialMode() { return pin != null && pin.credentialHeld(); }"));
        assertTrue("startup migration runs before the first gate",
                src.indexOf("pin.reconcile(SystemCredential.isSet(this));") < src.indexOf("showPinGate(getIntent());"));
    }

    /**
     * Migration: phones that entered credential mode before the marker existed still store the
     * hash. Startup reconciliation writes the marker FIRST, then removes the record; a crash in
     * between (marker + hash) is finished on the next start; repeated runs change nothing.
     */
    @Test public void existingCredentialPhonesLoseTheHashOnStartup() throws Exception {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        VaultPin p = new VaultPin(prefs, 1000);
        p.set("004217".toCharArray()); // legacy state: hash stored, device credential present

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

    // ------------------------------------------------------------------ F2: boot silent unlock, once per boot (fixed)

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

        String src = mainActivity();
        assertFalse("no per-instance flag", src.contains("bootUnlockEligible"));
        int gate = src.indexOf("private void showCredentialGate(int s) {");
        String body = src.substring(gate, src.indexOf("\n    }\n", gate));
        assertTrue(body.contains("if (freshBoot && bootUnlock.tryConsume(bootId())) {"));
        int lock = src.indexOf("private void lock() {");
        String lockBody = src.substring(lock, src.indexOf("\n    }\n", lock));
        assertTrue("lock() disarms the silent path for this boot", lockBody.contains("bootUnlock.noteLock(bootId());"));
        assertTrue(src.contains("Settings.Global.BOOT_COUNT"));
    }

    // ------------------------------------------------------------------ release lockdown

    /** Runs under every variant: release must never be dev; dev variants must be. */
    @Test public void releaseBuildTypeIsNeverDev() {
        boolean release = "release".equals(BuildConfig.BUILD_TYPE);
        if (release) {
            assertFalse(BuildConfig.VAULT_DEV_BUILD);
            assertFalse(DevTools.SCREENSHOTS);
            assertEquals("release", DevTools.VARIANT);
            assertFalse(MainActivity.devBuild());
            assertTrue(ApplianceLockdown.userRestrictions(MainActivity.devBuild(), BuildConfig.VAULT_ALLOW_APP_UPDATES)
                    .contains(UserManager.DISALLOW_DEBUGGING_FEATURES));
            assertTrue(ApplianceLockdown.refuseForAdb(MainActivity.devBuild(), 1));
            assertTrue(BuildConfig.VAULT_REQUIRE_SECURE_HARDWARE);
        } else {
            assertTrue(BuildConfig.BUILD_TYPE + " is a dev build", MainActivity.devBuild());
            assertFalse(ApplianceLockdown.refuseForAdb(MainActivity.devBuild(), 1));
        }
        System.out.println("AUDIT variant=" + BuildConfig.BUILD_TYPE + " devBuild=" + MainActivity.devBuild()
                + " SCREENSHOTS=" + DevTools.SCREENSHOTS + " VAULT_DEV_BUILD=" + BuildConfig.VAULT_DEV_BUILD);
    }

    /** Wireless debugging (adb_wifi_enabled) refuses like USB debugging, and is observed too. */
    @Test public void adbRefusalCoversWirelessDebugging() throws Exception {
        String src = mainActivity();
        int at = src.indexOf("private int adbEnabled() {");
        String body = src.substring(at, src.indexOf("\n    }\n", at));
        assertTrue(body.contains("Settings.Global.ADB_ENABLED"));
        assertTrue(body.contains("ADB_WIFI_ENABLED"));
        assertEquals("adb_wifi_enabled", MainActivity.ADB_WIFI_ENABLED);
        assertTrue(src.contains("registerContentObserver(Settings.Global.getUriFor(ADB_WIFI_ENABLED), false, adbObserver)"));
    }

    /**
     * A request held behind the lock is bound to the connection it arrived on: a new connection or
     * that connection's disconnect drops it, and unlock dispatches it only to that same live session.
     */
    @Test public void heldRequestIsBoundToItsConnection() throws Exception {
        String src = mainActivity();
        int d = src.indexOf("private void dispatchHeldRequest() {");
        String dispatch = src.substring(d, src.indexOf("\n    }\n", d));
        assertTrue(dispatch.contains("source = heldSource;"));
        assertTrue(dispatch.contains("source != null && source == transport && !source.isClosed()"));
        assertFalse("never re-targeted at whatever transport is current", dispatch.contains("source = transport;"));
        assertEquals("both hold sites record the source", 2,
                src.split("heldRequest = json; heldSummary = b; heldSource = source;", -1).length - 1);
        assertEquals("held only from the live connection", 2,
                src.split("if \\(!unlocked && source == transport\\) \\{ heldRequest = json;", -1).length - 1);
        int h = src.indexOf("private void handleIntent(Intent intent) {");
        String handle = src.substring(h, src.indexOf("\n    }\n", h));
        assertEquals("cleared on a new connection, locked and unlocked", 2,
                handle.split("clearHeldRequest\\(\\);", -1).length - 1);
        int o = src.indexOf("public void onDisconnected(AccessoryTransport source, String reason) {");
        String disc = src.substring(o, src.indexOf("\n    }\n", o));
        assertTrue(disc.contains("droppedHeld = heldSource == source;") && disc.contains("clearHeldRequest();"));
    }

    /** Bitcoin xpub sharing replies under btcStillOwned, which now refuses while debugging is on. */
    @Test public void btcShareOwnershipChecksAdb() throws Exception {
        String src = mainActivity();
        int at = src.indexOf("private boolean btcStillOwned(");
        String body = src.substring(at, src.indexOf("\n    }\n", at));
        assertTrue(body.contains("!adbRefused()"));
        int sign = src.indexOf("private boolean signingStillOwned(");
        assertTrue(src.substring(sign, src.indexOf("\n    }\n", sign)).contains("!adbRefused()"));
    }
}
