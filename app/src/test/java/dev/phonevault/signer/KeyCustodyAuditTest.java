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
 * Key-custody / lockdown audit (2026-10-13). Proof tests only: each documents a property of the
 * CURRENT code. Tests named {@code finding*} pass because the weakness exists; flip them when fixed.
 * No real PINs or seeds: the PIN below is a synthetic test value.
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

    // ------------------------------------------------------------------ F1: PIN hash survives credential mode

    /**
     * The app-level PBKDF2 PIN record is everything an offline guesser needs: hash + salt + work
     * factor sit in prefs, and guessing never touches the attempt counter or the Titan M. With the
     * production 200k iterations the full 10^6 space is ~2e11 HMAC-SHA256 calls (minutes on a GPU);
     * here a reduced work factor and a 10^4 slice keep the test fast. The search is the same code.
     */
    @Test public void findingPinRecordAllowsOfflineGuessingWithoutAttemptCounter() throws Exception {
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
        assertEquals("offline guessing never touched the counter", VaultPin.MAX_ATTEMPTS, p.attemptsRemaining());
    }

    /**
     * ... and that record is written in credential mode too, and never cleared: SET PIN stores it
     * BEFORE installing the same PIN as the device credential, and the gate's mode switch reads
     * pin.isSet(), so the hash must stay for credential mode to work at all.
     */
    @Test public void findingCredentialModeKeepsTheAppPinHash() throws Exception {
        String src = mainActivity();
        int set = src.indexOf("pin.set(chosen);");
        int install = src.indexOf("SystemCredential.install(this, forSystem);", set);
        assertTrue("pin.set precedes the device-credential install", set >= 0 && install > set);
        assertFalse("nothing clears the app PIN hash once the chip holds the PIN", src.contains("pin.clear()"));
        assertTrue("credential-mode gate is reached only while the app hash exists",
                src.contains("final boolean creating = !pin.isSet();")
                        && src.contains("if (!creating && !sealed && credentialMode())"));
    }

    // ------------------------------------------------------------------ F2: boot silent unlock re-arms per instance

    /**
     * The no-prompt boot unlock is gated by an INSTANCE field (documented as "the FIRST gate of this
     * process"), the activity declares no configChanges (a hardware keyboard / uiMode change recreates
     * it), and the silent path calls unlock(s) without any PIN prompt — it relies only on the seed
     * key's 30 s chip window, which lock() cannot close.
     */
    @Test public void findingBootSilentUnlockIsReArmedByActivityRecreation() throws Exception {
        String src = mainActivity();
        assertTrue("per-instance, not per-boot", src.contains("    private boolean bootUnlockEligible = true;"));
        assertFalse("no static / persisted boot marker", src.contains("static boolean bootUnlockEligible"));
        int gate = src.indexOf("private void showCredentialGate(int s) {");
        int end = src.indexOf("bootUnlockEligible = false;\n        LinearLayout root", gate);
        String silent = src.substring(gate, end);
        assertTrue(silent.contains("android.os.SystemClock.elapsedRealtime() < 10 * 60 * 1000L"));
        assertTrue("silent path unlocks with no prompt", silent.contains("unlock(s);"));
        assertFalse("silent path never asks for the PIN", silent.contains("confirmDevicePin"));
        int lock = src.indexOf("private void lock() {");
        String lockBody = src.substring(lock, src.indexOf("\n    }\n", lock));
        assertFalse("lock() does not disarm the silent path or record a lock time",
                lockBody.contains("bootUnlockEligible") || lockBody.contains("lastCredentialConfirm"));
        String manifest = read("src/main/AndroidManifest.xml");
        assertFalse("MainActivity handles no config change itself (keyboard attach => recreate)",
                manifest.contains("configChanges"));
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

    /** Wireless debugging (Settings.Global.ADB_WIFI_ENABLED) is not part of the refusal check. */
    @Test public void findingAdbRefusalReadsOnlyUsbAdbSetting() throws Exception {
        String src = mainActivity();
        assertTrue(src.contains("Settings.Global.getInt(getContentResolver(), Settings.Global.ADB_ENABLED, 0)"));
        assertFalse(src.contains("ADB_WIFI_ENABLED"));
    }

    /** Bitcoin xpub sharing replies under btcStillOwned, which has no adbRefused() term. */
    @Test public void findingBtcShareOwnershipOmitsAdbCheck() throws Exception {
        String src = mainActivity();
        int at = src.indexOf("private boolean btcStillOwned(");
        String body = src.substring(at, src.indexOf("\n    }\n", at));
        assertFalse(body.contains("adbRefused"));
        int sign = src.indexOf("private boolean signingStillOwned(");
        assertTrue(src.substring(sign, src.indexOf("\n    }\n", sign)).contains("!adbRefused()"));
    }
}
