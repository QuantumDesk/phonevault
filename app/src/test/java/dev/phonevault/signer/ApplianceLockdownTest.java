package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.os.UserManager;

import org.junit.Test;

import java.util.Collections;
import java.util.List;

/** Device-owner lockdown gating: release locks everything down; dev builds keep adb and the harness working. */
public final class ApplianceLockdownTest {
    private static final String[] RELEASE_ONLY = {
            UserManager.DISALLOW_DEBUGGING_FEATURES,
            UserManager.DISALLOW_CONFIG_DATE_TIME,
            UserManager.DISALLOW_MOUNT_PHYSICAL_MEDIA,
            UserManager.DISALLOW_SYSTEM_ERROR_DIALOGS,
    };

    @Test public void releaseAddsTheFullLockdown() {
        List<String> r = ApplianceLockdown.userRestrictions(false, false);
        for (String s : RELEASE_ONLY) assertTrue(s, r.contains(s));
        assertTrue(r.contains(UserManager.DISALLOW_INSTALL_APPS));
        assertTrue(r.contains(UserManager.DISALLOW_UNINSTALL_APPS));
        assertTrue(r.contains(UserManager.DISALLOW_USB_FILE_TRANSFER));
        assertTrue(ApplianceLockdown.restrictsCameraAndInput(false));
    }

    @Test public void devBuildsKeepAdbAndUpdates() {
        List<String> r = ApplianceLockdown.userRestrictions(true, true);
        for (String s : RELEASE_ONLY) assertFalse(s, r.contains(s));
        assertFalse(r.contains(UserManager.DISALLOW_INSTALL_APPS));
        assertFalse(ApplianceLockdown.restrictsCameraAndInput(true));
        // the base set is the same in every build
        assertTrue(r.contains(UserManager.DISALLOW_ADD_USER));
        assertTrue(r.contains(UserManager.DISALLOW_SAFE_BOOT));
        assertTrue(ApplianceLockdown.userRestrictions(false, false).containsAll(r));
    }

    @Test public void releaseRefusesWhileUsbDebuggingIsOn() {
        assertTrue(ApplianceLockdown.refuseForAdb(false, 1));
        assertTrue("any non-zero value is on", ApplianceLockdown.refuseForAdb(false, 2));
        assertFalse(ApplianceLockdown.refuseForAdb(false, 0));
        assertFalse("dev builds rely on adb (tools/dev-device)", ApplianceLockdown.refuseForAdb(true, 1));
        assertEquals("USB debugging is on. This phone isn't safe to sign with.", ApplianceLockdown.ADB_REFUSAL);
    }

    @Test public void onlyTheDefaultKeyboardIsPermitted() {
        assertEquals(Collections.singletonList("com.android.inputmethod.latin"),
                ApplianceLockdown.permittedInputMethods("com.android.inputmethod.latin/.LatinIME"));
        assertEquals(Collections.singletonList("org.lineageos.ime"), ApplianceLockdown.permittedInputMethods("org.lineageos.ime"));
        assertEquals(Collections.emptyList(), ApplianceLockdown.permittedInputMethods(null));
        assertEquals(Collections.emptyList(), ApplianceLockdown.permittedInputMethods(""));
        assertNull(ApplianceLockdown.imePackage("not a package/.X"));
    }

    /** Runs under every variant: release must never be dev; dev variants must be. */
    @Test public void releaseBuildTypeIsNeverDev() {
        boolean release = "release".equals(BuildConfig.BUILD_TYPE);
        if (release) {
            assertFalse(BuildConfig.VAULT_DEV_BUILD);
            assertFalse(DevTools.SCREENSHOTS);
            assertFalse(MainActivity.devBuild());
            assertTrue(ApplianceLockdown.userRestrictions(MainActivity.devBuild(), BuildConfig.VAULT_ALLOW_APP_UPDATES)
                    .contains(UserManager.DISALLOW_DEBUGGING_FEATURES));
            assertTrue(ApplianceLockdown.refuseForAdb(MainActivity.devBuild(), 1));
            assertTrue(BuildConfig.VAULT_REQUIRE_SECURE_HARDWARE);
        } else {
            assertTrue(BuildConfig.BUILD_TYPE + " is a dev build", MainActivity.devBuild());
            assertFalse(ApplianceLockdown.refuseForAdb(MainActivity.devBuild(), 1));
        }
    }

    /** Wireless debugging (adb_wifi_enabled) refuses like USB debugging, and is observed too. */
    @Test public void adbRefusalCoversWirelessDebugging() throws Exception {
        assertEquals("adb_wifi_enabled", ApplianceLockdown.ADB_WIFI_ENABLED);
        assertEquals(0, ApplianceLockdown.debuggingSetting(0, 0));
        assertEquals("USB debugging", 1, ApplianceLockdown.debuggingSetting(1, 0));
        assertEquals("wireless debugging alone", 1, ApplianceLockdown.debuggingSetting(0, 1));
        assertEquals(2, ApplianceLockdown.debuggingSetting(2, 1));
        assertTrue(ApplianceLockdown.refuseForAdb(false, ApplianceLockdown.debuggingSetting(0, 1)));
        assertFalse(ApplianceLockdown.refuseForAdb(true, ApplianceLockdown.debuggingSetting(0, 1)));
        // The phone reads both settings into that decision and observes both (Settings is phone-only).
        String body = SourceGuard.definition("private int adbEnabled() {");
        assertTrue(body.contains("Settings.Global.ADB_ENABLED"));
        assertTrue(body.contains("ApplianceLockdown.ADB_WIFI_ENABLED"));
        assertTrue(body.contains("ApplianceLockdown.debuggingSetting(usb, wifi)"));
        assertTrue(SourceGuard.anyContains("registerContentObserver(Settings.Global.getUriFor(Settings.Global.ADB_ENABLED), false, adbObserver)"));
        assertTrue(SourceGuard.anyContains("registerContentObserver(Settings.Global.getUriFor(ApplianceLockdown.ADB_WIFI_ENABLED), false, adbObserver)"));
        assertTrue(SourceGuard.definition("private boolean adbRefused() {")
                .contains("ApplianceLockdown.refuseForAdb(devBuild(), adbEnabled())"));
    }

    /**
     * Bitcoin answers (xpub sharing included) and every signature are re-checked with
     * RequestOwnership sets that refuse while debugging is on, and the live state's
     * debuggingRefused is MainActivity's adbRefused(). Package-wide: the checks move with the code.
     */
    @Test public void btcShareAndSigningOwnershipChecksAdb() throws Exception {
        assertTrue(RequestOwnership.BTC_UNDECIDED.contains(RequestOwnership.Require.NO_ADB));
        assertTrue(RequestOwnership.BTC_SHOW.contains(RequestOwnership.Require.NO_ADB));
        assertTrue(RequestOwnership.SIGNING.contains(RequestOwnership.Require.NO_ADB));
        assertTrue(SourceGuard.anyContains("@Override public boolean debuggingRefused() { return adbRefused(); }"));
        assertTrue(SourceGuard.definition("private boolean owns(").contains("RequestOwnership.holds(live, "));
        String share = SourceGuard.definition("private void showBtcShare(");
        assertTrue(share.contains("owns(source, s, decision, RequestOwnership.BTC_UNDECIDED) || !decision.beginSigning()"));
        // the Sign worker's three re-checks under stateLock (before the seed opens, before sending, EVM sign)
        assertEquals(3, SourceGuard.count("owns\\(source, s, decision, RequestOwnership\\.SIGNING\\)"));
    }
}
