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
        String src = SourceGuard.mainActivity();
        String body = SourceGuard.body(src, "private int adbEnabled() {");
        assertTrue(body.contains("Settings.Global.ADB_ENABLED"));
        assertTrue(body.contains("ADB_WIFI_ENABLED"));
        assertEquals("adb_wifi_enabled", MainActivity.ADB_WIFI_ENABLED);
        assertTrue(src.contains("registerContentObserver(Settings.Global.getUriFor(ADB_WIFI_ENABLED), false, adbObserver)"));
    }

    /**
     * Bitcoin answers (xpub sharing included) and every signature are re-checked with
     * RequestOwnership sets that refuse while debugging is on, and the live state's
     * debuggingRefused is MainActivity's adbRefused().
     */
    @Test public void btcShareAndSigningOwnershipChecksAdb() throws Exception {
        assertTrue(RequestOwnership.BTC_UNDECIDED.contains(RequestOwnership.Require.NO_ADB));
        assertTrue(RequestOwnership.BTC_SHOW.contains(RequestOwnership.Require.NO_ADB));
        assertTrue(RequestOwnership.SIGNING.contains(RequestOwnership.Require.NO_ADB));
        String src = SourceGuard.mainActivity();
        assertTrue(src.contains("@Override public boolean debuggingRefused() { return adbRefused(); }"));
        assertTrue(SourceGuard.body(src, "private boolean owns(").contains("RequestOwnership.holds(live, "));
        String share = SourceGuard.body(src, "private void showBtcShare(");
        assertTrue(share.contains("owns(source, s, decision, RequestOwnership.BTC_UNDECIDED) || !decision.beginSigning()"));
        // the Sign worker's three re-checks under stateLock (before the seed opens, before sending, EVM sign)
        assertEquals(3, SourceGuard.code(src).split("owns\\(source, s, decision, RequestOwnership\\.SIGNING\\)", -1).length - 1);
    }
}
