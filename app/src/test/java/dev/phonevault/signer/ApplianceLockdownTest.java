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
}
