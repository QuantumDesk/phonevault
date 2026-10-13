package dev.phonevault.signer;

import android.os.UserManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * The device-owner lockdown of the appliance, as plain decisions (unit-tested; MainActivity
 * applies them). A DEVELOPMENT build (debug, dev-appliance: {@code BuildConfig.VAULT_DEV_BUILD})
 * keeps adb, the test harness (tools/dev-device) and the crash dialogs working; a RELEASE build
 * also turns off debugging features, the clock settings, physical media, the system error
 * dialogs, the camera, third-party accessibility services and third-party keyboards, and refuses
 * to show or approve anything while USB debugging is on.
 */
final class ApplianceLockdown {
    private ApplianceLockdown() {}

    static final String ADB_REFUSAL_TITLE = "USB debugging is on";
    static final String ADB_REFUSAL = "USB debugging is on. This phone isn't safe to sign with.";

    /** The user restrictions to add (never removed here). */
    static List<String> userRestrictions(boolean devBuild, boolean allowAppUpdates) {
        List<String> r = new ArrayList<>(Arrays.asList(
                UserManager.DISALLOW_ADD_USER,
                UserManager.DISALLOW_MODIFY_ACCOUNTS,
                UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES,
                UserManager.DISALLOW_SAFE_BOOT,
                UserManager.DISALLOW_USB_FILE_TRANSFER,
                UserManager.DISALLOW_CONFIG_WIFI,
                UserManager.DISALLOW_CONFIG_BLUETOOTH,
                UserManager.DISALLOW_BLUETOOTH,
                UserManager.DISALLOW_BLUETOOTH_SHARING,
                UserManager.DISALLOW_CONFIG_MOBILE_NETWORKS,
                UserManager.DISALLOW_CONFIG_TETHERING,
                UserManager.DISALLOW_CONFIG_VPN,
                UserManager.DISALLOW_SHARE_LOCATION));
        if (!allowAppUpdates) {
            // Release: the app set is frozen. Dev builds leave these off so `adb install -r`
            // works; no network + kiosk still prevent sideloading in dev.
            r.add(UserManager.DISALLOW_INSTALL_APPS);
            r.add(UserManager.DISALLOW_UNINSTALL_APPS);
        }
        if (!devBuild) {
            r.add(UserManager.DISALLOW_DEBUGGING_FEATURES);  // adb off and unswitchable
            r.add(UserManager.DISALLOW_CONFIG_DATE_TIME);    // the clock can't be turned back
            r.add(UserManager.DISALLOW_MOUNT_PHYSICAL_MEDIA);
            r.add(UserManager.DISALLOW_SYSTEM_ERROR_DIALOGS); // API 28 (= minSdk): no crash/ANR dialog over the kiosk
        }
        return Collections.unmodifiableList(r);
    }

    /** Camera off, third-party accessibility services and keyboards refused: release only. */
    static boolean restrictsCameraAndInput(boolean devBuild) { return !devBuild; }

    /**
     * The keyboards a release build permits: only the package of the system default input method
     * (Settings.Secure.DEFAULT_INPUT_METHOD, "pkg/.Service"), which the system credential prompt
     * uses for the PIN. The app types PINs, words and names on its own keypads. Android always
     * permits system input methods anyway, so this cannot lock the user out.
     */
    static List<String> permittedInputMethods(String defaultInputMethod) {
        String pkg = imePackage(defaultInputMethod);
        return pkg == null ? Collections.emptyList() : Collections.singletonList(pkg);
    }

    static String imePackage(String defaultInputMethod) {
        if (defaultInputMethod == null) return null;
        String s = defaultInputMethod.trim();
        int slash = s.indexOf('/');
        String pkg = slash >= 0 ? s.substring(0, slash) : s;
        return pkg.isEmpty() || !pkg.matches("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+") ? null : pkg;
    }

    /**
     * True when the phone must refuse to show or approve anything: a release build with USB
     * debugging on ({@code Settings.Global.ADB_ENABLED}; {@code adbEnabled} is its value, 0 when the
     * setting does not exist; any non-zero value is treated as on).
     */
    static boolean refuseForAdb(boolean devBuild, int adbEnabled) {
        return !devBuild && adbEnabled != 0;
    }
}
