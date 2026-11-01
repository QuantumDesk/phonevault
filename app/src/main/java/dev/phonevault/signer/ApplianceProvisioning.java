package dev.phonevault.signer;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;
import android.view.View;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.IntSupplier;

/**
 * Everything a factory-fresh unit needs once the OS has made this app device owner on first
 * boot (frameworks-base patch 0003). Idempotent, so it runs from BOTH the device-admin
 * receiver's {@code onEnabled} (first boot, before any UI exists) and every activity start.
 * No adb step exists anywhere in provisioning.
 */
final class ApplianceProvisioning {
    private static final String TAG = "VaultProvision";
    /** Setup wizards that would otherwise win HOME resolution (priority 9) or ask questions. */
    static final String[] SETUP_WIZARDS = {
            "org.lineageos.setupwizard",
            "com.android.provision",
            "com.google.android.setupwizard",
    };

    private ApplianceProvisioning() {}

    /** @return true if every step applied; false if the caller is not (yet) device owner. */
    static boolean apply(Context context, DevicePolicyManager policy) {
        if (!policy.isDeviceOwnerApp(context.getPackageName())) return false;
        ComponentName admin = VaultDeviceAdminReceiver.component(context);
        ComponentName home = new ComponentName(context, MainActivity.class);

        policy.setLockTaskPackages(admin, new String[] {context.getPackageName()});
        // Android's lock screen names the device owner's organization in its disclosure line
        // ("This device belongs to …"); without a name it says "your organization".
        policy.setOrganizationName(admin, "Phone Vault");

        // We are HOME. A persistent preferred activity beats intent-filter priority, so even an
        // image that still ships a setup wizard resolves HOME to the vault.
        IntentFilter homeFilter = new IntentFilter(Intent.ACTION_MAIN);
        homeFilter.addCategory(Intent.CATEGORY_HOME);
        homeFilter.addCategory(Intent.CATEGORY_DEFAULT);
        policy.addPersistentPreferredActivity(admin, homeFilter, home);

        // No lock screen: the in-app PIN is the gate. Returns false only if a credential exists,
        // which an appliance never has.
        if (!policy.setKeyguardDisabled(admin, true)) {
            // Expected once the vault PIN is the device credential: the keyguard stays suppressed
            // from provisioning time; Android's PIN screen appears only at boot (encrypted storage).
            Log.i(TAG, "keyguard disable not re-applied (device credential present)");
        }
        if (SystemCredential.isSet(context)) SystemCredential.applyLockPolicy(context);

        // Display & auto-lock -> Screen timeout (default 2 minutes; a saved choice is kept) and
        // brightness (only once chosen there), re-applied on every pass so a boot or
        // re-provisioning restores the user's choice. A device owner may set SCREEN_OFF_TIMEOUT
        // and SCREEN_BRIGHTNESS(_MODE) through setSystemSetting; no WRITE_SETTINGS (or any other)
        // permission is involved.
        DisplaySettings display = new DisplaySettings(
                context.getSharedPreferences(DisplaySettings.PREFS_FILE, Context.MODE_PRIVATE));
        try {
            policy.setSystemSetting(admin, android.provider.Settings.System.SCREEN_OFF_TIMEOUT,
                    String.valueOf(display.screenTimeoutMs()));
        } catch (RuntimeException e) {
            Log.w(TAG, "screen timeout not applied: " + e.getMessage());
        }
        if (display.brightnessChosen()) applyBrightness(context, policy, display.brightnessPercent(), display.brightnessAuto());

        // Hide any setup wizard the image still carries (release images strip them; this keeps a
        // factory boot deterministic either way).
        PackageManager pm = context.getPackageManager();
        for (String wizard : SETUP_WIZARDS) {
            try {
                pm.getPackageInfo(wizard, PackageManager.MATCH_SYSTEM_ONLY);
            } catch (PackageManager.NameNotFoundException absent) {
                continue;
            }
            try {
                if (!policy.isApplicationHidden(admin, wizard)) {
                    policy.setApplicationHidden(admin, wizard, true);
                    Log.i(TAG, "hid setup wizard " + wizard);
                }
            } catch (RuntimeException e) {
                Log.w(TAG, "could not hide " + wizard + ": " + e.getMessage());
            }
        }
        return true;
    }

    /**
     * Device owner: Settings.System.SCREEN_BRIGHTNESS_MODE and, for a manual choice,
     * SCREEN_BRIGHTNESS (DisplaySettings#systemBrightness). Best effort.
     *
     * @return whether the system took it (false: the caller falls back to the window's brightness)
     */
    static boolean applyBrightness(Context context, DevicePolicyManager policy, int percent, boolean auto) {
        try {
            if (!policy.isDeviceOwnerApp(context.getPackageName())) return false;
            ComponentName admin = VaultDeviceAdminReceiver.component(context);
            policy.setSystemSetting(admin, Settings.System.SCREEN_BRIGHTNESS_MODE, String.valueOf(
                    auto ? DisplaySettings.BRIGHTNESS_MODE_AUTOMATIC : DisplaySettings.BRIGHTNESS_MODE_MANUAL));
            if (!auto) {
                policy.setSystemSetting(admin, Settings.System.SCREEN_BRIGHTNESS,
                        String.valueOf(DisplaySettings.systemBrightness(percent)));
            }
            return true;
        } catch (RuntimeException e) {
            Log.w(TAG, "brightness not applied: " + e.getMessage());
            return false;
        }
    }

    // ------------------------------------------------------------------ every activity start (MainActivity)

    /** A PhoneVault appliance image, as opposed to a development phone running the app. */
    static boolean applianceImage() {
        return "PhoneVault".equals(Build.BRAND);
    }

    /**
     * Self-provisioning, the appliance lockdown (appliance image only), immersive full screen and
     * lock task. A lockdown step the system refuses throws.
     *
     * @return whether lock task is now active
     */
    static boolean enterVaultMode(Activity activity, DevicePolicyManager policy, boolean devBuild) {
        // Self-provisioning (HOME preference, keyguard off, lock-task packages, setup
        // wizards hidden). Also runs from the admin receiver on first boot; idempotent.
        if (!apply(activity, policy)) return false;
        if (applianceImage()) {
            enforceApplianceRestrictions(activity, policy, devBuild);
        }
        if (!policy.isLockTaskPermitted(activity.getPackageName())) return false;
        activity.getWindow().getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                        | View.SYSTEM_UI_FLAG_FULLSCREEN
                        | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                        | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                        | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                        | View.SYSTEM_UI_FLAG_LAYOUT_STABLE);
        ActivityManager activityManager = (ActivityManager) activity.getSystemService(
                Context.ACTIVITY_SERVICE);
        if (activityManager.getLockTaskModeState()
                == ActivityManager.LOCK_TASK_MODE_NONE) {
            activity.startLockTask();
        }
        return activityManager.getLockTaskModeState()
                != ActivityManager.LOCK_TASK_MODE_NONE;
    }

    private static void enforceApplianceRestrictions(Context context, DevicePolicyManager policy, boolean dev) {
        ComponentName admin = VaultDeviceAdminReceiver.component(context);
        // ApplianceLockdown: the base set, the frozen app set (release), and in a release build
        // also debugging features, date/time, physical media and system error dialogs.
        for (String restriction : ApplianceLockdown.userRestrictions(dev, BuildConfig.VAULT_ALLOW_APP_UPDATES)) {
            policy.addUserRestriction(admin, restriction);
        }
        if (ApplianceLockdown.restrictsCameraAndInput(dev)) {
            policy.setCameraDisabled(admin, true);
            // System services/keyboards are always permitted by Android; these lists refuse the rest.
            if (!policy.setPermittedAccessibilityServices(admin, Collections.emptyList())) {
                throw new IllegalStateException("Accessibility services could not be restricted");
            }
            String ime = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.DEFAULT_INPUT_METHOD);
            if (!policy.setPermittedInputMethods(admin, new ArrayList<>(ApplianceLockdown.permittedInputMethods(ime)))) {
                throw new IllegalStateException("Input methods could not be restricted");
            }
        }
        // Only the power menu (long-press Power: power off / restart) works inside the kiosk.
        // Without it the sole way off is a forced hardware restart. The OS image trims the menu
        // to power + restart (config_globalActionsList); nothing else of lock task is opened up.
        policy.setLockTaskFeatures(VaultDeviceAdminReceiver.component(context),
                DevicePolicyManager.LOCK_TASK_FEATURE_GLOBAL_ACTIONS);
        policy.setScreenCaptureDisabled(VaultDeviceAdminReceiver.component(context),
                !DevTools.SCREENSHOTS);
        if (!policy.setStatusBarDisabled(VaultDeviceAdminReceiver.component(context), true)) {
            throw new IllegalStateException("Status bar could not be disabled");
        }
    }

    /** Device owner: idle screen-off (burn-in + walk-away). Best effort; never fatal. */
    static void applyIdlePolicy(Context context, DevicePolicyManager policy, IntSupplier screenOffMs) {
        try {
            ComponentName admin = null;
            List<ComponentName> admins = policy.getActiveAdmins();
            if (admins != null) {
                for (ComponentName c : admins) {
                    if (context.getPackageName().equals(c.getPackageName())) admin = c;
                }
            }
            if (admin == null) return;
            policy.setSystemSetting(admin, Settings.System.SCREEN_OFF_TIMEOUT,
                    String.valueOf(screenOffMs.getAsInt()));
        } catch (Exception e) {
            Log.w("Vault", "idle policy not applied", e);
        }
    }
}
