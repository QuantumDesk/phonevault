package dev.phonevault.signer;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.util.Log;

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

        // Display & auto-lock -> Screen timeout (default 60 s), re-applied on every pass so a boot
        // or re-provisioning restores the user's choice. A device owner may set SCREEN_OFF_TIMEOUT
        // through setSystemSetting; no WRITE_SETTINGS (or any other) permission is involved.
        try {
            DisplaySettings display = new DisplaySettings(
                    context.getSharedPreferences(DisplaySettings.PREFS_FILE, Context.MODE_PRIVATE));
            policy.setSystemSetting(admin, android.provider.Settings.System.SCREEN_OFF_TIMEOUT,
                    String.valueOf(display.screenTimeoutMs()));
        } catch (RuntimeException e) {
            Log.w(TAG, "screen timeout not applied: " + e.getMessage());
        }

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
}
