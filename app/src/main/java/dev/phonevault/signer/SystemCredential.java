package dev.phonevault.signer;

import android.app.Activity;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.util.Log;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * The vault PIN as the Android lock credential (pin-credential-design.md, option A + b).
 *
 * <p>Once installed, Gatekeeper on the Titan M verifies the PIN and throttles guesses in hardware,
 * file-based encryption keeps the app's storage sealed until the PIN is entered after every boot,
 * and the seed key ({@link VaultKeyStore}) only works for a short window after a successful check.
 * The keyguard stays suppressed by device-owner policy, so the check happens through a system
 * credential prompt shown over our own screens, only when the seed is actually needed.
 */
final class SystemCredential {
    private static final String TAG = "VaultCredential";
    /** Seconds the seed key stays usable after a successful credential check. */
    static final int AUTH_WINDOW_SECONDS = 30;
    /** System-enforced wipe after this many consecutive wrong PINs (factory reset). */
    static final int MAX_FAILED_FOR_WIPE = 10;

    private SystemCredential() {}

    /** The credential-bound mode needs API 30+ (auth-type-aware keys and credential-only prompts). */
    static boolean supported() { return Build.VERSION.SDK_INT >= Build.VERSION_CODES.R; }

    /** True when the device has a lock credential (ours: installed by {@link #install}). */
    static boolean isSet(Context context) {
        KeyguardManager keyguard = context.getSystemService(KeyguardManager.class);
        return supported() && keyguard != null && keyguard.isDeviceSecure();
    }

    /** True when a PIN set now becomes the device credential (device owner, API 30+). */
    static boolean willBind(Context context) {
        if (!supported()) return false;
        DevicePolicyManager policy = context.getSystemService(DevicePolicyManager.class);
        return policy != null && policy.isDeviceOwnerApp(context.getPackageName());
    }

    /**
     * Install {@code pin} as the device PIN. Device owner only, and only while NO credential exists
     * (the reset token activates immediately then). The token is cleared afterwards, so nothing on
     * the device can reset the PIN without the user. Zeroes {@code pin} on every path.
     */
    static boolean install(Context context, char[] pin) {
        byte[] token = new byte[32];
        try {
            if (!supported() || isSet(context)) return false;
            DevicePolicyManager policy = context.getSystemService(DevicePolicyManager.class);
            ComponentName admin = VaultDeviceAdminReceiver.component(context);
            if (policy == null || !policy.isDeviceOwnerApp(context.getPackageName())) return false;
            new SecureRandom().nextBytes(token);
            if (!policy.setResetPasswordToken(admin, token)) return false;
            if (!policy.isResetPasswordTokenActive(admin)) { policy.clearResetPasswordToken(admin); return false; }
            boolean ok = policy.resetPasswordWithToken(admin, new String(pin), token, 0);
            policy.clearResetPasswordToken(admin);
            if (ok) applyLockPolicy(context);
            Log.i(TAG, ok ? "device credential installed" : "device credential install refused");
            return ok;
        } catch (RuntimeException e) {
            Log.w(TAG, "credential install failed: " + e.getMessage());
            return false;
        } finally {
            Arrays.fill(token, (byte) 0);
            Arrays.fill(pin, '0');
        }
    }

    /**
     * Lock-screen hardening once a credential exists: Android's own PIN screen (shown once per
     * boot to unlock encrypted storage) shows no notifications and no trust-agent shortcuts, says
     * what it unlocks, and the system wipes the phone after {@link #MAX_FAILED_FOR_WIPE} failures.
     */
    static void applyLockPolicy(Context context) {
        DevicePolicyManager policy = context.getSystemService(DevicePolicyManager.class);
        ComponentName admin = VaultDeviceAdminReceiver.component(context);
        if (policy == null || !policy.isDeviceOwnerApp(context.getPackageName())) return;
        try {
            policy.setKeyguardDisabledFeatures(admin,
                    DevicePolicyManager.KEYGUARD_DISABLE_SECURE_NOTIFICATIONS
                            | DevicePolicyManager.KEYGUARD_DISABLE_UNREDACTED_NOTIFICATIONS
                            | DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS
                            | DevicePolicyManager.KEYGUARD_DISABLE_SECURE_CAMERA
                            | DevicePolicyManager.KEYGUARD_DISABLE_WIDGETS_ALL);
            policy.setDeviceOwnerLockScreenInfo(admin, "Phone Vault · enter your PIN to unlock");
            policy.setMaximumFailedPasswordsForWipe(admin, MAX_FAILED_FOR_WIPE);
        } catch (RuntimeException e) {
            Log.w(TAG, "lock policy not fully applied: " + e.getMessage());
        }
    }

    interface Result { void done(boolean confirmed, String message); }

    /**
     * Ask the system to verify the device PIN (credential only, no biometrics). A success opens the
     * {@link #AUTH_WINDOW_SECONDS} window in which the seed key works. Callback on the main thread.
     */
    static void confirm(Activity activity, String title, String subtitle, Result result) {
        if (!supported()) { result.done(false, "This Android version cannot verify the device PIN."); return; }
        try {
            show(activity, title, subtitle, result);
        } catch (RuntimeException e) {
            Log.w(TAG, "credential prompt failed: " + e);
            result.done(false, "The PIN prompt could not be shown.");
        }
    }

    private static void show(Activity activity, String title, String subtitle, Result result) {
        BiometricPrompt prompt = new BiometricPrompt.Builder(activity)
                .setTitle(title)
                .setSubtitle(subtitle)
                .setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build();
        prompt.authenticate(new CancellationSignal(), activity.getMainExecutor(),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {
                        result.done(true, null);
                    }
                    @Override public void onAuthenticationError(int code, CharSequence message) {
                        result.done(false, message == null ? "PIN not confirmed" : message.toString());
                    }
                });
    }
}
