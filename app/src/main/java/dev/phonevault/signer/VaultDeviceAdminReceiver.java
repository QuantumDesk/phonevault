package dev.phonevault.signer;

import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.os.UserHandle;
import android.util.Log;

public final class VaultDeviceAdminReceiver extends DeviceAdminReceiver {
    private static final String TAG = "VaultProvision";
    /**
     * A first boot on a freshly formatted /data is slow; the owner record can land well after the
     * enable broadcast reaches us. Keep trying for ten minutes rather than ten seconds — this
     * receiver is the ONLY thing that starts the app on a factory boot, so giving up early leaves
     * the device outside the kiosk until something else launches the activity.
     */
    private static final int MAX_RETRIES = 300;
    private static final long RETRY_MS = 2000;

    public static ComponentName component(Context context) {
        return new ComponentName(context, VaultDeviceAdminReceiver.class);
    }

    /**
     * First boot: DevicePolicyManagerService activates this admin and then makes it device
     * owner (patch 0003). The enable broadcast can arrive a moment before the owner record is
     * written, so provisioning is retried briefly until {@code isDeviceOwnerApp} is true.
     */
    @Override public void onEnabled(Context context, Intent intent) {
        provision(context, "admin enable");
    }

    /**
     * Every boot, as device owner. On a factory boot this is the fallback that matters: patch
     * 0003 activates the admin while the freshly wiped package is still in Android's "stopped"
     * state, so DEVICE_ADMIN_ENABLED can be dropped (seen 2026-09-24 after a wipe-after-10);
     * USER_STARTED arrives once the package is unstopped. {@link ApplianceProvisioning#apply} is
     * idempotent, so running it on every boot costs nothing.
     */
    @Override public void onUserStarted(Context context, Intent intent, UserHandle user) {
        provision(context, "user start");
    }

    private void provision(Context context, final String why) {
        provision(context, why, goAsync());
    }

    /** Shared with {@link PackageReplacedReceiver}. */
    static void provision(Context context, final String why, final android.content.BroadcastReceiver.PendingResult pending) {
        final Context app = context.getApplicationContext();
        final DevicePolicyManager policy =
                (DevicePolicyManager) app.getSystemService(Context.DEVICE_POLICY_SERVICE);
        final Handler handler = new Handler(Looper.getMainLooper());
        handler.post(new Runnable() {
            int attempts;
            @Override public void run() {
                boolean done;
                try {
                    done = ApplianceProvisioning.apply(app, policy);
                } catch (RuntimeException e) {
                    Log.w(TAG, "provisioning attempt failed: " + e.getMessage());
                    done = false;
                }
                if (done) {
                    Log.w(TAG, "appliance provisioned on " + why + " (attempt " + (attempts + 1) + ")");
                    showVault(app);
                    pending.finish();
                } else if (++attempts < MAX_RETRIES) {
                    if (attempts % 15 == 0) Log.w(TAG, "waiting to become device owner (" + attempts + " attempts)");
                    handler.postDelayed(this, RETRY_MS);
                } else {
                    Log.w(TAG, "not device owner after " + MAX_RETRIES + " attempts; the activity will retry");
                    pending.finish();
                }
            }
        });
    }

    /**
     * Bring the vault to the front. HOME now resolves to it, but a launcher (or the HOME chooser)
     * may already be showing if provisioning ran late; a device owner may start activities from
     * the background, and the activity itself enters lock task.
     */
    private static void showVault(Context app) {
        try {
            app.startActivity(new Intent(app, MainActivity.class)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT));
        } catch (RuntimeException e) {
            Log.w(TAG, "could not bring the vault to the front: " + e.getMessage());
        }
    }
}
