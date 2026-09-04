package dev.phonevault.signer;

import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

public final class VaultDeviceAdminReceiver extends DeviceAdminReceiver {
    private static final String TAG = "VaultProvision";
    private static final int MAX_RETRIES = 20;
    private static final long RETRY_MS = 500;

    public static ComponentName component(Context context) {
        return new ComponentName(context, VaultDeviceAdminReceiver.class);
    }

    /**
     * First boot: DevicePolicyManagerService activates this admin and then makes it device
     * owner (patch 0003). The enable broadcast can arrive a moment before the owner record is
     * written, so provisioning is retried briefly until {@code isDeviceOwnerApp} is true.
     */
    @Override public void onEnabled(Context context, Intent intent) {
        final PendingResult pending = goAsync();
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
                    Log.i(TAG, "appliance provisioned on admin enable (attempt " + (attempts + 1) + ")");
                    pending.finish();
                } else if (++attempts < MAX_RETRIES) {
                    handler.postDelayed(this, RETRY_MS);
                } else {
                    Log.w(TAG, "not device owner after " + MAX_RETRIES + " attempts; the activity will retry");
                    pending.finish();
                }
            }
        });
    }
}
