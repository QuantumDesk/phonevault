package dev.phonevault.signer;

import android.app.admin.DeviceAdminReceiver;
import android.content.ComponentName;
import android.content.Context;

public final class VaultDeviceAdminReceiver extends DeviceAdminReceiver {
    public static ComponentName component(Context context) {
        return new ComponentName(context, VaultDeviceAdminReceiver.class);
    }
}
