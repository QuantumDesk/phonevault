package dev.phonevault.signer;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * After this app is updated, Android can forget the persistent HOME preference and show a
 * launcher chooser. Re-run the idempotent provisioning and
 * bring the vault back to the front. Not exported: only the system sends MY_PACKAGE_REPLACED.
 */
public final class PackageReplacedReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (!Intent.ACTION_MY_PACKAGE_REPLACED.equals(intent.getAction())) return;
        VaultDeviceAdminReceiver.provision(context, "package update", goAsync());
    }
}
