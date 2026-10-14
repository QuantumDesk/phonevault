package dev.phonevault.signer;

import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.util.Log;
import android.view.View;

import java.io.File;
import java.io.FileOutputStream;

/**
 * DEVELOPMENT ONLY. This source set is compiled into debug/appliance builds; the release build
 * gets the no-op stub in {@code src/release/java}, so no screenshot code exists in a release APK.
 *
 * <p>Renders the current view to {@code files/vault_dump.png} so the UI can be reviewed even though
 * FLAG_SECURE / device-owner screen-capture policy block screencap. This intentionally captures
 * non-sensitive screens only. Backup, reauthentication, and replacement screens are excluded.
 * The development OS still permits external screenshots; never use it for valuable assets.
 *
 * <p>Requests are coalesced (a burst of touches yields one dump, 1.4 s after the last) and PNG
 * compression runs off the UI thread, so the hook cannot starve input dispatch during scripted
 * tests (a 4 MP PNG encode on the UI thread drops taps in fast keypad bursts).
 */
final class DevTools {
    /** Also lifts FLAG_SECURE and the DO screen-capture block. */
    static final boolean SCREENSHOTS = true;
    private static Runnable pendingDump; // UI thread only

    private DevTools() {}

    static void dumpUi(Activity activity) {
        final View root = activity.getWindow().getDecorView();
        if (pendingDump != null) root.removeCallbacks(pendingDump);
        if (activity instanceof MainActivity && ((MainActivity) activity).isSensitiveScreen()) {
            pendingDump = null;
            return;
        }
        pendingDump = () -> {
            pendingDump = null;
            if (activity instanceof MainActivity && ((MainActivity) activity).isSensitiveScreen()) return;
            try {
                if (root.getWidth() == 0 || root.getHeight() == 0) return;
                final Bitmap bmp = Bitmap.createBitmap(root.getWidth(), root.getHeight(), Bitmap.Config.ARGB_8888);
                root.draw(new Canvas(bmp)); // fast; the expensive PNG encode happens below, off-thread
                final File target = new File(activity.getFilesDir(), "vault_dump.png");
                final File temp = new File(activity.getFilesDir(), "vault_dump.png.tmp");
                new Thread(() -> {
                    try (FileOutputStream os = new FileOutputStream(temp)) {
                        bmp.compress(Bitmap.CompressFormat.PNG, 100, os);
                    } catch (Exception e) {
                        Log.e("VaultDump", "dump failed", e);
                        return;
                    }
                    if (!temp.renameTo(target)) Log.e("VaultDump", "dump rename failed");
                    else Log.i("VaultDump", "dumped " + bmp.getWidth() + "x" + bmp.getHeight());
                    bmp.recycle();
                }, "vault-dump").start();
            } catch (Exception e) {
                Log.e("VaultDump", "dump failed", e);
            }
        };
        root.postDelayed(pendingDump, 1400);
    }
}
