package dev.phonevault.signer;

import android.app.Activity;

/** Release: no screenshot code is compiled in. FLAG_SECURE and the DO capture block stay on. */
final class DevTools {
    static final boolean SCREENSHOTS = false;
    static final String VARIANT = "release";

    private DevTools() {}

    static void dumpUi(Activity activity) {
        // intentionally empty
    }
}
