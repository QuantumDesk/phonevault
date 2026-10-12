package dev.phonevault.signer;

import android.os.Build;
import android.view.HapticFeedbackConstants;
import android.view.View;

/**
 * Short haptic confirmations: approve &amp; sign, reject / refusal, PIN key ticks. Uses
 * View#performHapticFeedback, which the system performs on the app's behalf — no VIBRATE
 * permission. The "Haptics" setting (Display &amp; auto-lock, default on) turns all of it off; the
 * system's own touch-feedback setting is also respected.
 */
final class Haptics {
    private static volatile boolean enabled = true;
    /** Gap between the two pulses of the pre-API-30 reject fallback. */
    private static final long DOUBLE_GAP_MS = 110;

    private Haptics() {}

    static void setEnabled(boolean on) { enabled = on; }

    static boolean enabled() { return enabled; }

    /** Approve &amp; sign: one firm confirm. */
    static void confirm(View view) {
        if (!enabled || view == null) return;
        view.performHapticFeedback(Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
                ? HapticFeedbackConstants.CONFIRM : HapticFeedbackConstants.LONG_PRESS);
    }

    /** Reject, refusal, wrong PIN: a distinct double pulse. */
    static void reject(View view) {
        if (!enabled || view == null) return;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            view.performHapticFeedback(HapticFeedbackConstants.REJECT);
            return;
        }
        view.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
        view.postDelayed(() -> { if (enabled) view.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY); }, DOUBLE_GAP_MS);
    }

    /** A key press (PIN pad): a light tick. */
    static void tick(View view) {
        if (!enabled || view == null) return;
        view.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
    }
}
