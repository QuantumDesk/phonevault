package dev.phonevault.signer;

import android.content.Context;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Full-screen mono/pixel PIN pad. Fixed-length PIN ({@link VaultPin#PIN_LENGTH}); auto-submits when
 * full. The caller decides what the PIN means (set / confirm / unlock) via the submit callback.
 */
final class PinScreen {

    interface OnPin {
        /** Called with the entered digits; the array is zeroed by the caller after use. */
        void onPin(char[] pin);
    }

    private final Context context;
    private final LinearLayout root;
    private final TextView title;
    private final TextView subtitle;
    /** Summary of a USB request that arrived while locked (display only; nothing is answered). */
    private final LinearLayout pending;
    private final TextView pendingLabel;
    private final TextView pendingBody;
    private final TextView dots;
    private final TextView error;
    private final TextView policy;
    private final TextView submit;
    private final android.widget.ScrollView scroll;
    private boolean submitRequired;
    /** Fixed buffer + length instead of a StringBuilder, so digits can be zeroed, not just hidden. */
    private final char[] entered = new char[VaultPin.PIN_LENGTH];
    private int enteredLength;
    private final OnPin onPin;
    private boolean locked; // ignore input while a verify is in flight

    PinScreen(Context c, String titleText, String subtitleText, OnPin onPin) {
        this.context = c;
        this.onPin = onPin;
        int pad = VaultTheme.dp(c, 26);
        root = new LinearLayout(c);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, VaultTheme.dp(c, 56), pad, VaultTheme.dp(c, 30));
        root.setBackgroundColor(VaultTheme.BG);

        LinearLayout head = new LinearLayout(c);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);
        head.addView(VaultTheme.pixelLock(c, VaultTheme.dp(c, 2), VaultTheme.INK));
        title = VaultTheme.pixelText(c, titleText, 13, VaultTheme.INK);
        title.setPadding(VaultTheme.dp(c, 14), 0, 0, 0);
        head.addView(title);
        root.addView(head);

        subtitle = VaultTheme.bodyText(c, subtitleText, 16, VaultTheme.DIM);
        subtitle.setPadding(0, VaultTheme.dp(c, 14), 0, 0);
        root.addView(subtitle);

        pending = VaultTheme.box(c);
        pendingLabel = VaultTheme.bodyText(c, "", 13, VaultTheme.FAINT);
        pendingBody = VaultTheme.bodyText(c, "", 17, VaultTheme.INK);
        pendingBody.setPadding(0, VaultTheme.dp(c, 6), 0, 0);
        pending.addView(pendingLabel);
        pending.addView(pendingBody);
        pending.setVisibility(View.GONE);
        root.addView(pending, matchWrap(VaultTheme.dp(c, 18)));

        // top spacer
        root.addView(new View(c), new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        dots = VaultTheme.monoText(c, "", 22, VaultTheme.INK);
        dots.setGravity(Gravity.CENTER);
        dots.setLetterSpacing(0.12f);
        root.addView(dots, matchWrap(0));

        error = VaultTheme.bodyText(c, "", 15, VaultTheme.DANGER_INK);
        error.setGravity(Gravity.CENTER);
        error.setAllCaps(true);
        error.setLetterSpacing(0.06f);
        error.setPadding(0, VaultTheme.dp(c, 16), 0, 0);
        error.setMinHeight(VaultTheme.dp(c, 40));
        root.addView(error, matchWrap(0));

        // bottom spacer
        root.addView(new View(c), new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        root.addView(keypad(), matchWrap(0));
        policy = VaultTheme.bodyText(c, "", 14, VaultTheme.FAINT);
        policy.setPadding(0, VaultTheme.dp(c, 16), 0, 0);
        root.addView(policy);
        submit = VaultTheme.pixelButton(c, "Submit PIN · last attempt", true);
        submit.setVisibility(View.GONE);
        hardenTouch(submit);
        submit.setOnClickListener(v -> submit());
        root.addView(submit, matchWrap(VaultTheme.dp(c, 12)));
        scroll = new android.widget.ScrollView(c);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(VaultTheme.BG);
        scroll.addView(root);
        renderDots();
    }

    View view() { return scroll; }

    void setPolicy(String text) { policy.setText(text); }
    void setLargeText(boolean large) {
        subtitle.setTextSize(large ? 19 : 16);
        error.setTextSize(large ? 18 : 15);
        policy.setTextSize(large ? 17 : 14);
    }
    void setSubmitRequired(boolean required) {
        submitRequired = required;
        submit.setVisibility(required ? View.VISIBLE : View.GONE);
        submit.setEnabled(enteredLength == VaultPin.PIN_LENGTH && !locked);
    }
    void addCancel(Runnable action) {
        TextView cancel = VaultTheme.pixelButton(context, "Cancel", false);
        hardenTouch(cancel);
        cancel.setOnClickListener(v -> action.run());
        root.addView(cancel, matchWrap(VaultTheme.dp(context, 8)));
    }
    void dispose() {
        java.util.Arrays.fill(entered, '0');
        enteredLength = 0;
        locked = true;
    }

    void setTitle(String t) { title.setText(t); }

    void setSubtitle(String s) { subtitle.setText(s); }

    /** Show (or with null hide) the summary of a request waiting behind the gate. */
    void setPending(String label, String body) {
        if (body == null) { pending.setVisibility(View.GONE); return; }
        pendingLabel.setText(label);
        pendingBody.setText(body);
        pending.setVisibility(View.VISIBLE);
    }

    void showError(String message) {
        error.setText(message == null ? "" : message);
        reset();
    }

    void reset() {
        java.util.Arrays.fill(entered, '0');
        enteredLength = 0;
        locked = false;
        submit.setEnabled(false);
        renderDots();
    }

    private LinearLayout keypad() {
        String[][] rows = {{"1", "2", "3"}, {"4", "5", "6"}, {"7", "8", "9"}, {"⌫", "0", ""}};
        LinearLayout pad = new LinearLayout(context);
        pad.setOrientation(LinearLayout.VERTICAL);
        int gap = VaultTheme.dp(context, 8);
        for (String[] row : rows) {
            LinearLayout r = new LinearLayout(context);
            r.setOrientation(LinearLayout.HORIZONTAL);
            for (String key : row) {
                View b = key.isEmpty() ? new View(context) : keyButton(key);
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                        VaultTheme.dp(context, 64), 1f);
                lp.setMargins(gap / 2, gap / 2, gap / 2, gap / 2);
                r.addView(b, lp);
            }
            pad.addView(r);
        }
        return pad;
    }

    private TextView keyButton(String key) {
        TextView b = VaultTheme.pixelButton(context, key, false);
        b.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 22f);
        if ("⌫".equals(key)) b.setContentDescription("Delete last digit");
        hardenTouch(b);
        b.setOnClickListener(v -> press(key));
        return b;
    }

    private void press(String key) {
        if (locked) return;
        if ("⌫".equals(key)) {
            if (enteredLength > 0) entered[--enteredLength] = '0';
            renderDots();
            submit.setEnabled(false);
            return;
        }
        if (enteredLength >= VaultPin.PIN_LENGTH) return;
        entered[enteredLength++] = key.charAt(0);
        error.setText("");
        renderDots();
        submit.setEnabled(enteredLength == VaultPin.PIN_LENGTH);
        if (enteredLength == VaultPin.PIN_LENGTH && !submitRequired) submit();
    }

    private void submit() {
        if (!locked && enteredLength == VaultPin.PIN_LENGTH) {
            locked = true;
            submit.setEnabled(false);
            char[] pin = entered.clone(); // the callee zeroes its copy; we zero ours now
            java.util.Arrays.fill(entered, '0');
            enteredLength = 0;
            onPin.onPin(pin);
        }
    }

    private void renderDots() {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < VaultPin.PIN_LENGTH; i++) {
            s.append(i < enteredLength ? "■" : "□");
            if (i < VaultPin.PIN_LENGTH - 1) s.append(' ');
        }
        dots.setText(s);
    }

    private static LinearLayout.LayoutParams matchWrap(int topMargin) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        p.topMargin = topMargin;
        return p;
    }

    private static void hardenTouch(View view) {
        view.setFilterTouchesWhenObscured(true);
        view.setOnTouchListener((ignored, event) -> (event.getFlags()
                & (MotionEvent.FLAG_WINDOW_IS_OBSCURED
                | MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)) != 0);
    }
}
