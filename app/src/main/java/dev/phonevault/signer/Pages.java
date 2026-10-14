package dev.phonevault.signer;

import android.app.Activity;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.text.Layout;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONObject;

import java.util.List;
import java.util.Locale;

/**
 * The building blocks of every native page: the page frame with its header (brand, battery, ☰),
 * cards, actions, review rows, the review top (danger summary, rows, details toggle), and
 * presenting a page. Native, scrollable pages; sensitive operations never use floating dialogs.
 * Owns the name of the screen on display. UI thread only.
 */
final class Pages {
    /** What the pages borrow from MainActivity. */
    interface Host {
        /** Last battery reading, for the header indicator. */
        BatteryStatus battery();
        /** The ☰ menu is offered (see MainActivity#menuAvailable). */
        boolean menuAvailable();
        void showMenu();
        /** Whether {@code screen} may be shown now: phrase / restore-over screens only inside their sensitive flow. */
        boolean mayPresent(String screen);
        /** Buttons act only while the vault is unlocked and operational. */
        boolean actionsEnabled();
        /** Window flags change on the UI thread only (MainActivity#keepScreenOn). */
        void keepScreenOn(boolean on);
        void lock();
    }

    /** Set on a page's root before {@link #present}: called once the end of the page has been on screen. */
    interface ScrollEndWatcher { void reachedEnd(); }

    /** Kicker of a screenshot build's reviews, in place of the review's own. */
    static final String DEV_KICKER = "DEVELOPMENT · TEST ASSETS ONLY";

    private final Activity activity;
    private final Host host;
    /** The header indicator of the page on screen (see {@link #showBattery}). */
    private View batteryIndicator;
    private String screenName = "loading";

    Pages(Activity activity, Host host) {
        this.activity = activity;
        this.host = host;
    }

    /** The screen on display (e.g. "wallet", "pin", "loading"). */
    String screen() { return screenName; }

    /** For screens shown without {@link #present} (the PIN pages). */
    void setScreen(String screen) { screenName = screen; }

    /** Updates the header of the page on screen in place. */
    void showBattery(BatteryStatus status) {
        if (batteryIndicator != null) VaultTheme.showBattery(batteryIndicator, status);
    }

    LinearLayout page(String eyebrow, String title, String description) {
        LinearLayout root = new LinearLayout(activity);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(24), dp(48), dp(24), dp(30));
        root.setBackgroundColor(VaultTheme.BG);
        TextView brand = VaultTheme.pixelText(activity, "PHONE VAULT", 10, VaultTheme.ACCENT);
        // Header row: brand on the left, battery, then ☰ (when available). One menu everywhere.
        LinearLayout header = new LinearLayout(activity);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setMinimumHeight(dp(42));
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        header.addView(brand, blp);
        batteryIndicator = VaultTheme.batteryIndicator(activity);
        VaultTheme.showBattery(batteryIndicator, host.battery());
        header.addView(batteryIndicator);
        root.addView(header);
        if (host.menuAvailable()) {
            TextView menu = VaultTheme.pixelButton(activity, "☰", false);
            VaultTheme.size(menu, 22);
            menu.setPadding(0, 0, 0, 0);
            menu.setContentDescription("Menu");
            hardenTouch(menu);
            menu.setOnClickListener(v -> { if (host.menuAvailable()) host.showMenu(); });
            LinearLayout.LayoutParams mlp = new LinearLayout.LayoutParams(dp(56), dp(48));
            mlp.setMargins(dp(12), -dp(6), 0, 0);
            header.addView(menu, mlp);
        }
        TextView label = VaultTheme.bodyText(activity, eyebrow.toUpperCase(Locale.ROOT), 12, VaultTheme.FAINT);
        label.setPadding(0, dp(30), 0, dp(8));
        root.addView(label);
        TextView heading = VaultTheme.bodyText(activity, title, 28, VaultTheme.INK);
        heading.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        root.addView(heading);
        if (description != null && !description.isEmpty()) {
            String shown = ReviewStyle.groupEvmIn(description); // e.g. a refusal naming the requested account
            TextView caption = VaultTheme.bodyText(activity, shown, VaultTheme.BODY_SIZE, VaultTheme.DIM);
            if (!shown.equals(description)) keepGroupsWhole(caption);
            caption.setPadding(0, dp(12), 0, dp(12));
            root.addView(caption);
        }
        return root;
    }

    void present(LinearLayout root, String screen) {
        if (!host.mayPresent(screen)) return;
        screenName = screen;
        ScrollView scroll = new ScrollView(activity);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(VaultTheme.BG);
        scroll.addView(root);
        activity.setContentView(scroll);
        watchScrollEnd(scroll, root);
        DevTools.dumpUi(activity);
    }

    void action(LinearLayout parent, String label, boolean primary, Runnable run) {
        TextView button = VaultTheme.pixelButton(activity, label, primary);
        hardenTouch(button);
        button.setOnClickListener(v -> {
            if (host.actionsEnabled()) run.run();
        });
        parent.addView(button, matchWrap(dp(12)));
    }

    void card(LinearLayout parent, String label, String value) {
        LinearLayout box = VaultTheme.box(activity);
        box.addView(VaultTheme.bodyText(activity, label, 13, VaultTheme.FAINT));
        // Whole EVM addresses in groups of four; a card that IS an address is monospace.
        String shown = ReviewStyle.groupEvmIn(value);
        TextView text = Addresses.isEvm(value) ? VaultTheme.monoText(activity, shown, VaultTheme.BODY_SIZE, VaultTheme.INK)
                : VaultTheme.bodyText(activity, shown, VaultTheme.BODY_SIZE, VaultTheme.INK);
        if (!shown.equals(value)) keepGroupsWhole(text);
        text.setPadding(0, dp(6), 0, 0);
        box.addView(text);
        parent.addView(box, matchWrap(dp(12)));
    }

    void showLoading(String title, String caption) {
        LinearLayout root = page("PLEASE WAIT", title, caption);
        card(root, "Privacy", "Your receiving address stays hidden until the wallet is ready.");
        action(root, "Lock now", false, host::lock);
        present(root, "loading");
    }

    void showInfo(String title, String description, Runnable back) {
        LinearLayout root = page("NOTICE", title, description);
        action(root, "Continue", true, back);
        present(root, "information");
    }

    static String kicker(String reviewKicker) { return DevTools.SCREENSHOTS ? DEV_KICKER : reviewKicker; }

    /**
     * The top of every signing review (EVM transaction, message, Bitcoin PSBT), in reading order:
     * the danger summary, the signing account (EVM only; null for Bitcoin), every summary row, and
     * the details behind a Show/Hide toggle. Keeps the screen on while the review is up.
     */
    LinearLayout renderReview(String reviewKicker, String title, String subtitle, List<MessageReview.Row> dangers,
                              SigningAccount signingAs, List<MessageReview.Row> summary,
                              List<MessageReview.Row> details, String detailsWhat) {
        host.keepScreenOn(true);
        LinearLayout root = page(kicker(reviewKicker), title, subtitle);
        addDangerSummary(root, dangers);
        if (signingAs != null) root.addView(detail("Signing with", signingAs.signingWith()));
        for (MessageReview.Row row : summary) root.addView(detail(row));
        addDetailsToggle(root, details, detailsWhat);
        return root;
    }

    /** The review's secondary rows behind a Show/Hide button; open from the start if one is a DANGER. */
    private void addDetailsToggle(LinearLayout root, List<MessageReview.Row> rows, String what) {
        LinearLayout raw = new LinearLayout(activity);
        raw.setOrientation(LinearLayout.VERTICAL);
        for (MessageReview.Row row : rows) raw.addView(detail(row));
        boolean open = !ReviewStyle.dangers(rows).isEmpty(); // a DANGER is never folded away
        raw.setVisibility(open ? View.VISIBLE : View.GONE);
        TextView details = VaultTheme.pixelButton(activity, (open ? "Hide " : "Show ") + what, false);
        hardenTouch(details);
        details.setOnClickListener(v -> {
            boolean visible = raw.getVisibility() == View.VISIBLE;
            raw.setVisibility(visible ? View.GONE : View.VISIBLE);
            details.setText((visible ? "Show " : "Hide ") + what);
        });
        root.addView(details, matchWrap(dp(8)));
        root.addView(raw);
    }

    /** Wires a {@link ScrollEndWatcher} tag on the page root to its ScrollView (scrolls and layouts). */
    private void watchScrollEnd(ScrollView scroll, LinearLayout root) {
        if (!(root.getTag() instanceof ScrollEndWatcher)) return;
        ScrollEndWatcher watcher = (ScrollEndWatcher) root.getTag();
        Runnable check = () -> {
            if (scroll.getHeight() == 0) return;
            if (ApprovalGate.atEnd(root.getHeight(), scroll.getScrollY(), scroll.getHeight(), dp(24))) watcher.reachedEnd();
        };
        scroll.setOnScrollChangeListener((v, x, y, ox, oy) -> check.run());
        root.addOnLayoutChangeListener((v, l, t, r, b, ol, ot, or, ob) -> check.run());
        scroll.post(check);
    }

    View detail(String label, String value) {
        return detail(new MessageReview.Row(label, value));
    }

    /**
     * One review row. DANGER: red, stop glyph, "DANGER · TOPIC", on a red-outlined panel. WARNING:
     * amber, "!" glyph, "CHECK · TOPIC". Whole EVM addresses in the text are shown in groups of
     * four ("0x51dd 9Afd …"), so a line only wraps between groups.
     */
    View detail(MessageReview.Row r) {
        String label = r.label, value = r.value;
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.VERTICAL);
        ReviewStyle.Level level = ReviewStyle.level(r);
        boolean amber = BtcPsbtReview.TEST_NETWORK.equals(label);
        int ink = level == ReviewStyle.Level.DANGER ? VaultTheme.DANGER_INK
                : level == ReviewStyle.Level.CHECK ? VaultTheme.WARNING_INK : amber ? VaultTheme.AMBER : 0;
        TextView labelView = VaultTheme.bodyText(activity, ReviewStyle.heading(r), 13, ink != 0 ? ink : VaultTheme.FAINT);
        String shown = ReviewStyle.displayValue(label, value);
        TextView valueView = VaultTheme.monoText(activity, shown, amber ? VaultTheme.BODY_SIZE + 2 : VaultTheme.BODY_SIZE, ink != 0 ? ink : VaultTheme.INK);
        if (!shown.equals(value)) keepGroupsWhole(valueView);
        valueView.setTextIsSelectable(false);
        valueView.setPadding(0, dp(6), 0, dp(15));
        if (level != ReviewStyle.Level.NONE) {
            labelView.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
            LinearLayout heading = new LinearLayout(activity);
            heading.setOrientation(LinearLayout.HORIZONTAL);
            heading.setGravity(Gravity.CENTER_VERTICAL);
            LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            glp.rightMargin = dp(8);
            heading.addView(VaultTheme.levelGlyph(activity, level), glp);
            heading.addView(labelView, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
            row.addView(heading);
        } else {
            row.addView(labelView);
        }
        row.addView(valueView);
        SafetyScreens.style(activity, row, label, valueView, value);
        return row;
    }

    /** Grouped addresses: break lines only at the spaces between groups (no hyphenation inside one). */
    static void keepGroupsWhole(TextView t) {
        t.setHyphenationFrequency(Layout.HYPHENATION_FREQUENCY_NONE);
        t.setBreakStrategy(Layout.BREAK_STRATEGY_SIMPLE);
    }

    /**
     * Top of a review with DANGER rows: "N dangers below — read before signing" and each one's
     * topic, on the same red-outlined panel the rows use.
     */
    private void addDangerSummary(LinearLayout root, List<MessageReview.Row> dangers) {
        if (dangers.isEmpty()) return;
        LinearLayout panel = new LinearLayout(activity);
        panel.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0x33FF5A5A);
        bg.setStroke(dp(2), VaultTheme.DANGER_INK);
        bg.setCornerRadius(dp(6));
        panel.setBackground(bg);
        panel.setPadding(dp(12), dp(12), dp(12), dp(12));
        LinearLayout heading = new LinearLayout(activity);
        heading.setOrientation(LinearLayout.HORIZONTAL);
        heading.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        glp.rightMargin = dp(10);
        heading.addView(VaultTheme.levelGlyph(activity, ReviewStyle.Level.DANGER), glp);
        TextView title = VaultTheme.bodyText(activity, ReviewStyle.dangerSummary(dangers.size()), VaultTheme.BODY_SIZE, VaultTheme.DANGER_INK);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        heading.addView(title, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        panel.addView(heading);
        StringBuilder topics = new StringBuilder();
        for (MessageReview.Row d : dangers) {
            String t = ReviewStyle.topic(d);
            if (topics.length() > 0) topics.append('\n');
            topics.append("• ").append(t != null ? t : ReviewStyle.shortenEvm(ReviewStyle.firstSentence(d.value)));
        }
        TextView list = VaultTheme.bodyText(activity, topics.toString(), 13, VaultTheme.DANGER_INK);
        list.setPadding(0, dp(8), 0, 0);
        panel.addView(list);
        root.addView(panel, matchWrap(dp(4)));
    }

    /** Refuse touches while another window covers this one (tapjacking). */
    static void hardenTouch(View view) {
        view.setFilterTouchesWhenObscured(true);
        view.setOnTouchListener((ignored, event) -> (event.getFlags()
                & (MotionEvent.FLAG_WINDOW_IS_OBSCURED
                | MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)) != 0);
    }

    static LinearLayout.LayoutParams matchWrap(int topMargin) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.topMargin = topMargin;
        return params;
    }

    int dp(int value) {
        return Math.round(value * activity.getResources().getDisplayMetrics().density);
    }

    /** A USB response: alternating keys and values. */
    static JSONObject json(Object... pairs) {
        JSONObject object = new JSONObject();
        try {
            for (int index = 0; index < pairs.length; index += 2) {
                object.put((String) pairs[index], pairs[index + 1]);
            }
            return object;
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
