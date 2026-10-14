package dev.phonevault.signer;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Mono / pixel-art appliance theme — matches the boot animation & wallpaper (pure black ground,
 * white ink, pixel headings via Press Start 2P, monospace body for hex legibility). Warnings use
 * inverted white-on-black blocks rather than color so it stays monochrome while staying loud.
 */
final class VaultTheme {

    static final int BG = Color.rgb(6, 6, 8);          // near-black ground
    static final int SURFACE = Color.rgb(15, 16, 20);  // card/box fill
    static final int INK = Color.rgb(240, 240, 242);   // primary text
    static final int DIM = Color.rgb(150, 152, 158);   // secondary text
    static final int FAINT = Color.rgb(164, 168, 176); // readable secondary labels
    static final int ACCENT = Color.rgb(184, 239, 211);
    static final int LINE = Color.rgb(40, 42, 48);      // borders/dividers
    static final int DANGER_INK = ReviewStyle.DANGER_INK; // reserved for DANGER only (6.6:1 on BG)
    /** CHECK (WARNING) review rows: amber, 12:1 on BG; always with the "!" glyph, never color alone. */
    static final int WARNING_INK = ReviewStyle.WARNING_INK;
    static final int AMBER = Color.rgb(255, 184, 77);    // test-network banner (Bitcoin TESTNET / SIGNET)

    /** Base body text size in sp, before the Text size scale (one factor for every screen). */
    static final float BODY_SIZE = 16f;

    private static Typeface pixelFace;
    /**
     * The one text-size factor (Display &amp; auto-lock → Text size). Every helper here takes the
     * base size as written at the call site and applies this, so a screen never needs its own
     * "large ? x : y"; a size set after construction goes through {@link #size}.
     */
    private static volatile float textScale = DisplaySettings.STANDARD_TEXT_SCALE;

    private VaultTheme() {}

    static void setTextScale(float scale) { textScale = scale > 0f ? scale : DisplaySettings.STANDARD_TEXT_SCALE; }

    static float textScale() { return textScale; }

    /** A base size in sp under the current text scale. */
    static float sp(float baseSp) { return DisplaySettings.scaledSp(baseSp, textScale); }

    /** Set a view's text size from a base size (scaled). Use instead of TextView#setTextSize. */
    static void size(TextView t, float baseSp) { t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp(baseSp)); }

    static Typeface pixel(Context context) {
        if (pixelFace == null) {
            try {
                pixelFace = Typeface.createFromAsset(context.getAssets(), "fonts/PressStart2P.ttf");
            } catch (RuntimeException missing) {
                pixelFace = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD);
            }
        }
        return pixelFace;
    }

    static Typeface mono() {
        return Typeface.MONOSPACE;
    }

    static TextView bodyText(Context c, String value, float sizeSp, int color) {
        TextView t = monoText(c, value, sizeSp, color);
        t.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
        return t;
    }

    /** Pixel-font heading (chunky — keep sizes small). */
    static TextView pixelText(Context c, String value, float sizeSp, int color) {
        TextView t = new TextView(c);
        t.setText(value);
        t.setTypeface(pixel(c));
        size(t, sizeSp);
        t.setTextColor(color);
        t.setLineSpacing(dp(c, 4), 1f);
        return t;
    }

    /** Monospace body/value text (for addresses, hex, details). */
    static TextView monoText(Context c, String value, float sizeSp, int color) {
        TextView t = new TextView(c);
        t.setText(value);
        t.setTypeface(mono());
        size(t, sizeSp);
        t.setTextColor(color);
        t.setLineSpacing(0, 1.25f);
        return t;
    }

    /** A bordered "terminal box" container. */
    static LinearLayout box(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(SURFACE);
        bg.setStroke(px(c, 1), LINE);
        bg.setCornerRadius(dp(c, 12));
        l.setBackground(bg);
        int p = dp(c, 16);
        l.setPadding(p, p, p, p);
        return l;
    }

    /** A bordered outline button styled as pixel text on a dark fill. */
    static TextView pixelButton(Context c, String label, boolean primary) {
        TextView t = new android.widget.Button(c);
        t.setText(label);
        t.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        size(t, 16f);
        t.setAllCaps(false);
        t.setGravity(Gravity.CENTER);
        t.setTextColor(new android.content.res.ColorStateList(
                new int[][] {new int[] {-android.R.attr.state_enabled}, new int[] {}},
                new int[] {FAINT, primary ? BG : INK}));
        GradientDrawable bg = buttonShape(c, primary ? ACCENT : SURFACE);
        android.graphics.drawable.StateListDrawable states = new android.graphics.drawable.StateListDrawable();
        states.addState(new int[] {-android.R.attr.state_enabled}, buttonShape(c, LINE));
        states.addState(new int[] {android.R.attr.state_pressed}, buttonShape(c, primary ? INK : LINE));
        states.addState(new int[] {android.R.attr.state_focused}, buttonShape(c, primary ? INK : LINE));
        states.addState(new int[] {}, bg);
        t.setBackground(states);
        t.setBackgroundTintList(null);
        t.setMinHeight(dp(c, 56));
        t.setMinWidth(dp(c, 48));
        t.setStateListAnimator(null);
        int ph = dp(c, 18);
        int pv = dp(c, 16);
        t.setPadding(ph, pv, ph, pv);
        t.setClickable(true);
        t.setFocusable(true);
        return t;
    }

    private static GradientDrawable buttonShape(Context c, int color) {
        GradientDrawable shape = new GradientDrawable();
        shape.setColor(color);
        shape.setCornerRadius(dp(c, 10));
        shape.setStroke(px(c, 1), LINE);
        return shape;
    }

    /** Thin horizontal divider line. */
    static View divider(Context c) {
        View v = new View(c);
        v.setBackgroundColor(LINE);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, px(c, 1));
        lp.topMargin = dp(c, 14);
        lp.bottomMargin = dp(c, 14);
        v.setLayoutParams(lp);
        return v;
    }

    /** Black-on-white QR bitmap for the given content (e.g. the receiving address). */
    /**
     * A crisp QR: the symbol is rendered at an integer number of pixels per module (no resampling,
     * so every module is an exact square) inside a 4-module quiet zone on a white, rounded card.
     * Black modules on white is what every scanner is tuned for; the card gives the dark UI a
     * clean edge without brackets or borders.
     */
    static android.graphics.Bitmap qrBitmap(String content, int sizePx) {
        return qrBitmap(content, sizePx, 0);
    }

    static android.graphics.Bitmap qrBitmap(String content, int sizePx, int cornerRadiusPx) {
        try {
            com.google.zxing.qrcode.encoder.ByteMatrix m = com.google.zxing.qrcode.encoder.Encoder
                    .encode(content, com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.M).getMatrix();
            int n = m.getWidth(), quiet = 4;
            int scale = Math.max(1, sizePx / (n + quiet * 2));
            int side = (n + quiet * 2) * scale;
            android.graphics.Bitmap bmp = android.graphics.Bitmap.createBitmap(side, side,
                    android.graphics.Bitmap.Config.ARGB_8888);
            android.graphics.Canvas cv = new android.graphics.Canvas(bmp);
            android.graphics.Paint white = new android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG);
            white.setColor(0xFFFFFFFF);
            cv.drawRoundRect(0, 0, side, side, cornerRadiusPx, cornerRadiusPx, white);
            android.graphics.Paint black = new android.graphics.Paint();
            black.setColor(0xFF000000);
            for (int y = 0; y < n; y++) {
                for (int x = 0; x < n; x++) {
                    if (m.get(x, y) != 1) continue;
                    int left = (quiet + x) * scale, top = (quiet + y) * scale;
                    cv.drawRect(left, top, left + scale, top + scale, black);
                }
            }
            return bmp;
        } catch (Exception e) {
            return null;
        }
    }

    /** Thin hairline used as a row separator (fainter than {@link #divider}). */
    static View rule(Context c, int topMargin, int bottomMargin) {
        View v = new View(c);
        v.setBackgroundColor(LINE);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, px(c, 1));
        lp.topMargin = topMargin;
        lp.bottomMargin = bottomMargin;
        v.setLayoutParams(lp);
        return v;
    }

    /** A crisp pixel-art padlock drawn as a bitmap (matches the boot animation), sized by cell px. */
    static android.widget.ImageView pixelLock(Context c, int cell, int color) {
        String[] rows = {
                "..####..",
                ".#....#.",
                ".#....#.",
                "########",
                "########",
                "###..###",
                "##....##",
                "###..###",
                "########",
                "########",
        };
        android.widget.ImageView iv = new android.widget.ImageView(c);
        iv.setImageBitmap(pixelArt(rows, cell, color));
        return iv;
    }

    /** '#' cells of the pattern filled with color; everything else transparent. */
    private static android.graphics.Bitmap pixelArt(String[] rows, int cell, int color) {
        return pixelArt(rows, cell, color, 0);
    }

    /** '#' cells in {@code color}, 'o' cells in {@code second}; everything else transparent. */
    private static android.graphics.Bitmap pixelArt(String[] rows, int cell, int color, int second) {
        int w = rows[0].length(), h = rows.length;
        android.graphics.Bitmap bmp = android.graphics.Bitmap.createBitmap(
                w * cell, h * cell, android.graphics.Bitmap.Config.ARGB_8888);
        android.graphics.Canvas cv = new android.graphics.Canvas(bmp);
        android.graphics.Paint p = new android.graphics.Paint();
        android.graphics.Paint q = new android.graphics.Paint();
        p.setColor(color);
        q.setColor(second);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                char ch = rows[y].charAt(x);
                if (ch == '#' || ch == 'o') {
                    cv.drawRect(x * cell, y * cell, (x + 1) * cell, (y + 1) * cell, ch == '#' ? p : q);
                }
            }
        }
        return bmp;
    }

    // ------------------------------------------------------------------ review level glyphs

    /**
     * Drawn, not typed: the device font has no reliable "⛔" / "⚠" emoji. DANGER is a red stop
     * disc with a white bar (no entry); CHECK is an amber triangle with a "!" cut out. Shape and
     * word carry the level as well as the color.
     */
    private static final String[] STOP = {
            "...#####...",
            ".#########.",
            ".#########.",
            "###########",
            "#ooooooooo#",
            "#ooooooooo#",
            "#ooooooooo#",
            "###########",
            ".#########.",
            ".#########.",
            "...#####...",
    };
    private static final String[] CAUTION = {
            ".....#.....",
            "....###....",
            "....###....",
            "...##o##...",
            "...##o##...",
            "..###o###..",
            "..###o###..",
            ".#########.",
            ".####o####.",
            "###########",
            "###########",
    };

    /** The level glyph for a review row heading (12 dp-ish, pixel-crisp), with a spoken name. */
    static android.widget.ImageView levelGlyph(Context c, ReviewStyle.Level level) {
        android.widget.ImageView iv = new android.widget.ImageView(c);
        int cell = Math.max(2, Math.round(c.getResources().getDisplayMetrics().density * textScale * 1.5f));
        boolean danger = level == ReviewStyle.Level.DANGER;
        iv.setImageBitmap(pixelArt(danger ? STOP : CAUTION, cell, danger ? DANGER_INK : WARNING_INK, danger ? INK : BG));
        iv.setContentDescription(danger ? "Danger" : "Check");
        return iv;
    }

    // ------------------------------------------------------------------ battery indicator

    /** Fill cells inside the pixel battery outline. */
    private static final int BATTERY_CELLS = 8;
    private static final String[] BOLT = {
            "...##",
            "..##.",
            ".##..",
            "#####",
            "..##.",
            ".##..",
            "##...",
    };

    /**
     * Header battery indicator: [bolt when charging] [pixel battery] [87%]. Small and FAINT so it
     * never competes with the page. Update with {@link #showBattery}.
     */
    static LinearLayout batteryIndicator(Context c) {
        LinearLayout row = new LinearLayout(c);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        android.widget.ImageView bolt = new android.widget.ImageView(c);
        bolt.setImageBitmap(pixelArt(BOLT, dp(c, 1) + 1, ACCENT));
        bolt.setVisibility(View.GONE);
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        blp.rightMargin = dp(c, 4);
        row.addView(bolt, blp);
        row.addView(new android.widget.ImageView(c));
        TextView label = pixelText(c, "", 8, FAINT);
        label.setLineSpacing(0, 1f);
        label.setPadding(dp(c, 6), 0, 0, 0);
        row.addView(label);
        row.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_YES);
        return row;
    }

    static void showBattery(View indicator, BatteryStatus status) {
        if (!(indicator instanceof LinearLayout) || ((LinearLayout) indicator).getChildCount() < 3) return;
        LinearLayout row = (LinearLayout) indicator;
        Context c = row.getContext();
        row.setVisibility(status.known() ? View.VISIBLE : View.INVISIBLE);
        row.getChildAt(0).setVisibility(status.charging ? View.VISIBLE : View.GONE);
        ((android.widget.ImageView) row.getChildAt(1)).setImageBitmap(batteryGlyph(c, status));
        ((TextView) row.getChildAt(2)).setText(status.label());
        row.setContentDescription(status.description());
    }

    /** 13 x 7 cells: outline, a one-cell gap, BATTERY_CELLS fill columns, and the terminal nub. */
    private static android.graphics.Bitmap batteryGlyph(Context c, BatteryStatus status) {
        int filled = status.filledCells(BATTERY_CELLS);
        String[] rows = new String[7];
        for (int y = 0; y < 7; y++) {
            StringBuilder r = new StringBuilder();
            for (int x = 0; x < 13; x++) {
                boolean outline = x <= 11 && (y == 0 || y == 6 || x == 0 || x == 11);
                boolean nub = x == 12 && y >= 2 && y <= 4;
                boolean fill = y >= 2 && y <= 4 && x >= 2 && x < 2 + filled;
                r.append(outline || nub || fill ? '#' : '.');
            }
            rows[y] = r.toString();
        }
        return pixelArt(rows, dp(c, 1) + 1, status.low() ? INK : FAINT);
    }

    static int dp(Context c, int v) {
        return Math.round(v * c.getResources().getDisplayMetrics().density);
    }

    static int px(Context c, int v) {
        return Math.max(1, Math.round(v * c.getResources().getDisplayMetrics().density));
    }
}
