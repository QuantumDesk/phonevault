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
    static final int DANGER_INK = Color.rgb(255, 90, 90); // reserved for DANGER only (safety-critical legibility)

    private static Typeface pixelFace;

    private VaultTheme() {}

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
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp);
        t.setTextColor(color);
        t.setLineSpacing(dp(c, 4), 1f);
        return t;
    }

    /** Monospace body/value text (for addresses, hex, details). */
    static TextView monoText(Context c, String value, float sizeSp, int color) {
        TextView t = new TextView(c);
        t.setText(value);
        t.setTypeface(mono());
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp);
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
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f);
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

    /** A small square status indicator: hollow (waiting) or filled (active). */
    static View statusDot(Context c, boolean active) {
        View v = new View(c);
        int s = dp(c, 9);
        v.setLayoutParams(new LinearLayout.LayoutParams(s, s));
        GradientDrawable d = new GradientDrawable();
        d.setColor(active ? INK : BG);
        d.setStroke(px(c, 2), INK);
        d.setCornerRadius(0f);
        v.setBackground(d);
        return v;
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
        int w = rows[0].length(), h = rows.length;
        android.graphics.Bitmap bmp = android.graphics.Bitmap.createBitmap(
                w * cell, h * cell, android.graphics.Bitmap.Config.ARGB_8888);
        android.graphics.Canvas cv = new android.graphics.Canvas(bmp);
        android.graphics.Paint p = new android.graphics.Paint();
        p.setColor(color);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                if (rows[y].charAt(x) == '#') {
                    cv.drawRect(x * cell, y * cell, (x + 1) * cell, (y + 1) * cell, p);
                }
            }
        }
        android.widget.ImageView iv = new android.widget.ImageView(c);
        iv.setImageBitmap(bmp);
        return iv;
    }

    static int dp(Context c, int v) {
        return Math.round(v * c.getResources().getDisplayMetrics().density);
    }

    static int px(Context c, int v) {
        return Math.max(1, Math.round(v * c.getResources().getDisplayMetrics().density));
    }
}
