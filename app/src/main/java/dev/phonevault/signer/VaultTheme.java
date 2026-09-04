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
    static final int FAINT = Color.rgb(96, 98, 104);   // labels
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
        bg.setCornerRadius(0f); // sharp corners = pixel feel
        l.setBackground(bg);
        int p = dp(c, 16);
        l.setPadding(p, p, p, p);
        return l;
    }

    /** A bordered outline button styled as pixel text on a dark fill. */
    static TextView pixelButton(Context c, String label, boolean primary) {
        TextView t = new TextView(c);
        t.setText(label);
        t.setTypeface(pixel(c));
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 9f);
        t.setAllCaps(false);
        t.setGravity(Gravity.CENTER);
        t.setTextColor(primary ? BG : INK);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(primary ? INK : SURFACE);
        bg.setStroke(px(c, 1), primary ? INK : LINE);
        t.setBackground(bg);
        int ph = dp(c, 18);
        int pv = dp(c, 16);
        t.setPadding(ph, pv, ph, pv);
        t.setClickable(true);
        t.setFocusable(true);
        return t;
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
    static android.graphics.Bitmap qrBitmap(String content, int sizePx) {
        try {
            java.util.Map<com.google.zxing.EncodeHintType, Object> hints = new java.util.HashMap<>();
            hints.put(com.google.zxing.EncodeHintType.MARGIN, 1);
            hints.put(com.google.zxing.EncodeHintType.ERROR_CORRECTION,
                    com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.M);
            com.google.zxing.common.BitMatrix m = new com.google.zxing.MultiFormatWriter()
                    .encode(content, com.google.zxing.BarcodeFormat.QR_CODE, sizePx, sizePx, hints);
            int w = m.getWidth(), h = m.getHeight();
            int[] px = new int[w * h];
            for (int y = 0; y < h; y++) {
                for (int x = 0; x < w; x++) {
                    px[y * w + x] = m.get(x, y) ? 0xFF000000 : 0xFFFFFFFF;
                }
            }
            android.graphics.Bitmap bmp = android.graphics.Bitmap.createBitmap(w, h,
                    android.graphics.Bitmap.Config.ARGB_8888);
            bmp.setPixels(px, 0, w, 0, 0, w, h);
            return bmp;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Composite scanner-target corner brackets around a QR bitmap: a slightly larger canvas with
     * four L-shaped pixel brackets at the corners, outside the quiet zone.
     */
    static android.graphics.Bitmap framedQr(android.graphics.Bitmap qr, int bracket, int thick, int gap) {
        int pad = bracket + gap;
        int w = qr.getWidth() + pad * 2, h = qr.getHeight() + pad * 2;
        android.graphics.Bitmap out = android.graphics.Bitmap.createBitmap(w, h,
                android.graphics.Bitmap.Config.ARGB_8888);
        android.graphics.Canvas cv = new android.graphics.Canvas(out);
        cv.drawColor(0xFFFFFFFF);
        cv.drawBitmap(qr, pad, pad, null);
        android.graphics.Paint p = new android.graphics.Paint();
        p.setColor(0xFF000000);
        // top-left
        cv.drawRect(0, 0, bracket, thick, p);
        cv.drawRect(0, 0, thick, bracket, p);
        // top-right
        cv.drawRect(w - bracket, 0, w, thick, p);
        cv.drawRect(w - thick, 0, w, bracket, p);
        // bottom-left
        cv.drawRect(0, h - thick, bracket, h, p);
        cv.drawRect(0, h - bracket, thick, h, p);
        // bottom-right
        cv.drawRect(w - bracket, h - thick, w, h, p);
        cv.drawRect(w - thick, h - bracket, w, h, p);
        return out;
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
