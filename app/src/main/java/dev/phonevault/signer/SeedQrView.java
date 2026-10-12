package dev.phonevault.signer;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.view.View;

/**
 * A SeedQR drawn for hand transcription: black modules on a white card, a thin line around every
 * module, a heavier line every five, and 1-based row/column numbers that match the printed backup
 * card's grid (tools/backup-card). It is drawn square to the available width; it is not meant to be
 * scanned from the screen. {@link #wipe()} clears the modules (they encode the recovery phrase).
 */
final class SeedQrView extends View {
    private final SeedQr.Modules modules;
    private final Paint dark = new Paint();
    private final Paint card = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint minor = new Paint();
    private final Paint major = new Paint();
    private final Paint label = new Paint(Paint.ANTI_ALIAS_FLAG);

    SeedQrView(Context context, SeedQr.Modules modules) {
        super(context);
        this.modules = modules;
        dark.setColor(0xFF000000);
        card.setColor(0xFFFFFFFF);
        minor.setColor(0xFFB4B4B4);
        minor.setStrokeWidth(Math.max(1f, VaultTheme.dp(context, 1) / 2f));
        major.setColor(0xFF505050);
        major.setStrokeWidth(Math.max(2f, VaultTheme.dp(context, 1) * 1.2f));
        label.setColor(0xFF505050);
        label.setTypeface(Typeface.MONOSPACE);
        label.setTextAlign(Paint.Align.CENTER);
        // The modules are the seed: never expose them to accessibility services or autofill.
        setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
        setContentDescription(null);
    }

    void wipe() {
        modules.wipe();
        invalidate();
    }

    @Override protected void onMeasure(int widthSpec, int heightSpec) {
        int w = MeasureSpec.getSize(widthSpec);
        setMeasuredDimension(w, w);
    }

    @Override protected void onDraw(Canvas canvas) {
        int n = modules.size;
        float w = getWidth();
        float pad = VaultTheme.dp(getContext(), 8);
        float labelBand = VaultTheme.dp(getContext(), 18);
        float cell = (float) Math.floor((w - pad * 2 - labelBand) / n);
        float grid = cell * n;
        float ox = pad + labelBand + ((w - pad * 2 - labelBand) - grid) / 2f;
        float oy = ox;
        canvas.drawRoundRect(0, 0, w, oy + grid + pad, VaultTheme.dp(getContext(), 12), VaultTheme.dp(getContext(), 12), card);
        for (int r = 0; r < n; r++)
            for (int c = 0; c < n; c++)
                if (modules.get(r, c)) canvas.drawRect(ox + c * cell, oy + r * cell, ox + (c + 1) * cell, oy + (r + 1) * cell, dark);
        for (int i = 0; i <= n; i++) {
            Paint p = (i % 5 == 0 || i == n) ? major : minor;
            canvas.drawLine(ox + i * cell, oy, ox + i * cell, oy + grid, p);
            canvas.drawLine(ox, oy + i * cell, ox + grid, oy + i * cell, p);
        }
        label.setTextSize(Math.min(cell * 0.62f, labelBand * 0.62f));
        float ascent = -label.ascent();
        for (int i = 0; i < n; i++) {
            String s = Integer.toString(i + 1);
            canvas.drawText(s, ox + i * cell + cell / 2f, oy - VaultTheme.dp(getContext(), 4), label);
            canvas.drawText(s, ox - labelBand / 2f - VaultTheme.dp(getContext(), 1), oy + i * cell + cell / 2f + ascent / 2.6f, label);
        }
    }
}
