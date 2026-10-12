package dev.phonevault.signer;

/**
 * Battery reading for the page header and Home's low-battery card, from the extras of the sticky
 * ACTION_BATTERY_CHANGED broadcast (no permission needed). Pure, so the thresholds are JVM-tested.
 * The vault only ever WARNS about a low battery; it never blocks signing.
 */
final class BatteryStatus {
    /** Below this (and not on power) Home shows "Charge before signing". */
    static final int LOW_PERCENT = 15;
    /** BatteryManager.BATTERY_STATUS_CHARGING / _FULL (copied so this class stays pure). */
    static final int STATUS_CHARGING = 2;
    static final int STATUS_FULL = 5;

    static final BatteryStatus UNKNOWN = new BatteryStatus(-1, false);

    /** 0..100, or -1 when the platform did not report a level. */
    final int percent;
    /** Connected to power (charging or full on the charger). */
    final boolean charging;

    BatteryStatus(int percent, boolean charging) {
        this.percent = percent;
        this.charging = charging;
    }

    /** From EXTRA_LEVEL, EXTRA_SCALE, EXTRA_STATUS and EXTRA_PLUGGED. */
    static BatteryStatus of(int level, int scale, int status, int plugged) {
        int percent = level >= 0 && scale > 0 ? Math.min(100, Math.round(level * 100f / scale)) : -1;
        boolean charging = plugged > 0 || status == STATUS_CHARGING || status == STATUS_FULL;
        return new BatteryStatus(percent, charging);
    }

    boolean known() { return percent >= 0; }

    /** Low and not being charged: the only case Home warns about. */
    boolean low() { return known() && percent < LOW_PERCENT && !charging; }

    /** Header text: "87%"; blank when unknown. The charging glyph is drawn separately. */
    String label() { return known() ? percent + "%" : ""; }

    /** Spoken description for the header indicator. */
    String description() {
        if (!known()) return "Battery level unavailable";
        return "Battery " + percent + " percent" + (charging ? ", charging" : "");
    }

    /** Filled cells (0..cells) of the pixel battery glyph; any charge shows at least one cell. */
    int filledCells(int cells) {
        if (!known() || percent == 0) return 0;
        return Math.max(1, Math.min(cells, Math.round(percent * cells / 100f)));
    }

    @Override public boolean equals(Object o) {
        if (!(o instanceof BatteryStatus)) return false;
        BatteryStatus b = (BatteryStatus) o;
        return b.percent == percent && b.charging == charging;
    }

    @Override public int hashCode() { return percent * 2 + (charging ? 1 : 0); }
}
