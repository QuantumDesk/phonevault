package dev.phonevault.signer;

import java.math.BigDecimal;
import java.math.BigInteger;

/** Exact decimal amounts for review screens. */
final class Units {
    private Units() {}

    /**
     * Exact decimal value of {@code value} base units with {@code decimals}: every significant digit
     * is kept, only trailing fractional zeros are dropped; with {@code grouped} the whole part has
     * comma separators (1,234.5). No rounding, no scientific notation. Zero is always "0".
     */
    static String format(BigInteger value, int decimals, boolean grouped) {
        if (value.signum() < 0 || decimals < 0) throw new IllegalArgumentException("negative amount or decimals");
        // Zero is special-cased: stripTrailingZeros on a scaled zero differs across Java versions.
        String plain = value.signum() == 0 ? "0"
                : new BigDecimal(value).movePointLeft(decimals).stripTrailingZeros().toPlainString();
        if (!grouped) return plain;
        int dot = plain.indexOf('.');
        String whole = dot < 0 ? plain : plain.substring(0, dot);
        String fraction = dot < 0 ? "" : plain.substring(dot);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < whole.length(); i++) {
            if (i > 0 && (whole.length() - i) % 3 == 0) out.append(',');
            out.append(whole.charAt(i));
        }
        return out + fraction;
    }
}
