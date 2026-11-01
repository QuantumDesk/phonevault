package dev.phonevault.signer;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * PINs a thief tries first, refused wherever a PIN is CHOSEN (first-run SET PIN, which also
 * precedes a restore; any later PIN change goes through here too). Never applied to unlock: a
 * phone set up before this check keeps working with its PIN. The wrong-PIN erase still limits
 * guessing; this keeps the first few guesses from being the right one.
 *
 * <p>Refused: one digit six times; a straight run up or down, also across 9→0 (123456, 987654,
 * 890123); a repeated 2- or 3-digit group (121212, 123123); three doubled digits (112233); and
 * {@link #COMMON}.
 */
final class GuessablePins {
    private GuessablePins() {}

    /** Shown on SET PIN when the first entry is refused. */
    static final String MESSAGE = "That PIN is one of the first a thief would try. Choose six digits that aren't a pattern.";

    /**
     * The most common 6-digit PINs. Source: P. Markert, D. V. Bailey, M. Golla, M. Dürmuth and
     * A. J. Aviv, "This PIN Can Be Easily Guessed: Analyzing the Security of Smartphone Unlock PINs",
     * IEEE Symposium on Security and Privacy 2020 (the 6-digit frequency lists and the iOS
     * blocklist the study extracted). Patterns the rules above already refuse are listed anyway,
     * so this list reads as the study's.
     */
    static final Set<String> COMMON = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "123456", "654321", "111111", "000000", "123123", "112233", "121212", "159753",
            "147258", "696969", "520520", "666666", "101010", "789456", "147852", "123321",
            "456789", "999999", "555555", "777777")));

    /** True when {@code pin} (six ASCII digits) is refused. Never keeps or copies the PIN. */
    static boolean guessable(char[] pin) {
        if (pin == null || pin.length != VaultPin.PIN_LENGTH) return false; // the length rule is the PIN screen's
        for (char c : pin) if (c < '0' || c > '9') return false;
        return sameDigit(pin) || straightRun(pin, 1) || straightRun(pin, 9) || repeatsEvery(pin, 2)
                || repeatsEvery(pin, 3) || doubledDigits(pin) || common(pin);
    }

    private static boolean sameDigit(char[] pin) { return repeatsEvery(pin, 1); }

    /** Each digit is the previous plus {@code step} (mod 10): 1 counts up, 9 counts down. */
    private static boolean straightRun(char[] pin, int step) {
        for (int i = 1; i < pin.length; i++) if ((pin[i - 1] - '0' + step) % 10 != pin[i] - '0') return false;
        return true;
    }

    /** The first {@code period} digits repeated: 121212 (2), 123123 (3). */
    private static boolean repeatsEvery(char[] pin, int period) {
        for (int i = period; i < pin.length; i++) if (pin[i] != pin[i - period]) return false;
        return true;
    }

    /** 112233-style: three doubled digits. */
    private static boolean doubledDigits(char[] pin) {
        for (int i = 0; i + 1 < pin.length; i += 2) if (pin[i] != pin[i + 1]) return false;
        return true;
    }

    private static boolean common(char[] pin) {
        for (String c : COMMON) {
            if (c.length() != pin.length) continue;
            boolean same = true;
            for (int i = 0; i < pin.length; i++) same &= c.charAt(i) == pin[i];
            if (same) return true;
        }
        return false;
    }
}
