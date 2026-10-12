package dev.phonevault.signer;

import org.web3j.crypto.Keys;

import java.util.Locale;

/**
 * Address-poisoning detection. Attackers send dust from vanity addresses that copy the first and
 * last characters of an address you use, hoping you paste the fake from your history. People
 * check the ends of an address; so does this: two DIFFERENT addresses look alike when
 *
 * <ul>
 *   <li>their first 4 and last 4 hex characters match (case-insensitive), or</li>
 *   <li>at least 7 characters match across the two ends with at least 3 at each end, or</li>
 *   <li>their first 6 and last 6 characters are each within one edit (Levenshtein ≤ 1).</li>
 * </ul>
 *
 * For random addresses each rule fires with probability below 10⁻⁸ per pair, so a hit against
 * the few hundred addresses on the phone is essentially always deliberate.
 */
final class LookAlike {
    private LookAlike() {}

    static boolean similar(String a, String b) {
        String x = hex(a), y = hex(b);
        if (x.equals(y)) return false;
        int pre = 0;
        while (pre < 40 && x.charAt(pre) == y.charAt(pre)) pre++;
        int suf = 0;
        while (suf < 40 && x.charAt(39 - suf) == y.charAt(39 - suf)) suf++;
        if (pre >= 4 && suf >= 4) return true;
        if (pre >= 3 && suf >= 3 && pre + suf >= 7) return true;
        return levenshtein(x.substring(0, 6), y.substring(0, 6)) <= 1 && levenshtein(x.substring(34), y.substring(34)) <= 1;
    }

    /**
     * The two addresses side by side in 4-character chunks (EIP-55 casing), one chunk per line,
     * differing chunks marked "✗ DIFFERENT". Shown in a monospace font so the columns align.
     */
    static String grid(String known, String candidate) {
        String k = Keys.toChecksumAddress(known).substring(2), c = Keys.toChecksumAddress(candidate).substring(2);
        StringBuilder out = new StringBuilder("     BEFORE  THIS ONE\n");
        out.append("     0x      0x\n");
        for (int i = 0; i < 10; i++) {
            String a = k.substring(4 * i, 4 * i + 4), b = c.substring(4 * i, 4 * i + 4);
            boolean same = a.equalsIgnoreCase(b);
            out.append(String.format(Locale.ROOT, "%2d   %s    %s%s", i + 1, a, b, same ? "" : "  " + DIFFERENT_MARK));
            if (i < 9) out.append('\n');
        }
        return out.toString();
    }

    static final String DIFFERENT_MARK = "✗ DIFFERENT";

    /** Number of 4-character chunks that differ (tests and the summary line). */
    static int differingChunks(String a, String b) {
        String x = hex(a), y = hex(b);
        int n = 0;
        for (int i = 0; i < 10; i++) if (!x.substring(4 * i, 4 * i + 4).equals(y.substring(4 * i, 4 * i + 4))) n++;
        return n;
    }

    /** 0xAbCd…1234 in checksum casing. */
    static String shortForm(String address) {
        String c = Keys.toChecksumAddress(address);
        return c.substring(0, 6) + "…" + c.substring(c.length() - 4);
    }

    private static String hex(String address) {
        if (address == null || !address.matches("0x[0-9a-fA-F]{40}")) throw new IllegalArgumentException("not an address");
        return address.substring(2).toLowerCase(Locale.ROOT);
    }

    static int levenshtein(String a, String b) {
        int[] prev = new int[b.length() + 1], cur = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) prev[j] = j;
        for (int i = 1; i <= a.length(); i++) {
            cur[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                cur[j] = Math.min(Math.min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] t = prev; prev = cur; cur = t;
        }
        return prev[b.length()];
    }
}
