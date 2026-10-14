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
        if (AddressKeys.isBtc(a) || AddressKeys.isBtc(b)) return btcSimilar(a, b);
        if (!Addresses.isEvm(a) || !Addresses.isEvm(b)) return false;
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
        if (AddressKeys.isBtc(known) || AddressKeys.isBtc(candidate)) return btcGrid(known, candidate);
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
        if (AddressKeys.isBtc(a) || AddressKeys.isBtc(b)) {
            String[] x = chunks(AddressKeys.address(a)), y = chunks(AddressKeys.address(b));
            int n = 0;
            for (int i = 0; i < Math.max(x.length, y.length); i++) if (i >= x.length || i >= y.length || !x[i].equals(y[i])) n++;
            return n;
        }
        String x = hex(a), y = hex(b);
        int n = 0;
        for (int i = 0; i < 10; i++) if (!x.substring(4 * i, 4 * i + 4).equals(y.substring(4 * i, 4 * i + 4))) n++;
        return n;
    }

    /** Number of 4-character chunks shown in the grid (10 for EVM). */
    static int chunkCount(String a, String b) {
        if (!AddressKeys.isBtc(a) && !AddressKeys.isBtc(b)) return 10;
        return Math.max(chunks(AddressKeys.address(a)).length, chunks(AddressKeys.address(b)).length);
    }


    // ------------------------------------------------------------------ Bitcoin

    /**
     * Bitcoin addresses on the same network, compared on the part an attacker can grind: after
     * "bc1q"/"tb1p" (HRP, separator, witness version) for SegWit, after the version character for
     * base58. Same three rules as for EVM. Bech32 carries 5 bits and base58 ~5.9 bits per
     * character, so a random pair matches even less often than two hex addresses.
     */
    static boolean btcSimilar(String a, String b) {
        if (!AddressKeys.isBtc(a) || !AddressKeys.isBtc(b)) return false;
        if (!AddressKeys.network(a).equals(AddressKeys.network(b))) return false;
        String x = btcBody(AddressKeys.address(a)), y = btcBody(AddressKeys.address(b));
        if (x.equals(y) || x.length() < 12 || y.length() < 12) return false;
        int max = Math.min(x.length(), y.length());
        int pre = 0;
        while (pre < max && x.charAt(pre) == y.charAt(pre)) pre++;
        int suf = 0;
        while (suf < max && x.charAt(x.length() - 1 - suf) == y.charAt(y.length() - 1 - suf)) suf++;
        if (pre >= 4 && suf >= 4) return true;
        if (pre >= 3 && suf >= 3 && pre + suf >= 7) return true;
        return levenshtein(x.substring(0, 6), y.substring(0, 6)) <= 1
                && levenshtein(x.substring(x.length() - 6), y.substring(y.length() - 6)) <= 1;
    }

    static String btcBody(String address) {
        int sep = address.lastIndexOf('1');
        boolean segwit = address.startsWith("bc1") || address.startsWith("tb1");
        return segwit && sep >= 2 && sep + 2 <= address.length() ? address.substring(sep + 2) : address.substring(1);
    }

    private static String[] chunks(String s) {
        String[] out = new String[(s.length() + 3) / 4];
        for (int i = 0; i < out.length; i++) out[i] = s.substring(4 * i, Math.min(s.length(), 4 * i + 4));
        return out;
    }

    private static String btcGrid(String known, String candidate) {
        String[] k = chunks(AddressKeys.address(known)), c = chunks(AddressKeys.address(candidate));
        StringBuilder out = new StringBuilder("     BEFORE  THIS ONE\n");
        int n = Math.max(k.length, c.length);
        for (int i = 0; i < n; i++) {
            String a = i < k.length ? k[i] : "", b = i < c.length ? c[i] : "";
            out.append(String.format(Locale.ROOT, "%2d   %-4s    %-4s%s", i + 1, a, b, a.equals(b) ? "" : "  " + DIFFERENT_MARK));
            if (i < n - 1) out.append('\n');
        }
        return out.toString();
    }

    private static String hex(String address) {
        if (!Addresses.isEvm(address)) throw new IllegalArgumentException("not an address");
        return Addresses.lowercase(address).substring(2);
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
