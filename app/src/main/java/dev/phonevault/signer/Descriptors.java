package dev.phonevault.signer;

/** BIP-380 output-descriptor checksums. */
final class Descriptors {
    private Descriptors() {}

    private static final String INPUT_CHARSET =
            "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    private static final String CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final long[] GENERATOR = {0xf5dee51989L, 0xa9fdca3312L, 0x1bab10e32dL, 0x3706b1677aL, 0x644d626ffdL};

    private static long polymod(long chk, int value) {
        long top = chk >>> 35;
        chk = ((chk & 0x7ffffffffL) << 5) ^ value;
        for (int i = 0; i < 5; i++) if (((top >>> i) & 1) != 0) chk ^= GENERATOR[i];
        return chk;
    }

    /** The 8-character checksum of a descriptor body (without '#'). */
    static String checksum(String body) {
        long c = 1;
        int cls = 0, clscount = 0;
        for (int i = 0; i < body.length(); i++) {
            int pos = INPUT_CHARSET.indexOf(body.charAt(i));
            if (pos < 0) throw new IllegalArgumentException("invalid descriptor character");
            c = polymod(c, pos & 31);
            cls = cls * 3 + (pos >> 5);
            if (++clscount == 3) {
                c = polymod(c, cls);
                cls = 0;
                clscount = 0;
            }
        }
        if (clscount > 0) c = polymod(c, cls);
        for (int j = 0; j < 8; j++) c = polymod(c, 0);
        c ^= 1;
        StringBuilder out = new StringBuilder(8);
        for (int j = 0; j < 8; j++) out.append(CHECKSUM_CHARSET.charAt((int) ((c >>> (5 * (7 - j))) & 31)));
        return out.toString();
    }

    static String withChecksum(String body) { return body + "#" + checksum(body); }

    /** True when {@code s} is BODY#CHECKSUM with a correct checksum. */
    static boolean valid(String s) {
        int hash = s.lastIndexOf('#');
        if (hash < 0 || s.length() - hash - 1 != 8) return false;
        try {
            return checksum(s.substring(0, hash)).equals(s.substring(hash + 1));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
