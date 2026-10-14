package dev.phonevault.signer;

/** Hex for test fixtures. Strict: even length, ASCII 0-9 a-f A-F only, no prefix. */
final class Hex {
    private Hex() {}

    static byte[] bytes(String hex) {
        if (hex.length() % 2 != 0) throw new IllegalArgumentException("odd hex length");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) (digit(hex.charAt(2 * i)) << 4 | digit(hex.charAt(2 * i + 1)));
        return out;
    }

    static String of(byte[] bytes) {
        StringBuilder s = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) s.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        return s.toString();
    }

    private static int digit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw new IllegalArgumentException("not a hex digit: " + c);
    }
}
