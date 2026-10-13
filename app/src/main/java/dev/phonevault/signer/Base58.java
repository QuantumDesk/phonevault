package dev.phonevault.signer;

import java.math.BigInteger;
import java.util.Arrays;

/** Base58 and Base58Check (legacy addresses, extended keys). */
final class Base58 {
    private Base58() {}

    static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger FIFTY_EIGHT = BigInteger.valueOf(58);

    static String encode(byte[] data) {
        int zeros = 0;
        while (zeros < data.length && data[zeros] == 0) zeros++;
        BigInteger v = new BigInteger(1, data);
        StringBuilder out = new StringBuilder();
        while (v.signum() > 0) {
            BigInteger[] qr = v.divideAndRemainder(FIFTY_EIGHT);
            out.append(ALPHABET.charAt(qr[1].intValue()));
            v = qr[0];
        }
        for (int i = 0; i < zeros; i++) out.append('1');
        return out.reverse().toString();
    }

    static byte[] decode(String s) {
        if (s == null || s.isEmpty() || s.length() > 128) throw new IllegalArgumentException("invalid base58 length");
        BigInteger v = BigInteger.ZERO;
        for (int i = 0; i < s.length(); i++) {
            int d = ALPHABET.indexOf(s.charAt(i));
            if (d < 0) throw new IllegalArgumentException("invalid base58 character");
            v = v.multiply(FIFTY_EIGHT).add(BigInteger.valueOf(d));
        }
        int zeros = 0;
        while (zeros < s.length() && s.charAt(zeros) == '1') zeros++;
        byte[] body = v.signum() == 0 ? new byte[0] : v.toByteArray();
        if (body.length > 0 && body[0] == 0) body = Arrays.copyOfRange(body, 1, body.length);
        byte[] out = new byte[zeros + body.length];
        System.arraycopy(body, 0, out, zeros, body.length);
        return out;
    }

    static String encodeCheck(byte[] payload) {
        byte[] check = BtcCrypto.sha256d(payload);
        byte[] all = Arrays.copyOf(payload, payload.length + 4);
        System.arraycopy(check, 0, all, payload.length, 4);
        return encode(all);
    }

    static byte[] decodeCheck(String s) {
        byte[] all = decode(s);
        if (all.length < 5) throw new IllegalArgumentException("base58check too short");
        byte[] payload = Arrays.copyOf(all, all.length - 4);
        byte[] check = BtcCrypto.sha256d(payload);
        for (int i = 0; i < 4; i++) {
            if (check[i] != all[payload.length + i]) throw new IllegalArgumentException("base58check checksum mismatch");
        }
        return payload;
    }
}
