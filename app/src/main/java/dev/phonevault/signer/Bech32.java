package dev.phonevault.signer;

import java.io.ByteArrayOutputStream;
import java.util.Locale;

/**
 * Bech32 (BIP-173) and Bech32m (BIP-350) strings, and SegWit addresses on top of them: witness
 * version 0 uses Bech32, versions 1–16 use Bech32m.
 */
final class Bech32 {
    private Bech32() {}

    static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int BECH32_CONST = 1, BECH32M_CONST = 0x2bc830a3;

    enum Encoding { BECH32, BECH32M }

    static final class Decoded {
        final String hrp;
        final byte[] data; // 5-bit values
        final Encoding encoding;
        Decoded(String hrp, byte[] data, Encoding encoding) { this.hrp = hrp; this.data = data; this.encoding = encoding; }
    }

    static final class WitnessProgram {
        final int version;
        final byte[] program;
        WitnessProgram(int version, byte[] program) { this.version = version; this.program = program; }
    }

    private static int polymod(byte[] values) {
        int[] gen = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
        int chk = 1;
        for (byte v : values) {
            int b = chk >>> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ (v & 0xff);
            for (int i = 0; i < 5; i++) if (((b >>> i) & 1) != 0) chk ^= gen[i];
        }
        return chk;
    }

    private static byte[] hrpExpand(String hrp) {
        byte[] out = new byte[hrp.length() * 2 + 1];
        for (int i = 0; i < hrp.length(); i++) {
            out[i] = (byte) (hrp.charAt(i) >> 5);
            out[i + hrp.length() + 1] = (byte) (hrp.charAt(i) & 31);
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static String encode(String hrp, byte[] data, Encoding encoding) {
        byte[] values = concat(hrpExpand(hrp), concat(data, new byte[6]));
        int mod = polymod(values) ^ (encoding == Encoding.BECH32 ? BECH32_CONST : BECH32M_CONST);
        StringBuilder out = new StringBuilder(hrp).append('1');
        for (byte d : data) out.append(CHARSET.charAt(d));
        for (int i = 0; i < 6; i++) out.append(CHARSET.charAt((mod >>> (5 * (5 - i))) & 31));
        return out.toString();
    }

    /** Strict decode (BIP-173 rules: 8–90 chars, no mixed case, printable HRP, valid checksum). */
    static Decoded decode(String s) {
        if (s == null || s.length() < 8 || s.length() > 90) throw new IllegalArgumentException("invalid bech32 length");
        boolean lower = false, upper = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 33 || c > 126) throw new IllegalArgumentException("invalid bech32 character");
            if (c >= 'a' && c <= 'z') lower = true;
            if (c >= 'A' && c <= 'Z') upper = true;
        }
        if (lower && upper) throw new IllegalArgumentException("mixed-case bech32");
        String str = s.toLowerCase(Locale.ROOT);
        int pos = str.lastIndexOf('1');
        if (pos < 1 || pos + 7 > str.length()) throw new IllegalArgumentException("invalid bech32 separator position");
        String hrp = str.substring(0, pos);
        byte[] data = new byte[str.length() - pos - 1];
        for (int i = 0; i < data.length; i++) {
            int v = CHARSET.indexOf(str.charAt(pos + 1 + i));
            if (v < 0) throw new IllegalArgumentException("invalid bech32 data character");
            data[i] = (byte) v;
        }
        int check = polymod(concat(hrpExpand(hrp), data));
        Encoding enc;
        if (check == BECH32_CONST) enc = Encoding.BECH32;
        else if (check == BECH32M_CONST) enc = Encoding.BECH32M;
        else throw new IllegalArgumentException("invalid bech32 checksum");
        byte[] payload = new byte[data.length - 6];
        System.arraycopy(data, 0, payload, 0, payload.length);
        return new Decoded(hrp, payload, enc);
    }

    static byte[] convertBits(byte[] in, int from, int to, boolean pad) {
        int acc = 0, bits = 0, maxv = (1 << to) - 1;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte b : in) {
            int v = b & 0xff;
            if ((v >>> from) != 0) throw new IllegalArgumentException("invalid data range");
            acc = (acc << from) | v;
            bits += from;
            while (bits >= to) {
                bits -= to;
                out.write((acc >>> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0) out.write((acc << (to - bits)) & maxv);
        } else if (bits >= from || ((acc << (to - bits)) & maxv) != 0) {
            throw new IllegalArgumentException("invalid padding");
        }
        return out.toByteArray();
    }

    static String segwitAddress(String hrp, int version, byte[] program) {
        if (version < 0 || version > 16) throw new IllegalArgumentException("invalid witness version");
        validateProgram(version, program);
        byte[] conv = convertBits(program, 8, 5, true);
        byte[] data = new byte[conv.length + 1];
        data[0] = (byte) version;
        System.arraycopy(conv, 0, data, 1, conv.length);
        return encode(hrp, data, version == 0 ? Encoding.BECH32 : Encoding.BECH32M);
    }

    /** Decode a SegWit address for {@code expectedHrp} (BIP-173/350), or throw. */
    static WitnessProgram decodeSegwit(String expectedHrp, String address) {
        Decoded d = decode(address);
        if (!d.hrp.equals(expectedHrp)) throw new IllegalArgumentException("wrong network prefix");
        if (d.data.length < 1) throw new IllegalArgumentException("empty witness data");
        int version = d.data[0];
        if (version > 16) throw new IllegalArgumentException("invalid witness version");
        byte[] program = convertBits(java.util.Arrays.copyOfRange(d.data, 1, d.data.length), 5, 8, false);
        validateProgram(version, program);
        if ((version == 0) != (d.encoding == Encoding.BECH32)) throw new IllegalArgumentException("wrong checksum variant for witness version");
        return new WitnessProgram(version, program);
    }

    private static void validateProgram(int version, byte[] program) {
        if (program.length < 2 || program.length > 40) throw new IllegalArgumentException("invalid witness program length");
        if (version == 0 && program.length != 20 && program.length != 32) throw new IllegalArgumentException("invalid v0 program length");
    }
}
