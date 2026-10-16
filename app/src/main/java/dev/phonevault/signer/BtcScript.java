package dev.phonevault.signer;

import java.util.Arrays;

/**
 * Output scripts the phone can explain: the five standard address types (P2PKH, P2SH, P2WPKH,
 * P2WSH, P2TR) and OP_RETURN data. Anything else has no address a person could compare, so a
 * transaction paying to it is refused.
 */
final class BtcScript {
    private BtcScript() {}

    enum Kind { P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN, UNKNOWN }

    static final int OP_RETURN = 0x6a;
    /** Largest OP_RETURN output shown as data (Bitcoin Core's relay default before v30 was 83 bytes; v30 lifts it). */
    static final int MAX_DATA_SCRIPT = 10_000;

    static byte[] p2wpkh(byte[] hash20) {
        if (hash20.length != 20) throw new IllegalArgumentException("hash must be 20 bytes");
        byte[] s = new byte[22];
        s[0] = 0x00;
        s[1] = 0x14;
        System.arraycopy(hash20, 0, s, 2, 20);
        return s;
    }

    /** OP_HASH160 &lt;20&gt; OP_EQUAL. */
    static byte[] p2sh(byte[] hash20) {
        if (hash20.length != 20) throw new IllegalArgumentException("hash must be 20 bytes");
        byte[] s = new byte[23];
        s[0] = (byte) 0xa9;
        s[1] = 0x14;
        System.arraycopy(hash20, 0, s, 2, 20);
        s[22] = (byte) 0x87;
        return s;
    }

    static byte[] p2tr(byte[] xonly32) {
        if (xonly32.length != 32) throw new IllegalArgumentException("key must be 32 bytes");
        byte[] s = new byte[34];
        s[0] = 0x51;
        s[1] = 0x20;
        System.arraycopy(xonly32, 0, s, 2, 32);
        return s;
    }

    /**
     * OP_DUP OP_HASH160 &lt;20&gt; OP_EQUALVERIFY OP_CHECKSIG: a P2PKH output script, and the BIP-143
     * script code for P2WPKH (native or nested in P2SH).
     */
    static byte[] p2pkhScript(byte[] hash20) {
        if (hash20.length != 20) throw new IllegalArgumentException("hash must be 20 bytes");
        byte[] s = new byte[25];
        s[0] = 0x76;
        s[1] = (byte) 0xa9;
        s[2] = 0x14;
        System.arraycopy(hash20, 0, s, 3, 20);
        s[23] = (byte) 0x88;
        s[24] = (byte) 0xac;
        return s;
    }

    static Kind kind(byte[] s) {
        if (s.length == 25 && (s[0] & 0xff) == 0x76 && (s[1] & 0xff) == 0xa9 && s[2] == 0x14
                && (s[23] & 0xff) == 0x88 && (s[24] & 0xff) == 0xac) return Kind.P2PKH;
        if (s.length == 23 && (s[0] & 0xff) == 0xa9 && s[1] == 0x14 && (s[22] & 0xff) == 0x87) return Kind.P2SH;
        if (s.length == 22 && s[0] == 0x00 && s[1] == 0x14) return Kind.P2WPKH;
        if (s.length == 34 && s[0] == 0x00 && s[1] == 0x20) return Kind.P2WSH;
        if (s.length == 34 && s[0] == 0x51 && s[1] == 0x20) return Kind.P2TR;
        if (s.length >= 1 && (s[0] & 0xff) == OP_RETURN && s.length <= MAX_DATA_SCRIPT && pushOnly(s, 1)) return Kind.OP_RETURN;
        return Kind.UNKNOWN;
    }

    /** True when the script from {@code at} consists only of well-formed data pushes. */
    static boolean pushOnly(byte[] s, int at) {
        int i = at;
        while (i < s.length) {
            int op = s[i++] & 0xff;
            int n;
            if (op == 0x00 || (op >= 0x51 && op <= 0x60) || op == 0x4f) continue; // OP_0, OP_1..16, OP_1NEGATE
            if (op >= 0x01 && op <= 0x4b) n = op;
            else if (op == 0x4c) { if (i + 1 > s.length) return false; n = s[i] & 0xff; i += 1; }
            else if (op == 0x4d) { if (i + 2 > s.length) return false; n = (s[i] & 0xff) | ((s[i + 1] & 0xff) << 8); i += 2; }
            else if (op == 0x4e) {
                if (i + 4 > s.length) return false;
                long len = (s[i] & 0xffL) | ((s[i + 1] & 0xffL) << 8) | ((s[i + 2] & 0xffL) << 16) | ((s[i + 3] & 0xffL) << 24);
                if (len > s.length) return false;
                n = (int) len;
                i += 4;
            }
            else return false;
            if (i + n > s.length) return false;
            i += n;
        }
        return true;
    }

    /** A single minimal data push of {@code data} (1…75 bytes: the length byte as the opcode). */
    static byte[] push(byte[] data) {
        if (data.length < 1 || data.length > 75) throw new IllegalArgumentException("push of 1-75 bytes only");
        byte[] s = new byte[1 + data.length];
        s[0] = (byte) data.length;
        System.arraycopy(data, 0, s, 1, data.length);
        return s;
    }

    /** Bytes of data carried by an OP_RETURN script (the script minus the opcode). */
    static int dataLength(byte[] s) { return Math.max(0, s.length - 1); }

    /** The address a standard script pays to on {@code network}, or null (OP_RETURN / unknown). */
    static String address(byte[] s, BtcNetwork network) {
        switch (kind(s)) {
            case P2PKH: return base58(network.p2pkhVersion, Arrays.copyOfRange(s, 3, 23));
            case P2SH: return base58(network.p2shVersion, Arrays.copyOfRange(s, 2, 22));
            case P2WPKH:
            case P2WSH: return Bech32.segwitAddress(network.hrp, 0, Arrays.copyOfRange(s, 2, s.length));
            case P2TR: return Bech32.segwitAddress(network.hrp, 1, Arrays.copyOfRange(s, 2, 34));
            default: return null;
        }
    }

    private static String base58(int version, byte[] hash20) {
        byte[] payload = new byte[21];
        payload[0] = (byte) version;
        System.arraycopy(hash20, 0, payload, 1, 20);
        return Base58.encodeCheck(payload);
    }

    /** What a person reads for this kind of script. */
    static String kindLabel(Kind k) {
        switch (k) {
            case P2PKH: return "Legacy (P2PKH)";
            case P2SH: return "Script hash (P2SH)";
            case P2WPKH: return "Native SegWit (P2WPKH)";
            case P2WSH: return "SegWit script (P2WSH)";
            case P2TR: return "Taproot (P2TR)";
            case OP_RETURN: return "Data (OP_RETURN)";
            default: return "Unknown script";
        }
    }

    /** "bc1q w508 d6qe …" — 4-character groups, a line break every {@code perLine} groups (0: none). */
    static String grouped(String address, int perLine) {
        StringBuilder out = new StringBuilder();
        for (int i = 0, g = 0; i < address.length(); i += 4, g++) {
            if (g > 0) out.append(perLine > 0 && g % perLine == 0 ? '\n' : ' ');
            out.append(address, i, Math.min(address.length(), i + 4));
        }
        return out.toString();
    }
}
