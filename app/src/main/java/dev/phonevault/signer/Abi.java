package dev.phonevault.signer;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * A strict Solidity ABI decoder for the call shapes the phone explains (NFT calls, Uniswap
 * routers). "Strict" means canonical: the bytes are decoded against a fixed type list and then
 * re-encoded, and the two must be byte-for-byte identical. Anything a contract might read
 * differently from this decoder — non-canonical offsets, overlapping or reordered tails, dirty
 * address/bool/uintN padding, trailing bytes — is therefore refused, so the values shown on the
 * phone are the values the contract will use.
 *
 * <p>Decoded values: address → lower-case "0x…" String; uintN/intN → BigInteger; bool → Boolean;
 * bytes → byte[]; T[] and tuples → unmodifiable List&lt;Object&gt;.
 */
final class Abi {
    private Abi() {}

    /** Calldata larger than this is never decoded (the USB frame limit is 32 KiB of hex anyway). */
    static final int MAX_BYTES = 16 * 1024;
    private static final int MAX_ELEMENTS = 64;
    private static final int MAX_DEPTH = 6;

    static final class AbiException extends Exception {
        AbiException(String message) { super(message); }
    }

    enum Kind { ADDRESS, UINT, INT, BOOL, BYTES, ARRAY, TUPLE }

    static final class Type {
        final Kind kind;
        final int bits;
        final Type element;
        final Type[] fields;

        private Type(Kind kind, int bits, Type element, Type[] fields) {
            this.kind = kind;
            this.bits = bits;
            this.element = element;
            this.fields = fields;
        }

        boolean dynamic() {
            if (kind == Kind.BYTES || kind == Kind.ARRAY) return true;
            if (kind == Kind.TUPLE) for (Type f : fields) if (f.dynamic()) return true;
            return false;
        }

        /** Head size in bytes when the type is static. */
        int staticSize() {
            if (kind != Kind.TUPLE) return 32;
            int size = 0;
            for (Type f : fields) size += f.dynamic() ? 32 : f.staticSize();
            return size;
        }
    }

    static final Type ADDRESS = new Type(Kind.ADDRESS, 160, null, null);
    static final Type BOOL = new Type(Kind.BOOL, 8, null, null);
    static final Type BYTES = new Type(Kind.BYTES, 0, null, null);
    static final Type UINT256 = uint(256);

    static Type uint(int bits) { return new Type(Kind.UINT, bits, null, null); }
    static Type int_(int bits) { return new Type(Kind.INT, bits, null, null); }
    static Type array(Type element) { return new Type(Kind.ARRAY, 0, element, null); }
    static Type tuple(Type... fields) { return new Type(Kind.TUPLE, 0, null, fields.clone()); }

    /** Calldata hex ("0x…", even length) to bytes; refuses anything else. */
    static byte[] hex(String data) throws AbiException {
        if (data == null || !data.matches("0x([0-9a-fA-F]{2})*")) throw new AbiException("calldata must be even-length 0x hex");
        int n = (data.length() - 2) / 2;
        if (n > MAX_BYTES) throw new AbiException("calldata is too long to review (" + n + " bytes)");
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) out[i] = (byte) Integer.parseInt(data.substring(2 + 2 * i, 4 + 2 * i), 16);
        return out;
    }

    static String selector(byte[] call) {
        return call.length < 4 ? null : toHex(Arrays.copyOf(call, 4));
    }

    /** Decodes the arguments after a 4-byte selector, strictly. */
    static List<Object> decodeCall(byte[] call, Type... params) throws AbiException {
        if (call.length < 4) throw new AbiException("calldata shorter than a selector");
        return decode(Arrays.copyOfRange(call, 4, call.length), params);
    }

    /** Decodes {@code data} as the tuple {@code params} and requires it to be the canonical encoding. */
    static List<Object> decode(byte[] data, Type... params) throws AbiException {
        return decodeWithTrailing(data, 0, false, params).values;
    }

    /** Values plus any bytes after the canonical encoding (only where a caller allows them). */
    static final class Decoded {
        final List<Object> values;
        final byte[] trailing;

        Decoded(List<Object> values, byte[] trailing) {
            this.values = values;
            this.trailing = trailing;
        }
    }

    /**
     * Like {@link #decode}, but up to {@code maxTrailing} bytes may follow the canonical encoding
     * (Solidity's decoder never reads them); with {@code zeroOnly} they must all be zero. The
     * canonical encoding must still match the data byte for byte.
     */
    static Decoded decodeWithTrailing(byte[] data, int maxTrailing, boolean zeroOnly, Type... params) throws AbiException {
        if (data.length > MAX_BYTES) throw new AbiException("ABI data is too long");
        Type root = tuple(params);
        @SuppressWarnings("unchecked")
        List<Object> values = (List<Object>) read(data, 0, data.length, root, 0);
        byte[] again = encode(root, values);
        int extra = data.length - again.length;
        if (extra < 0 || extra > maxTrailing || !Arrays.equals(again, Arrays.copyOf(data, again.length))) {
            throw new AbiException(again.length != data.length
                    ? "ABI data is not canonical (" + data.length + " bytes; canonical form is " + again.length + ")"
                    : "ABI data is not canonical (offsets or padding differ from the standard encoding)");
        }
        byte[] trailing = Arrays.copyOfRange(data, again.length, data.length);
        if (zeroOnly) for (byte b : trailing) if (b != 0) throw new AbiException("non-zero bytes after the ABI data");
        return new Decoded(values, trailing);
    }

    // ------------------------------------------------------------------ reading

    private static Object read(byte[] d, int base, int end, Type t, int depth) throws AbiException {
        if (depth > MAX_DEPTH) throw new AbiException("ABI data nested too deeply");
        switch (t.kind) {
            case ADDRESS: {
                BigInteger v = word(d, base, end);
                if (v.bitLength() > 160) throw new AbiException("address with non-zero padding");
                String hex = v.toString(16);
                return "0x" + "0000000000000000000000000000000000000000".substring(hex.length()) + hex;
            }
            case UINT: {
                BigInteger v = word(d, base, end);
                if (v.bitLength() > t.bits) throw new AbiException("uint" + t.bits + " out of range");
                return v;
            }
            case INT: {
                BigInteger v = signed(word(d, base, end));
                if (v.bitLength() >= t.bits) throw new AbiException("int" + t.bits + " out of range");
                return v;
            }
            case BOOL: {
                BigInteger v = word(d, base, end);
                if (v.compareTo(BigInteger.ONE) > 0) throw new AbiException("bool that is neither 0 nor 1");
                return v.signum() == 1;
            }
            case BYTES: {
                int len = smallInt(word(d, base, end), "bytes length");
                if (base + 32 + len > end) throw new AbiException("bytes run past the end");
                return Arrays.copyOfRange(d, base + 32, base + 32 + len);
            }
            case ARRAY: {
                int n = smallInt(word(d, base, end), "array length");
                if (n > MAX_ELEMENTS) throw new AbiException("array too long");
                Type[] items = new Type[n];
                Arrays.fill(items, t.element);
                return readTuple(d, base + 32, end, items, depth);
            }
            default:
                return readTuple(d, base, end, t.fields, depth);
        }
    }

    private static List<Object> readTuple(byte[] d, int base, int end, Type[] fields, int depth) throws AbiException {
        List<Object> out = new ArrayList<>(fields.length);
        int head = base;
        for (Type f : fields) {
            if (f.dynamic()) {
                int offset = smallInt(word(d, head, end), "offset");
                if (base + offset >= end) throw new AbiException("offset out of range");
                out.add(read(d, base + offset, end, f, depth + 1));
                head += 32;
            } else {
                out.add(read(d, head, end, f, depth + 1));
                head += f.staticSize();
            }
        }
        return Collections.unmodifiableList(out);
    }

    private static BigInteger word(byte[] d, int at, int end) throws AbiException {
        if (at < 0 || at + 32 > end || at + 32 > d.length) throw new AbiException("ABI data truncated");
        return new BigInteger(1, Arrays.copyOfRange(d, at, at + 32));
    }

    private static BigInteger signed(BigInteger word) {
        return word.testBit(255) ? word.subtract(BigInteger.ONE.shiftLeft(256)) : word;
    }

    private static int smallInt(BigInteger v, String what) throws AbiException {
        if (v.bitLength() > 24) throw new AbiException(what + " too large");
        return v.intValue();
    }

    // ------------------------------------------------------------------ canonical encoding

    static byte[] encode(Type t, Object value) throws AbiException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        write(out, t, value);
        return out.toByteArray();
    }

    @SuppressWarnings("unchecked")
    private static void write(ByteArrayOutputStream out, Type t, Object v) throws AbiException {
        switch (t.kind) {
            case ADDRESS: out.write(pad(new BigInteger(((String) v).substring(2), 16)), 0, 32); return;
            case UINT: out.write(pad((BigInteger) v), 0, 32); return;
            case INT: {
                BigInteger x = (BigInteger) v;
                out.write(pad(x.signum() < 0 ? x.add(BigInteger.ONE.shiftLeft(256)) : x), 0, 32);
                return;
            }
            case BOOL: out.write(pad((Boolean) v ? BigInteger.ONE : BigInteger.ZERO), 0, 32); return;
            case BYTES: {
                byte[] b = (byte[]) v;
                out.write(pad(BigInteger.valueOf(b.length)), 0, 32);
                out.write(b, 0, b.length);
                int rem = (32 - b.length % 32) % 32;
                out.write(new byte[rem], 0, rem);
                return;
            }
            case ARRAY: {
                List<Object> items = (List<Object>) v;
                out.write(pad(BigInteger.valueOf(items.size())), 0, 32);
                Type[] types = new Type[items.size()];
                Arrays.fill(types, t.element);
                writeTuple(out, types, items);
                return;
            }
            default:
                writeTuple(out, t.fields, (List<Object>) v);
        }
    }

    private static void writeTuple(ByteArrayOutputStream out, Type[] fields, List<Object> values) throws AbiException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        ByteArrayOutputStream tail = new ByteArrayOutputStream();
        int headSize = 0;
        for (Type f : fields) headSize += f.dynamic() ? 32 : f.staticSize();
        for (int i = 0; i < fields.length; i++) {
            if (fields[i].dynamic()) {
                head.write(pad(BigInteger.valueOf(headSize + tail.size())), 0, 32);
                write(tail, fields[i], values.get(i));
            } else {
                write(head, fields[i], values.get(i));
            }
        }
        byte[] h = head.toByteArray(), tl = tail.toByteArray();
        out.write(h, 0, h.length);
        out.write(tl, 0, tl.length);
    }

    private static byte[] pad(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }

    // ------------------------------------------------------------------ helpers

    static String toHex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(String.format(Locale.ROOT, "%02x", x & 0xff));
        return s.toString();
    }

    static String address(Object v) { return (String) v; }
    static BigInteger uint(Object v) { return (BigInteger) v; }
    static boolean bool(Object v) { return (Boolean) v; }
    static byte[] bytes(Object v) { return (byte[]) v; }
    @SuppressWarnings("unchecked")
    static List<Object> list(Object v) { return (List<Object>) v; }
}
