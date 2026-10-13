package dev.phonevault.signer;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * BIP-32 hierarchical deterministic keys for the Bitcoin accounts (the EVM path keeps using
 * web3j's implementation). A {@link Key} with a private part is secret: callers {@link
 * Key#destroy()} it as soon as they are done, and only ever hand out {@link Key#neuter()} copies.
 */
final class Bip32 {
    private Bip32() {}

    static final int HARDENED = 0x80000000;
    private static final byte[] SEED_KEY = "Bitcoin seed".getBytes(StandardCharsets.US_ASCII);

    static final class Key {
        /** 32-byte secret, or null for a public-only key. Zeroed by {@link #destroy()}. */
        private byte[] priv;
        final byte[] pub;       // 33-byte compressed
        final byte[] chainCode; // 32
        final int depth;
        final byte[] parentFingerprint; // 4
        final int childNumber;

        Key(byte[] priv, byte[] pub, byte[] chainCode, int depth, byte[] parentFingerprint, int childNumber) {
            this.priv = priv;
            this.pub = pub;
            this.chainCode = chainCode;
            this.depth = depth;
            this.parentFingerprint = parentFingerprint;
            this.childNumber = childNumber;
        }

        boolean hasPrivate() { return priv != null; }

        /** The secret itself (not a copy): only for signing, by code that destroys this key afterwards. */
        byte[] privateKey() {
            if (priv == null) throw new IllegalStateException("public-only key");
            return priv;
        }

        Key neuter() { return new Key(null, pub, chainCode, depth, parentFingerprint, childNumber); }

        byte[] fingerprint() { return Arrays.copyOf(BtcCrypto.hash160(pub), 4); }

        void destroy() {
            if (priv != null) Arrays.fill(priv, (byte) 0);
            priv = null;
        }

        /** Base58Check extended public key with the given version (xpub 0x0488B21E, tpub 0x043587CF). */
        String serializePublic(int version) {
            byte[] out = new byte[78];
            out[0] = (byte) (version >>> 24);
            out[1] = (byte) (version >>> 16);
            out[2] = (byte) (version >>> 8);
            out[3] = (byte) version;
            out[4] = (byte) depth;
            System.arraycopy(parentFingerprint, 0, out, 5, 4);
            out[9] = (byte) (childNumber >>> 24);
            out[10] = (byte) (childNumber >>> 16);
            out[11] = (byte) (childNumber >>> 8);
            out[12] = (byte) childNumber;
            System.arraycopy(chainCode, 0, out, 13, 32);
            System.arraycopy(pub, 0, out, 45, 33);
            return Base58.encodeCheck(out);
        }
    }

    static Key master(byte[] seed) {
        if (seed == null || seed.length < 16 || seed.length > 64) throw new IllegalArgumentException("BIP-32 seed must be 16-64 bytes");
        byte[] i = BtcCrypto.hmacSha512(SEED_KEY, seed);
        try {
            byte[] il = Arrays.copyOfRange(i, 0, 32);
            BtcCrypto.validPrivate(il); // 0 < IL < n, else the seed is unusable (probability ~2^-127)
            return new Key(il, BtcCrypto.pubCompressed(il), Arrays.copyOfRange(i, 32, 64), 0, new byte[4], 0);
        } finally {
            Arrays.fill(i, (byte) 0);
        }
    }

    /** CKDpriv for a private key, CKDpub (non-hardened only) for a public one. */
    static Key child(Key parent, int index) {
        boolean hardened = (index & HARDENED) != 0;
        if (parent.depth >= 255) throw new IllegalArgumentException("BIP-32 depth limit");
        byte[] data = new byte[37];
        if (hardened) {
            if (!parent.hasPrivate()) throw new IllegalArgumentException("hardened derivation needs the private key");
            System.arraycopy(parent.priv, 0, data, 1, 32);
        } else {
            System.arraycopy(parent.pub, 0, data, 0, 33);
        }
        data[33] = (byte) (index >>> 24);
        data[34] = (byte) (index >>> 16);
        data[35] = (byte) (index >>> 8);
        data[36] = (byte) index;
        byte[] i = BtcCrypto.hmacSha512(parent.chainCode, data);
        Arrays.fill(data, (byte) 0);
        try {
            BigInteger il = BtcCrypto.toInt(Arrays.copyOfRange(i, 0, 32));
            if (il.compareTo(BtcCrypto.N) >= 0) throw new IllegalArgumentException("BIP-32 child index " + index + " is invalid");
            byte[] chain = Arrays.copyOfRange(i, 32, 64);
            byte[] fp = parent.fingerprint();
            if (parent.hasPrivate()) {
                BigInteger k = il.add(BtcCrypto.toInt(parent.priv)).mod(BtcCrypto.N);
                if (k.signum() == 0) throw new IllegalArgumentException("BIP-32 child index " + index + " is invalid");
                byte[] priv = BtcCrypto.bytes32(k);
                return new Key(priv, BtcCrypto.pubCompressed(priv), chain, parent.depth + 1, fp, index);
            }
            ECPoint q = BtcCrypto.mulG(il).add(BtcCrypto.decodePoint(parent.pub)).normalize();
            if (q.isInfinity()) throw new IllegalArgumentException("BIP-32 child index " + index + " is invalid");
            return new Key(null, q.getEncoded(true), chain, parent.depth + 1, fp, index);
        } finally {
            Arrays.fill(i, (byte) 0);
        }
    }

    /** Derive along {@code path}; intermediate private keys are destroyed (the start key is not). */
    static Key derive(Key start, int... path) {
        Key k = start;
        for (int index : path) {
            Key next = child(k, index);
            if (k != start) k.destroy();
            k = next;
        }
        return k;
    }

    /** A Base58Check extended PUBLIC key (any version; checked by the caller). */
    static Key parsePublic(String encoded, int expectedVersion) {
        byte[] b = Base58.decodeCheck(encoded);
        if (b.length != 78) throw new IllegalArgumentException("extended key must be 78 bytes");
        int version = ((b[0] & 0xff) << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);
        if (version != expectedVersion) throw new IllegalArgumentException("unexpected extended key version");
        int child = ((b[9] & 0xff) << 24) | ((b[10] & 0xff) << 16) | ((b[11] & 0xff) << 8) | (b[12] & 0xff);
        byte[] pub = Arrays.copyOfRange(b, 45, 78);
        if (!BtcCrypto.validCompressed(pub)) throw new IllegalArgumentException("invalid public key in extended key");
        return new Key(null, pub, Arrays.copyOfRange(b, 13, 45), b[4] & 0xff, Arrays.copyOfRange(b, 5, 9), child);
    }

    /** "m/84'/0'/0'/1/5". */
    static String pathString(int[] path) {
        StringBuilder s = new StringBuilder("m");
        for (int p : path) s.append('/').append(p & ~HARDENED).append((p & HARDENED) != 0 ? "'" : "");
        return s.toString();
    }
}
