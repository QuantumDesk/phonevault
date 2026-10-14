package dev.phonevault.signer;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Bitcoin's primitives on secp256k1, built on the Bouncy Castle lightweight API the app already
 * ships (no new dependency): SHA-256 / HASH160 / tagged hashes, HMAC-SHA512 for BIP-32, ECDSA with
 * RFC 6979 deterministic nonces (low-S, DER) for SegWit v0, and BIP-340 Schnorr signatures plus the
 * BIP-341/86 key-path tweak for Taproot.
 *
 * <p>Private scalars live in {@code byte[]} that callers zero; the arithmetic needs
 * {@link BigInteger}, which cannot be zeroed (the same limitation as the EVM path's web3j keys).
 * Every signature is verified before it is returned. Nothing here logs.
 */
final class BtcCrypto {
    private BtcCrypto() {}

    static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    static final ECDomainParameters CURVE = new ECDomainParameters(
            CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
    static final BigInteger N = CURVE_PARAMS.getN();
    static final BigInteger HALF_N = N.shiftRight(1);
    static final BigInteger P = CURVE_PARAMS.getCurve().getField().getCharacteristic();
    static final ECPoint G = CURVE_PARAMS.getG();

    // ------------------------------------------------------------------ hashes

    static byte[] sha256(byte[]... parts) {
        SHA256Digest d = new SHA256Digest();
        for (byte[] p : parts) d.update(p, 0, p.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }

    static byte[] sha256d(byte[] data) { return sha256(sha256(data)); }

    static byte[] hash160(byte[] data) {
        byte[] sha = sha256(data);
        RIPEMD160Digest r = new RIPEMD160Digest();
        r.update(sha, 0, sha.length);
        byte[] out = new byte[20];
        r.doFinal(out, 0);
        return out;
    }

    /** BIP-340 tagged hash: SHA256(SHA256(tag) ‖ SHA256(tag) ‖ data…). */
    static byte[] taggedHash(String tag, byte[]... parts) {
        byte[] t = sha256(tag.getBytes(StandardCharsets.UTF_8));
        byte[][] all = new byte[parts.length + 2][];
        all[0] = t;
        all[1] = t;
        System.arraycopy(parts, 0, all, 2, parts.length);
        return sha256(all);
    }

    static byte[] hmacSha512(byte[] key, byte[] data) {
        HMac mac = new HMac(new SHA512Digest());
        mac.init(new KeyParameter(key));
        mac.update(data, 0, data.length);
        byte[] out = new byte[64];
        mac.doFinal(out, 0);
        return out;
    }

    // ------------------------------------------------------------------ scalars and points

    static BigInteger toInt(byte[] b) { return new BigInteger(1, b); }

    /** Big-endian 32 bytes. */
    static byte[] bytes32(BigInteger v) {
        byte[] raw = v.toByteArray();
        if (raw.length == 32) return raw;
        byte[] out = new byte[32];
        if (raw.length > 32) {
            if (raw.length != 33 || raw[0] != 0) throw new IllegalArgumentException("value exceeds 32 bytes");
            System.arraycopy(raw, 1, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        Arrays.fill(raw, (byte) 0);
        return out;
    }

    static ECPoint mulG(BigInteger k) { return new FixedPointCombMultiplier().multiply(G, k).normalize(); }

    static byte[] pubCompressed(byte[] priv32) { return mulG(validPrivate(priv32)).getEncoded(true); }

    static BigInteger validPrivate(byte[] priv32) {
        if (priv32 == null || priv32.length != 32) throw new IllegalArgumentException("private key must be 32 bytes");
        BigInteger d = toInt(priv32);
        if (d.signum() == 0 || d.compareTo(N) >= 0) throw new IllegalArgumentException("private key out of range");
        return d;
    }

    static ECPoint decodePoint(byte[] encoded) {
        ECPoint p = CURVE.getCurve().decodePoint(encoded).normalize();
        if (p.isInfinity() || !p.isValid()) throw new IllegalArgumentException("invalid public key");
        return p;
    }

    /** A compressed (33-byte, 02/03) secp256k1 public key that is on the curve. */
    static boolean validCompressed(byte[] pub) {
        if (pub == null || pub.length != 33 || (pub[0] != 2 && pub[0] != 3)) return false;
        try { decodePoint(pub); return true; } catch (RuntimeException e) { return false; }
    }

    static boolean hasEvenY(ECPoint p) { return !p.normalize().getAffineYCoord().toBigInteger().testBit(0); }

    static byte[] xOnly(ECPoint p) { return bytes32(p.normalize().getAffineXCoord().toBigInteger()); }

    /** BIP-340 lift_x: the point with x and an even y, or null. */
    static ECPoint liftX(byte[] x32) {
        if (x32 == null || x32.length != 32) return null;
        BigInteger x = toInt(x32);
        if (x.compareTo(P) >= 0) return null;
        BigInteger c = x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);
        BigInteger y = c.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        if (!y.modPow(BigInteger.valueOf(2), P).equals(c)) return null;
        if (y.testBit(0)) y = P.subtract(y);
        return CURVE.getCurve().createPoint(x, y).normalize();
    }

    // ------------------------------------------------------------------ ECDSA (SegWit v0)

    /**
     * ECDSA over a 32-byte digest, RFC 6979 nonce (HMAC-SHA256), low-S, DER-encoded (no sighash
     * byte). Verified against the public key before it is returned.
     */
    static byte[] signEcdsa(byte[] priv32, byte[] digest32) {
        if (digest32 == null || digest32.length != 32) throw new IllegalArgumentException("digest must be 32 bytes");
        BigInteger d = validPrivate(priv32);
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(d, CURVE));
        BigInteger[] rs = signer.generateSignature(digest32);
        BigInteger r = rs[0], s = rs[1];
        if (s.compareTo(HALF_N) > 0) s = N.subtract(s);
        byte[] der = der(r, s);
        if (!verifyEcdsa(mulG(d).getEncoded(true), digest32, der)) throw new IllegalStateException("ECDSA self-check failed");
        return der;
    }

    /** Strict-DER, low-S ECDSA verification (BIP-66 / BIP-146 style). */
    static boolean verifyEcdsa(byte[] pub, byte[] digest32, byte[] der) {
        BigInteger[] rs = parseDer(der);
        if (rs == null || rs[1].compareTo(HALF_N) > 0) return false;
        try {
            ECDSASigner v = new ECDSASigner();
            v.init(false, new ECPublicKeyParameters(decodePoint(pub), CURVE));
            return v.verifySignature(digest32, rs[0], rs[1]);
        } catch (RuntimeException e) {
            return false;
        }
    }

    static byte[] der(BigInteger r, BigInteger s) {
        byte[] rb = r.toByteArray(), sb = s.toByteArray(); // minimal two's complement: a 0x00 pad when the top bit is set
        ByteArrayOutputStream out = new ByteArrayOutputStream(72);
        out.write(0x30);
        out.write(4 + rb.length + sb.length);
        out.write(0x02);
        out.write(rb.length);
        out.write(rb, 0, rb.length);
        out.write(0x02);
        out.write(sb.length);
        out.write(sb, 0, sb.length);
        return out.toByteArray();
    }

    /** {r, s} from a strict DER signature (no sighash byte), or null. */
    static BigInteger[] parseDer(byte[] sig) {
        if (sig == null || sig.length < 8 || sig.length > 72) return null;
        if ((sig[0] & 0xFF) != 0x30 || (sig[1] & 0xFF) != sig.length - 2) return null;
        int lenR = sig[3] & 0xFF;
        if (sig[2] != 0x02 || lenR == 0 || 5 + lenR >= sig.length) return null;
        int lenS = sig[5 + lenR] & 0xFF;
        if (sig[4 + lenR] != 0x02 || lenS == 0 || 6 + lenR + lenS != sig.length) return null;
        byte[] r = Arrays.copyOfRange(sig, 4, 4 + lenR), s = Arrays.copyOfRange(sig, 6 + lenR, 6 + lenR + lenS);
        if (!minimalPositive(r) || !minimalPositive(s)) return null;
        BigInteger ri = toInt(r), si = toInt(s);
        if (ri.signum() == 0 || si.signum() == 0 || ri.compareTo(N) >= 0 || si.compareTo(N) >= 0) return null;
        return new BigInteger[] {ri, si};
    }

    private static boolean minimalPositive(byte[] v) {
        if ((v[0] & 0x80) != 0) return false;                       // negative
        return !(v.length > 1 && v[0] == 0 && (v[1] & 0x80) == 0);  // needless padding
    }

    // ------------------------------------------------------------------ BIP-340 Schnorr

    /**
     * BIP-340 signature of {@code msg} (any length) with the 32-byte secret key and 32 bytes of
     * auxiliary randomness. Returns R.x ‖ s (64 bytes), verified before return.
     */
    static byte[] signSchnorr(byte[] priv32, byte[] msg, byte[] aux32) {
        if (aux32 == null || aux32.length != 32) throw new IllegalArgumentException("aux must be 32 bytes");
        BigInteger d0 = validPrivate(priv32);
        ECPoint p = mulG(d0);
        BigInteger d = hasEvenY(p) ? d0 : N.subtract(d0);
        byte[] px = xOnly(p);
        byte[] dBytes = bytes32(d);
        byte[] t = taggedHash("BIP0340/aux", aux32);
        for (int i = 0; i < 32; i++) t[i] ^= dBytes[i];
        byte[] rand = taggedHash("BIP0340/nonce", t, px, msg);
        Arrays.fill(t, (byte) 0);
        Arrays.fill(dBytes, (byte) 0);
        BigInteger k0 = toInt(rand).mod(N);
        Arrays.fill(rand, (byte) 0);
        if (k0.signum() == 0) throw new IllegalStateException("BIP-340 nonce is zero");
        ECPoint r = mulG(k0);
        BigInteger k = hasEvenY(r) ? k0 : N.subtract(k0);
        byte[] rx = xOnly(r);
        BigInteger e = toInt(taggedHash("BIP0340/challenge", rx, px, msg)).mod(N);
        byte[] sig = new byte[64];
        System.arraycopy(rx, 0, sig, 0, 32);
        System.arraycopy(bytes32(k.add(e.multiply(d)).mod(N)), 0, sig, 32, 32);
        if (!verifySchnorr(px, msg, sig)) throw new IllegalStateException("BIP-340 self-check failed");
        return sig;
    }

    static boolean verifySchnorr(byte[] pubX32, byte[] msg, byte[] sig) {
        if (sig == null || sig.length != 64) return false;
        ECPoint p = liftX(pubX32);
        if (p == null) return false;
        BigInteger r = toInt(Arrays.copyOfRange(sig, 0, 32));
        BigInteger s = toInt(Arrays.copyOfRange(sig, 32, 64));
        if (r.compareTo(P) >= 0 || s.compareTo(N) >= 0) return false;
        BigInteger e = toInt(taggedHash("BIP0340/challenge", Arrays.copyOfRange(sig, 0, 32), pubX32, msg)).mod(N);
        ECPoint rr = mulG(s).add(p.multiply(N.subtract(e)).normalize()).normalize();
        if (rr.isInfinity() || !hasEvenY(rr)) return false;
        return rr.getAffineXCoord().toBigInteger().equals(r);
    }

    static byte[] randomAux(SecureRandom random) {
        byte[] aux = new byte[32];
        random.nextBytes(aux);
        return aux;
    }

    // ------------------------------------------------------------------ BIP-341 / BIP-86 tweak

    /** t = H_TapTweak(P.x) for a key with no script tree (BIP-86). */
    static byte[] tapTweak(byte[] internalX32) { return tapTweak(internalX32, null); }

    /** t = H_TapTweak(P.x ‖ merkle root); the phone itself only ever uses a null root (BIP-86). */
    static byte[] tapTweak(byte[] internalX32, byte[] merkleRoot) {
        return merkleRoot == null ? taggedHash("TapTweak", internalX32) : taggedHash("TapTweak", internalX32, merkleRoot);
    }

    /** Output key Q.x = (lift_x(P) + t·G).x for a key-path-only Taproot output (BIP-86). */
    static byte[] taprootOutputKey(byte[] internalX32) { return taprootOutputKey(internalX32, null); }

    static byte[] taprootOutputKey(byte[] internalX32, byte[] merkleRoot) {
        ECPoint p = liftX(internalX32);
        if (p == null) throw new IllegalArgumentException("internal key is not on the curve");
        BigInteger t = toInt(tapTweak(internalX32, merkleRoot));
        if (t.compareTo(N) >= 0) throw new IllegalArgumentException("taproot tweak out of range");
        ECPoint q = p.add(mulG(t)).normalize();
        if (q.isInfinity()) throw new IllegalArgumentException("taproot output key is infinity");
        return xOnly(q);
    }

    /**
     * The secret key for a BIP-86 key-path spend: d' = (±d + t) mod n with the sign chosen so the
     * internal key has an even y. The caller zeroes the result.
     */
    static byte[] taprootTweakedPrivate(byte[] priv32) { return taprootTweakedPrivate(priv32, null); }

    static byte[] taprootTweakedPrivate(byte[] priv32, byte[] merkleRoot) {
        BigInteger d0 = validPrivate(priv32);
        ECPoint p = mulG(d0);
        BigInteger d = hasEvenY(p) ? d0 : N.subtract(d0);
        BigInteger t = toInt(tapTweak(xOnly(p), merkleRoot));
        if (t.compareTo(N) >= 0) throw new IllegalArgumentException("taproot tweak out of range");
        BigInteger tweaked = d.add(t).mod(N);
        if (tweaked.signum() == 0) throw new IllegalArgumentException("tweaked key is zero");
        return bytes32(tweaked);
    }

    // ------------------------------------------------------------------ encoding helpers

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        return s.toString();
    }

    static byte[] reversed(byte[] b) {
        byte[] out = new byte[b.length];
        for (int i = 0; i < b.length; i++) out[i] = b[b.length - 1 - i];
        return out;
    }
}
