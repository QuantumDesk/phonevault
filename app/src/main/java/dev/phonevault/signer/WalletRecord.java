package dev.phonevault.signer;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * The single on-disk wallet record: one self-checking blob so the active identity is never split
 * across two preference keys that can be observed half-written.
 *
 * <pre>
 *   magic "PVW3" | u16 ivLen | iv | u32 ctLen | ciphertext | sha256(everything before)
 * </pre>
 *
 * Pure Java (no Android types) so the format, checksum and corruption handling are unit-tested.
 * Durability (atomic rename + fsync + read-back) is the storage layer's job — see VaultKeyStore.
 */
final class WalletRecord {
    static final byte[] MAGIC = {'P', 'V', 'W', '3'};
    private static final int DIGEST_BYTES = 32;

    final byte[] iv;
    final byte[] ciphertext;

    WalletRecord(byte[] iv, byte[] ciphertext) {
        if (iv == null || iv.length == 0 || iv.length > 0xFFFF) throw new IllegalArgumentException("bad iv");
        if (ciphertext == null || ciphertext.length == 0) throw new IllegalArgumentException("bad ciphertext");
        this.iv = iv.clone();
        this.ciphertext = ciphertext.clone();
    }

    byte[] encode() {
        ByteBuffer body = ByteBuffer.allocate(MAGIC.length + 2 + iv.length + 4 + ciphertext.length);
        body.put(MAGIC).putShort((short) iv.length).put(iv).putInt(ciphertext.length).put(ciphertext);
        byte[] payload = body.array();
        byte[] digest = sha256(payload);
        byte[] out = Arrays.copyOf(payload, payload.length + DIGEST_BYTES);
        System.arraycopy(digest, 0, out, payload.length, DIGEST_BYTES);
        return out;
    }

    /** Strict decode: any truncation, trailing data, bad magic or checksum mismatch throws. */
    static WalletRecord decode(byte[] blob) {
        if (blob == null || blob.length < MAGIC.length + 2 + 1 + 4 + 1 + DIGEST_BYTES) {
            throw new IllegalArgumentException("wallet record truncated");
        }
        int payloadLength = blob.length - DIGEST_BYTES;
        byte[] payload = Arrays.copyOf(blob, payloadLength);
        byte[] storedDigest = Arrays.copyOfRange(blob, payloadLength, blob.length);
        if (!MessageDigest.isEqual(sha256(payload), storedDigest)) {
            throw new IllegalArgumentException("wallet record checksum mismatch");
        }
        ByteBuffer in = ByteBuffer.wrap(payload);
        byte[] magic = new byte[MAGIC.length];
        in.get(magic);
        if (!Arrays.equals(magic, MAGIC)) throw new IllegalArgumentException("wallet record bad magic");
        int ivLength = in.getShort() & 0xFFFF;
        if (ivLength == 0 || ivLength > in.remaining() - 4) throw new IllegalArgumentException("wallet record bad iv length");
        byte[] iv = new byte[ivLength];
        in.get(iv);
        int ctLength = in.getInt();
        if (ctLength <= 0 || ctLength != in.remaining()) throw new IllegalArgumentException("wallet record bad ciphertext length");
        byte[] ciphertext = new byte[ctLength];
        in.get(ciphertext);
        return new WalletRecord(iv, ciphertext);
    }

    boolean sameAs(WalletRecord other) {
        return other != null && MessageDigest.isEqual(iv, other.iv)
                && MessageDigest.isEqual(ciphertext, other.ciphertext);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
