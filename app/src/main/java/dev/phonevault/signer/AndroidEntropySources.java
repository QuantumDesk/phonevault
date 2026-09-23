package dev.phonevault.signer;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Concrete {@link EntropySource}s available on the device. The kernel CSPRNG is required (it already
 * folds in the Snapdragon QRNG + interrupt jitter). CPU-jitter is a cheap belt-and-suspenders second
 * source so generation never rides on a single pipe (entropy-design.md R1/R2).
 *
 * <p>R2: {@link #titanM()} is an independent hardware source. Android exposes no raw read of the
 * Titan M TRNG, so it uses the chip indirectly: a fresh AES-256 key is generated INSIDE StrongBox,
 * the keystore has the chip pick the GCM IV, and zeros are encrypted. The ciphertext is the AES
 * keystream under a chip-generated key and IV, so its unpredictability comes only from randomness
 * produced in the Titan M, independent of the kernel pool. The key is deleted afterwards.
 */
final class AndroidEntropySources {

    private AndroidEntropySources() {}

    static List<EntropySource> device() {
        List<EntropySource> sources = new ArrayList<>();
        sources.add(kernel());
        sources.add(titanM());
        sources.add(jitter());
        return sources;
    }

    /** Kernel CSPRNG via the strong instance (blocks until seeded; reads getrandom/dev/random). */
    static EntropySource kernel() {
        return new EntropySource() {
            public String name() { return "kernel-getrandom"; }
            public boolean required() { return true; }
            public byte[] draw(int numBytes) throws Exception {
                SecureRandom strong = SecureRandom.getInstanceStrong();
                byte[] out = new byte[numBytes];
                strong.nextBytes(out);
                return out;
            }
        };
    }

    /**
     * CPU-timing jitter collector: accumulate many high-resolution timing deltas (which vary due to
     * cache/branch/scheduler noise) and condition them through SHA-256. Independent of the kernel
     * pool. Not sufficient alone — it is mixed with the kernel source.
     */
    static EntropySource jitter() {
        return new EntropySource() {
            public String name() { return "cpu-jitter"; }
            public boolean required() { return false; }
            public byte[] draw(int numBytes) throws Exception {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] acc = new byte[0];
                int rounds = (numBytes + 31) / 32;
                for (int r = 0; r < rounds; r++) {
                    for (int i = 0; i < 4096; i++) {
                        long t0 = System.nanoTime();
                        // unpredictable-latency busy work
                        double x = Math.sqrt((t0 & 0xffff) + i + 1) * Math.log1p(i + 1);
                        long t1 = System.nanoTime();
                        long delta = t1 - t0 + (long) (x * 1000);
                        sha.update((byte) (delta));
                        sha.update((byte) (delta >>> 8));
                        sha.update((byte) (delta >>> 16));
                    }
                    byte[] block = sha.digest();
                    byte[] next = new byte[acc.length + block.length];
                    System.arraycopy(acc, 0, next, 0, acc.length);
                    System.arraycopy(block, 0, next, acc.length, block.length);
                    java.util.Arrays.fill(acc, (byte) 0); // zero the superseded accumulator
                    acc = next;
                    sha.update(block); // chain
                    java.util.Arrays.fill(block, (byte) 0);
                }
                byte[] out = new byte[numBytes];
                System.arraycopy(acc, 0, out, 0, numBytes);
                java.util.Arrays.fill(acc, (byte) 0);
                return out;
            }
        };
    }

    /** Titan M (StrongBox) randomness, see the class comment. Not required: if StrongBox is
     *  unavailable the SeedVault policy still needs two healthy sources before it will generate. */
    static EntropySource titanM() {
        return new EntropySource() {
            public String name() { return "titan-m-strongbox"; }
            public boolean required() { return false; }
            public byte[] draw(int numBytes) throws Exception {
                String alias = "phone-vault-entropy-" + java.util.UUID.randomUUID();
                java.security.KeyStore ks = java.security.KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);
                try {
                    javax.crypto.KeyGenerator gen = javax.crypto.KeyGenerator.getInstance(
                            android.security.keystore.KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
                    gen.init(new android.security.keystore.KeyGenParameterSpec.Builder(alias,
                            android.security.keystore.KeyProperties.PURPOSE_ENCRYPT)
                            .setKeySize(256)
                            .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setRandomizedEncryptionRequired(true) // the chip chooses the IV
                            .setIsStrongBoxBacked(true)
                            .build());
                    javax.crypto.SecretKey key = gen.generateKey();
                    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
                    byte[] zeros = new byte[numBytes];
                    byte[] sealed = cipher.doFinal(zeros); // keystream ‖ 16-byte tag
                    if (sealed.length < numBytes) throw new IllegalStateException("short StrongBox output");
                    byte[] out = java.util.Arrays.copyOf(sealed, numBytes);
                    java.util.Arrays.fill(sealed, (byte) 0);
                    return out;
                } finally {
                    try { ks.deleteEntry(alias); } catch (Exception ignored) { }
                }
            }
        };
    }
}
