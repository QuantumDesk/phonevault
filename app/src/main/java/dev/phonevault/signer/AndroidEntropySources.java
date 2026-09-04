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
 * <p>TODO (R2, independent Titan M): add a source that pulls raw bytes from the Titan M TRNG via a
 * StrongBox operation, so a second *hardware* source contributes independently of the kernel path.
 * Not a public one-call API on this Keymaster version — tracked in entropy-design.md open items.
 */
final class AndroidEntropySources {

    private AndroidEntropySources() {}

    static List<EntropySource> device() {
        List<EntropySource> sources = new ArrayList<>();
        sources.add(kernel());
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
}
