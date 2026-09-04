package dev.phonevault.signer;

/**
 * One independent entropy source contributing to seed generation.
 *
 * <p>Each source is pulled independently (entropy-design.md R2) and health-checked live at
 * generation time (R3/R4). Implementations MUST return fresh bytes on each {@link #draw} and MUST
 * NOT silently substitute a fallback (e.g. never quietly proxy the kernel pool when the caller
 * asked for the Titan M TRNG — that is the "present but not connected" ColdCard failure).
 */
interface EntropySource {

    /** Stable identifier shown on the diagnostics screen (R7), e.g. "kernel-getrandom", "titan-m". */
    String name();

    /**
     * If true, this source failing its health check aborts generation regardless of how many other
     * sources are healthy. If false, it may degrade (see {@code SeedVault} policy). The kernel
     * CSPRNG is required; belt-and-suspenders sources (jitter) are not.
     */
    boolean required();

    /**
     * Draw {@code numBytes} of fresh entropy. Must block until real entropy is available (never
     * return pre-seed / low-quality bytes) and must throw rather than return a stub on failure.
     */
    byte[] draw(int numBytes) throws Exception;
}
