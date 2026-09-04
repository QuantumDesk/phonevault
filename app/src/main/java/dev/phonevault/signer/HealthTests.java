package dev.phonevault.signer;

/**
 * NIST SP 800-90B startup health tests (entropy-design.md R4) run on raw source output before it is
 * trusted. These catch stuck-at, constant, and grossly low-rate outputs — the "cold water from the
 * tap with nothing screaming" failure. Returns {@code null} when healthy, else a human-readable
 * reason. Operates over bytes (treated as 8-bit samples), which is coarse but the right backstop for
 * a startup check on a small window; per-source assurance still comes from mixing multiple sources.
 */
final class HealthTests {

    private HealthTests() {}

    /** Cutoff for the Repetition Count Test: a value repeating this many times in a row fails. */
    static final int RCT_CUTOFF = 12;
    /** Window and cutoff for the Adaptive Proportion Test over 8-bit samples. */
    static final int APT_WINDOW = 512;
    static final int APT_CUTOFF = 165; // conservative for 8-bit samples over a 512 window

    /** @return null if all startup tests pass, otherwise the first failure reason. */
    static String startup(byte[] samples) {
        if (samples == null || samples.length == 0) {
            return "no samples to health-test";
        }
        String rct = repetitionCount(samples);
        if (rct != null) return rct;
        String apt = adaptiveProportion(samples);
        if (apt != null) return apt;
        return distributionSanity(samples);
    }

    /** Repetition Count Test: fail if any single sample value repeats >= RCT_CUTOFF times in a row. */
    static String repetitionCount(byte[] samples) {
        int run = 1;
        for (int i = 1; i < samples.length; i++) {
            if (samples[i] == samples[i - 1]) {
                run++;
                if (run >= RCT_CUTOFF) {
                    return "repetition count test failed (value repeated " + run + " times)";
                }
            } else {
                run = 1;
            }
        }
        return null;
    }

    /**
     * Adaptive Proportion Test: within each window, fix the first sample and count matches; fail if
     * a value dominates the window beyond the cutoff (indicates collapsed entropy).
     */
    static String adaptiveProportion(byte[] samples) {
        for (int start = 0; start + APT_WINDOW <= samples.length; start += APT_WINDOW) {
            byte reference = samples[start];
            int matches = 1;
            for (int i = start + 1; i < start + APT_WINDOW; i++) {
                if (samples[i] == reference) matches++;
            }
            if (matches >= APT_CUTOFF) {
                return "adaptive proportion test failed (value seen " + matches
                        + " times in a " + APT_WINDOW + "-sample window)";
            }
        }
        return null;
    }

    /**
     * Coarse distribution backstop: on windows large enough to expect coverage, require a minimum
     * number of distinct byte values so an obviously skewed source is rejected.
     */
    static String distributionSanity(byte[] samples) {
        if (samples.length < 64) return null; // too small to judge; RCT/APT already ran
        boolean[] seen = new boolean[256];
        int distinct = 0;
        for (byte b : samples) {
            int v = b & 0xFF;
            if (!seen[v]) {
                seen[v] = true;
                distinct++;
            }
        }
        int required = Math.min(32, samples.length / 4);
        if (distinct < required) {
            return "distribution sanity failed (only " + distinct
                    + " distinct byte values in " + samples.length + " samples)";
        }
        return null;
    }
}
