package dev.phonevault.signer;

import org.web3j.crypto.Bip32ECKeyPair;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.MnemonicUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Entropy-design-compliant BIP39 seed generation (see vault-os/docs/entropy-design.md).
 *
 * <p>The seed is a SHA-512 hash-combine of independent, health-checked sources (R1/R5), producing a
 * 256-bit value -> a 24-word BIP39 mnemonic (exportable backup) -> the EVM key at m/44'/60'/0'/0/index
 * (BIP32/44). No single source is load-bearing: any one healthy input yields a safe output. This
 * replaces the previous single-source {@code Keys.createEcKeyPair(new SecureRandom())}.
 */
final class SeedVault {

    /** Domain separation constant folded into every mix (R1). */
    static final byte[] DOMAIN = "vault-os/seed/v1".getBytes(StandardCharsets.US_ASCII);
    /** Bytes drawn from each source and mixed in at full width (R5: equal cryptographic weight). */
    static final int SOURCE_BYTES = 32;
    /** BIP39 entropy width: 32 bytes -> 24 words. */
    static final int ENTROPY_BYTES = 32;
    /**
     * Bytes drawn per source purely for the startup health tests: two full Adaptive Proportion
     * Test windows ({@link HealthTests#APT_WINDOW}), so RCT, APT and the distribution check all
     * actually execute. (Previously only 2×32 bytes were checked, so the APT never ran.) These
     * bytes are discarded after the check; the mix uses a separate {@link #SOURCE_BYTES} draw.
     *
     * <p>Honesty note: both device sources emit *conditioned* output (kernel CSPRNG; SHA-256 over
     * jitter deltas). These tests are therefore a stuck/collapsed-source backstop, not an
     * SP 800-90B raw-noise entropy assessment — see entropy-design.md status.
     */
    static final int HEALTH_SAMPLE_BYTES = 2 * HealthTests.APT_WINDOW;
    private static final int HARDENED = Bip32ECKeyPair.HARDENED_BIT;

    private SeedVault() {}

    /**
     * Outcome of a single source's liveness + health check (R3/R4), surfaced for diagnostics (R7).
     * Status only: the bytes a source contributed are zeroed as soon as they are mixed, so a report
     * retained for a diagnostics screen can never help reconstruct the seed.
     */
    static final class SourceReport {
        final String name;
        final boolean required;
        final boolean live;      // two successive draws differed and the call actually returned bytes
        final boolean healthy;   // live AND passed the NIST 800-90B startup tests
        final String detail;

        SourceReport(String name, boolean required, boolean live, boolean healthy, String detail) {
            this.name = name;
            this.required = required;
            this.live = live;
            this.healthy = healthy;
            this.detail = detail;
        }
    }

    /** A report plus the (short-lived) bytes behind it. Never escapes {@link #generate}. */
    private static final class Checked {
        final SourceReport report;
        final byte[] bytes; // null unless healthy
        Checked(SourceReport report, byte[] bytes) { this.report = report; this.bytes = bytes; }
    }

    /**
     * Result of a generation: the backup mnemonic, derived address, and per-source diagnostics.
     * The raw 32-byte entropy is NOT retained — the mnemonic is its only representation.
     */
    static final class Generation {
        final String mnemonic;      // 24 words — the user's backup
        final String address;       // derived EVM address (checksummed by Credentials)
        final List<SourceReport> reports;
        // No Credentials are retained: the key is re-derived from the mnemonic at commit time,
        // so a discarded candidate leaves no private key object behind.

        Generation(String mnemonic, String address, List<SourceReport> reports) {
            this.mnemonic = mnemonic;
            this.address = address;
            this.reports = Collections.unmodifiableList(reports);
        }
    }

    /** Thrown when the fail-loud policy (R4) refuses to emit a seed. */
    static final class EntropyPolicyException extends Exception {
        EntropyPolicyException(String message) { super(message); }
    }

    /**
     * Generate a seed by mixing the given sources plus optional user entropy (dice / passphrase
     * material, R6). {@code userEntropy} may be empty. {@code passphrase} is the BIP39 passphrase
     * (may be empty). {@code accountIndex} selects m/44'/60'/0'/0/index.
     */
    static Generation generate(List<EntropySource> sources, byte[] userEntropy,
                               String passphrase, int accountIndex) throws Exception {
        if (sources == null || sources.isEmpty()) {
            throw new EntropyPolicyException("No entropy sources provided");
        }
        if (accountIndex < 0) throw new IllegalArgumentException("accountIndex must be >= 0");
        byte[] user = userEntropy == null ? new byte[0] : userEntropy;

        List<Checked> checked = new ArrayList<>();
        List<SourceReport> reports = new ArrayList<>();
        byte[] digest = null;
        byte[] entropy = null;
        try {
            int healthyCount = 0;
            for (EntropySource source : sources) {
                Checked c = checkSource(source);
                checked.add(c);
                reports.add(c.report);
                if (c.report.required && !c.report.healthy) {
                    throw new EntropyPolicyException(
                            "Required entropy source '" + c.report.name + "' failed: " + c.report.detail);
                }
                if (c.report.healthy) healthyCount++;
            }

            // Fail-loud policy (R4): >=2 healthy proceed; ==1 requires user entropy; 0 refuses.
            boolean hasUserEntropy = user.length > 0;
            if (healthyCount == 0) {
                throw new EntropyPolicyException(
                        "No entropy source passed its health check; refusing to generate a seed");
            }
            if (healthyCount == 1 && !hasUserEntropy) {
                throw new EntropyPolicyException(
                        "Only one entropy source is healthy; add dice/passphrase entropy before continuing");
            }

            // Mix (R5): SHA-512( DOMAIN || each healthy source's 32 bytes || user ) [:32].
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            sha512.update(DOMAIN);
            int mixed = 0;
            for (Checked c : checked) {
                if (c.report.healthy && c.bytes != null) {
                    sha512.update(c.bytes);
                    mixed++;
                }
            }
            sha512.update(user);
            if (mixed == 0) { // defensive; policy above already guarantees >=1
                throw new EntropyPolicyException("No healthy source contributed to the mix");
            }
            digest = sha512.digest();
            entropy = Arrays.copyOf(digest, ENTROPY_BYTES);

            String mnemonic = MnemonicUtils.generateMnemonic(entropy);
            String address = deriveEvm(mnemonic, passphrase == null ? "" : passphrase, accountIndex).getAddress();
            return new Generation(mnemonic, address, reports);
        } finally {
            // Zero every intermediate that could reconstruct the seed (R1/R5 hygiene).
            for (Checked c : checked) if (c.bytes != null) Arrays.fill(c.bytes, (byte) 0);
            if (digest != null) Arrays.fill(digest, (byte) 0);
            if (entropy != null) Arrays.fill(entropy, (byte) 0);
        }
    }

    /** Re-derive the EVM key for a backed-up mnemonic (recovery / additional accounts). */
    static Credentials deriveEvm(String mnemonic, String passphrase, int accountIndex) {
        if (!MnemonicUtils.validateMnemonic(mnemonic)) {
            throw new IllegalArgumentException("Invalid BIP39 mnemonic");
        }
        byte[] seed = MnemonicUtils.generateSeed(mnemonic, passphrase == null ? "" : passphrase);
        try {
            Bip32ECKeyPair master = Bip32ECKeyPair.generateKeyPair(seed);
            int[] path = {44 | HARDENED, 60 | HARDENED, 0 | HARDENED, 0, accountIndex};
            Bip32ECKeyPair derived = Bip32ECKeyPair.deriveKeyPair(master, path);
            return Credentials.create(derived);
        } finally {
            Arrays.fill(seed, (byte) 0); // the BIP39 seed; web3j keeps the private key as BigInteger
        }
    }

    /**
     * Liveness (R3) + NIST SP 800-90B startup health tests (R4) for one source. Draws two
     * independent samples; requires they differ and that the concatenation passes the Repetition
     * Count Test and Adaptive Proportion Test plus a coarse distribution sanity check.
     */
    private static Checked checkSource(EntropySource source) {
        String name = source.name();
        boolean required = source.required();
        byte[] health = null;
        byte[] first = null;
        byte[] second = null;
        boolean firstHandedOff = false; // only a healthy contribution leaves this method un-zeroed
        try {
            // 1. Startup health tests over a window large enough for every test to run.
            health = source.draw(HEALTH_SAMPLE_BYTES);
            if (health == null || health.length != HEALTH_SAMPLE_BYTES) {
                return new Checked(new SourceReport(name, required, false, false,
                        "source did not return " + HEALTH_SAMPLE_BYTES + " health-sample bytes"), null);
            }
            String healthFailure = HealthTests.startup(health);
            if (healthFailure != null) {
                return new Checked(new SourceReport(name, required, true, false, healthFailure), null);
            }
            // 2. Liveness: two fresh draws must differ; the first is the contribution.
            first = source.draw(SOURCE_BYTES);
            second = source.draw(SOURCE_BYTES);
            if (first == null || second == null
                    || first.length != SOURCE_BYTES || second.length != SOURCE_BYTES) {
                return new Checked(new SourceReport(name, required, false, false,
                        "source did not return " + SOURCE_BYTES + " bytes"), null);
            }
            if (Arrays.equals(first, second)) {
                return new Checked(new SourceReport(name, required, false, false,
                        "two successive draws were identical (stuck source)"), null);
            }
            firstHandedOff = true;
            return new Checked(new SourceReport(name, required, true, true,
                    "healthy (RCT/APT/distribution over " + HEALTH_SAMPLE_BYTES + " B)"), first);
        } catch (Exception exception) {
            return new Checked(new SourceReport(name, required, false, false,
                    "draw failed: " + exception.getMessage()), null);
        } finally {
            if (health != null) Arrays.fill(health, (byte) 0);
            if (second != null) Arrays.fill(second, (byte) 0);
            if (first != null && !firstHandedOff) Arrays.fill(first, (byte) 0);
        }
    }
}
