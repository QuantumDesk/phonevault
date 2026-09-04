package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.web3j.crypto.MnemonicUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Proves the entropy mix, BIP39, and BIP44 derivation are deterministic and auditable (R7), and
 * that the fail-loud policy (R4) actually refuses weak inputs.
 */
public class SeedVaultTest {

    /**
     * A deterministic source (for test vectors). Each draw is a varied byte pattern derived from
     * the next seed in the list (the last seed repeats), at whatever length is requested — so the
     * health-sample draw ({@link SeedVault#HEALTH_SAMPLE_BYTES}) passes RCT/APT/distribution and
     * the two liveness draws differ unless the seeds are identical.
     */
    private static final class FixedSource implements EntropySource {
        private final String name;
        private final boolean required;
        private final List<Integer> seeds;
        private int index;
        int draws;

        FixedSource(String name, boolean required, Integer... seeds) {
            this.name = name;
            this.required = required;
            this.seeds = new ArrayList<>(Arrays.asList(seeds));
        }

        public String name() { return name; }
        public boolean required() { return required; }
        public byte[] draw(int numBytes) {
            int seed = seeds.get(Math.min(index, seeds.size() - 1));
            index++;
            draws++;
            return filled(seed, numBytes);
        }
    }

    private static byte[] filled(int b, int length) {
        byte[] out = new byte[length];
        // a per-index varied pattern so RCT/APT/distribution pass and successive draws differ
        for (int i = 0; i < out.length; i++) out[i] = (byte) ((b * 31 + i * 7) & 0xFF);
        return out;
    }

    /** Seed order: health sample, liveness draw 1 (= contribution), liveness draw 2. */
    private List<EntropySource> twoHealthySources() {
        List<EntropySource> sources = new ArrayList<>();
        sources.add(new FixedSource("kernel-getrandom", true, 0, 1, 2));
        sources.add(new FixedSource("titan-m", false, 0, 3, 4));
        return sources;
    }

    @Test
    public void healthSampleIsLargeEnoughForEveryStartupTest() throws Exception {
        assertTrue("APT must get at least one full window",
                SeedVault.HEALTH_SAMPLE_BYTES >= HealthTests.APT_WINDOW);
        FixedSource k = new FixedSource("kernel-getrandom", true, 0, 1, 2);
        FixedSource t = new FixedSource("titan-m", false, 0, 3, 4);
        List<EntropySource> sources = new ArrayList<>();
        sources.add(k);
        sources.add(t);
        SeedVault.generate(sources, new byte[0], "", 0);
        assertEquals("health sample + two liveness draws", 3, k.draws);
        assertEquals(3, t.draws);
    }

    @Test
    public void collapsedSourceFailsTheAdaptiveProportionTest() {
        // A source whose health sample is dominated by one value: passes RCT (no long runs) but
        // must fail APT — the test that previously never executed.
        EntropySource collapsed = new EntropySource() {
            public String name() { return "kernel-getrandom"; }
            public boolean required() { return true; }
            public byte[] draw(int n) {
                byte[] out = new byte[n];
                for (int i = 0; i < n; i++) out[i] = (byte) (i % 3 == 0 ? (i & 0x7F) : 0x42);
                return out;
            }
        };
        List<EntropySource> sources = new ArrayList<>();
        sources.add(collapsed);
        sources.add(new FixedSource("titan-m", false, 0, 3, 4));
        try {
            SeedVault.generate(sources, "dice".getBytes(), "", 0);
            fail("expected the collapsed source to be rejected");
        } catch (Exception e) {
            assertTrue(e instanceof SeedVault.EntropyPolicyException);
            assertTrue(e.getMessage(), e.getMessage().contains("adaptive proportion"));
        }
    }

    @Test
    public void deterministicMixProducesStableMnemonicAndAddress() throws Exception {
        SeedVault.Generation g1 = SeedVault.generate(twoHealthySources(), new byte[0], "", 0);
        SeedVault.Generation g2 = SeedVault.generate(twoHealthySources(), new byte[0], "", 0);

        // Same inputs -> same 24-word mnemonic and same address (auditable, R7).
        assertEquals(g1.mnemonic, g2.mnemonic);
        assertEquals(g1.address, g2.address);
        assertEquals("must be a 24-word BIP39 mnemonic", 24, g1.mnemonic.split(" ").length);
        assertTrue(MnemonicUtils.validateMnemonic(g1.mnemonic));
        assertTrue(g1.address.matches("0x[0-9a-fA-F]{40}"));

        // Re-deriving from the backup mnemonic reproduces the same account (recovery path).
        assertEquals(g1.address,
                SeedVault.deriveEvm(g1.mnemonic, "", 0).getAddress());
        // A different account index yields a different address.
        assertFalse(g1.address.equals(SeedVault.deriveEvm(g1.mnemonic, "", 1).getAddress()));
        // A BIP39 passphrase changes the derived key (the "25th word").
        assertFalse(g1.address.equals(SeedVault.deriveEvm(g1.mnemonic, "hunter2", 0).getAddress()));
    }

    @Test
    public void everyHealthySourceChangesTheOutput() throws Exception {
        String withTitan = SeedVault.generate(twoHealthySources(), new byte[0], "", 0).mnemonic;

        List<EntropySource> onlyKernelPlusUser = new ArrayList<>();
        onlyKernelPlusUser.add(new FixedSource("kernel-getrandom", true, 0, 1, 2));
        String withoutTitan = SeedVault.generate(
                onlyKernelPlusUser, "dice-rolls".getBytes(), "", 0).mnemonic;

        // Dropping a contributing source must change the seed (proves it was actually mixed in).
        assertFalse(withTitan.equals(withoutTitan));
    }

    @Test
    public void userEntropyChangesTheOutput() throws Exception {
        String noUser = SeedVault.generate(twoHealthySources(), new byte[0], "", 0).mnemonic;
        String withUser = SeedVault.generate(twoHealthySources(), "123456".getBytes(), "", 0).mnemonic;
        assertFalse(noUser.equals(withUser));
    }

    @Test
    public void singleHealthySourceRequiresUserEntropy() {
        List<EntropySource> one = new ArrayList<>();
        one.add(new FixedSource("kernel-getrandom", true, 0, 1, 2));
        try {
            SeedVault.generate(one, new byte[0], "", 0);
            fail("expected policy to refuse one source with no user entropy");
        } catch (Exception e) {
            assertTrue(e instanceof SeedVault.EntropyPolicyException);
        }
    }

    @Test
    public void requiredSourceStuckAbortsGeneration() {
        List<EntropySource> sources = new ArrayList<>();
        // healthy-looking sample, then two IDENTICAL liveness draws (stuck source)
        sources.add(new FixedSource("kernel-getrandom", true, 0, 9, 9));
        sources.add(new FixedSource("titan-m", false, 0, 3, 4));
        try {
            SeedVault.generate(sources, "dice".getBytes(), "", 0);
            fail("expected required stuck source to abort");
        } catch (Exception e) {
            assertTrue(e instanceof SeedVault.EntropyPolicyException);
            assertTrue(e.getMessage().contains("kernel-getrandom"));
        }
    }

    @Test
    public void healthTestsCatchStuckAndSkewedSources() {
        byte[] stuck = new byte[64]; // all zeros -> repetition + no distribution
        assertNotNull(HealthTests.startup(stuck));

        byte[] good = new byte[512];
        for (int i = 0; i < good.length; i++) good[i] = (byte) ((i * 131 + 17) & 0xFF);
        assertNull("varied output should pass startup tests", HealthTests.startup(good));
    }
}
