package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * Proof tests from the 2026-10-13 adversarial audit of Bitcoin signing. Each test first demonstrated
 * a gap against the code of the time; the gaps are fixed and the tests now assert the fixed
 * behaviour on the same vectors.
 */
public final class BtcAuditProofTest {

    private static boolean anyWarningOrDanger(BtcPsbtReview r) {
        for (MessageReview.Row row : r.summary) {
            if (row.label.equals(MessageReview.WARNING) || row.label.equals(MessageReview.DANGER)) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ F1: change far past any gap limit
    //
    // The phone used to show "Change back to your wallet ✓" (no warning) for /1/i up to max(1000,
    // highest spent index + 1000). The companion's own scanner (scan.rs GAP = 20) and standard recovery
    // wallets stop 20 unused addresses past the last used one, so such change is invisible to them.
    // An untrusted Esplora can push the companion's change index there (see scan.rs test
    // lying_server_pushes_change_index_far_past_the_gap_limit). Now ✓ only within the gap limit.

    @Test public void changeFarPastTheGapLimitIsWarned() throws Exception {
        Psbt p = BtcPsbtTest.psbt(BtcPsbtTest.fixture("p2wpkh-send-with-change")); // spends /0/0 and /0/1
        BtcPsbtReview r = BtcPsbtTest.review(BtcPsbtTest.ownOutput(p, 1, BtcWallet.Type.P2WPKH, 0, 1, 900), BtcNetwork.BITCOIN);
        assertFalse("index 900 is not verified change", r.outputs.get(1).change);
        assertTrue(r.outputs.get(1).ownElsewhere);
        assertNull(BtcPsbtTest.value(r, "Change back to your wallet ✓"));
        assertTrue(BtcPsbtTest.has(r, MessageReview.WARNING, "m/84'/0'/0'/1/900, which your wallet app may not show "
                + "(it is far beyond the addresses your wallet app scans (gap limit))"));
        // the same for an own receive address of an account the PSBT does not spend from
        BtcPsbtReview recv = BtcPsbtTest.review(BtcPsbtTest.ownOutput(p, 1, BtcWallet.Type.P2WPKH, 19, 0, 999), BtcNetwork.BITCOIN);
        assertFalse(recv.outputs.get(1).ownReceive);
        assertNull(BtcPsbtTest.value(recv, "Your own address ✓"));
        assertTrue(BtcPsbtTest.has(recv, MessageReview.WARNING, "m/84'/0'/19'/0/999, which your wallet app may not show (it is far beyond"));
    }

    // ------------------------------------------------------------------ F2: relative lock time (BIP-68)

    private static Psbt withSequences(Psbt p, long version, long sequence) {
        BtcPsbtTest.Maps m = new BtcPsbtTest.Maps(p);
        List<BtcTx.Input> ins = new ArrayList<>();
        for (BtcTx.Input in : p.tx.inputs) ins.add(new BtcTx.Input(in.prevTxid, in.vout, in.scriptSig, sequence));
        m.tx(new BtcTx(version, ins, new ArrayList<>(p.tx.outputs), 0, false));
        return m.parse();
    }

    @Test public void relativeTimeLocksAreWarned() throws Exception {
        Psbt p = BtcPsbtTest.psbt(BtcPsbtTest.fixture("p2wpkh-send-with-change"));
        // version 2, nSequence 0x0000ffff: BIP-68 height lock of 65,535 blocks (~455 days) after each coin confirms
        Psbt blocks = withSequences(p, 2, 0x0000ffffL);
        assertEquals("Input 1 can't be mined until 65,535 blocks (about 455 days) after the coin it spends was confirmed "
                + "(a relative lock time, BIP-68). Sign only if you meant to delay it.", BtcPsbtReview.relativeLockWarning(blocks.tx));
        assertTrue(BtcPsbtTest.has(BtcPsbtTest.review(blocks, BtcNetwork.BITCOIN), MessageReview.WARNING, "relative lock time"));
        // nSequence 0x0040ffff: BIP-68 time lock of 65,535 × 512 s (~388 days)
        BtcPsbtReview rt = BtcPsbtTest.review(withSequences(p, 2, 0x0040ffffL), BtcNetwork.BITCOIN);
        assertTrue(BtcPsbtTest.has(rt, MessageReview.WARNING, "can't be mined until about 388 days after"));
        // a week or less is not warned: 1008 blocks, 1181 × 512 s
        assertNull(BtcPsbtReview.relativeLockWarning(withSequences(p, 2, 1008).tx));
        assertNotNull(BtcPsbtReview.relativeLockWarning(withSequences(p, 2, 1009).tx));
        assertNull(BtcPsbtReview.relativeLockWarning(withSequences(p, 2, (1L << 22) | 1181).tx));
        assertNotNull(BtcPsbtReview.relativeLockWarning(withSequences(p, 2, (1L << 22) | 1182).tx));
        // not enforced: version 1, the disable bit, RBF / final sequences
        assertNull(BtcPsbtReview.relativeLockWarning(withSequences(p, 1, 0x0000ffffL).tx));
        assertNull(BtcPsbtReview.relativeLockWarning(withSequences(p, 2, (1L << 31) | 0xffff).tx));
        for (long seq : new long[] {0xfffffffdL, 0xfffffffeL, 0xffffffffL}) {
            BtcPsbtReview ok = BtcPsbtTest.review(withSequences(p, 2, seq), BtcNetwork.BITCOIN);
            assertFalse(Long.toHexString(seq), anyWarningOrDanger(ok));
        }
    }

    // ------------------------------------------------------------------ F3: amount memory poisoned by a Taproot lie

    @Test public void aTaprootAmountLieIsNotRememberedSoTheHonestPsbtStillSigns() throws Exception {
        Psbt honest = BtcPsbtTest.psbt(BtcPsbtTest.fixture("p2tr-send-with-change"));
        BtcAmountMemory memory = new BtcAmountMemory();
        BtcTx.Output real = Psbt.witnessUtxo(Psbt.find(honest.inputs.get(0), Psbt.IN_WITNESS_UTXO).value);
        BtcPsbtTest.Maps lie = new BtcPsbtTest.Maps(honest);
        lie.replace(lie.in.get(0), Psbt.IN_WITNESS_UTXO,
                Psbt.entry(Psbt.IN_WITNESS_UTXO, new byte[0], BtcPsbtTest.witnessUtxo(real.value + 1_000_000, real.script)));
        // Taproot needs no previous transaction, so the lie is reviewed (its signature is useless on chain)...
        BtcPsbtReview r = BtcPsbtReview.build(lie.parse(), BtcNetwork.BITCOIN, BtcKeysTest.wallet(BtcNetwork.BITCOIN), null, memory);
        // ...but its amount is unproven, so the phone does not remember it (as MainActivity records after signing)
        for (BtcPsbtReview.SignInput in : r.inputs) {
            assertFalse(in.amountProven);
            if (in.amountProven) memory.record(r.psbt.tx.inputs.get(in.index).outpoint(), in.amount, in.script);
        }
        // ...and the TRUE amount is still reviewed afterwards
        BtcPsbtReview ok = BtcPsbtReview.build(honest, BtcNetwork.BITCOIN, BtcKeysTest.wallet(BtcNetwork.BITCOIN), null, memory);
        assertEquals(real.value, ok.inputs.get(0).amount);
        // SegWit v0 inputs always carry their verified previous transaction: proven, remembered
        BtcPsbtReview segwit = BtcPsbtTest.review(BtcPsbtTest.psbt(BtcPsbtTest.fixture("p2wpkh-send-with-change")), BtcNetwork.BITCOIN);
        for (BtcPsbtReview.SignInput in : segwit.inputs) assertTrue(in.amountProven);
    }

    // ------------------------------------------------------------------ F4: tip estimate drift widens the silent window

    @Test public void heightLocksAboutAWeekPastTheRealTipAreWarned() throws Exception {
        Psbt p = BtcPsbtTest.psbt(BtcPsbtTest.fixture("p2wpkh-send-with-change"));
        long now = 1_791_900_000L; // 2026-10-13
        long estimated = BtcPsbtReview.estimatedTip(BtcNetwork.BITCOIN, now);
        long realAt586 = BtcPsbtReview.MAIN_ANCHOR_HEIGHT + (now - BtcPsbtReview.MAIN_ANCHOR_TIME) / 586;
        long lock = estimated + BtcPsbtReview.LOCK_WARN_BLOCKS; // the largest lock that is not warned
        assertNull(BtcPsbtReview.lockTimeWarning(withLock(p, lock).tx, BtcNetwork.BITCOIN, now));
        assertNotNull(BtcPsbtReview.lockTimeWarning(withLock(p, lock + 1).tx, BtcNetwork.BITCOIN, now));
        long daysAhead = (lock - realAt586) * 586 / 86_400;
        assertTrue("silent lock is " + daysAhead + " days past a 586 s/block tip", daysAhead <= 8);
        // an honest anti-fee-sniping lock at the real tip (586 s, or even 582 s, blocks) is never warned
        long realAt582 = BtcPsbtReview.MAIN_ANCHOR_HEIGHT + (now - BtcPsbtReview.MAIN_ANCHOR_TIME) / 582;
        assertNull(BtcPsbtReview.lockTimeWarning(withLock(p, realAt586).tx, BtcNetwork.BITCOIN, now));
        assertNull(BtcPsbtReview.lockTimeWarning(withLock(p, realAt582).tx, BtcNetwork.BITCOIN, now));
        // and the window stays about a week a few years on
        long y2029 = 1_893_456_000L;
        long silent2029 = BtcPsbtReview.estimatedTip(BtcNetwork.BITCOIN, y2029) + BtcPsbtReview.LOCK_WARN_BLOCKS
                - (BtcPsbtReview.MAIN_ANCHOR_HEIGHT + (y2029 - BtcPsbtReview.MAIN_ANCHOR_TIME) / 586);
        assertTrue("2029: " + silent2029 + " blocks", silent2029 * 586 / 86_400 <= 8);
    }

    private static Psbt withLock(Psbt p, long lock) {
        BtcPsbtTest.Maps m = new BtcPsbtTest.Maps(p);
        List<BtcTx.Input> ins = new ArrayList<>();
        for (BtcTx.Input in : p.tx.inputs) ins.add(new BtcTx.Input(in.prevTxid, in.vout, in.scriptSig, 0xfffffffdL));
        m.tx(new BtcTx(2, ins, new ArrayList<>(p.tx.outputs), lock, false));
        return m.parse();
    }
}
