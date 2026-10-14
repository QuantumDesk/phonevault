package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * Proof tests from the 2026-10-13 adversarial audit of Bitcoin signing. Each test PASSES against
 * the current code and thereby demonstrates a gap (the assertions describe today's behaviour, not
 * the desired one). When a gap is fixed, flip the corresponding assertions.
 */
public final class BtcAuditProofTest {

    private static boolean anyWarningOrDanger(BtcPsbtReview r) {
        for (MessageReview.Row row : r.summary) {
            if (row.label.equals(MessageReview.WARNING) || row.label.equals(MessageReview.DANGER)) return true;
        }
        return false;
    }

    private static boolean summaryMentions(BtcPsbtReview r, String fragment) {
        for (MessageReview.Row row : r.summary) if (row.value.contains(fragment)) return true;
        return false;
    }

    // ------------------------------------------------------------------ F1: change far past any gap limit
    //
    // The phone shows "Change back to your wallet ✓" (no warning) for /1/i up to max(1000, highest
    // spent index + 1000). The companion's own scanner (scan.rs GAP = 20) and standard recovery
    // wallets stop 20 unused addresses past the last used one, so such change is invisible to them.
    // An untrusted Esplora can push the companion's change index there (see scan.rs test
    // lying_server_pushes_change_index_far_past_the_gap_limit).

    @Test public void changeFarPastTheGapLimitIsVerifiedChangeWithoutWarning() throws Exception {
        Psbt p = BtcPsbtTest.psbt(BtcPsbtTest.fixture("p2wpkh-send-with-change")); // spends /0/0 and /0/1
        BtcPsbtReview r = BtcPsbtTest.review(BtcPsbtTest.ownOutput(p, 1, BtcWallet.Type.P2WPKH, 0, 1, 900), BtcNetwork.BITCOIN);
        assertTrue("index 900 is accepted as change", r.outputs.get(1).change);
        assertFalse(r.outputs.get(1).ownElsewhere);
        assertNotNull(BtcPsbtTest.value(r, "Change back to your wallet ✓"));
        assertFalse("no WARNING/DANGER row although 880 unused change addresses precede it", anyWarningOrDanger(r));
        // the same for an own receive address of an account the PSBT does not spend from
        BtcPsbtReview recv = BtcPsbtTest.review(BtcPsbtTest.ownOutput(p, 1, BtcWallet.Type.P2WPKH, 19, 0, 999), BtcNetwork.BITCOIN);
        assertTrue(recv.outputs.get(1).ownReceive);
        assertTrue(BtcPsbtTest.has(recv, "Your own address ✓", "m/84'/0'/19'/0/999"));
        assertFalse(anyWarningOrDanger(recv));
    }

    // ------------------------------------------------------------------ F2: relative lock time (BIP-68) is never warned

    private static Psbt withSequences(Psbt p, long version, long sequence) {
        BtcPsbtTest.Maps m = new BtcPsbtTest.Maps(p);
        List<BtcTx.Input> ins = new ArrayList<>();
        for (BtcTx.Input in : p.tx.inputs) ins.add(new BtcTx.Input(in.prevTxid, in.vout, in.scriptSig, sequence));
        m.tx(new BtcTx(version, ins, new ArrayList<>(p.tx.outputs), 0, false));
        return m.parse();
    }

    @Test public void relativeTimeLocksBypassTheFarFutureLockWarning() throws Exception {
        Psbt p = BtcPsbtTest.psbt(BtcPsbtTest.fixture("p2wpkh-send-with-change"));
        long now = 1_791_900_000L;
        // version 2, nSequence 0x0000ffff: BIP-68 height lock of 65,535 blocks (~455 days) after each coin confirms
        Psbt blocks = withSequences(p, 2, 0x0000ffffL);
        assertNull(BtcPsbtReview.lockTimeWarning(blocks.tx, BtcNetwork.BITCOIN, now));
        BtcPsbtReview rb = BtcPsbtTest.review(blocks, BtcNetwork.BITCOIN);
        assertFalse(anyWarningOrDanger(rb));
        assertFalse(summaryMentions(rb, "lock"));
        // nSequence 0x0040ffff: BIP-68 time lock of 65,535 × 512 s (~388 days)
        BtcPsbtReview rt = BtcPsbtTest.review(withSequences(p, 2, 0x0040ffffL), BtcNetwork.BITCOIN);
        assertFalse(anyWarningOrDanger(rt));
        // the details only say "Replace-by-fee: Yes"; nothing mentions the relative lock
        for (MessageReview.Row row : rt.details) assertFalse(row.label + ": " + row.value, row.value.contains("relative"));
        // contrast: the equivalent absolute lock IS warned (the new rule)
        long tip = BtcPsbtReview.MAIN_ANCHOR_HEIGHT + (now - BtcPsbtReview.MAIN_ANCHOR_TIME) / BtcPsbtReview.MAIN_SECONDS_PER_BLOCK;
        BtcPsbtTest.Maps abs = new BtcPsbtTest.Maps(p);
        List<BtcTx.Input> ins = new ArrayList<>();
        for (BtcTx.Input in : p.tx.inputs) ins.add(new BtcTx.Input(in.prevTxid, in.vout, in.scriptSig, 0xfffffffdL));
        abs.tx(new BtcTx(2, ins, new ArrayList<>(p.tx.outputs), tip + 65_535, false));
        assertNotNull(BtcPsbtReview.lockTimeWarning(abs.parse().tx, BtcNetwork.BITCOIN, now));
    }

    // ------------------------------------------------------------------ F3: amount memory is poisoned by a Taproot lie

    @Test public void aTaprootAmountLieThatWasSignedBlocksTheHonestPsbtLater() throws Exception {
        Psbt honest = BtcPsbtTest.psbt(BtcPsbtTest.fixture("p2tr-send-with-change"));
        BtcAmountMemory memory = new BtcAmountMemory();
        BtcTx.Output real = Psbt.witnessUtxo(Psbt.find(honest.inputs.get(0), Psbt.IN_WITNESS_UTXO).value);
        BtcPsbtTest.Maps lie = new BtcPsbtTest.Maps(honest);
        lie.replace(lie.in.get(0), Psbt.IN_WITNESS_UTXO,
                Psbt.entry(Psbt.IN_WITNESS_UTXO, new byte[0], BtcPsbtTest.witnessUtxo(real.value + 1_000_000, real.script)));
        // Taproot needs no previous transaction, so the lie is reviewed (its signature is useless on chain)...
        BtcPsbtReview r = BtcPsbtReview.build(lie.parse(), BtcNetwork.BITCOIN, BtcKeysTest.wallet(BtcNetwork.BITCOIN), null, memory);
        for (BtcPsbtReview.SignInput in : r.inputs) memory.record(r.psbt.tx.inputs.get(in.index).outpoint(), in.amount, in.script);
        // ...and then the TRUE amount is refused as the "lie" until the app restarts
        try {
            BtcPsbtReview.build(honest, BtcNetwork.BITCOIN, BtcKeysTest.wallet(BtcNetwork.BITCOIN), null, memory);
            fail("honest PSBT should be refused by the poisoned memory");
        } catch (RequestRefusal e) {
            assertTrue(e.getMessage(), e.getMessage().contains("signed earlier as worth 3,000,000 sats, now it is claimed as 2,000,000 sats"));
        }
    }

    // ------------------------------------------------------------------ F4: tip estimate drift widens the silent window

    @Test public void heightLocksWeeksAheadOfTheRealTipAreNotWarned() throws Exception {
        Psbt p = BtcPsbtTest.psbt(BtcPsbtTest.fixture("p2wpkh-send-with-change"));
        long now = 1_791_900_000L; // 2026-10-13
        long estimated = BtcPsbtReview.MAIN_ANCHOR_HEIGHT + (now - BtcPsbtReview.MAIN_ANCHOR_TIME) / BtcPsbtReview.MAIN_SECONDS_PER_BLOCK;
        long realAt586 = BtcPsbtReview.MAIN_ANCHOR_HEIGHT + (now - BtcPsbtReview.MAIN_ANCHOR_TIME) / 586;
        long lock = estimated + BtcPsbtReview.LOCK_WARN_BLOCKS; // the largest lock that is not warned
        BtcPsbtTest.Maps m = new BtcPsbtTest.Maps(p);
        List<BtcTx.Input> ins = new ArrayList<>();
        for (BtcTx.Input in : p.tx.inputs) ins.add(new BtcTx.Input(in.prevTxid, in.vout, in.scriptSig, 0xfffffffdL));
        m.tx(new BtcTx(2, ins, new ArrayList<>(p.tx.outputs), lock, false));
        assertNull(BtcPsbtReview.lockTimeWarning(m.parse().tx, BtcNetwork.BITCOIN, now));
        long daysAhead = (lock - realAt586) * 586 / 86_400;
        assertTrue("silent lock is " + daysAhead + " days past a 586 s/block tip", daysAhead >= 16);
    }
}
