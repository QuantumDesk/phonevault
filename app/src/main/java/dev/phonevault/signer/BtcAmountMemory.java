package dev.phonevault.signer;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The amount and script of every coin this phone has signed for since the app started (memory
 * only, bounded). A PSBT that later claims a DIFFERENT amount or script for the same coin is
 * refused.
 *
 * <p>Why: a SegWit v0 (BIP-143) signature commits to the amount of the input it signs, so a host
 * lying about that input's amount only gets an invalid signature. But it does not commit to the
 * OTHER inputs' amounts: a host can ask for two signatures over the same coins, each time lying
 * about a different input, and combine the two valid halves into a transaction whose real fee is
 * far larger than either review showed (the 2020 "SegWit fee attack"). Taproot (BIP-341) closes
 * this by committing every signature to all spent amounts and scripts. For SegWit v0 coins the
 * phone REQUIRES the non-witness UTXO (BtcPsbtReview refuses an input without it) and checks it
 * against the outpoint and the witness UTXO; this memory is a second line that catches the second
 * session of the attack while the app runs.
 */
final class BtcAmountMemory {
    static final int MAX_ENTRIES = 10_000;

    private final Map<String, String> seen = new LinkedHashMap<String, String>(64, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, String> eldest) { return size() > MAX_ENTRIES; }
    };

    private static String value(long amount, byte[] script) { return amount + ":" + BtcCrypto.hex(script); }

    /** A description of the conflict, or null when the coin is new or matches what was signed. */
    synchronized String conflict(String outpoint, long amount, byte[] script) {
        String before = seen.get(outpoint);
        if (before == null || before.equals(value(amount, script))) return null;
        long was = Long.parseLong(before.substring(0, before.indexOf(':')));
        return "this coin was signed earlier as worth " + BtcPsbtReview.sats(was) + ", now it is claimed as "
                + BtcPsbtReview.sats(amount) + (was == amount ? " with a different script" : "");
    }

    synchronized void record(String outpoint, long amount, byte[] script) { seen.put(outpoint, value(amount, script)); }
}
