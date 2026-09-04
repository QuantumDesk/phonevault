package dev.phonevault.signer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.Arrays;

/** The on-disk wallet record must round-trip exactly and reject every kind of damage. */
public class WalletRecordTest {
    private static final byte[] IV = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    private static final byte[] CT = new byte[97];
    static { for (int i = 0; i < CT.length; i++) CT[i] = (byte) (i * 7 + 3); }

    @Test public void roundTrip() {
        byte[] blob = new WalletRecord(IV, CT).encode();
        WalletRecord back = WalletRecord.decode(blob);
        assertArrayEquals(IV, back.iv);
        assertArrayEquals(CT, back.ciphertext);
        assertTrue(back.sameAs(new WalletRecord(IV, CT)));
        assertArrayEquals("encoding is deterministic", blob, back.encode());
    }

    @Test public void everySingleBitFlipIsDetected() {
        byte[] blob = new WalletRecord(IV, CT).encode();
        for (int i = 0; i < blob.length; i++) {
            byte[] damaged = blob.clone();
            damaged[i] ^= 1;
            try {
                WalletRecord.decode(damaged);
                fail("bit flip at byte " + i + " was not detected");
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
    }

    @Test public void truncationAndTrailingDataAreRejected() {
        byte[] blob = new WalletRecord(IV, CT).encode();
        for (int cut = 1; cut <= 40; cut++) {
            try {
                WalletRecord.decode(Arrays.copyOf(blob, blob.length - cut));
                fail("truncated by " + cut);
            } catch (IllegalArgumentException expected) { /* ok */ }
        }
        try {
            WalletRecord.decode(Arrays.copyOf(blob, blob.length + 1));
            fail("trailing byte accepted");
        } catch (IllegalArgumentException expected) { /* ok */ }
        try {
            WalletRecord.decode(new byte[0]);
            fail("empty accepted");
        } catch (IllegalArgumentException expected) { /* ok */ }
    }

    @Test public void differentRecordsAreNotSame() {
        WalletRecord a = new WalletRecord(IV, CT);
        byte[] ct2 = CT.clone();
        ct2[5] ^= 0x10;
        assertTrue(!a.sameAs(new WalletRecord(IV, ct2)));
        assertTrue(!a.sameAs(null));
    }
}
