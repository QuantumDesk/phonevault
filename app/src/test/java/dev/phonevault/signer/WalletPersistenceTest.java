package dev.phonevault.signer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Fault injection at every persistence boundary: journal, write, rename, read-back, settle
 * (legacy cleanup + marker), restart reconciliation, migration, erase.
 */
public class WalletPersistenceTest {

    /** In-memory storage with switchable faults; "restart" = same maps, new WalletPersistence. */
    static final class FakeStorage implements WalletStorage {
        byte[] blob;
        final Map<String, Object> flags = new HashMap<>();
        boolean failWrite, failRead, failDelete, torn;
        int failCommitsRemaining; // next N commitFlags() return false (in-memory update still applied
        boolean commitAppliesEvenWhenFailing = true; // mirrors SharedPreferences: memory updated, disk not

        @Override public byte[] readBlob() throws IOException {
            if (failRead) throw new IOException("read fault");
            return blob == null ? null : blob.clone();
        }
        @Override public void writeBlobAtomically(byte[] b) throws IOException {
            if (failWrite) throw new IOException("write fault");
            if (torn) { blob = java.util.Arrays.copyOf(b, b.length - 3); return; } // rename of a bad temp
            blob = b.clone();
        }
        @Override public void deleteBlob() throws IOException {
            if (failDelete) throw new IOException("delete fault");
            blob = null;
        }
        @Override public boolean blobExists() { return blob != null; }
        @Override public String getFlag(String k) { Object v = flags.get(k); return v instanceof String ? (String) v : null; }
        @Override public boolean getBooleanFlag(String k) { Object v = flags.get(k); return v instanceof Boolean && (Boolean) v; }
        @Override public boolean commitFlags(Map<String, Object> puts, Set<String> removes) {
            boolean ok = failCommitsRemaining <= 0;
            if (!ok) failCommitsRemaining--;
            if (ok || commitAppliesEvenWhenFailing) {
                for (String r : removes) flags.remove(r);
                flags.putAll(puts);
            }
            return ok;
        }
    }

    private static WalletRecord record(int seed) {
        byte[] iv = new byte[12];
        byte[] ct = new byte[64];
        for (int i = 0; i < iv.length; i++) iv[i] = (byte) (seed + i);
        for (int i = 0; i < ct.length; i++) ct[i] = (byte) (seed * 3 + i);
        return new WalletRecord(iv, ct);
    }

    @Test public void emptyStorageAllowsCreationAndStoreSettles() throws Exception {
        FakeStorage s = new FakeStorage();
        WalletPersistence p = new WalletPersistence(s);
        assertNull(p.load());
        assertTrue(p.creationAllowed());
        p.store(record(1));
        assertTrue(record(1).sameAs(p.load()));
        assertTrue(s.getBooleanFlag(WalletPersistence.V3_ESTABLISHED));
        assertFalse(s.getBooleanFlag(WalletPersistence.WRITE_PENDING));
        assertFalse(p.creationAllowed());
    }

    @Test public void legacyWalletMigratesOnceAndLegacyKeysAreProvablyRemoved() throws Exception {
        FakeStorage s = new FakeStorage();
        s.flags.put(WalletPersistence.LEGACY_IV, "0102030405060708090a0b0c");
        s.flags.put(WalletPersistence.LEGACY_ENCRYPTED_MNEMONIC, "ff".repeat(48));
        WalletPersistence p = new WalletPersistence(s);
        WalletRecord migrated = p.load();
        assertNotNull(migrated);
        assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, migrated.iv);
        assertNull(s.getFlag(WalletPersistence.LEGACY_ENCRYPTED_MNEMONIC));
        assertNull(s.getFlag(WalletPersistence.LEGACY_IV));
        assertTrue(s.getBooleanFlag(WalletPersistence.V3_ESTABLISHED));
        assertTrue(s.blobExists());
    }

    @Test public void halfLegacyStorageIsRefusedNotGuessed() {
        FakeStorage s = new FakeStorage();
        s.flags.put(WalletPersistence.LEGACY_IV, "0102030405060708090a0b0c");
        try {
            new WalletPersistence(s).load();
            fail("must refuse incomplete legacy storage");
        } catch (WalletPersistence.PersistenceException expected) {
            assertTrue(expected.getMessage().contains("incomplete"));
        }
    }

    @Test public void writeFaultLeavesJournalPendingAndRestartIsSealed() throws Exception {
        FakeStorage s = new FakeStorage();
        WalletPersistence p = new WalletPersistence(s);
        s.failWrite = true;
        try {
            p.store(record(2));
            fail("write fault must surface");
        } catch (WalletPersistence.PersistenceException expected) { /* ok */ }
        assertTrue("journal must stay pending", s.getBooleanFlag(WalletPersistence.WRITE_PENDING));
        // "Restart": no record on disk, journal pending → sealed, never a fresh wallet.
        s.failWrite = false;
        WalletPersistence restarted = new WalletPersistence(s);
        try {
            restarted.load();
            fail("must be sealed");
        } catch (WalletPersistence.PersistenceException expected) {
            assertTrue(expected.getMessage().contains("sealed"));
        }
        assertFalse(restarted.creationAllowed());
    }

    @Test public void tornWriteFailsReadBackAndKeepsJournal() throws Exception {
        FakeStorage s = new FakeStorage();
        WalletPersistence p = new WalletPersistence(s);
        s.torn = true;
        try {
            p.store(record(3));
            fail("torn record must fail read-back");
        } catch (WalletPersistence.PersistenceException expected) {
            assertTrue(expected.getMessage().contains("corrupt") || expected.getMessage().contains("read-back"));
        }
        assertTrue(s.getBooleanFlag(WalletPersistence.WRITE_PENDING));
        // The corrupt blob on disk must never be accepted as an identity.
        try {
            new WalletPersistence(s).load();
            fail("corrupt record must not load");
        } catch (WalletPersistence.PersistenceException expected) { /* ok */ }
    }

    @Test public void restartAfterInterruptedWriteReconcilesFromTheValidRecord() throws Exception {
        // Journal pending but a valid record exists (process died after rename, before settle):
        // the record IS the identity; load settles the flags and proves it.
        FakeStorage s = new FakeStorage();
        s.blob = record(4).encode();
        s.flags.put(WalletPersistence.WRITE_PENDING, Boolean.TRUE);
        s.flags.put(WalletPersistence.LEGACY_IV, "0102030405060708090a0b0c");
        s.flags.put(WalletPersistence.LEGACY_ENCRYPTED_MNEMONIC, "ff".repeat(48));
        WalletPersistence p = new WalletPersistence(s);
        assertTrue(record(4).sameAs(p.load()));
        assertFalse(s.getBooleanFlag(WalletPersistence.WRITE_PENDING));
        assertNull("stale legacy wallet must be gone", s.getFlag(WalletPersistence.LEGACY_ENCRYPTED_MNEMONIC));
        assertTrue(s.getBooleanFlag(WalletPersistence.V3_ESTABLISHED));
    }

    @Test public void failedSettleIsReportedAndLegacyCannotResurrect() throws Exception {
        // The record is written fine but the cleanup commit fails. The write must
        // NOT be reported as success, the journal must stay pending, and after a restart in which
        // the record vanished, the legacy wallet must not come back.
        FakeStorage s = new FakeStorage();
        s.flags.put(WalletPersistence.LEGACY_IV, "0102030405060708090a0b0c");
        s.flags.put(WalletPersistence.LEGACY_ENCRYPTED_MNEMONIC, "ff".repeat(48));
        s.blob = record(5).encode(); // a v3 record already exists alongside stale legacy keys
        s.flags.put(WalletPersistence.WRITE_PENDING, Boolean.TRUE);
        s.commitAppliesEvenWhenFailing = false; // disk AND memory refuse the cleanup
        s.failCommitsRemaining = 1;
        WalletPersistence p = new WalletPersistence(s);
        try {
            p.load();
            fail("unsettled identity must not be reported as loaded");
        } catch (WalletPersistence.PersistenceException expected) {
            assertTrue(expected.getMessage().contains("settled"));
        }
        assertTrue(s.getBooleanFlag(WalletPersistence.WRITE_PENDING));
        // Storage healthy again → settles on the next load.
        assertTrue(record(5).sameAs(new WalletPersistence(s).load()));
        assertTrue(s.getBooleanFlag(WalletPersistence.V3_ESTABLISHED));
        assertNull(s.getFlag(WalletPersistence.LEGACY_ENCRYPTED_MNEMONIC));
        // Now the record disappears (disk damage): sealed, never legacy, never create.
        s.blob = null;
        try {
            new WalletPersistence(s).load();
            fail("must be sealed");
        } catch (WalletPersistence.PersistenceException expected) {
            assertTrue(expected.getMessage().contains("sealed"));
        }
        assertFalse(new WalletPersistence(s).creationAllowed());
    }

    @Test public void journalCommitFailureRefusesTheWriteBeforeAnythingTouchesDisk() throws Exception {
        // commit() returns false even though memory was updated (SharedPreferences semantics):
        // the flag reads back as set, but the commit result says the disk may not have it → refuse.
        FakeStorage s = new FakeStorage();
        WalletPersistence p = new WalletPersistence(s);
        s.failCommitsRemaining = 2; // journal commit fails first → store refuses before writing
        try {
            p.store(record(6));
            fail("journal commit failure must refuse the write");
        } catch (WalletPersistence.PersistenceException expected) {
            assertTrue(expected.getMessage().contains("journal"));
        }
        assertNull("nothing written without a durable journal", s.blob);
    }

    @Test public void replacementStoresNewRecordAndOldOneIsGone() throws Exception {
        FakeStorage s = new FakeStorage();
        WalletPersistence p = new WalletPersistence(s);
        p.store(record(7));
        p.store(record(8));
        assertTrue(record(8).sameAs(p.load()));
        assertFalse(record(7).sameAs(p.load()));
    }

    @Test public void eraseIsVerifiedAndReallowsCreation() throws Exception {
        FakeStorage s = new FakeStorage();
        WalletPersistence p = new WalletPersistence(s);
        p.store(record(9));
        p.erase();
        assertFalse(s.blobExists());
        assertFalse(s.getBooleanFlag(WalletPersistence.V3_ESTABLISHED));
        assertTrue(p.creationAllowed());
        assertNull(p.load());
        // Erase that cannot delete the record must throw (fail closed).
        p.store(record(10));
        s.failDelete = true;
        try {
            p.erase();
            fail("unverifiable erase must throw");
        } catch (WalletPersistence.PersistenceException expected) { /* ok */ }
        assertTrue(s.blobExists());
    }

    @Test public void readFaultIsNotTreatedAsAbsent() {
        FakeStorage s = new FakeStorage();
        s.failRead = true;
        try {
            new WalletPersistence(s).load();
            fail("an unreadable record must not look like 'no wallet'");
        } catch (WalletPersistence.PersistenceException expected) {
            assertEquals("wallet record unreadable", expected.getMessage());
        }
    }
}
