package dev.phonevault.signer;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The durability policy for the wallet record, independent of Android so it is fault-injected
 * in unit tests.
 *
 * <h3>Invariants</h3>
 * <ul>
 *   <li>The active identity is whatever {@link WalletRecord} verifies from disk. Nothing else.</li>
 *   <li>A write is journaled ({@code write_pending}) BEFORE it starts and settled only after the
 *       record has been read back and compared byte-for-byte.</li>
 *   <li>Settling = one atomic flag commit that removes the legacy two-key wallet, clears the
 *       journal and sets a permanent {@code v3_established} marker — and the commit result is
 *       checked and read back. If it cannot be proven, the write is reported as
 *       {@link PersistenceException} and the journal stays pending.</li>
 *   <li>Once {@code v3_established} is set, the legacy preference wallet is never consulted again:
 *       a missing record is "sealed", never "create a fresh wallet" and never "fall back".</li>
 *   <li>Only a verified {@link #erase()} clears the marker and re-allows creation.</li>
 * </ul>
 */
final class WalletPersistence {
    /** Legacy (pre-record) storage, migrated on first load. */
    static final String LEGACY_ENCRYPTED_MNEMONIC = "encrypted_mnemonic_v2";
    static final String LEGACY_IV = "mnemonic_iv_v2";
    /** Journal flag: a record write was started and not yet verified + settled. */
    static final String WRITE_PENDING = "wallet_write_pending_v3";
    /** Permanent marker: the single-record format is the only source of truth from now on. */
    static final String V3_ESTABLISHED = "wallet_v3_established";

    /** Durable state is uncertain (write, fsync, rename, read-back or settle failed). */
    static final class PersistenceException extends Exception {
        PersistenceException(String message, Throwable cause) { super(message, cause); }
        PersistenceException(String message) { super(message); }
    }

    private final WalletStorage storage;

    WalletPersistence(WalletStorage storage) {
        this.storage = storage;
    }

    /**
     * The active record, or {@code null} if there is none AND creating one is allowed. Any
     * "I don't know" state throws.
     */
    WalletRecord load() throws PersistenceException {
        WalletRecord record = readRecord();
        if (record != null) {
            settle(); // a verifiable record on disk IS the identity; make the flags agree
            return record;
        }
        if (storage.getBooleanFlag(V3_ESTABLISHED)) {
            throw new PersistenceException("wallet storage is sealed: the wallet record is missing "
                    + "but a wallet was established; refusing to create or fall back");
        }
        if (storage.getBooleanFlag(WRITE_PENDING)) {
            throw new PersistenceException("wallet storage is sealed: a write was interrupted and no "
                    + "verifiable wallet record exists; refusing to generate a new wallet");
        }
        String legacyCiphertext = storage.getFlag(LEGACY_ENCRYPTED_MNEMONIC);
        String legacyIv = storage.getFlag(LEGACY_IV);
        if ((legacyCiphertext == null) != (legacyIv == null)) {
            throw new PersistenceException("legacy seed storage is incomplete; refusing to guess");
        }
        if (legacyCiphertext == null) return null; // genuinely empty: creation allowed
        WalletRecord migrated = new WalletRecord(hex(legacyIv), hex(legacyCiphertext));
        store(migrated); // durable + verified + settled before the legacy keys are gone
        return migrated;
    }

    /** True when {@link #load()} returned null: no record, no journal, no marker, no legacy. */
    boolean creationAllowed() {
        return !storage.blobExists() && !storage.getBooleanFlag(V3_ESTABLISHED)
                && !storage.getBooleanFlag(WRITE_PENDING)
                && storage.getFlag(LEGACY_ENCRYPTED_MNEMONIC) == null;
    }

    /** Journal → atomic write → read back → compare → settle. Throws if any step is unproven. */
    void store(WalletRecord record) throws PersistenceException {
        if (!commit(map(WRITE_PENDING, Boolean.TRUE), Collections.emptySet())
                || !storage.getBooleanFlag(WRITE_PENDING)) {
            throw new PersistenceException("could not journal the wallet write");
        }
        byte[] encoded = record.encode();
        try {
            storage.writeBlobAtomically(encoded);
        } catch (IOException failure) {
            throw new PersistenceException("wallet record write failed", failure);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
        WalletRecord readBack = readRecord();
        if (readBack == null || !readBack.sameAs(record)) {
            throw new PersistenceException("wallet record read-back does not match what was written");
        }
        settle();
    }

    /**
     * The identity is established: remove the legacy wallet, clear the journal, set the permanent
     * marker — atomically — and PROVE it by reading the flags back. Idempotent.
     */
    private void settle() throws PersistenceException {
        boolean alreadySettled = storage.getBooleanFlag(V3_ESTABLISHED)
                && !storage.getBooleanFlag(WRITE_PENDING)
                && storage.getFlag(LEGACY_ENCRYPTED_MNEMONIC) == null
                && storage.getFlag(LEGACY_IV) == null;
        if (alreadySettled) return;
        Set<String> removes = new HashSet<>(Arrays.asList(LEGACY_ENCRYPTED_MNEMONIC, LEGACY_IV, WRITE_PENDING));
        boolean committed = commit(map(V3_ESTABLISHED, Boolean.TRUE), removes);
        boolean proven = storage.getBooleanFlag(V3_ESTABLISHED)
                && !storage.getBooleanFlag(WRITE_PENDING)
                && storage.getFlag(LEGACY_ENCRYPTED_MNEMONIC) == null
                && storage.getFlag(LEGACY_IV) == null;
        if (!committed || !proven) {
            throw new PersistenceException("wallet identity could not be settled (legacy cleanup / "
                    + "journal / marker commit failed); storage stays journaled");
        }
    }

    /**
     * Destroy the record, the legacy keys and every flag, and prove each is gone. Clears the
     * v3 marker so a fresh wallet may be created afterwards.
     */
    void erase() throws PersistenceException {
        try {
            storage.deleteBlob();
        } catch (IOException failure) {
            throw new PersistenceException("wallet record could not be deleted", failure);
        }
        Set<String> removes = new HashSet<>(Arrays.asList(
                LEGACY_ENCRYPTED_MNEMONIC, LEGACY_IV, WRITE_PENDING, V3_ESTABLISHED));
        boolean committed = commit(Collections.emptyMap(), removes);
        boolean gone = !storage.blobExists()
                && storage.getFlag(LEGACY_ENCRYPTED_MNEMONIC) == null
                && storage.getFlag(LEGACY_IV) == null
                && !storage.getBooleanFlag(WRITE_PENDING)
                && !storage.getBooleanFlag(V3_ESTABLISHED);
        if (!committed || !gone) {
            throw new PersistenceException("erase could not be verified (committed=" + committed
                    + ", gone=" + gone + ")");
        }
    }

    /** Strict read: absent → null; present-but-invalid → throws (the identity must not be guessed). */
    private WalletRecord readRecord() throws PersistenceException {
        byte[] blob;
        try {
            blob = storage.readBlob();
        } catch (IOException failure) {
            throw new PersistenceException("wallet record unreadable", failure);
        }
        if (blob == null) return null;
        try {
            return WalletRecord.decode(blob);
        } catch (IllegalArgumentException corrupt) {
            throw new PersistenceException("wallet record corrupt: " + corrupt.getMessage(), corrupt);
        } finally {
            Arrays.fill(blob, (byte) 0);
        }
    }

    private boolean commit(Map<String, Object> puts, Set<String> removes) {
        return storage.commitFlags(puts, removes);
    }

    private static Map<String, Object> map(String key, Object value) {
        Map<String, Object> m = new HashMap<>();
        m.put(key, value);
        return m;
    }

    private static byte[] hex(String value) {
        return org.web3j.utils.Numeric.hexStringToByteArray(value);
    }
}
