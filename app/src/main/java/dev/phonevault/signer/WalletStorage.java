package dev.phonevault.signer;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

/**
 * The raw durable primitives {@link WalletPersistence} builds on. Kept minimal and dumb so the
 * Android implementation is a thin shim and the JVM tests can inject faults at every boundary
 * (write, rename, read-back, flag commit, restart).
 */
interface WalletStorage {
    /** The record blob, or {@code null} if absent. Throws only on an I/O error. */
    byte[] readBlob() throws IOException;

    /** Atomic replace: write to a temp file, fsync, rename over the record. */
    void writeBlobAtomically(byte[] blob) throws IOException;

    /** Remove the record and any temp/backup the atomic writer keeps. */
    void deleteBlob() throws IOException;

    boolean blobExists();

    String getFlag(String key);

    boolean getBooleanFlag(String key);

    /**
     * One atomic in-memory update of the small flag store; returns whether it was made durable.
     * Values are {@code String} or {@code Boolean}.
     */
    boolean commitFlags(Map<String, Object> puts, Set<String> removes);
}
