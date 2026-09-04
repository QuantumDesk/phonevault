package dev.phonevault.signer;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.AtomicFile;

import org.web3j.crypto.Credentials;
import org.web3j.utils.Numeric;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Generates a BIP39 seed via {@link SeedVault} and stores the mnemonic encrypted by a
 * non-exportable StrongBox-backed Android Keystore key. The EVM key is derived from the mnemonic
 * at m/44'/60'/0'/0/0; the 24-word backup is revealable for the user.
 *
 * <h3>Durability model</h3>
 * The wallet is ONE self-checking record ({@link WalletRecord}) in ONE file written with
 * {@link AtomicFile} (write temp → fsync → rename) and then read back from disk and compared.
 * Before a write starts, a {@code write_pending} journal flag is committed; it is cleared only
 * after the read-back matches. If the app dies or the write fails, the flag survives and
 * {@link #loadOrCreate()} refuses to generate a new wallet — it will only load a record that
 * decodes and verifies from disk. Callers must treat {@link PersistenceException} as
 * "the active identity is unknown until reconciled from disk" — never keep using the old
 * in-memory key.
 */
final class VaultKeyStore {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "phone-vault-wrapping-key-v1";
    private static final String PREFS = "vault";
    /** Legacy (pre-record) storage, migrated on first load. */
    private static final String LEGACY_ENCRYPTED_MNEMONIC = "encrypted_mnemonic_v2";
    private static final String LEGACY_IV = "mnemonic_iv_v2";
    /** Journal flag: a record write was started and not yet verified. */
    private static final String WRITE_PENDING = "wallet_write_pending_v3";
    private static final String RECORD_FILE = "wallet.pvw3";
    private static final int ACCOUNT_INDEX = 0;

    /** Durable state is uncertain (write, fsync, rename or read-back failed). */
    static final class PersistenceException extends Exception {
        PersistenceException(String message, Throwable cause) { super(message, cause); }
        PersistenceException(String message) { super(message); }
    }

    private final SharedPreferences preferences;
    private final File recordFile;
    private volatile List<SeedVault.SourceReport> lastReports;

    VaultKeyStore(Context context) {
        preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        recordFile = new File(context.getFilesDir(), RECORD_FILE);
    }

    /** True once a seed record exists (throws if the record is present but corrupt). */
    synchronized boolean hasWallet() throws Exception {
        return readRecordOrMigrate() != null;
    }

    /**
     * Load the wallet from durable storage, or generate one if — and only if — no record exists
     * and no write is pending. A pending write with no verifiable record means the identity is
     * unknown: refuse (sealed) rather than silently minting a fresh wallet over it.
     */
    synchronized Credentials loadOrCreate() throws Exception {
        ensureWrappingKey();
        enforceSecureHardwarePolicy();
        WalletRecord record = readRecordOrMigrate();
        if (record != null) {
            Credentials credentials = SeedVault.deriveEvm(decrypt(record), "", ACCOUNT_INDEX);
            clearWritePending(); // a verifiable record on disk IS the identity; the journal is settled
            return credentials;
        }
        if (preferences.getBoolean(WRITE_PENDING, false)) {
            throw new PersistenceException("wallet storage is sealed: a write was interrupted and no "
                    + "verifiable wallet record exists; refusing to generate a new wallet");
        }
        return generateAndStore(new byte[0]);
    }

    /** Authoritative identity from disk after an uncertain commit. Throws if none verifies. */
    synchronized Credentials reconcile() throws Exception {
        ensureWrappingKey();
        WalletRecord record = readRecordFromDisk();
        if (record == null) throw new PersistenceException("no verifiable wallet record on disk");
        Credentials credentials = SeedVault.deriveEvm(decrypt(record), "", ACCOUNT_INDEX);
        clearWritePending();
        return credentials;
    }

    /** Generate a fresh seed from device entropy (+ optional user entropy) and persist it. */
    synchronized Credentials generateAndStore(byte[] userEntropy) throws Exception {
        SeedVault.Generation generation = prepareReplacement(userEntropy);
        return commitReplacement(generation.mnemonic);
    }

    /** Phase 1: generate a candidate WITHOUT touching the stored wallet. */
    synchronized SeedVault.Generation prepareReplacement(byte[] userEntropy) throws Exception {
        ensureWrappingKey();
        enforceSecureHardwarePolicy();
        SeedVault.Generation generation = SeedVault.generate(
                AndroidEntropySources.device(), userEntropy, "", ACCOUNT_INDEX);
        lastReports = generation.reports;
        return generation;
    }

    /**
     * Phase 2: durably replace the stored wallet with the backed-up candidate. Returns the new
     * credentials only after the record has been read back from disk and verified. On
     * {@link PersistenceException} the caller must NOT assume either identity — reconcile.
     */
    synchronized Credentials commitReplacement(String mnemonic) throws Exception {
        ensureWrappingKey();
        enforceSecureHardwarePolicy();
        Credentials credentials = SeedVault.deriveEvm(mnemonic, "", ACCOUNT_INDEX);
        writeRecord(encrypt(mnemonic));
        return credentials;
    }

    /** Decrypt and return the 24-word backup for the reveal screen. Handle with care. */
    synchronized String revealMnemonic() throws Exception {
        ensureWrappingKey();
        WalletRecord record = readRecordOrMigrate();
        if (record == null) throw new IllegalStateException("No wallet to reveal");
        return decrypt(record);
    }

    List<SeedVault.SourceReport> lastGenerationReports() {
        return lastReports;
    }

    /**
     * Destroy the wallet: the record file (and AtomicFile's backup/temp), legacy preferences AND
     * the StrongBox wrapping alias. Verified, never assumed — an unverifiable erase throws so the
     * PIN gate stays shut (VaultPin.Outcome.ERASE_FAILED).
     */
    synchronized void secureErase() throws Exception {
        lastReports = null;
        new AtomicFile(recordFile).delete();
        boolean committed = preferences.edit()
                .remove(LEGACY_ENCRYPTED_MNEMONIC).remove(LEGACY_IV).remove(WRITE_PENDING).commit();
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS);
        keyStore.load(null);
        boolean fileGone = readRecordFromDiskLenient() == null && !recordFile.exists();
        boolean prefsGone = preferences.getString(LEGACY_ENCRYPTED_MNEMONIC, null) == null
                && preferences.getString(LEGACY_IV, null) == null;
        boolean aliasGone = !keyStore.containsAlias(KEY_ALIAS);
        if (!committed || !fileGone || !prefsGone || !aliasGone) {
            throw new IllegalStateException("Secure erase could not be verified (fileGone=" + fileGone
                    + ", prefsGone=" + prefsGone + ", aliasGone=" + aliasGone + ", committed=" + committed + ")");
        }
    }

    // ------------------------------------------------------------------ record storage

    /** Read the record from disk, or migrate a legacy two-key preference wallet into one. */
    private WalletRecord readRecordOrMigrate() throws Exception {
        WalletRecord record = readRecordFromDisk();
        if (record != null) return record;
        String legacyCiphertext = preferences.getString(LEGACY_ENCRYPTED_MNEMONIC, null);
        String legacyIv = preferences.getString(LEGACY_IV, null);
        if ((legacyCiphertext == null) != (legacyIv == null)) {
            throw new IllegalStateException("Legacy seed storage is incomplete; refusing to replace it");
        }
        if (legacyCiphertext == null) return null;
        WalletRecord migrated = new WalletRecord(
                Numeric.hexStringToByteArray(legacyIv), Numeric.hexStringToByteArray(legacyCiphertext));
        writeRecord(migrated); // durable + verified before the legacy keys are removed
        return migrated;
    }

    /** Strict read: absent → null; present-but-invalid → throws (the identity must not be guessed). */
    private WalletRecord readRecordFromDisk() throws PersistenceException {
        byte[] blob;
        try {
            blob = new AtomicFile(recordFile).readFully();
        } catch (FileNotFoundException absent) {
            return null;
        } catch (IOException failure) {
            throw new PersistenceException("wallet record unreadable", failure);
        }
        try {
            return WalletRecord.decode(blob);
        } catch (IllegalArgumentException corrupt) {
            throw new PersistenceException("wallet record corrupt: " + corrupt.getMessage(), corrupt);
        } finally {
            Arrays.fill(blob, (byte) 0);
        }
    }

    private WalletRecord readRecordFromDiskLenient() {
        try { return readRecordFromDisk(); } catch (Exception e) { return null; }
    }

    /**
     * Journal → atomic write → fsync → rename → read back → compare → journal cleared. Any failure
     * leaves the journal flag set and throws {@link PersistenceException}.
     */
    private void writeRecord(WalletRecord record) throws PersistenceException {
        if (!preferences.edit().putBoolean(WRITE_PENDING, true).commit()) {
            throw new PersistenceException("could not journal the wallet write");
        }
        AtomicFile atomic = new AtomicFile(recordFile);
        FileOutputStream out = null;
        byte[] encoded = record.encode();
        try {
            out = atomic.startWrite();
            out.write(encoded);
            out.flush();
            out.getFD().sync();
            atomic.finishWrite(out);
            out = null;
        } catch (IOException failure) {
            if (out != null) atomic.failWrite(out);
            throw new PersistenceException("wallet record write failed", failure);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
        WalletRecord readBack = readRecordFromDisk();
        if (readBack == null || !readBack.sameAs(record)) {
            throw new PersistenceException("wallet record read-back does not match what was written");
        }
        // Only now is the new identity established; retire legacy keys and settle the journal.
        preferences.edit().remove(LEGACY_ENCRYPTED_MNEMONIC).remove(LEGACY_IV).commit();
        clearWritePending();
    }

    private void clearWritePending() {
        if (preferences.getBoolean(WRITE_PENDING, false)) {
            preferences.edit().remove(WRITE_PENDING).commit();
        }
    }

    // ------------------------------------------------------------------ keystore + crypto

    private void ensureWrappingKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) return;

        KeyGenParameterSpec.Builder specification = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUnlockedDeviceRequired(true)
                .setIsStrongBoxBacked(true);
        try {
            generateWrappingKey(specification.build());
        } catch (StrongBoxUnavailableException unavailable) {
            if (BuildConfig.VAULT_REQUIRE_SECURE_HARDWARE) {
                throw new IllegalStateException("Secure hardware key storage is required", unavailable);
            }
            KeyGenParameterSpec fallback = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .setUnlockedDeviceRequired(true)
                    .build();
            generateWrappingKey(fallback);
        }
    }

    private void generateWrappingKey(KeyGenParameterSpec specification) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
        generator.init(specification);
        generator.generateKey();
    }

    private void enforceSecureHardwarePolicy() throws Exception {
        if (!BuildConfig.VAULT_REQUIRE_SECURE_HARDWARE) return;
        SecretKey key = wrappingKey();
        KeyInfo info;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), ANDROID_KEYSTORE);
            info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
        } catch (InvalidKeySpecException exception) {
            throw new IllegalStateException("Unable to verify hardware key storage", exception);
        }
        if (!info.isInsideSecureHardware()) {
            throw new IllegalStateException("Wrapping key is not stored in secure hardware");
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                && info.getSecurityLevel() != KeyProperties.SECURITY_LEVEL_STRONGBOX) {
            throw new IllegalStateException("Wrapping key is not stored in StrongBox");
        }
    }

    private SecretKey wrappingKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        return ((KeyStore.SecretKeyEntry) keyStore.getEntry(KEY_ALIAS, null)).getSecretKey();
    }

    private WalletRecord encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey());
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted;
        try {
            encrypted = cipher.doFinal(plaintextBytes);
        } finally {
            Arrays.fill(plaintextBytes, (byte) 0);
        }
        return new WalletRecord(cipher.getIV(), encrypted);
    }

    private String decrypt(WalletRecord record) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(), new GCMParameterSpec(128, record.iv));
        byte[] plaintext = cipher.doFinal(record.ciphertext);
        try {
            return new String(plaintext, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plaintext, (byte) 0); // the String copy is GC-managed; see docs
        }
    }
}
