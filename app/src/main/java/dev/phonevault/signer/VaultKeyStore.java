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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
 * <p>Durability lives in {@link WalletPersistence} (journal → atomic write → read-back → settled
 * flags, permanent v3 marker, verified erase), which is fault-injected in unit tests; this class
 * only supplies the Android storage primitives and the StrongBox crypto. Any
 * {@link WalletPersistence.PersistenceException} means "the active identity is unknown until
 * reconciled from disk" — callers must never keep using the old in-memory key.
 */
final class VaultKeyStore {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "phone-vault-wrapping-key-v1";
    private static final String PREFS = "vault";
    private static final String RECORD_FILE = "wallet.pvw3";
    private static final int ACCOUNT_INDEX = 0;

    private final WalletPersistence persistence;
    private volatile List<SeedVault.SourceReport> lastReports;

    VaultKeyStore(Context context) {
        SharedPreferences preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        File recordFile = new File(context.getFilesDir(), RECORD_FILE);
        persistence = new WalletPersistence(new AndroidWalletStorage(recordFile, preferences));
    }

    /** True once a seed record exists (throws if storage is sealed or corrupt). */
    synchronized boolean hasWallet() throws Exception {
        return persistence.load() != null;
    }

    /**
     * Load the wallet from durable storage, or generate one only if storage is genuinely empty
     * (no record, no journal, no v3 marker, no legacy keys). Every uncertain state throws.
     */
    synchronized Credentials loadOrCreate() throws Exception {
        ensureWrappingKey();
        enforceSecureHardwarePolicy();
        WalletRecord record = persistence.load();
        if (record != null) return SeedVault.deriveEvm(decrypt(record), "", ACCOUNT_INDEX);
        if (!persistence.creationAllowed()) {
            throw new WalletPersistence.PersistenceException("wallet storage is sealed; refusing to create");
        }
        return generateAndStore(new byte[0]);
    }

    /** Authoritative identity from disk after an uncertain commit. Throws if none verifies. */
    synchronized Credentials reconcile() throws Exception {
        ensureWrappingKey();
        WalletRecord record = persistence.load();
        if (record == null) throw new WalletPersistence.PersistenceException("no verifiable wallet record on disk");
        return SeedVault.deriveEvm(decrypt(record), "", ACCOUNT_INDEX);
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
     * credentials only after the record has been read back, verified AND the flags settled
     * (legacy wallet removed, journal cleared, v3 marker set — all proven).
     */
    synchronized Credentials commitReplacement(String mnemonic) throws Exception {
        ensureWrappingKey();
        enforceSecureHardwarePolicy();
        Credentials credentials = SeedVault.deriveEvm(mnemonic, "", ACCOUNT_INDEX);
        persistence.store(encrypt(mnemonic));
        return credentials;
    }

    /** Decrypt and return the 24-word backup for the reveal screen. Handle with care. */
    synchronized String revealMnemonic() throws Exception {
        ensureWrappingKey();
        WalletRecord record = persistence.load();
        if (record == null) throw new IllegalStateException("No wallet to reveal");
        return decrypt(record);
    }

    List<SeedVault.SourceReport> lastGenerationReports() {
        return lastReports;
    }

    /**
     * Destroy the wallet: record, legacy keys, every flag AND the StrongBox wrapping alias.
     * Verified, never assumed — an unverifiable erase throws so the PIN gate stays shut
     * (VaultPin.Outcome.ERASE_FAILED).
     */
    synchronized void secureErase() throws Exception {
        lastReports = null;
        persistence.erase(); // throws unless record + flags are provably gone
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS);
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) {
            throw new IllegalStateException("Secure erase could not be verified: wrapping alias still present");
        }
    }

    // ------------------------------------------------------------------ Android storage shim

    /** AtomicFile for the record + SharedPreferences for the small flag store. */
    static final class AndroidWalletStorage implements WalletStorage {
        private final File recordFile;
        private final SharedPreferences preferences;

        AndroidWalletStorage(File recordFile, SharedPreferences preferences) {
            this.recordFile = recordFile;
            this.preferences = preferences;
        }

        @Override public byte[] readBlob() throws IOException {
            try {
                return new AtomicFile(recordFile).readFully();
            } catch (FileNotFoundException absent) {
                return null;
            }
        }

        @Override public void writeBlobAtomically(byte[] blob) throws IOException {
            AtomicFile atomic = new AtomicFile(recordFile);
            FileOutputStream out = atomic.startWrite();
            try {
                out.write(blob);
                out.flush();
                out.getFD().sync();
                atomic.finishWrite(out);
            } catch (IOException failure) {
                atomic.failWrite(out);
                throw failure;
            }
        }

        @Override public void deleteBlob() {
            new AtomicFile(recordFile).delete(); // base, .new and legacy .bak
        }

        @Override public boolean blobExists() {
            return recordFile.exists() || new File(recordFile.getPath() + ".bak").exists();
        }

        @Override public String getFlag(String key) {
            return preferences.getString(key, null);
        }

        @Override public boolean getBooleanFlag(String key) {
            return preferences.getBoolean(key, false);
        }

        @Override public boolean commitFlags(Map<String, Object> puts, Set<String> removes) {
            SharedPreferences.Editor editor = preferences.edit();
            for (String key : removes) editor.remove(key);
            for (Map.Entry<String, Object> entry : puts.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof Boolean) editor.putBoolean(entry.getKey(), (Boolean) value);
                else editor.putString(entry.getKey(), String.valueOf(value));
            }
            return editor.commit();
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
