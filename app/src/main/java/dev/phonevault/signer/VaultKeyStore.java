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
 * at m/44'/60'/0'/0/0; the recovery phrase (24 words when created here, 12–24 when restored) is
 * revealable for the user.
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
    /**
     * Credential-bound seed key (pin-credential-design.md): usable only within
     * {@link SystemCredential#AUTH_WINDOW_SECONDS} of a successful device-PIN check, and only on an
     * unlocked device. Created once a device credential exists; v1 records migrate to it.
     */
    private static final String KEY_ALIAS_V2 = "phone-vault-seed-key-v2";
    private static final String PREFS = "vault";
    private static final String RECORD_FILE = "wallet.pvw3";
    private static final int ACCOUNT_INDEX = 0;

    private final WalletPersistence persistence;
    private final Context context;
    private volatile List<SeedVault.SourceReport> lastReports;

    VaultKeyStore(Context context) {
        this.context = context.getApplicationContext();
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

    /**
     * Derive account {@code index} of the stored wallet, under {@code passphrase} (null or empty:
     * the standard wallet). One decrypt of the record with the seed key, so it runs inside the
     * same PIN window as {@link #loadOrCreate}. Only that account's key is returned; the passphrase
     * is neither stored nor kept here.
     */
    synchronized SeedVault.Derived deriveAccount(int index, String passphrase) throws Exception {
        return deriveAccount(index, passphrase, AccountScheme.STANDARD);
    }

    /** As {@link #deriveAccount(int, String)}, with the account numbered by {@code scheme}. */
    synchronized SeedVault.Derived deriveAccount(int index, String passphrase, AccountScheme scheme) throws Exception {
        ensureWrappingKey();
        enforceSecureHardwarePolicy();
        WalletRecord record = persistence.load();
        if (record == null) throw new WalletPersistence.PersistenceException("no verifiable wallet record on disk");
        return SeedVault.deriveAccount(decrypt(record), passphrase, index, scheme);
    }

    /**
     * The first {@code count} addresses of the STANDARD wallet (no passphrase) under {@code scheme}:
     * public addresses only, for USB listAddresses after the user approves sharing them. Same PIN
     * window as {@link #deriveAccount}.
     */
    synchronized List<String> standardAddresses(AccountScheme scheme, int count) throws Exception {
        return addresses(scheme, count, "");
    }

    /** As {@link #standardAddresses}, for the wallet {@code passphrase} opens (null or empty: the standard wallet). */
    synchronized List<String> addresses(AccountScheme scheme, int count, String passphrase) throws Exception {
        ensureWrappingKey();
        enforceSecureHardwarePolicy();
        WalletRecord record = persistence.load();
        if (record == null) throw new WalletPersistence.PersistenceException("no verifiable wallet record on disk");
        return SeedVault.addresses(decrypt(record), passphrase, scheme, count);
    }

    /** Work done with the standard wallet's BIP-39 seed; the seed is zeroed when it returns. */
    interface SeedUse<T> { T apply(byte[] seed) throws Exception; }

    /**
     * Run {@code use} with the STANDARD wallet's BIP-39 seed (no passphrase): one decrypt of the
     * record with the seed key, so it needs the same PIN window as {@link #deriveAccount}. The seed
     * array is zeroed afterwards whatever happens (the decrypted phrase is a String, as for the
     * EVM path, and becomes unreachable). Bitcoin derives its account xpubs and signing keys here.
     */
    synchronized <T> T withStandardSeed(SeedUse<T> use) throws Exception {
        ensureWrappingKey();
        enforceSecureHardwarePolicy();
        WalletRecord record = persistence.load();
        if (record == null) throw new WalletPersistence.PersistenceException("no verifiable wallet record on disk");
        byte[] seed = SeedVault.bip39Seed(decrypt(record), "");
        try {
            return use.apply(seed);
        } finally {
            java.util.Arrays.fill(seed, (byte) 0);
        }
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

    /**
     * Import an existing BIP39 phrase as the wallet (restore). Same durable, verified path as
     * {@link #commitReplacement(String)} — journal → atomic write → read-back → settle — but the
     * caller reaches it only from the restore flow (validated by {@link SeedRestore}) and marks
     * the backup as already verified, since the user provided the words.
     */
    synchronized Credentials restore(String mnemonic) throws Exception {
        return commitReplacement(mnemonic);
    }

    /** Decrypt and return the recovery phrase (12–24 words) for the reveal screen. Handle with care. */
    synchronized String revealMnemonic() throws Exception {
        ensureWrappingKey();
        WalletRecord record = persistence.load();
        if (record == null) throw new IllegalStateException("No wallet to reveal");
        return decrypt(record);
    }

    /** Check the originating authorization after acquiring the store, before secret access. */
    synchronized String revealMnemonic(java.util.function.BooleanSupplier authorized) throws Exception {
        if (!authorized.getAsBoolean()) throw new IllegalStateException("Backup authorization expired");
        // A lock may cancel an operation already authorized here; its result is never published
        // by the activity unless the same sensitive flow and unlock session still own it.
        return revealMnemonic();
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
        if (keyStore.containsAlias(KEY_ALIAS_V2)) keyStore.deleteEntry(KEY_ALIAS_V2);
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS) || keyStore.containsAlias(KEY_ALIAS_V2)) {
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
        if (SystemCredential.isSet(context)) {
            if (!keyStore.containsAlias(KEY_ALIAS_V2)) generateCredentialBoundKey();
            return;
        }
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

    private void generateCredentialBoundKey() throws Exception {
        KeyGenParameterSpec.Builder specification = new KeyGenParameterSpec.Builder(
                KEY_ALIAS_V2,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUnlockedDeviceRequired(true)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(SystemCredential.AUTH_WINDOW_SECONDS,
                        KeyProperties.AUTH_DEVICE_CREDENTIAL)
                .setIsStrongBoxBacked(true);
        try {
            generateWrappingKey(specification.build());
        } catch (StrongBoxUnavailableException unavailable) {
            if (BuildConfig.VAULT_REQUIRE_SECURE_HARDWARE) {
                throw new IllegalStateException("Secure hardware key storage is required", unavailable);
            }
            generateWrappingKey(specification.setIsStrongBoxBacked(false).build());
        }
    }

    /**
     * Would the chip let the seed key work right now, without asking for the PIN? Runs one complete
     * throwaway operation (encrypt nothing under a fresh random IV, result discarded). {@code init}
     * alone is not enough: keystore2 admits it by its own receipt time of the auth token, but the
     * StrongBox checks the window only on the first update/finish (SeedKeyWindow), so an init-only
     * probe said "usable" up to ~1 s after the chip had closed the window. Finishing the operation
     * also frees its StrongBox slot instead of leaving it open until garbage collection. This only
     * saves a redundant prompt: the keystore still enforces the window on the real operation.
     * Creates the credential-bound key if it does not exist yet.
     */
    synchronized boolean seedKeyUsableNow() {
        try {
            ensureWrappingKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key(activeAlias()));
            cipher.doFinal(new byte[0]);
            return true;
        } catch (Exception refused) {
            return false;
        }
    }

    /** True once the credential-bound key protects the record (v1 gone). */
    synchronized boolean credentialBound() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        return keyStore.containsAlias(KEY_ALIAS_V2) && !keyStore.containsAlias(KEY_ALIAS);
    }

    /**
     * Move the record from the v1 key to the credential-bound v2 key. The caller has just confirmed
     * the device PIN. One journaled store under v2, read back and compared, THEN v1 is deleted; any
     * failure before that leaves v1 usable (decrypt falls back) and the next unlock retries.
     */
    synchronized void migrateToCredentialKey() throws Exception {
        if (!SystemCredential.isSet(context)) throw new IllegalStateException("No device credential yet");
        ensureWrappingKey();
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        if (!keyStore.containsAlias(KEY_ALIAS)) return; // already migrated (or never had v1)
        WalletRecord record = persistence.load();
        if (record != null) {
            String plaintext = decrypt(record);
            boolean alreadyV2;
            try { decryptWith(KEY_ALIAS_V2, record); alreadyV2 = true; } catch (javax.crypto.AEADBadTagException notYet) { alreadyV2 = false; }
            if (!alreadyV2) {
                persistence.store(encryptWith(KEY_ALIAS_V2, plaintext));
                WalletRecord back = persistence.load();
                if (back == null || !plaintext.equals(decryptWith(KEY_ALIAS_V2, back))) {
                    throw new WalletPersistence.PersistenceException("migrated record did not verify under the credential-bound key");
                }
            }
        }
        keyStore.deleteEntry(KEY_ALIAS);
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) throw new IllegalStateException("old wrapping key could not be removed");
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

    /** The key new records are sealed with: v2 once it exists, else v1. */
    private String activeAlias() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        return keyStore.containsAlias(KEY_ALIAS_V2) ? KEY_ALIAS_V2 : KEY_ALIAS;
    }

    private SecretKey key(String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        KeyStore.Entry entry = keyStore.getEntry(alias, null);
        if (!(entry instanceof KeyStore.SecretKeyEntry)) throw new IllegalStateException("wrapping key " + alias + " missing");
        return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
    }

    private SecretKey wrappingKey() throws Exception { return key(activeAlias()); }

    private WalletRecord encrypt(String plaintext) throws Exception { return encryptWith(activeAlias(), plaintext); }

    private WalletRecord encryptWith(String alias, String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key(alias));
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted;
        try {
            encrypted = cipher.doFinal(plaintextBytes);
        } finally {
            Arrays.fill(plaintextBytes, (byte) 0);
        }
        return new WalletRecord(cipher.getIV(), encrypted);
    }

    /** Decrypt with the active key; during a v1→v2 migration the record may still be under v1. */
    private String decrypt(WalletRecord record) throws Exception {
        String alias = activeAlias();
        try {
            return decryptWith(alias, record);
        } catch (javax.crypto.AEADBadTagException stillOld) {
            if (!KEY_ALIAS_V2.equals(alias)) throw stillOld;
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            if (!keyStore.containsAlias(KEY_ALIAS)) throw stillOld;
            return decryptWith(KEY_ALIAS, record);
        }
    }

    private String decryptWith(String alias, WalletRecord record) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(alias), new GCMParameterSpec(128, record.iv));
        byte[] plaintext = cipher.doFinal(record.ciphertext);
        try {
            return new String(plaintext, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plaintext, (byte) 0); // the String copy is GC-managed; see docs
        }
    }
}
