package dev.phonevault.signer;

import android.content.Context;
import android.content.SharedPreferences;

import org.web3j.utils.Numeric;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * In-app PIN gate (roadmap Tier 1 #1). The seed stays StrongBox-wrapped at rest; the PIN is an
 * access gate in front of decrypting it. Because the keyguard is disabled for boot-into-app, the
 * wrapping key's {@code setUnlockedDeviceRequired} no longer gates anything — this does.
 *
 * <p>Stored as PBKDF2-HMAC-SHA256(pin, salt, iterations) with a per-device random salt. Wrong
 * attempts are counted persistently; at {@link #MAX_ATTEMPTS} the supplied wipe hook runs and the
 * PIN is cleared (the wallet is gone — that is the point).
 *
 * <p>That hash exists only in the no-chip fallback mode. Once the PIN is the device credential
 * ({@link SystemCredential}) only a marker is stored ({@link #markCredentialHeld}).
 */
final class VaultPin {
    static final int PIN_LENGTH = 6;
    static final int MAX_ATTEMPTS = 10;
    private static final int ITERATIONS = 200_000;
    private static final int KEY_BITS = 256;
    private static final String PREFS = "vault";
    private static final String HASH = "pin_hash_v1";
    private static final String SALT = "pin_salt_v1";
    private static final String ITER = "pin_iter_v1";
    private static final String ATTEMPTS = "pin_attempts_v1";
    /**
     * Credential-mode marker: the PIN is the Android lock credential and the Titan M (Gatekeeper)
     * is its only verifier. While it is present the app keeps NO hash/salt/work factor — an
     * offline copy of prefs must give a guesser nothing to search without the chip's throttle.
     * Authoritative once written: a leftover hash next to it is removed, never consulted.
     */
    private static final String CREDENTIAL = "pin_device_credential_v1";

    /**
     * {@code ERASE_FAILED}: the attempt limit was reached but the wallet could NOT be verifiably
     * destroyed. The PIN is kept (the gate stays shut) — the caller must refuse to load the key.
     */
    enum Outcome { OK, WRONG, WIPED, ERASE_FAILED }

    /** Destroys the wallet; must throw if the erase cannot be verified. */
    interface Eraser {
        void erase() throws Exception;
    }

    static final class Result {
        final Outcome outcome;
        final int attemptsRemaining;
        Result(Outcome outcome, int attemptsRemaining) {
            this.outcome = outcome;
            this.attemptsRemaining = attemptsRemaining;
        }
    }

    private final SharedPreferences preferences;
    private final int iterations;

    VaultPin(Context context) {
        this(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE), ITERATIONS);
    }

    /** Test seam: inject storage and a smaller work factor. */
    VaultPin(SharedPreferences preferences, int iterations) {
        this.preferences = preferences;
        this.iterations = iterations;
    }

    /** A PIN exists in either mode: the chip holds it (marker) or the app holds its hash. */
    synchronized boolean isSet() {
        return credentialHeld() || appPinSet();
    }

    /** The device credential holds the PIN (credential mode). Decides the gate's mode. */
    synchronized boolean credentialHeld() {
        return preferences.getBoolean(CREDENTIAL, false);
    }

    /** The app-level PBKDF2 record exists (no-chip fallback mode only). */
    synchronized boolean appPinSet() {
        return preferences.getString(HASH, null) != null && preferences.getString(SALT, null) != null;
    }

    /**
     * The PIN was installed as the device credential: write the marker FIRST (its own commit), then
     * drop the hash, salt, work factor and app attempt counter (the chip throttles from now on). A
     * crash between the two leaves marker + hash, which {@link #reconcile} finishes. Idempotent.
     */
    synchronized void markCredentialHeld() {
        if (!credentialHeld() && !preferences.edit().putBoolean(CREDENTIAL, true).commit()) {
            throw new IllegalStateException("Credential-mode marker could not be committed");
        }
        if (preferences.contains(HASH) || preferences.contains(SALT) || preferences.contains(ITER)
                || preferences.contains(ATTEMPTS)) {
            if (!preferences.edit().remove(HASH).remove(SALT).remove(ITER).remove(ATTEMPTS).commit()) {
                throw new IllegalStateException("App PIN record could not be removed");
            }
        }
    }

    /**
     * Startup reconciliation (and migration of phones that entered credential mode before the
     * marker existed, which still store the hash). {@code deviceCredentialSet}: the system reports a
     * lock credential. If it does, or the marker is already present, the chip holds the PIN:
     * marker on, app record gone. Otherwise (fallback mode) nothing changes.
     */
    synchronized void reconcile(boolean deviceCredentialSet) {
        if (deviceCredentialSet || credentialHeld()) markCredentialHeld();
    }

    synchronized int attemptsRemaining() {
        return Math.max(0, MAX_ATTEMPTS - preferences.getInt(ATTEMPTS, 0));
    }

    /**
     * Set (or replace) the app-held PIN: the no-chip fallback mode only. Digits only, exactly
     * {@link #PIN_LENGTH}. Refused in credential mode (the chip holds the PIN there).
     */
    synchronized void set(char[] pin) throws Exception {
        byte[] hash = null;
        try {
            validate(pin);
            if (credentialHeld()) throw new IllegalStateException("The device credential holds the PIN");
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            hash = derive(pin, salt, iterations);
            boolean stored = preferences.edit()
                    .putString(HASH, Numeric.toHexStringNoPrefix(hash))
                    .putString(SALT, Numeric.toHexStringNoPrefix(salt))
                    .putInt(ITER, iterations)
                    .putInt(ATTEMPTS, 0)
                    .commit();
            if (!stored) throw new IllegalStateException("PIN could not be committed to storage");
        } finally {
            if (hash != null) Arrays.fill(hash, (byte) 0);
            if (pin != null) Arrays.fill(pin, '0'); // zeroed on every path, including a throw
        }
    }

    /**
     * Verify a PIN. On the {@link #MAX_ATTEMPTS}th consecutive failure the eraser runs; only a
     * verified erase clears the PIN ({@code WIPED}). If the erase throws, the PIN is kept and
     * {@code ERASE_FAILED} is returned — the gate never fails open.
     *
     * <p>The attempt counter is committed BEFORE the PIN is checked, so pulling power mid-check
     * cannot yield a free attempt; it is reset only after a verified success.
     */
    synchronized Result verify(char[] pin, Eraser eraser) throws Exception {
        try {
            if (credentialHeld()) throw new IllegalStateException("The device credential holds the PIN");
            if (!appPinSet()) throw new IllegalStateException("No PIN is set");
            if (eraseOutstanding()) {
                // Limit already reached and the wallet is still not verifiably gone: no further
                // PIN comparisons (that would be attempt 11+) — only the erase is retried.
                try {
                    if (eraser == null) throw new IllegalStateException("No eraser configured");
                    eraser.erase();
                } catch (Exception failure) {
                    return new Result(Outcome.ERASE_FAILED, 0);
                }
                clear();
                return new Result(Outcome.WIPED, 0);
            }
            int attempts = preferences.getInt(ATTEMPTS, 0) + 1;
            if (!preferences.edit().putInt(ATTEMPTS, attempts).commit()) {
                throw new IllegalStateException("Attempt counter could not be committed");
            }
            byte[] salt = Numeric.hexStringToByteArray(preferences.getString(SALT, ""));
            byte[] expected = Numeric.hexStringToByteArray(preferences.getString(HASH, ""));
            int storedIterations = preferences.getInt(ITER, iterations);
            byte[] actual = derive(pin, salt, storedIterations);
            boolean ok = MessageDigest.isEqual(expected, actual);
            Arrays.fill(actual, (byte) 0);
            Arrays.fill(expected, (byte) 0);
            if (ok) {
                // A correct PIN must also reset the persistent counter; if that write fails we
                // refuse to report success (an elevated counter would erase the wallet later).
                if (!preferences.edit().putInt(ATTEMPTS, 0).commit()) {
                    throw new IllegalStateException("Attempt counter could not be reset; refusing to unlock");
                }
                return new Result(Outcome.OK, MAX_ATTEMPTS);
            }
            if (attempts >= MAX_ATTEMPTS) {
                try {
                    if (eraser == null) throw new IllegalStateException("No eraser configured");
                    eraser.erase();
                } catch (Exception failure) {
                    // Fail closed: PIN stays, counter stays at the limit, wallet must not load.
                    return new Result(Outcome.ERASE_FAILED, 0);
                }
                clear();
                return new Result(Outcome.WIPED, 0);
            }
            return new Result(Outcome.WRONG, MAX_ATTEMPTS - attempts);
        } finally {
            Arrays.fill(pin, '0');
        }
    }

    /** True once the attempt limit has been hit without a verified erase. */
    synchronized boolean eraseOutstanding() {
        return !credentialHeld() && appPinSet() && preferences.getInt(ATTEMPTS, 0) >= MAX_ATTEMPTS;
    }

    synchronized void clear() {
        if (!preferences.edit().remove(HASH).remove(SALT).remove(ITER).remove(ATTEMPTS).commit()) {
            throw new IllegalStateException("PIN could not be cleared");
        }
    }

    private static void validate(char[] pin) {
        if (pin == null || pin.length != PIN_LENGTH) {
            throw new IllegalArgumentException("PIN must be exactly " + PIN_LENGTH + " digits");
        }
        for (char c : pin) {
            if (c < '0' || c > '9') throw new IllegalArgumentException("PIN must be digits only");
        }
    }

    private static byte[] derive(char[] pin, byte[] salt, int iterations) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(pin, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }
}
