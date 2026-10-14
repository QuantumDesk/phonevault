package dev.phonevault.signer;

import android.security.KeyStoreException;
import android.security.keystore.UserNotAuthenticatedException;

/** Reading keystore failures: the PIN window lapsed, and a loggable exception chain. */
final class KeystoreFailures {
    private KeystoreFailures() {}

    /** Keystore refused because the PIN window lapsed (the op took longer than the window). */
    static boolean authLapsed(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof UserNotAuthenticatedException) return true;
            // Keystore2 may report the same refusal as a KeyStoreException instead.
            if (c instanceof KeyStoreException
                    && ((KeyStoreException) c).getNumericErrorCode()
                            == KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED) return true;
            String m = c.getMessage();
            if (m != null && (m.contains("not authenticated") || m.contains("KEY_USER_NOT_AUTHENTICATED"))) return true;
        }
        return false;
    }

    /** Class names and messages of an exception chain for the log (no key material is ever in them). */
    static String chain(Throwable t) {
        StringBuilder b = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) b.append(c.getClass().getName()).append(": ").append(c.getMessage()).append(" <- ");
        return b.toString();
    }
}
