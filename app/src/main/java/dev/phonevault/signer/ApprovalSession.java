package dev.phonevault.signer;

import org.json.JSONObject;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;

/** Binds one reviewed transaction to the exact signing identity shown on screen. */
final class ApprovalSession {
    final Eip1559Request request;
    private final Credentials reviewedCredentials;
    private final String reviewedAddress;

    ApprovalSession(Eip1559Request request, Credentials credentials) {
        if (request == null || credentials == null) {
            throw new IllegalArgumentException("Approval requires a request and signing identity");
        }
        this.request = request;
        this.reviewedCredentials = credentials;
        this.reviewedAddress = credentials.getAddress().toLowerCase(java.util.Locale.ROOT);
    }

    String signerAddressLabel() {
        return Keys.toChecksumAddress(reviewedAddress);
    }

    JSONObject signIfIdentityUnchanged(Credentials currentCredentials) throws Exception {
        if (currentCredentials == null
                || !reviewedAddress.equals(currentCredentials.getAddress().toLowerCase(java.util.Locale.ROOT))) {
            throw new IllegalStateException(
                    "Signing identity changed after review; request must be reviewed again");
        }
        return EvmSigner.sign(request, reviewedCredentials);
    }
}
