package dev.phonevault.signer;

import org.json.JSONObject;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;

/**
 * Binds one reviewed transaction to the exact signing identity shown on screen. The review is
 * built here, once, from the same {@link Eip1559Request} object that {@link #signIfIdentityUnchanged}
 * signs, so what the user approves and what is signed cannot diverge.
 */
final class ApprovalSession {
    final Eip1559Request request;
    final TransactionReview review;
    private final Credentials reviewedCredentials;
    private final String reviewedAddress;

    ApprovalSession(Eip1559Request request, Credentials credentials) {
        this(request, credentials, TokenList.empty());
    }

    ApprovalSession(Eip1559Request request, Credentials credentials, TokenList tokens) {
        this(request, credentials, tokens, null);
    }

    /**
     * @param safety the phone's address book and recipient history (contact names, first-time and
     *               look-alike checks); display only, never part of what is signed. May be null.
     */
    ApprovalSession(Eip1559Request request, Credentials credentials, TokenList tokens, AddressSafety safety) {
        if (request == null || credentials == null) {
            throw new IllegalArgumentException("Approval requires a request and signing identity");
        }
        this.request = request;
        this.reviewedCredentials = credentials;
        this.reviewedAddress = credentials.getAddress().toLowerCase(java.util.Locale.ROOT);
        this.review = TransactionReview.build(request, reviewedAddress, tokens, safety);
    }

    String reviewedAddress() { return reviewedAddress; }

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
