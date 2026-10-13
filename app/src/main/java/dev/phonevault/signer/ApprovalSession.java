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
    /**
     * The Mac's simulation claim checked against this phone's decoding, or null when the request
     * carries none. Shown in its own box below the review; never part of what is signed.
     */
    final SimulationCheck.Result hostSimulation;
    private final Credentials reviewedCredentials;
    private final String reviewedAddress;
    /**
     * Which account (of which wallet) the reviewed key is, for the "Signing with" row and the
     * review's "From · Account N" row. Display only; null in tests that do not name one.
     */
    final SigningAccount signingAs;

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
        this(request, credentials, tokens, safety, null);
    }

    /** @param account the account {@code credentials} belongs to (must be the same address), or null */
    ApprovalSession(Eip1559Request request, Credentials credentials, TokenList tokens, AddressSafety safety,
                    SigningAccount account) {
        if (request == null || credentials == null) {
            throw new IllegalArgumentException("Approval requires a request and signing identity");
        }
        this.request = request;
        this.reviewedCredentials = credentials;
        this.reviewedAddress = credentials.getAddress().toLowerCase(java.util.Locale.ROOT);
        this.signingAs = account;
        this.review = TransactionReview.build(request, reviewedAddress, tokens, safety, account);
        this.hostSimulation = SimulationCheck.review(request, reviewedAddress, tokens);
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
        // Defence in depth: the request was refused before review if its "from" named another
        // account (RequestRefusal.requireFrom); never sign one that slipped past.
        if (request.from != null && !request.from.equals(reviewedAddress)) {
            throw new IllegalStateException("Request is for another account; switch accounts on the phone");
        }
        return EvmSigner.sign(request, reviewedCredentials);
    }
}
