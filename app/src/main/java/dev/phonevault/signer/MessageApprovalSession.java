package dev.phonevault.signer;

import org.json.JSONObject;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.util.Locale;

/**
 * Binds one reviewed message request, and the review built from it, to the exact signing
 * identity shown on screen (the message counterpart of {@link ApprovalSession}).
 *
 * <p>The digest is taken from the parsed request when the session is created — the same parsed
 * object the review was rendered from — and is the only thing ever signed.
 */
final class MessageApprovalSession {
    final MessageRequest request;
    final MessageReview review;
    private final byte[] digest;
    private final Credentials reviewedCredentials;
    private final String reviewedAddress;

    MessageApprovalSession(MessageRequest request, Credentials credentials) {
        if (request == null || credentials == null) {
            throw new IllegalArgumentException("Approval requires a request and signing identity");
        }
        this.request = request;
        this.reviewedCredentials = credentials;
        this.reviewedAddress = credentials.getAddress().toLowerCase(Locale.ROOT);
        this.review = MessageReview.of(request, reviewedAddress);
        this.digest = request.digest();
    }

    String signerAddressLabel() {
        return Keys.toChecksumAddress(reviewedAddress);
    }

    String digestHex() { return Numeric.toHexString(digest); }

    JSONObject signIfIdentityUnchanged(Credentials currentCredentials) throws Exception {
        if (currentCredentials == null
                || !reviewedAddress.equals(currentCredentials.getAddress().toLowerCase(Locale.ROOT))) {
            throw new IllegalStateException(
                    "Signing identity changed after review; request must be reviewed again");
        }
        return sign(request.id, digest, reviewedCredentials);
    }

    /**
     * Sign a 32-byte digest as-is (no further hashing). Response:
     * {@code {"id","status":"approved","address","signature":"0x r‖s‖v (65 bytes, v 27/28)","digest"}}.
     */
    static JSONObject sign(String id, byte[] digest, Credentials credentials) throws Exception {
        if (digest == null || digest.length != 32) throw new IllegalArgumentException("digest must be 32 bytes");
        Sign.SignatureData sig = Sign.signMessage(digest, credentials.getEcKeyPair(), false);
        byte[] out = new byte[65];
        System.arraycopy(sig.getR(), 0, out, 0, 32);
        System.arraycopy(sig.getS(), 0, out, 32, 32);
        out[64] = sig.getV()[0];
        return new JSONObject()
                .put("id", id)
                .put("status", "approved")
                .put("address", credentials.getAddress())
                .put("signature", Numeric.toHexString(out))
                .put("digest", Numeric.toHexString(digest));
    }
}
