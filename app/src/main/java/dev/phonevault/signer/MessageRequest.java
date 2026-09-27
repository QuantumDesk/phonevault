package dev.phonevault.signer;

import org.json.JSONException;
import org.json.JSONObject;

import java.math.BigInteger;

/**
 * A host request to sign a message rather than a transaction. Same flat, all-string,
 * schema-exact USB frame as {@code signEip1559} (see {@link AccessoryTransport#parseStrictRequest}):
 *
 * <pre>
 * {"id":"…","method":"personal_sign","chainId":"0x1","message":"0x&lt;hex bytes&gt;"}
 * {"id":"…","method":"eth_signTypedData_v4","chainId":"0x1","typedData":"&lt;EIP-712 JSON text&gt;"}
 * </pre>
 *
 * {@code chainId} is the network the host is working on (one of the reviewed chain profiles). It
 * is not signed; the review compares it with the chain the message itself names and warns on a
 * mismatch. The parsed message object is the single source of both the digest and the review.
 */
final class MessageRequest {
    static final String PERSONAL_SIGN = "personal_sign";
    static final String SIGN_TYPED_DATA_V4 = "eth_signTypedData_v4";

    enum Kind { PERSONAL, TYPED_DATA }

    final String id;
    final long chainId;
    final Kind kind;
    /** Non-null for {@link Kind#PERSONAL}. */
    final PersonalMessage personal;
    /** Non-null for {@link Kind#TYPED_DATA}. */
    final Eip712.TypedData typedData;

    private MessageRequest(String id, long chainId, Kind kind, PersonalMessage personal, Eip712.TypedData typedData) {
        this.id = id;
        this.chainId = chainId;
        this.kind = kind;
        this.personal = personal;
        this.typedData = typedData;
    }

    static boolean handles(String method) {
        return PERSONAL_SIGN.equals(method) || SIGN_TYPED_DATA_V4.equals(method);
    }

    static MessageRequest parse(JSONObject json) throws JSONException {
        String method = json.optString("method");
        if (PERSONAL_SIGN.equals(method)) {
            Eip1559Request.requireExactFields(json, "id", "method", "chainId", "message");
        } else if (SIGN_TYPED_DATA_V4.equals(method)) {
            Eip1559Request.requireExactFields(json, "id", "method", "chainId", "typedData");
        } else {
            throw new JSONException("Unsupported method");
        }
        String id = Eip1559Request.validatedId(json.getString("id"));
        BigInteger chainValue = Eip1559Request.quantity(json.getString("chainId"));
        if (chainValue.signum() <= 0 || chainValue.bitLength() > 63) throw new JSONException("chainId out of range");
        long chainId = chainValue.longValue();
        if (!Eip1559Request.supportedChain(chainId)) {
            throw new JSONException("Unsupported network: no reviewed chain profile for " + chainId);
        }
        if (PERSONAL_SIGN.equals(method)) {
            String hex = json.getString("message");
            if (!hex.matches("0x[0-9a-fA-F]+") || (hex.length() & 1) != 0) {
                throw new JSONException("message must be non-empty, even-length 0x-prefixed hex");
            }
            if ((hex.length() - 2) / 2 > PersonalMessage.MAX_MESSAGE_BYTES) {
                throw new JSONException("message exceeds " + PersonalMessage.MAX_MESSAGE_BYTES + " bytes");
            }
            byte[] bytes = new byte[(hex.length() - 2) / 2];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(hex.substring(2 + 2 * i, 4 + 2 * i), 16);
            }
            return new MessageRequest(id, chainId, Kind.PERSONAL, PersonalMessage.of(bytes), null);
        }
        try {
            return new MessageRequest(id, chainId, Kind.TYPED_DATA, null, Eip712.parse(json.getString("typedData")));
        } catch (Eip712.InvalidTypedData e) {
            throw new JSONException(e.getMessage());
        }
    }

    /** The 32 bytes that will be signed, derived only from the parsed message object. */
    byte[] digest() {
        return kind == Kind.PERSONAL ? personal.digest() : typedData.digest();
    }
}
