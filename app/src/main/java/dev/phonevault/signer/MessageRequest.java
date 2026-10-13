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
 *
 * <p>Optional fields: {@code "from"} (the account the host expects) and {@code "origin"} (the web
 * origin the host says asked, see {@link #optionalOrigin}); neither is signed.
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
    /** Optional signer the host expects (lowercase), or null; see {@link Eip1559Request#optionalFrom}. */
    String from;
    /**
     * Optional web origin the HOST says the request came from ("https://app.uniswap.org"), or
     * null. Display only and unverifiable by the phone; see {@link #optionalOrigin}.
     */
    String origin;

    static final int MAX_ORIGIN_LENGTH = 255;
    private static final java.util.regex.Pattern HTTPS_ORIGIN =
            java.util.regex.Pattern.compile("https://([a-z0-9-]+(?:\\.[a-z0-9-]+)*)(?::([1-9][0-9]{0,4}))?");
    private static final java.util.regex.Pattern LOCAL_ORIGIN =
            java.util.regex.Pattern.compile("http://(localhost|127\\.0\\.0\\.1|\\[::1\\])(?::([1-9][0-9]{0,4}))?");

    /**
     * The optional {@code "origin"} field of a message-signing request (the companion adds it when a
     * browser site or WalletConnect dapp asked): scheme + host [+ port], nothing else. Accepted:
     * {@code https://<lowercase ASCII/punycode host>[:port]}, or {@code http://localhost},
     * {@code http://127.0.0.1}, {@code http://[::1]} [+ port]; at most 255 characters; port
     * 1–65535 without leading zeros. Anything else refuses the whole request.
     */
    static String optionalOrigin(JSONObject json) throws JSONException {
        if (!json.has("origin")) return null;
        Object value = json.get("origin");
        if (!(value instanceof String)) throw new JSONException("origin must be a string");
        String o = (String) value;
        java.util.regex.Matcher m = HTTPS_ORIGIN.matcher(o);
        if (!m.matches()) m = LOCAL_ORIGIN.matcher(o);
        if (o.length() > MAX_ORIGIN_LENGTH || !m.matches()
                || (m.group(2) != null && Integer.parseInt(m.group(2)) > 65535)) {
            throw new JSONException("origin must be https://host[:port] (lowercase ASCII) or http://localhost[:port]");
        }
        return o;
    }

    /** The origin's host, without scheme or port ("app.uniswap.org", "localhost", "[::1]"). */
    static String originHost(String origin) {
        String rest = origin.substring(origin.indexOf("://") + 3);
        if (rest.startsWith("[")) return rest.substring(0, rest.indexOf(']') + 1);
        int colon = rest.indexOf(':');
        return colon < 0 ? rest : rest.substring(0, colon);
    }

    /** How the review shows an origin: "app.uniswap.org" for https, the full origin for local http. */
    static String originDisplay(String origin) {
        return origin.startsWith("https://") ? origin.substring("https://".length()) : origin;
    }

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
        if (!handles(method)) throw new JSONException("Unsupported method");
        String from = Eip1559Request.optionalFrom(json);
        String origin = optionalOrigin(json);
        java.util.List<String> fields = new java.util.ArrayList<>(java.util.Arrays.asList(
                "id", "method", "chainId", PERSONAL_SIGN.equals(method) ? "message" : "typedData"));
        if (from != null) fields.add("from");
        if (origin != null) fields.add("origin");
        Eip1559Request.requireExactFields(json, fields.toArray(new String[0]));
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
            if (Eip7702.isAuthorizationTuple(bytes)) throw RequestRefusal.delegation("message is a 0x05 authorization tuple");
            MessageRequest personal = new MessageRequest(id, chainId, Kind.PERSONAL, PersonalMessage.of(bytes), null);
            personal.from = from;
            personal.origin = origin;
            return personal;
        }
        Eip712.TypedData typed;
        try {
            typed = Eip712.parse(json.getString("typedData"));
        } catch (Eip712.InvalidTypedData e) {
            throw new JSONException(e.getMessage());
        }
        String delegation = Eip7702.typedDataDelegation(typed);
        if (delegation != null) throw RequestRefusal.delegation(delegation);
        MessageRequest typedRequest = new MessageRequest(id, chainId, Kind.TYPED_DATA, null, typed);
        typedRequest.from = from;
        typedRequest.origin = origin;
        return typedRequest;
    }

    /** The 32 bytes that will be signed, derived only from the parsed message object. */
    byte[] digest() {
        return kind == Kind.PERSONAL ? personal.digest() : typedData.digest();
    }
}
