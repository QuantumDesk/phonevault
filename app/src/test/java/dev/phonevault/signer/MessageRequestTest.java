package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.web3j.crypto.Credentials;
import org.web3j.utils.Numeric;

import java.nio.charset.StandardCharsets;

/** The USB request schema for personal_sign / eth_signTypedData_v4 and the signing session. */
public final class MessageRequestTest {
    private static final Credentials OTHER_TEST_KEY = Credentials.create(
            "6c0883a69102937d6231471b5dbb6204fe51296170827966f278a5e6f4f4f5f");

    static JSONObject personal(String hex) throws Exception {
        return new JSONObject().put("id", "msg-1").put("method", "personal_sign").put("chainId", "0x1").put("message", hex);
    }

    static JSONObject typed(String typedData) throws Exception {
        return new JSONObject().put("id", "td-1").put("method", "eth_signTypedData_v4").put("chainId", "0x1").put("typedData", typedData);
    }

    @Test public void typedDataSurvivesTheStrictUsbFrameAsAnEscapedString() throws Exception {
        String typedData = MessageSigningVectorsTest.vector("all-atomic-types", "typedData");
        // What the host sends: one flat, all-string JSON object; the typed data is a JSON string value.
        String line = typed(typedData).toString();
        assertTrue(line.getBytes(StandardCharsets.UTF_8).length < AccessoryTransport.MAX_REQUEST_BYTES);
        JSONObject framed = AccessoryTransport.parseStrictRequest(line);
        MessageRequest request = MessageRequest.parse(framed);
        assertEquals(MessageRequest.Kind.TYPED_DATA, request.kind);
        assertEquals(MessageSigningVectorsTest.vector("all-atomic-types", "digest"), Numeric.toHexString(request.digest()));
    }

    @Test public void personalMessageRoundTripSignsTheDisplayedBytes() throws Exception {
        String hex = MessageSigningVectorsTest.vector("personal-hello", "message");
        MessageRequest request = MessageRequest.parse(AccessoryTransport.parseStrictRequest(personal(hex).toString()));
        assertEquals("Hello, Phone Vault!", request.personal.text);
        MessageApprovalSession session = new MessageApprovalSession(request, MessageSigningVectorsTest.COW);
        JSONObject response = session.signIfIdentityUnchanged(MessageSigningVectorsTest.COW);
        assertEquals("msg-1", response.getString("id"));
        assertEquals("approved", response.getString("status"));
        assertEquals(MessageSigningVectorsTest.COW.getAddress(), response.getString("address"));
        assertEquals(MessageSigningVectorsTest.vector("personal-hello", "signature"), response.getString("signature"));
        assertEquals(MessageSigningVectorsTest.vector("personal-hello", "digest"), response.getString("digest"));
        assertEquals(5, response.length());
        assertTrue(session.review.details.toString().contains(session.digestHex()));
    }

    @Test public void sessionRefusesAChangedIdentity() throws Exception {
        MessageRequest request = MessageRequest.parse(personal("0x68656c6c6f"));
        MessageApprovalSession session = new MessageApprovalSession(request, MessageSigningVectorsTest.COW);
        try {
            session.signIfIdentityUnchanged(OTHER_TEST_KEY);
            fail("signed with a different identity than the one reviewed");
        } catch (IllegalStateException expected) {
        }
        try {
            session.signIfIdentityUnchanged(null);
            fail("signed without an identity");
        } catch (IllegalStateException expected) {
        }
    }

    @Test public void schemaIsExact() throws Exception {
        rejects(personal("0x68656c6c6f").put("extra", "1"));
        rejects(personal("0x68656c6c6f").put("typedData", "{}"));
        JSONObject missing = personal("0x68656c6c6f");
        missing.remove("chainId");
        rejects(missing);
        rejects(typed("{}").put("message", "0x00"));
        rejects(personal("0x68656c6c6f").put("method", "eth_sign")); // raw eth_sign is never offered
        rejects(personal("0x68656c6c6f").put("method", "eth_signTypedData_v3"));
        rejects(personal("0x68656c6c6f").put("id", "bad id with spaces"));
    }

    @Test public void chainIdMustBeAReviewedNetwork() throws Exception {
        rejects(personal("0x68656c6c6f").put("chainId", "0x0"));
        rejects(personal("0x68656c6c6f").put("chainId", "0x01"));
        rejects(personal("0x68656c6c6f").put("chainId", "0x38")); // BNB: no reviewed profile
        rejects(personal("0x68656c6c6f").put("chainId", "1"));
        MessageRequest base = MessageRequest.parse(personal("0x68656c6c6f").put("chainId", "0x2105"));
        assertEquals(8453, base.chainId);
    }

    @Test public void personalMessageMustBeBoundedEvenHex() throws Exception {
        rejects(personal("0x"));
        rejects(personal("0x123"));
        rejects(personal("68656c6c6f"));
        rejects(personal("0xzz"));
        rejects(personal("hello"));
        StringBuilder big = new StringBuilder("0x");
        for (int i = 0; i <= PersonalMessage.MAX_MESSAGE_BYTES; i++) big.append("61");
        rejects(personal(big.toString()));
        String max = big.substring(0, big.length() - 2);
        MessageRequest ok = MessageRequest.parse(personal(max));
        assertEquals(PersonalMessage.MAX_MESSAGE_BYTES, ok.personal.length());
        assertTrue(MessageRequest.parse(personal("0x48454C4C4F")).personal.text.equals("HELLO"));
    }

    @Test public void typedDataErrorsSurfaceAsJsonExceptions() throws Exception {
        rejects(typed("not json"));
        rejects(typed(MessageSigningVectorsTest.vector("eip712-mail", "typedData").replace("\"primaryType\":\"Mail\"", "\"primaryType\":\"Letter\"")));
    }

    @Test public void handlesOnlyTheTwoMessageMethods() {
        assertTrue(MessageRequest.handles("personal_sign"));
        assertTrue(MessageRequest.handles("eth_signTypedData_v4"));
        assertFalse(MessageRequest.handles("eth_sign"));
        assertFalse(MessageRequest.handles("signEip1559"));
        assertFalse(MessageRequest.handles(""));
    }

    @Test public void strictJsonKeepsNumbersExactAndRefusesAmbiguity() throws Exception {
        Object parsed = StrictJson.parse("{\"a\":115792089237316195423570985008687907853269984665640564039457584007913129639935,\"b\":[true,false,\"\\u00e9\"]}");
        assertNotNull(parsed);
        String[] bad = {"{\"a\":1,\"a\":2}", "{\"a\":null}", "{\"a\":01}", "{\"a\":1.}", "{\"a\":.5}", "{\"a\":+1}",
                "{\"a\":\"\\x41\"}", "{\"a\":\"\\ud800\"}", "{\"a\":\"\\udc00x\"}", "{'a':1}", "{\"a\":1,}", "[1,]",
                "{\"a\":1} x", "", "{\"a\":tru}", "{\"a\":NaN}", "{\"a\":\"line\nbreak\"}"};
        for (String text : bad) {
            try {
                StrictJson.parse(text);
                fail("accepted " + text);
            } catch (StrictJson.ParseException expected) {
            }
        }
        StringBuilder deep = new StringBuilder();
        for (int i = 0; i <= StrictJson.MAX_DEPTH + 1; i++) deep.append('[');
        for (int i = 0; i <= StrictJson.MAX_DEPTH + 1; i++) deep.append(']');
        try {
            StrictJson.parse(deep.toString());
            fail("accepted excessive nesting");
        } catch (StrictJson.ParseException expected) {
        }
    }

    private static void rejects(JSONObject json) {
        try {
            MessageRequest.parse(json);
            fail("accepted " + json);
        } catch (JSONException expected) {
        } catch (RuntimeException unexpected) {
            fail("threw " + unexpected + " instead of a schema error for " + json);
        }
    }
}
