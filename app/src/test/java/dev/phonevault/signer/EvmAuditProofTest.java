package dev.phonevault.signer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONObject;
import org.junit.Test;
import org.web3j.utils.Numeric;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Tests from the adversarial audit of the EVM signing path (host = untrusted). The findings are
 * fixed; each test now asserts the fixed behaviour.
 */
public final class EvmAuditProofTest {

    private static String hex(String s) { return Numeric.toHexString(s.getBytes(StandardCharsets.UTF_8)); }

    // ------------------------------------------------------------------ F1: StrictJson \\u escapes

    /**
     * StrictJson.hex4 accepts ASCII HEXDIG only (RFC 8259; the companion's is_ascii_hexdigit):
     * Arabic-Indic and fullwidth digits are refused, so an odd spelling of typed data cannot reach
     * the signed EIP-712 digest.
     */
    @Test public void f1_strictJsonRefusesNonAsciiHexDigitsInUnicodeEscapes() throws Exception {
        for (String bad : new String[] {"\"\\u\uFF10\uFF10\uFF14\uFF11\"", "\"\\u\u0660\u0660\u0664\u0661\"", "\"\\u+041\""}) {
            try { StrictJson.parse(bad); fail("accepted " + bad); } catch (StrictJson.ParseException expected) { }
        }
        assertEquals("A", StrictJson.parse("\"\\u0041\""));
        assertEquals("\u00ff\u00FF", StrictJson.parse("\"\\u00ff\\u00FF\""));

        String plain = "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"}],"
                + "\"Mail\":[{\"name\":\"contents\",\"type\":\"string\"}]},\"primaryType\":\"Mail\","
                + "\"domain\":{\"name\":\"X\"},\"message\":{\"contents\":\"A\"}}";
        String odd = plain.replace("{\"contents\":\"A\"}", "{\"\\u\uFF10\uFF10\uFF16\uFF13ontents\":\"\\u\u0660\u0660\u0664\u0661\"}");
        assertNotEquals(plain, odd);
        Eip712.parse(plain).digest();
        try { Eip712.parse(odd); fail("odd escapes reached the typed-data parser"); } catch (Exception expected) { }
    }

    // ------------------------------------------------------------------ F2: invisible characters

    /**
     * Default-ignorable code points that are NOT category Cf (U+034F, variation selectors, Hangul
     * fillers, …) now force the unreadable-data path in personal_sign and are escaped by visible().
     */
    @Test public void f2_invisibleDefaultIgnorableCharactersAreFlagged() throws Exception {
        String hidden = "I agree\u034F to the terms\uFE0F";
        MessageRequest b = MessageRequest.parse(new JSONObject().put("id", "b").put("method", "personal_sign")
                .put("chainId", "0x1").put("message", hex(hidden)));
        assertNull("hidden-char message is not shown as readable text", b.personal.text);
        assertEquals(MessageReview.Category.UNREADABLE,
                MessageReview.of(b, "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826").category);

        assertEquals("Uni\\u{034F}swap", MessageReview.visible("Uni\u034Fswap"));
        assertEquals("Uni\\u{3164}swap", MessageReview.visible("Uni\u3164swap"));
        assertEquals("Uni\\u{115F}swap", MessageReview.visible("Uni\u115Fswap"));
        assertEquals("Uni\\u{FE0F}swap", MessageReview.visible("Uni\uFE0Fswap"));
        assertEquals("Uni\\u{200B}swap", MessageReview.visible("Uni\u200Bswap"));
        assertEquals("Uni\\u{E0041}swap", MessageReview.visible("Uni" + new String(Character.toChars(0xE0041)) + "swap"));
        for (int cp : new int[] {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180F, 0x3164, 0xFE00, 0xFE0F,
                0xFFA0, 0xE0000, 0xE0FFF, 0x200B, 0x00AD}) {
            assertFalse(Integer.toHexString(cp), PersonalMessage.printable(cp));
        }
        for (int cp : new int[] {'A', 0xE9, 0xAC00 /* Hangul syllable */, 0x1F600 /* emoji */}) {
            assertTrue(Integer.toHexString(cp), PersonalMessage.printable(cp));
        }
    }

    // ------------------------------------------------------------------ F3: flat-frame parser leniency

    /**
     * parseStrictRequest refuses anything after the closing brace (a NUL included) and validates
     * every \\u escape (no "\\u+041"); only JSON whitespace may follow the object.
     */
    @Test public void f3_flatFrameRefusesTrailingDataAndBadUnicodeEscapes() throws Exception {
        for (String bad : new String[] {
                "{\"id\":\"a\",\"method\":\"getAddress\"}\u0000{\"method\":\"signEip1559\",\"to\":\"0xevil\"}",
                "{\"id\":\"a\",\"method\":\"getAddress\"}\u0000",
                "{\"id\":\"\\u+041\",\"method\":\"getAddress\"}",
                "{\"id\":\"\\u\uFF10\uFF10\uFF14\uFF11\",\"method\":\"getAddress\"}",
                "{\"id\":\"a\",/*c*/\"method\":\"getAddress\"}",
                "{\"id\":\"a\\'\",\"method\":\"getAddress\"}"}) {
            try { AccessoryTransport.parseStrictRequest(bad); fail("accepted " + bad); } catch (org.json.JSONException expected) { }
        }
        JSONObject ok = AccessoryTransport.parseStrictRequest("{\"id\":\"\\u0041\",\"method\":\"getAddress\"} \r");
        assertEquals("A", ok.getString("id"));
        assertEquals("getAddress", ok.getString("method"));
    }

    // ------------------------------------------------------------------ F4 (JVM): regex before length check

    private static String longOrigin() {
        StringBuilder o = new StringBuilder("https://a");
        for (int i = 0; i < 15000; i++) o.append(".a");
        return o.toString(); // ~30 KB: fits a 32 KiB USB frame
    }

    /**
     * The 255-character origin limit is checked BEFORE the host-name regex (no StackOverflowError),
     * and the transport's reader catches Throwable: even an Error thrown by a listener ends the
     * session and is reported through onDisconnected.
     */
    @Test public void f4_longOriginIsRefusedByLengthAndTransportErrorsEndTheSession() throws Exception {
        JSONObject request = new JSONObject().put("id", "m").put("method", "personal_sign").put("chainId", "0x1")
                .put("message", hex("hello")).put("origin", longOrigin());
        try {
            MessageRequest.parse(request);
            fail("expected a refusal");
        } catch (org.json.JSONException expected) {
            assertTrue(expected.getMessage().contains("origin"));
        }

        CountDownLatch disconnected = new CountDownLatch(1);
        AtomicReference<String> reason = new AtomicReference<>();
        AccessoryTransport.Listener listener = new AccessoryTransport.Listener() {
            @Override public void onConnected(AccessoryTransport source) { }
            @Override public void onRequest(AccessoryTransport source, JSONObject json) {
                throw new StackOverflowError("listener blew its stack");
            }
            @Override public void onDisconnected(AccessoryTransport source, String why) { reason.set(why); disconnected.countDown(); }
        };
        byte[] line = (new JSONObject().put("id", "x").put("method", "getAddress").toString() + "\n").getBytes(StandardCharsets.UTF_8);
        Closeable fd = () -> { };
        AccessoryTransport t = AccessoryTransport.openForTest(fd, new ByteArrayInputStream(line), new ByteArrayOutputStream(), listener);
        t.start();
        assertTrue("session reports the failure", disconnected.await(5, TimeUnit.SECONDS));
        assertTrue(reason.get(), reason.get().contains("StackOverflowError"));
        assertTrue("transport closed", t.isClosed());
    }
}
