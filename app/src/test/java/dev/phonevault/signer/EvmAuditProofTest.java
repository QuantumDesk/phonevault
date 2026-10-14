package dev.phonevault.signer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
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
 * Proof tests from the adversarial audit of the EVM signing path (host = untrusted). Each test
 * DEMONSTRATES current behaviour that the audit report flags; they pass against the code as it is.
 * When a finding is fixed, flip the corresponding assertion.
 */
public final class EvmAuditProofTest {

    private static String hex(String s) { return Numeric.toHexString(s.getBytes(StandardCharsets.UTF_8)); }

    // ------------------------------------------------------------------ F1: StrictJson \\u escapes

    /**
     * StrictJson.hex4 uses Character.digit(c, 16), which accepts Unicode digits (Arabic-Indic,
     * fullwidth 0-9 / A-F). RFC 8259 allows only ASCII HEXDIG, and the companion's Rust parser
     * (message.rs hex4: is_ascii_hexdigit) refuses them, so the "parse identically" promise of
     * StrictJson's class comment does not hold.
     */
    @Test public void f1_strictJsonAcceptsNonAsciiHexDigitsInUnicodeEscapes() throws Exception {
        assertEquals("A", StrictJson.parse("\"\\u\uFF10\uFF10\uFF14\uFF11\"")); // fullwidth 0041
        assertEquals("A", StrictJson.parse("\"\\u\u0660\u0660\u0664\u0661\"")); // Arabic-Indic 0041

        // ...and it reaches the signed EIP-712 digest: the phone signs typed data whose key and
        // value are spelled with such escapes, with the same digest as the plain spelling.
        String plain = "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"}],"
                + "\"Mail\":[{\"name\":\"contents\",\"type\":\"string\"}]},\"primaryType\":\"Mail\","
                + "\"domain\":{\"name\":\"X\"},\"message\":{\"contents\":\"A\"}}";
        String odd = plain.replace("{\"contents\":\"A\"}", "{\"\\u\uFF10\uFF10\uFF16\uFF13ontents\":\"\\u\u0660\u0660\u0664\u0661\"}");
        assertNotEquals(plain, odd);
        assertArrayEquals(Eip712.parse(plain).digest(), Eip712.parse(odd).digest());
    }

    // ------------------------------------------------------------------ F2: invisible characters

    /**
     * PersonalMessage promises that zero-width/formatting characters force the "unreadable data"
     * path, and MessageReview.visible() promises to escape anything that could hide in a string.
     * Default-ignorable code points that are NOT category Cf slip through both: U+034F COMBINING
     * GRAPHEME JOINER (Mn), U+FE0F VARIATION SELECTOR-16 (Mn), U+115F / U+3164 Hangul fillers
     * (Lo, render blank). Two different signed byte strings then render identically.
     */
    @Test public void f2_invisibleDefaultIgnorableCharactersAreShownAsPlainText() throws Exception {
        String shown = "I agree to the terms";
        String hidden = "I agree\u034F to the terms\uFE0F";
        MessageRequest a = MessageRequest.parse(new JSONObject().put("id", "a").put("method", "personal_sign")
                .put("chainId", "0x1").put("message", hex(shown)));
        MessageRequest b = MessageRequest.parse(new JSONObject().put("id", "b").put("method", "personal_sign")
                .put("chainId", "0x1").put("message", hex(hidden)));
        assertNotNull("hidden-char message is treated as readable text", b.personal.text);
        assertEquals(MessageReview.Category.MESSAGE,
                MessageReview.of(b, "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826").category); // not UNREADABLE, no DANGER
        assertFalse(java.util.Arrays.equals(a.digest(), b.digest()));

        // EIP-712 strings: visible() leaves these unescaped (contrast: U+200B is escaped).
        for (String s : new String[] {"Uni\u034Fswap", "Uni\u3164swap", "Uni\u115Fswap", "Uni\uFE0Fswap"}) {
            assertEquals(s, MessageReview.visible(s));
        }
        assertEquals("Uni\\u{200B}swap", MessageReview.visible("Uni\u200Bswap"));
    }

    // ------------------------------------------------------------------ F3: flat-frame parser leniency

    /**
     * parseStrictRequest ends at nextClean() == 0, so a raw NUL after the closing brace hides any
     * trailing data; and JSONTokener's \\u uses Integer.parseInt, so "\\u+041" decodes to "A".
     * (JVM org.json 20240303; Android's JSONTokener has the same nextClean/parseInt shape.)
     */
    @Test public void f3_flatFrameAcceptsNulHiddenTrailingDataAndSignedUnicodeEscape() throws Exception {
        JSONObject r = AccessoryTransport.parseStrictRequest(
                "{\"id\":\"a\",\"method\":\"getAddress\"}\u0000{\"method\":\"signEip1559\",\"to\":\"0xevil\"}");
        assertEquals("getAddress", r.getString("method"));
        assertEquals("A", AccessoryTransport.parseStrictRequest("{\"id\":\"\\u+041\",\"method\":\"getAddress\"}").getString("id"));
    }

    // ------------------------------------------------------------------ F4 (JVM): regex before length check

    private static String longOrigin() {
        StringBuilder o = new StringBuilder("https://a");
        for (int i = 0; i < 15000; i++) o.append(".a");
        return o.toString(); // ~30 KB: fits a 32 KiB USB frame
    }

    /**
     * MessageRequest.optionalOrigin runs the host-name regex BEFORE the 255-character length check.
     * On HotSpot the repeated group recurses per label and throws StackOverflowError — an Error,
     * which AccessoryTransport's reader (catch Exception) does not catch: the reader thread dies,
     * fail()/onDisconnected never run and the session is left open but deaf. (On the phone the
     * regex engine is ICU, which backtracks on a heap stack; see report: unconfirmed on device.)
     */
    @Test public void f4_longOriginOverflowsRegexAndWedgesTheTransportOnJvm() throws Exception {
        JSONObject request = new JSONObject().put("id", "m").put("method", "personal_sign").put("chainId", "0x1")
                .put("message", hex("hello")).put("origin", longOrigin());
        try {
            MessageRequest.parse(request);
            fail("expected an error");
        } catch (StackOverflowError expected) {
            // the length check at MessageRequest.java:65 is never reached
        }

        CountDownLatch disconnected = new CountDownLatch(1);
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        AccessoryTransport.Listener listener = new AccessoryTransport.Listener() {
            @Override public void onConnected(AccessoryTransport source) { }
            @Override public void onRequest(AccessoryTransport source, JSONObject json) {
                try { MessageRequest.parse(json); } catch (Exception e) { throw new RuntimeException(e); }
                catch (Error e) { thrown.set(e); throw e; }
            }
            @Override public void onDisconnected(AccessoryTransport source, String reason) { disconnected.countDown(); }
        };
        byte[] line = (request.toString() + "\n").getBytes(StandardCharsets.UTF_8);
        assertTrue(line.length < AccessoryTransport.MAX_REQUEST_BYTES);
        Closeable fd = () -> { };
        AccessoryTransport t = AccessoryTransport.openForTest(fd, new ByteArrayInputStream(line), new ByteArrayOutputStream(), listener);
        t.start();
        // Even the end of input (which normally ends the session with "USB cable disconnected") is never seen.
        assertFalse("session never reports the failure", disconnected.await(2, TimeUnit.SECONDS));
        assertTrue(thrown.get() instanceof StackOverflowError);
        assertFalse("transport left open with a dead reader", t.isClosed());
        t.close();
    }
}
