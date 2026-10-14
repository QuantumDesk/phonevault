package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

/** The strict JSON reader under typed data: only RFC 8259 spellings reach a signed digest. */
public final class StrictJsonTest {

    /**
     * StrictJson.hex4 accepts ASCII HEXDIG only (RFC 8259; the companion's is_ascii_hexdigit):
     * Arabic-Indic and fullwidth digits are refused, so an odd spelling of typed data cannot reach
     * the signed EIP-712 digest.
     */
    @Test public void unicodeEscapesAcceptAsciiHexDigitsOnly() throws Exception {
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
}
