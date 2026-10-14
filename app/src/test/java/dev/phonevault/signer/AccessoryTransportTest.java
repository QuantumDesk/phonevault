package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public final class AccessoryTransportTest {
    @Test public void readsOneBoundedRequestAtATime() throws Exception {
        ByteArrayInputStream input = new ByteArrayInputStream("one\ntwo\n".getBytes(StandardCharsets.UTF_8));
        assertEquals("one", AccessoryTransport.readBoundedLine(input, 8));
        assertEquals("two", AccessoryTransport.readBoundedLine(input, 8));
        assertNull(AccessoryTransport.readBoundedLine(input, 8));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsBeforeBufferingPastLimit() throws Exception {
        ByteArrayInputStream input = new ByteArrayInputStream("123456789\n".getBytes(StandardCharsets.UTF_8));
        AccessoryTransport.readBoundedLine(input, 8);
    }

    @Test public void acceptsExactlyTheLimit() throws Exception {
        ByteArrayInputStream input = new ByteArrayInputStream("12345678\n".getBytes(StandardCharsets.UTF_8));
        assertEquals("12345678", AccessoryTransport.readBoundedLine(input, 8));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsTruncatedFrameAtEndOfStream() throws Exception {
        ByteArrayInputStream input = new ByteArrayInputStream("partial".getBytes(StandardCharsets.UTF_8));
        AccessoryTransport.readBoundedLine(input, 8);
    }

    @Test(expected = java.nio.charset.CharacterCodingException.class)
    public void rejectsMalformedUtf8() throws Exception {
        ByteArrayInputStream input = new ByteArrayInputStream(new byte[]{(byte) 0xc3, 0x28, '\n'});
        AccessoryTransport.readBoundedLine(input, 8);
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsDuplicateJsonFields() throws Exception {
        AccessoryTransport.parseStrictRequest(
                "{\"id\":\"first\",\"id\":\"second\",\"method\":\"getAddress\"}");
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsNonStringJsonValues() throws Exception {
        AccessoryTransport.parseStrictRequest("{\"id\":1,\"method\":\"getAddress\"}");
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsLenientBareJsonStrings() throws Exception {
        AccessoryTransport.parseStrictRequest("{\"id\":bare,\"method\":\"getAddress\"}");
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsTrailingJsonValue() throws Exception {
        AccessoryTransport.parseStrictRequest("{\"id\":\"one\"}{} ");
    }

    @Test public void acceptsStrictFlatRequestObject() throws Exception {
        assertEquals("getAddress", AccessoryTransport.parseStrictRequest(
                "{\"id\":\"one\",\"method\":\"getAddress\"}").getString("method"));
    }

    // ------------------------------------------------------------------ the one nested field

    private static final String TX = "\"id\":\"t\",\"method\":\"signEip1559\",\"chainId\":\"0x1\",\"nonce\":\"0x0\","
            + "\"maxPriorityFeePerGas\":\"0x1\",\"maxFeePerGas\":\"0x2\",\"gasLimit\":\"0x5208\","
            + "\"to\":\"0x00000000000000000000000000000000000000aa\",\"value\":\"0x1\",\"data\":\"0x\"";
    private static final String CLAIM = "{\"changes\":[{\"asset\":\"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48\",\"delta\":\"-1\","
            + "\"symbol\":\"USDC\",\"decimals\":6},{\"asset\":\"native\",\"delta\":\"-21000\"}],\"node\":\"n\",\"block\":\"0x1\"}";

    /** What the companion sends: flat strings plus `from` and the nested `hostSimulation` object. */
    @Test public void acceptsTheHostSimulationObjectAndFrom() throws Exception {
        org.json.JSONObject r = AccessoryTransport.parseStrictRequest("{" + TX
                + ",\"from\":\"0x00000000000000000000000000000000000000bb\",\"hostSimulation\":" + CLAIM + "}");
        Eip1559Request parsed = Eip1559Request.parse(r);
        assertEquals("0x00000000000000000000000000000000000000bb", parsed.from);
        assertEquals(2, parsed.hostSimulation.changes.size());
        assertEquals(Integer.valueOf(6), parsed.hostSimulation.changes.get(0).decimals);
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsADuplicateKeyInsideTheClaim() throws Exception {
        AccessoryTransport.parseStrictRequest("{" + TX + ",\"hostSimulation\":{\"node\":\"a\",\"node\":\"b\",\"changes\":[],\"block\":\"0x1\"}}");
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsNestedValuesInAnyOtherField() throws Exception {
        AccessoryTransport.parseStrictRequest("{" + TX.replace("\"data\":\"0x\"", "\"data\":{\"x\":\"0x\"}") + "}");
    }

    @Test(expected = org.json.JSONException.class)
    public void rejectsAnUnterminatedClaim() throws Exception {
        AccessoryTransport.parseStrictRequest("{" + TX + ",\"hostSimulation\":{\"changes\":[}");
    }

    @Test public void aFractionalDecimalsIsStillRefusedBySchema() throws Exception {
        org.json.JSONObject r = AccessoryTransport.parseStrictRequest("{" + TX + ",\"hostSimulation\":"
                + CLAIM.replace("\"decimals\":6", "\"decimals\":6.0") + "}");
        try { Eip1559Request.parse(r); org.junit.Assert.fail("6.0 accepted as decimals"); }
        catch (org.json.JSONException expected) { org.junit.Assert.assertTrue(expected.getMessage().contains("decimals")); }
    }

    /**
     * parseStrictRequest refuses anything after the closing brace (a NUL included) and validates
     * every \\u escape (no "\\u+041"); only JSON whitespace may follow the object.
     */
    @Test public void flatFrameRefusesTrailingDataAndBadUnicodeEscapes() throws Exception {
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
}
