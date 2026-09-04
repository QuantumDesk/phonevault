package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

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
}
