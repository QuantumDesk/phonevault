package dev.phonevault.signer;

import org.web3j.crypto.Hash;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * An EIP-191 version 0x45 ({@code personal_sign}) message: raw bytes, signed as
 * keccak256("\x19Ethereum Signed Message:\n" ‖ decimal byte length ‖ bytes).
 *
 * <p>The bytes are the only input to both the digest and the display. They are shown as text
 * only when they are strict UTF-8 made entirely of printable characters (plus line feeds and
 * tabs); anything else — control or formatting characters, bidi overrides, zero-width
 * characters, private-use or unassigned code points — is shown as hex with an "unreadable data"
 * warning, because the text a person would read could differ from the bytes being signed.
 */
final class PersonalMessage {
    static final int MAX_MESSAGE_BYTES = 8192;
    private static final byte[] PREFIX = "\u0019Ethereum Signed Message:\n".getBytes(StandardCharsets.US_ASCII);

    private final byte[] bytes;
    private final byte[] digest;
    /** The message as text, or null when it is not safely readable. */
    final String text;
    /** Parsed sign-in message, or null. */
    final Siwe siwe;
    /** Why a message that starts like a sign-in message could not be parsed, or null. */
    final String siweError;

    private PersonalMessage(byte[] bytes) {
        this.bytes = bytes.clone();
        this.digest = digest(this.bytes);
        this.text = readableText(this.bytes);
        Siwe parsed = null;
        String error = null;
        if (text != null && Siwe.looksLike(text)) {
            try {
                parsed = Siwe.parse(text);
            } catch (Siwe.InvalidSiwe e) {
                error = e.getMessage();
            }
        }
        this.siwe = parsed;
        this.siweError = error;
    }

    static PersonalMessage of(byte[] bytes) {
        if (bytes == null || bytes.length == 0) throw new IllegalArgumentException("Message is empty");
        if (bytes.length > MAX_MESSAGE_BYTES) {
            throw new IllegalArgumentException("Message exceeds " + MAX_MESSAGE_BYTES + " bytes");
        }
        return new PersonalMessage(bytes);
    }

    byte[] bytes() { return bytes.clone(); }
    int length() { return bytes.length; }
    /** keccak256 of the EIP-191 0x45 envelope: exactly what is signed. */
    byte[] digest() { return digest.clone(); }

    static byte[] digest(byte[] message) {
        byte[] length = Integer.toString(message.length).getBytes(StandardCharsets.US_ASCII);
        byte[] preimage = new byte[PREFIX.length + length.length + message.length];
        System.arraycopy(PREFIX, 0, preimage, 0, PREFIX.length);
        System.arraycopy(length, 0, preimage, PREFIX.length, length.length);
        System.arraycopy(message, 0, preimage, PREFIX.length + length.length, message.length);
        return Hash.sha3(preimage);
    }

    /** Strict UTF-8 text made only of printable characters, LF and TAB (CRLF allowed); else null. */
    static String readableText(byte[] bytes) {
        String decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
        if (decoded.trim().isEmpty()) return null; // whitespace-only is not something a person can read
        for (int i = 0; i < decoded.length(); ) {
            int cp = decoded.codePointAt(i);
            int next = i + Character.charCount(cp);
            if (cp == '\r') {
                if (next >= decoded.length() || decoded.charAt(next) != '\n') return null;
            } else if (!printable(cp)) {
                return null;
            }
            i = next;
        }
        return decoded;
    }

    static boolean printable(int cp) {
        if (cp == '\n' || cp == '\t') return true;
        switch (Character.getType(cp)) {
            case Character.CONTROL:
            case Character.FORMAT:          // bidi overrides, zero-width joiners, BOM, …
            case Character.PRIVATE_USE:
            case Character.SURROGATE:
            case Character.UNASSIGNED:
            case Character.LINE_SEPARATOR:
            case Character.PARAGRAPH_SEPARATOR:
                return false;
            default:
                return true;
        }
    }
}
