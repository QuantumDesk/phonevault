package dev.phonevault.signer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A deliberately small RFC 8259 parser for the nested typed-data payload.
 *
 * <p>Android's built-in {@code org.json} silently keeps the last of two duplicate keys and turns
 * large integers into doubles, and it differs from the {@code org.json} artifact the JVM tests
 * run against. Anything that feeds a signature must parse identically on the phone and in the
 * tests, so typed data goes through this parser instead:
 * <ul>
 *   <li>objects become an unmodifiable insertion-ordered map; a duplicate key is an error;</li>
 *   <li>numbers are kept as their exact literal text ({@link Num}); nothing is rounded;</li>
 *   <li>strings are decoded strictly: raw control characters and unpaired surrogates are errors;</li>
 *   <li>{@code null} is an error (typed data has no null);</li>
 *   <li>nesting is bounded and trailing data is an error.</li>
 * </ul>
 * The companion's Rust parser (companion/src-tauri/src/message.rs) enforces the same rules.
 */
final class StrictJson {
    static final int MAX_DEPTH = 16;

    /** A JSON number, kept as its literal text (validated against the RFC 8259 grammar). */
    static final class Num {
        final String literal;
        Num(String literal) { this.literal = literal; }
        @Override public String toString() { return literal; }
    }

    static final class ParseException extends Exception {
        ParseException(String message) { super(message); }
    }

    private final String text;
    private int at;

    private StrictJson(String text) { this.text = text; }

    /** Parse one JSON value occupying the whole text (surrounding whitespace allowed). */
    static Object parse(String text) throws ParseException {
        if (text == null) throw new ParseException("JSON text is missing");
        StrictJson parser = new StrictJson(text);
        parser.skipWhitespace();
        Object value = parser.value(0);
        parser.skipWhitespace();
        if (parser.at != text.length()) throw new ParseException("Trailing data after JSON value");
        return value;
    }

    private Object value(int depth) throws ParseException {
        if (depth > MAX_DEPTH) throw new ParseException("JSON nesting deeper than " + MAX_DEPTH);
        if (at >= text.length()) throw new ParseException("JSON ended early");
        char c = text.charAt(at);
        switch (c) {
            case '{': return object(depth);
            case '[': return array(depth);
            case '"': return string();
            case 't': literal("true"); return Boolean.TRUE;
            case 'f': literal("false"); return Boolean.FALSE;
            case 'n': throw new ParseException("null is not allowed in typed data");
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return number();
                throw new ParseException("Unexpected character in JSON at offset " + at);
        }
    }

    private Map<String, Object> object(int depth) throws ParseException {
        at++; // '{'
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        skipWhitespace();
        if (peek() == '}') { at++; return Collections.unmodifiableMap(map); }
        while (true) {
            skipWhitespace();
            if (peek() != '"') throw new ParseException("JSON object keys must be strings");
            String key = string();
            if (map.containsKey(key)) throw new ParseException("Duplicate JSON key: " + key);
            skipWhitespace();
            if (peek() != ':') throw new ParseException("Missing ':' after JSON key");
            at++;
            skipWhitespace();
            map.put(key, value(depth + 1));
            skipWhitespace();
            char next = peek();
            at++;
            if (next == '}') return Collections.unmodifiableMap(map);
            if (next != ',') throw new ParseException("Missing ',' between JSON object members");
        }
    }

    private List<Object> array(int depth) throws ParseException {
        at++; // '['
        ArrayList<Object> list = new ArrayList<>();
        skipWhitespace();
        if (peek() == ']') { at++; return Collections.unmodifiableList(list); }
        while (true) {
            skipWhitespace();
            list.add(value(depth + 1));
            skipWhitespace();
            char next = peek();
            at++;
            if (next == ']') return Collections.unmodifiableList(list);
            if (next != ',') throw new ParseException("Missing ',' between JSON array elements");
        }
    }

    private String string() throws ParseException {
        at++; // opening quote
        StringBuilder out = new StringBuilder();
        while (true) {
            if (at >= text.length()) throw new ParseException("Unterminated JSON string");
            char c = text.charAt(at++);
            if (c == '"') break;
            if (c < 0x20) throw new ParseException("Raw control character in JSON string");
            if (c != '\\') { out.append(c); continue; }
            if (at >= text.length()) throw new ParseException("Unterminated JSON escape");
            char e = text.charAt(at++);
            switch (e) {
                case '"': out.append('"'); break;
                case '\\': out.append('\\'); break;
                case '/': out.append('/'); break;
                case 'b': out.append('\b'); break;
                case 'f': out.append('\f'); break;
                case 'n': out.append('\n'); break;
                case 'r': out.append('\r'); break;
                case 't': out.append('\t'); break;
                case 'u': out.append(hex4()); break;
                default: throw new ParseException("Invalid JSON escape \\" + e);
            }
        }
        String s = out.toString();
        // Unpaired surrogates have no UTF-8 encoding: refuse rather than substitute '?'.
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))) {
                    throw new ParseException("Unpaired surrogate in JSON string");
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                throw new ParseException("Unpaired surrogate in JSON string");
            }
        }
        return s;
    }

    private char hex4() throws ParseException {
        if (at + 4 > text.length()) throw new ParseException("Truncated \\u escape");
        int v = 0;
        for (int i = 0; i < 4; i++) {
            int d = Character.digit(text.charAt(at + i), 16);
            if (d < 0) throw new ParseException("Invalid \\u escape");
            v = (v << 4) | d;
        }
        at += 4;
        return (char) v;
    }

    private Num number() throws ParseException {
        int start = at;
        if (peek() == '-') at++;
        if (peek() == '0') {
            at++;
        } else if (peek() >= '1' && peek() <= '9') {
            while (peek() >= '0' && peek() <= '9') at++;
        } else {
            throw new ParseException("Invalid JSON number");
        }
        if (peek() == '.') {
            at++;
            if (!(peek() >= '0' && peek() <= '9')) throw new ParseException("Invalid JSON number");
            while (peek() >= '0' && peek() <= '9') at++;
        }
        if (peek() == 'e' || peek() == 'E') {
            at++;
            if (peek() == '+' || peek() == '-') at++;
            if (!(peek() >= '0' && peek() <= '9')) throw new ParseException("Invalid JSON number");
            while (peek() >= '0' && peek() <= '9') at++;
        }
        return new Num(text.substring(start, at));
    }

    private void literal(String word) throws ParseException {
        if (!text.startsWith(word, at)) throw new ParseException("Invalid JSON literal");
        at += word.length();
    }

    private char peek() { return at < text.length() ? text.charAt(at) : '\0'; }

    private void skipWhitespace() {
        while (at < text.length()) {
            char c = text.charAt(at);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') at++;
            else return;
        }
    }
}
