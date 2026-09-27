package dev.phonevault.signer;

import org.web3j.crypto.Keys;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The ERC-20 token list built into the APK ({@code res/raw/tokens.json}). It is display metadata
 * only: it lets the review say "50 USDC" instead of a raw uint256, and it never changes what is
 * signed.
 *
 * <p>Integrity: the file's SHA-256 is pinned below, so the list can only change together with the
 * code in an app release (and the APK signature). A file that does not match the pin, or that
 * breaks any rule in {@link #parse}, is refused as a whole and the review treats every contract as
 * unknown. There is no update path at runtime; a signed, updatable list is future work
 * (path-to-release.md §2). Sources for every entry: {@code app/token-list/SOURCES.md}.
 *
 * <p>The Mac companion compiles the SAME file in (companion/src-tauri/src/tokens.rs) and its
 * tests check this pin and its own against the file's bytes.
 */
final class TokenList {
    /** SHA-256 of app/src/main/res/raw/tokens.json. Change only together with the file. */
    static final String PINNED_SHA256 = "1021c5c5be1393df34c089d79e48aada223c6517ab03e70035efd0132e081506";

    static final int MAX_DECIMALS = 36;
    private static final int MAX_BYTES = 64 * 1024;

    static final class Token {
        final long chainId;
        /** lower-case 0x address; {@link #checksumAddress()} for display */
        final String address;
        final String symbol;
        final String name;
        final int decimals;

        Token(long chainId, String address, String symbol, String name, int decimals) {
            this.chainId = chainId;
            this.address = address;
            this.symbol = symbol;
            this.name = name;
            this.decimals = decimals;
        }

        String checksumAddress() { return Keys.toChecksumAddress(address); }
    }

    static final class InvalidTokenListException extends Exception {
        InvalidTokenListException(String message) { super(message); }
    }

    private final Map<String, Token> byKey;
    private final boolean available;
    private final String problem;

    private TokenList(Map<String, Token> byKey, boolean available, String problem) {
        this.byKey = Collections.unmodifiableMap(byKey);
        this.available = available;
        this.problem = problem;
    }

    /** No tokens: every contract is unknown. */
    static TokenList empty() { return new TokenList(new HashMap<>(), true, null); }

    /** Used when the bundled list failed its integrity check: every contract is unknown, and the review says why. */
    static TokenList unavailable(String problem) { return new TokenList(new HashMap<>(), false, problem); }

    /** True unless the built-in list was refused. */
    boolean available() { return available; }

    String problem() { return problem; }

    int size() { return byKey.size(); }

    /** The token at {@code address} on {@code chainId}, or null when the contract is not in the list. */
    Token lookup(long chainId, String address) {
        if (address == null) return null;
        return byKey.get(key(chainId, address.toLowerCase(Locale.ROOT)));
    }

    /** Loads the bundled bytes: refused unless their SHA-256 equals {@link #PINNED_SHA256}. */
    static TokenList loadPinned(byte[] bytes) throws InvalidTokenListException {
        if (bytes == null || bytes.length == 0 || bytes.length > MAX_BYTES)
            throw new InvalidTokenListException("token list is missing or too large");
        String actual = sha256Hex(bytes);
        if (!PINNED_SHA256.equals(actual))
            throw new InvalidTokenListException("token list hash " + actual + " does not match the pinned " + PINNED_SHA256);
        return parse(new String(bytes, StandardCharsets.UTF_8));
    }

    static String sha256Hex(byte[] bytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder out = new StringBuilder(64);
            for (byte b : digest) out.append(String.format(Locale.ROOT, "%02x", b & 0xff));
            return out.toString();
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    /**
     * Strict parse (duplicate keys, unknown fields and nulls are errors). Rules, mirrored by the
     * companion: version 1; chain in the phone's allow-list; address 0x + 40 hex in exact EIP-55
     * casing and not zero; symbol 1-11 ASCII letters/digits; name 1-64 printable ASCII; decimals an
     * integer 0-36; no duplicate address and no duplicate symbol on the same chain.
     */
    static TokenList parse(String text) throws InvalidTokenListException {
        Object root;
        try {
            root = StrictJson.parse(text);
        } catch (StrictJson.ParseException e) {
            throw new InvalidTokenListException("token list is not strict JSON: " + e.getMessage());
        }
        Map<?, ?> top = object(root, "token list");
        exactKeys(top, "token list", "version", "tokens");
        if (!"1".equals(number(top.get("version"), "version")))
            throw new InvalidTokenListException("unsupported token list version");
        if (!(top.get("tokens") instanceof List))
            throw new InvalidTokenListException("tokens must be an array");
        List<?> entries = (List<?>) top.get("tokens");
        if (entries.isEmpty()) throw new InvalidTokenListException("token list is empty");
        Map<String, Token> byKey = new HashMap<>();
        Set<String> symbols = new HashSet<>();
        int index = 0;
        for (Object entry : entries) {
            String where = "token #" + index++;
            Map<?, ?> t = object(entry, where);
            exactKeys(t, where, "chainId", "address", "symbol", "name", "decimals");
            String chainText = number(t.get("chainId"), where + " chainId");
            if (!chainText.matches("[1-9][0-9]{0,17}")) throw new InvalidTokenListException(where + ": bad chainId");
            long chainId = Long.parseLong(chainText);
            if (!Eip1559Request.supportedChain(chainId))
                throw new InvalidTokenListException(where + ": chain " + chainId + " is not in the phone's allow-list");
            String address = string(t.get("address"), where + " address");
            if (!address.matches("0x[0-9a-fA-F]{40}") || address.matches("0x0{40}"))
                throw new InvalidTokenListException(where + ": bad address");
            if (!Keys.toChecksumAddress(address).equals(address))
                throw new InvalidTokenListException(where + ": address is not in EIP-55 checksum casing");
            String symbol = string(t.get("symbol"), where + " symbol");
            if (!symbol.matches("[A-Za-z0-9]{1,11}")) throw new InvalidTokenListException(where + ": bad symbol");
            String name = string(t.get("name"), where + " name");
            if (!name.matches("[\\x20-\\x7e]{1,64}") || !name.trim().equals(name))
                throw new InvalidTokenListException(where + ": bad name");
            String decimalsText = number(t.get("decimals"), where + " decimals");
            if (!decimalsText.matches("0|[1-9][0-9]?")) throw new InvalidTokenListException(where + ": bad decimals");
            int decimals = Integer.parseInt(decimalsText);
            if (decimals > MAX_DECIMALS) throw new InvalidTokenListException(where + ": too many decimals");
            String lower = address.toLowerCase(Locale.ROOT);
            if (byKey.put(key(chainId, lower), new Token(chainId, lower, symbol, name, decimals)) != null)
                throw new InvalidTokenListException(where + ": duplicate address on chain " + chainId);
            if (!symbols.add(chainId + ":" + symbol.toUpperCase(Locale.ROOT)))
                throw new InvalidTokenListException(where + ": duplicate symbol " + symbol + " on chain " + chainId);
        }
        return new TokenList(byKey, true, null);
    }

    private static String key(long chainId, String lowerAddress) { return chainId + ":" + lowerAddress; }

    private static Map<?, ?> object(Object value, String what) throws InvalidTokenListException {
        if (!(value instanceof Map)) throw new InvalidTokenListException(what + " must be an object");
        return (Map<?, ?>) value;
    }

    private static void exactKeys(Map<?, ?> map, String what, String... keys) throws InvalidTokenListException {
        Set<Object> expected = new HashSet<>(java.util.Arrays.asList((Object[]) keys));
        if (!map.keySet().equals(expected)) throw new InvalidTokenListException(what + ": fields must be exactly " + expected);
    }

    private static String number(Object value, String what) throws InvalidTokenListException {
        if (!(value instanceof StrictJson.Num)) throw new InvalidTokenListException(what + " must be a number");
        return ((StrictJson.Num) value).literal;
    }

    private static String string(Object value, String what) throws InvalidTokenListException {
        if (!(value instanceof String)) throw new InvalidTokenListException(what + " must be a string");
        return (String) value;
    }
}
