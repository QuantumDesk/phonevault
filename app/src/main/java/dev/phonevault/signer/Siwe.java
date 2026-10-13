package dev.phonevault.signer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sign-In with Ethereum (EIP-4361) message, parsed for display only. The signature is always
 * over the raw message bytes ({@link PersonalMessage}); this class never changes what is signed.
 * A message whose first line claims to be a sign-in but does not follow the grammar is flagged
 * on the review screen rather than silently shown as plain text.
 */
final class Siwe {
    private static final String HEADER_SUFFIX = " wants you to sign in with your Ethereum account:";
    private static final Pattern HEADER = Pattern.compile(
            "(?:([A-Za-z][A-Za-z0-9+.-]*)://)?([^\\s/?#]+)" + Pattern.quote(HEADER_SUFFIX));
    private static final Pattern ADDRESS = Pattern.compile("0x[0-9a-fA-F]{40}");
    private static final Pattern CHAIN_ID = Pattern.compile("[1-9][0-9]{0,17}");
    private static final Pattern NONCE = Pattern.compile("[A-Za-z0-9]{8,64}");
    private static final Pattern DATE_TIME = Pattern.compile(
            "[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})");
    private static final Pattern URI = Pattern.compile("[A-Za-z][A-Za-z0-9+.-]*:\\S+");
    private static final Pattern URI_AUTHORITY = Pattern.compile("[A-Za-z][A-Za-z0-9+.-]*://([^/?#]*).*");

    final String scheme;
    final String domain;
    final String address;
    final String statement;
    final String uri;
    final String version;
    final long chainId;
    final String nonce;
    final String issuedAt;
    final String expirationTime;
    final String notBefore;
    final String requestId;
    final List<String> resources;

    static final class InvalidSiwe extends Exception {
        InvalidSiwe(String message) { super(message); }
    }

    private Siwe(String scheme, String domain, String address, String statement, String uri, String version,
                 long chainId, String nonce, String issuedAt, String expirationTime, String notBefore,
                 String requestId, List<String> resources) {
        this.scheme = scheme;
        this.domain = domain;
        this.address = address;
        this.statement = statement;
        this.uri = uri;
        this.version = version;
        this.chainId = chainId;
        this.nonce = nonce;
        this.issuedAt = issuedAt;
        this.expirationTime = expirationTime;
        this.notBefore = notBefore;
        this.requestId = requestId;
        this.resources = resources;
    }

    /** True when the first line claims to be an EIP-4361 sign-in request. */
    static boolean looksLike(String text) {
        int newline = text.indexOf('\n');
        String first = newline < 0 ? text : text.substring(0, newline);
        return first.endsWith(HEADER_SUFFIX);
    }

    static Siwe parse(String text) throws InvalidSiwe {
        String[] lines = text.split("\n", -1);
        int n = lines.length;
        if (n > 0 && lines[n - 1].isEmpty()) n--; // tolerate one trailing newline
        Cursor c = new Cursor(lines, n);

        Matcher header = HEADER.matcher(c.next("header"));
        if (!header.matches()) throw new InvalidSiwe("the first line does not name a valid domain");
        String scheme = header.group(1);
        String domain = header.group(2);
        if (domain.contains("@")) throw new InvalidSiwe("the domain contains user information ('@')");
        asciiAuthority(domain); // an internationalized name that has no valid ASCII form is malformed

        String address = c.next("address");
        if (!ADDRESS.matcher(address).matches()) throw new InvalidSiwe("the account line is not an address");
        if (!c.next("blank line").isEmpty()) throw new InvalidSiwe("missing blank line after the address");

        String statement = null;
        String line = c.next("statement or blank line");
        if (!line.isEmpty()) {
            statement = line;
            if (!c.next("blank line").isEmpty()) throw new InvalidSiwe("missing blank line after the statement");
        }

        String uri = c.field("URI: ");
        if (!URI.matcher(uri).matches()) throw new InvalidSiwe("URI is not an absolute URI");
        String version = c.field("Version: ");
        if (!"1".equals(version)) throw new InvalidSiwe("unsupported version " + version);
        String chain = c.field("Chain ID: ");
        if (!CHAIN_ID.matcher(chain).matches()) throw new InvalidSiwe("Chain ID is not a positive integer");
        String nonce = c.field("Nonce: ");
        if (!NONCE.matcher(nonce).matches()) throw new InvalidSiwe("Nonce must be 8+ letters or digits");
        String issuedAt = c.field("Issued At: ");
        if (!DATE_TIME.matcher(issuedAt).matches()) throw new InvalidSiwe("Issued At is not an RFC 3339 time");

        String expiration = c.optional("Expiration Time: ");
        if (expiration != null && !DATE_TIME.matcher(expiration).matches()) throw new InvalidSiwe("Expiration Time is not an RFC 3339 time");
        String notBefore = c.optional("Not Before: ");
        if (notBefore != null && !DATE_TIME.matcher(notBefore).matches()) throw new InvalidSiwe("Not Before is not an RFC 3339 time");
        String requestId = c.optional("Request ID: ");
        List<String> resources = new ArrayList<>();
        if (c.hasNext() && "Resources:".equals(c.peek())) {
            c.next("Resources:");
            while (c.hasNext() && c.peek().startsWith("- ")) {
                String resource = c.next("resource").substring(2);
                if (!URI.matcher(resource).matches()) throw new InvalidSiwe("a resource is not an absolute URI");
                resources.add(resource);
            }
        }
        if (c.hasNext()) throw new InvalidSiwe("unexpected line: " + c.peek());
        return new Siwe(scheme, domain, address, statement, uri, version, Long.parseLong(chain), nonce,
                issuedAt, expiration, notBefore, requestId, Collections.unmodifiableList(resources));
    }

    /** True when the domain contains any non-ASCII character (an internationalized, possibly lookalike, name). */
    boolean lookalike() {
        for (int i = 0; i < domain.length(); i++) if (domain.charAt(i) > 0x7e || domain.charAt(i) < 0x21) return true;
        return false;
    }

    /** The domain as shown on the phone: host in ASCII (punycode, lowercase) plus any port. */
    String displayDomain() {
        try {
            return asciiAuthority(domain);
        } catch (InvalidSiwe e) {
            return domain; // unreachable: parse() already converted it
        }
    }

    /** The domain's host only (no port), ASCII lowercase, for comparison with a host-reported origin. */
    String asciiHost() {
        String a = displayDomain();
        if (a.startsWith("[")) {
            int close = a.indexOf(']');
            return close < 0 ? a : a.substring(0, close + 1);
        }
        int colon = a.lastIndexOf(':');
        return colon < 0 ? a : a.substring(0, colon);
    }

    /**
     * "host[:port]" with the host converted by {@link java.net.IDN#toASCII} (IDNA 2003 nameprep +
     * punycode) and lowercased. An IPv6 literal is only lowercased.
     */
    static String asciiAuthority(String authority) throws InvalidSiwe {
        if (authority.startsWith("[")) return authority.toLowerCase(java.util.Locale.ROOT);
        String host = authority, port = "";
        int colon = authority.lastIndexOf(':');
        if (colon >= 0 && authority.substring(colon + 1).matches("[0-9]{1,5}")) {
            host = authority.substring(0, colon);
            port = authority.substring(colon);
        }
        if (host.isEmpty()) throw new InvalidSiwe("the domain is empty");
        String ascii;
        try {
            ascii = java.net.IDN.toASCII(host);
        } catch (IllegalArgumentException e) {
            throw new InvalidSiwe("the domain is not a valid host name");
        }
        if (ascii.isEmpty()) throw new InvalidSiwe("the domain is not a valid host name");
        return ascii.toLowerCase(java.util.Locale.ROOT) + port;
    }

    /** host[:port] of the URI line, or null when the URI has no authority. */
    String uriAuthority() {
        Matcher m = URI_AUTHORITY.matcher(uri);
        return m.matches() ? m.group(1) : null;
    }

    private static final class Cursor {
        private final String[] lines;
        private final int end;
        private int at;

        Cursor(String[] lines, int end) { this.lines = lines; this.end = end; }
        boolean hasNext() { return at < end; }
        String peek() { return lines[at]; }
        String next(String what) throws InvalidSiwe {
            if (!hasNext()) throw new InvalidSiwe("message ends before the " + what);
            return lines[at++];
        }
        String field(String prefix) throws InvalidSiwe {
            String line = next(prefix.trim());
            if (!line.startsWith(prefix) || line.length() == prefix.length()) {
                throw new InvalidSiwe("expected '" + prefix.trim() + "' line");
            }
            return line.substring(prefix.length());
        }
        String optional(String prefix) throws InvalidSiwe {
            if (!hasNext() || !peek().startsWith(prefix)) return null;
            return field(prefix);
        }
    }
}
