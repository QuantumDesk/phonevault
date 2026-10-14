package dev.phonevault.signer;

import org.web3j.crypto.Keys;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * EVM address checks and the short on-screen form, in one place. Every accepting check is exact:
 * {@code 0x} (lowercase x) and 40 hex digits, nothing before or after.
 */
final class Addresses {
    private Addresses() {}

    /** 0x + 40 hex digits, either case. */
    static final Pattern EVM = Pattern.compile("0x[0-9a-fA-F]{40}");
    /** 0x + 40 lowercase hex digits (the phone's own normalised form). */
    static final Pattern EVM_LOWERCASE = Pattern.compile("0x[0-9a-f]{40}");
    /** A whole address inside text: not the start, end or middle of a longer word or hex string. */
    static final Pattern EVM_IN_TEXT = Pattern.compile("(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9A-Za-z])");

    static final String ZERO = "0x0000000000000000000000000000000000000000";

    /** 0x + 40 hex digits, either case; false for null. */
    static boolean isEvm(String s) { return s != null && EVM.matcher(s).matches(); }

    /** 0x + 40 lowercase hex digits; false for null. */
    static boolean isEvmLowercase(String s) { return s != null && EVM_LOWERCASE.matcher(s).matches(); }

    /** The zero address (exactly 0x and 40 zeros). */
    static boolean isZero(String s) { return ZERO.equals(s); }

    /** The address in lowercase (the canonical form for keys and comparison). */
    static String lowercase(String evm) { return evm.toLowerCase(Locale.ROOT); }

    /** True when {@code evm} (a valid address) is spelled exactly in its EIP-55 checksum casing. */
    static boolean isChecksummed(String evm) { return Keys.toChecksumAddress(lowercase(evm)).equals(evm); }

    /** True when the hex digits mix upper and lower case (and so claim an EIP-55 checksum). */
    static boolean hasMixedCase(String evm) {
        String hex = evm.substring(2);
        return !hex.equals(hex.toLowerCase(Locale.ROOT)) && !hex.equals(hex.toUpperCase(Locale.ROOT));
    }

    /** "0xAbCd…1234": the EIP-55 form, first 6 and last 4 characters. */
    static String shortEvm(String evm) { return shorten(Keys.toChecksumAddress(evm), 6, 4); }

    /** First {@code head} characters, "…", last {@code tail}; returned whole up to head + tail characters. */
    static String shorten(String s, int head, int tail) { return shorten(s, head, tail, head + tail); }

    /** First {@code head} characters, "…", last {@code tail}; returned whole up to {@code wholeUpTo} characters. */
    static String shorten(String s, int head, int tail, int wholeUpTo) {
        return s.length() <= wholeUpTo ? s : s.substring(0, head) + "…" + s.substring(s.length() - tail);
    }
}
