package dev.phonevault.signer;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;

/**
 * How review rows are PRESENTED (no Android types, so it is unit-tested): the level of a row
 * (DANGER, CHECK or plain), its topic ("DANGER · UNLIMITED PERMISSION"), the danger summary and
 * acknowledgement shown when a review has DANGER rows, the colors those levels use, and the
 * grouped form of EVM addresses on screen ("0x51dd 9Afd 5f32 …", groups of four like the
 * companion's pairing step). Nothing here changes what is signed, and QR / copy payloads never
 * use the grouped form.
 */
final class ReviewStyle {
    private ReviewStyle() {}

    // ------------------------------------------------------------------ colors (ARGB, dark ground)

    /** DANGER rows: red text on a red-outlined panel, with the stop glyph. 6.6:1 on {@link #GROUND}. */
    static final int DANGER_INK = 0xFFFF5A5A;
    /** CHECK (WARNING) rows: amber text with the "!" glyph. Not the test-network banner amber. */
    static final int WARNING_INK = 0xFFFFC53D;
    /** The page ground ({@code VaultTheme.BG}) the inks are measured against. */
    static final int GROUND = 0xFF060608;
    /** The card fill ({@code VaultTheme.SURFACE}). */
    static final int SURFACE = 0xFF0F1014;

    /** WCAG 2 contrast ratio of two opaque colors. */
    static double contrast(int a, int b) {
        double la = luminance(a), lb = luminance(b);
        return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    }

    private static double luminance(int argb) {
        return 0.2126 * channel((argb >> 16) & 0xFF) + 0.7152 * channel((argb >> 8) & 0xFF) + 0.0722 * channel(argb & 0xFF);
    }

    private static double channel(int c) {
        double s = c / 255.0;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    }

    // ------------------------------------------------------------------ levels and topics

    enum Level { DANGER, CHECK, NONE }

    /** The word shown for a WARNING row: it asks the user to check something, it is not a stop. */
    static final String CHECK_WORD = "CHECK";

    static Level level(String label) {
        if (MessageReview.DANGER.equalsIgnoreCase(label)) return Level.DANGER;
        if (MessageReview.WARNING.equalsIgnoreCase(label)) return Level.CHECK;
        return Level.NONE;
    }

    static Level level(MessageReview.Row row) { return level(row.label); }

    /**
     * The heading shown above a row: "DANGER · UNLIMITED PERMISSION", "CHECK · NEW RECIPIENT", or
     * the row's own label in capitals. A level row without a recognisable topic shows the level
     * word alone.
     */
    static String heading(MessageReview.Row row) {
        Level l = level(row);
        if (l == Level.NONE) return row.label.toUpperCase(Locale.ROOT);
        String word = l == Level.DANGER ? MessageReview.DANGER : CHECK_WORD;
        String topic = topic(row);
        return topic == null ? word : word + " · " + topic;
    }

    /** The row's topic: set where the row is built, else read from its text; null if unknown. */
    static String topic(MessageReview.Row row) {
        if (row.topic != null && !row.topic.isEmpty()) return row.topic.toUpperCase(Locale.ROOT);
        return topicOf(row.value);
    }

    /**
     * Topic from a DANGER / WARNING row's text, for rows built without one. Ordered: the opening
     * words decide first, then the most specific phrase; the first matching rule wins.
     */
    static String topicOf(String value) {
        if (value == null) return null;
        String v = value.toLowerCase(Locale.ROOT);
        // the opening words
        if (v.startsWith("looks like") || v.contains("different address")) return "LOOK-ALIKE ADDRESS";
        if (v.startsWith("the mac")) return "MAC SIMULATION";
        if (v.startsWith("first time sending")) return "NEW RECIPIENT";
        if (v.startsWith("first time approving")) return "NEW SPENDER";
        if (v.startsWith("unreadable data")) return "UNREADABLE DATA";
        if (v.startsWith("no minimum")) return "NO MINIMUM";
        if (v.startsWith("other address")) return "OTHER RECIPIENT";
        if (v.startsWith("two possible meanings")) return "TOKEN OR NFT?";
        if (v.startsWith("unknown token")) return "UNKNOWN TOKEN";
        // specific phrases
        if (v.contains("address history")) return "HISTORY UNAVAILABLE";
        if (v.contains("token list built into this app failed")) return "TOKEN LIST";
        if (v.contains("every nft")) return "ALL YOUR NFTS";
        if (v.contains("unlimited") || v.contains("maximum-value")) return "UNLIMITED PERMISSION";
        if (v.contains("data output is destroyed")) return "COINS DESTROYED";
        if (word(v, "fee") || v.contains("fee rate")) return "FEE";
        if (v.contains("sign-in") || v.contains("eip-4361")) return "SIGN-IN";
        if (v.contains("not this wallet") || v.contains("signs in as")) return "WRONG ACCOUNT";
        if (v.contains("which website") || v.contains("uri host")) return "WEBSITE";
        if (v.contains("your host is on") || word(v, "chain") || word(v, "network")) return "NETWORK";
        if (v.contains("permit2")) return "PERMIT2";
        if (v.contains("order that can transfer")) return "TRADE ORDER";
        if (v.contains("nft #")) return "NFT PERMISSION";
        if (v.contains("taken from") || v.contains("takes tokens from")) return "SOMEONE ELSE'S ASSETS";
        if (v.contains("allowance") || v.contains("move your tokens") || v.contains("will be able to take")
                || word(v, "spender")) return "PERMISSION";
        if (v.contains("also sends") || v.contains("also passes") || v.contains("also signs") || v.contains("also activates")) return "EXTRA ACTION";
        if (v.contains("usually lost") || v.contains("sent straight to it")) return "CONTRACT RECIPIENT";
        if (v.contains("nothing from this swap") || v.contains("left in the router")) return "SWAP";
        if (v.contains("offerer") || v.contains("owner is not")) return "WRONG ACCOUNT";
        return null;
    }

    /** {@code w} as a whole word (no letter on either side; a trailing plural "s" allowed). */
    private static boolean word(String lower, String w) {
        for (int i = lower.indexOf(w); i >= 0; i = lower.indexOf(w, i + 1)) {
            boolean before = i == 0 || !Character.isLetter(lower.charAt(i - 1));
            int e = i + w.length();
            if (e < lower.length() && lower.charAt(e) == 's') e++;
            boolean after = e >= lower.length() || !Character.isLetter(lower.charAt(e));
            if (before && after) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ danger summary and acknowledgement

    /** DANGER rows across the given lists (summary, details, the Mac's simulation box), in order. */
    @SafeVarargs
    static List<MessageReview.Row> dangers(List<MessageReview.Row>... lists) {
        List<MessageReview.Row> out = new ArrayList<>();
        for (List<MessageReview.Row> list : lists) {
            if (list == null) continue;
            for (MessageReview.Row r : list) if (level(r) == Level.DANGER) out.add(r);
        }
        return out;
    }

    /** "1 danger below — read before signing" / "3 dangers below — read before signing". */
    static String dangerSummary(int count) {
        return count + (count == 1 ? " danger" : " dangers") + " below — read before signing";
    }

    /**
     * The second checkbox a review with DANGER rows needs, stating the risk in the first DANGER
     * row's own words (its first sentence, addresses shortened so the line stays readable).
     */
    static String dangerAcknowledgement(List<MessageReview.Row> dangers) {
        if (dangers == null || dangers.isEmpty()) return null;
        String first = shortenEvm(firstSentence(dangers.get(0).value));
        String more = dangers.size() > 1 ? " (and " + (dangers.size() - 1) + " more danger"
                + (dangers.size() == 2 ? "" : "s") + " shown above)" : "";
        return "I understand: " + first + more;
    }

    /** Up to the first ". " that ends a sentence (decimals and "0x12…34" are not ends); at most ~220 chars. */
    static String firstSentence(String text) {
        if (text == null) return "";
        String t = text.replace('\n', ' ').trim();
        int end = -1;
        for (int i = 0; i + 1 < t.length(); i++) {
            char c = t.charAt(i);
            if ((c == '.' || c == '!' || c == '?') && t.charAt(i + 1) == ' ') { end = i + 1; break; }
        }
        String s = end > 0 ? t.substring(0, end) : t;
        if (s.length() > 220) s = s.substring(0, 219).trim() + "…";
        return s;
    }

    // ------------------------------------------------------------------ EVM addresses

    /** "0x51dd9Afd5f32…" → "0x51dd 9Afd 5f32 …" (case preserved). Anything else is returned as is. */
    static String groupEvm(String address) {
        if (!Addresses.isEvm(address)) return address;
        StringBuilder b = new StringBuilder(51).append(address, 0, 6);
        for (int i = 6; i < 42; i += 4) b.append(' ').append(address, i, i + 4);
        return b.toString();
    }

    /** The grouped address on two lines of five groups ("0x51dd 9Afd 5f32 1a2b 3c4d\n5e6f …"). */
    static String groupEvmTwoLines(String address) {
        if (!Addresses.isEvm(address)) return address;
        String g = groupEvm(address); // "0x" + 4, then 9 groups: the 5th space ends the first line
        int at = -1;
        for (int i = 0; i < 5; i++) at = g.indexOf(' ', at + 1);
        return g.substring(0, at) + "\n" + g.substring(at + 1);
    }

    /** Every whole 20-byte 0x address inside a text, grouped; longer hex (hashes, calldata) is untouched. */
    static String groupEvmIn(String text) {
        if (text == null || text.indexOf("0x") < 0) return text;
        Matcher m = Addresses.EVM_IN_TEXT.matcher(text);
        StringBuilder out = new StringBuilder(text.length() + 16);
        int at = 0;
        while (m.find()) {
            out.append(text, at, m.start()).append(groupEvm(m.group()));
            at = m.end();
        }
        return out.append(text, at, text.length()).toString();
    }

    /** Rows whose value is the signed content itself: shown character for character, never regrouped. */
    private static final java.util.Set<String> VERBATIM = new java.util.HashSet<>(java.util.Arrays.asList(
            "Message", "Statement", "Data (hex)", "Raw bytes", AddressSafety.COMPARE));

    /**
     * The value a review row shows: whole EVM addresses grouped, except where the value is the
     * signed text or bytes themselves (a personal message, a SIWE statement, raw data, an EIP-712
     * string or bytes field, the look-alike grid), which must appear exactly as signed.
     */
    static String displayValue(String label, String value) {
        if (label == null || VERBATIM.contains(label) || label.matches("(?s).* · (string|bytes[0-9]*)(\\[[0-9]*\\])*")) return value;
        return groupEvmIn(value);
    }

    /** "0xAbCd…1234" for every whole address in a text (for one-line sentences like the danger checkbox). */
    static String shortenEvm(String text) {
        if (text == null || text.indexOf("0x") < 0) return text;
        Matcher m = Addresses.EVM_IN_TEXT.matcher(text);
        StringBuilder out = new StringBuilder(text.length());
        int at = 0;
        while (m.find()) {
            out.append(text, at, m.start()).append(Addresses.shorten(m.group(), 6, 4)); // case as written
            at = m.end();
        }
        return out.append(text, at, text.length()).toString();
    }
}
