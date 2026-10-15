package dev.phonevault.signer;

import org.web3j.crypto.Keys;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The plain-language review of a {@link MessageRequest}, built from the SAME parsed object whose
 * digest is signed ({@link PersonalMessage} bytes or the {@link Eip712.TypedData} value tree).
 * Nothing here re-reads the host's JSON.
 *
 * <p>Rows labelled "DANGER" or "WARNING" are rendered in the danger style by the approval
 * screen, like the transaction review. The summary is shown first; the complete field tree,
 * hashes and raw bytes are under Details.
 */
final class MessageReview {
    static final String DANGER = "DANGER";
    static final String WARNING = "WARNING";
    static final String PERMIT2_ADDRESS = "0x000000000022d473030f116ddee9f6b43ac78ba3";
    private static final BigInteger UINT256_MAX = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
    private static final BigInteger UINT160_MAX = BigInteger.ONE.shiftLeft(160).subtract(BigInteger.ONE);
    private static final BigInteger UINT48_MAX = BigInteger.ONE.shiftLeft(48).subtract(BigInteger.ONE);
    /** 9999-12-31T23:59:59Z: anything later is shown as "no practical expiry". */
    private static final BigInteger LAST_DISPLAYABLE_SECOND = BigInteger.valueOf(253402300799L);
    private static final DateTimeFormatter UTC = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.ROOT)
            .withZone(ZoneOffset.UTC);

    enum Category { MESSAGE, UNREADABLE, SIGN_IN, PERMIT, PERMIT2, ORDER, TYPED_DATA }

    static final class Row {
        final String label;
        final String value;
        /** What a DANGER / WARNING row is about ("NEW RECIPIENT"); null: read from the text (ReviewStyle.topicOf). */
        final String topic;
        Row(String label, String value) { this(label, value, null); }
        Row(String label, String value, String topic) { this.label = label; this.value = value; this.topic = topic; }
        boolean danger() { return DANGER.equals(label) || WARNING.equals(label); }
        @Override public String toString() { return label + ": " + value; }
    }

    final Category category;
    final String kicker;
    final String title;
    final String subtitle;
    final List<Row> summary;
    final List<Row> details;
    final String reviewPrompt;
    final String signLabel;

    private MessageReview(Category category, String kicker, String title, String subtitle, List<Row> summary,
                          List<Row> details, String reviewPrompt, String signLabel) {
        this.category = category;
        this.kicker = kicker;
        this.title = title;
        this.subtitle = subtitle;
        this.summary = Collections.unmodifiableList(summary);
        this.details = Collections.unmodifiableList(details);
        this.reviewPrompt = reviewPrompt;
        this.signLabel = signLabel;
    }

    /** True if any summary row is a warning or danger row with this text fragment (tests). */
    boolean warns(String fragment) {
        for (Row r : summary) if (r.danger() && r.value.contains(fragment)) return true;
        return false;
    }

    String summaryValue(String label) {
        for (Row r : summary) if (r.label.equals(label)) return r.value;
        return null;
    }

    /** A row of the details (tests): e.g. the signing address, which the summary leaves to the review's top. */
    String detailValue(String label) {
        for (Row r : details) if (r.label.equals(label)) return r.value;
        return null;
    }

    /**
     * @param wallet the signing address shown on screen (the reviewed credential snapshot)
     */
    static MessageReview of(MessageRequest request, String wallet) {
        return of(request, wallet, null);
    }

    /**
     * @param account which account of which wallet {@code wallet} is (the "Signing address · Account 3"
     *                row), or null when unknown: the row then says only "Signing address"
     */
    static MessageReview of(MessageRequest request, String wallet, SigningAccount account) {
        String signer = wallet.toLowerCase(Locale.ROOT);
        if (account != null && !account.address.equals(signer)) {
            throw new IllegalArgumentException("The account description does not match the signing address");
        }
        String signerLabel = account == null ? "Signing address" : "Signing address · " + account.headline();
        return request.kind == MessageRequest.Kind.PERSONAL
                ? personal(request, signer, signerLabel) : typed(request, signer, signerLabel);
    }

    /** Label of the host-reported origin row: the Mac says which site asked; the phone can't check. */
    static final String ORIGIN_LABEL = "Requested by (your Mac says)";

    /** The network the Mac says it is on (the request's chain ID). */
    static final String NETWORK_LABEL = "Network (your Mac's)";

    /** The origin row (host-reported, not verified), or nothing when the request carries no origin. */
    private static void addOrigin(List<Row> rows, MessageRequest request) {
        if (request.origin == null) return;
        rows.add(new Row(ORIGIN_LABEL, MessageRequest.originDisplay(request.origin)
                + "\nReported by your Mac (browser or WalletConnect). This phone can't verify it."));
    }

    /** One line for the PIN gate while locked (no identity is loaded yet). */
    static String lockedSummary(MessageRequest request) {
        String network = Eip1559Request.networkLabel(request.chainId);
        if (request.kind == MessageRequest.Kind.PERSONAL) {
            PersonalMessage m = request.personal;
            String what = m.siwe != null ? "Sign-in request from " + m.siwe.displayDomain()
                    : m.text != null ? "Message signature request (" + m.length() + " bytes)"
                    : "Signature request for UNREADABLE data (" + m.length() + " bytes)";
            return what + " · your Mac is on " + network + ". Unlock to review before anything is signed.";
        }
        Eip712.TypedData t = request.typedData;
        String from = t.domainName() != null ? " from " + visible(t.domainName()) : "";
        return "Typed-data signature (" + t.primaryType + ")" + from + " · your Mac is on " + network
                + ". Unlock to review every field before anything is signed.";
    }

    // ------------------------------------------------------------------ personal_sign

    private static MessageReview personal(MessageRequest request, String signer, String signerLabel) {
        PersonalMessage m = request.personal;
        List<Row> rows = new ArrayList<>();
        List<Row> details = new ArrayList<>();
        details.add(new Row("Format", "EIP-191 personal message (version 0x45), " + m.length() + " bytes"));
        details.add(new Row("Raw bytes", Numeric.toHexString(m.bytes())));
        details.add(new Row("Signing digest", Numeric.toHexString(m.digest())));
        String host = Eip1559Request.networkLabel(request.chainId);

        if (m.text == null) {
            rows.add(new Row("Action", "Sign unreadable data"));
            rows.add(new Row(DANGER, "Unreadable data: these bytes are not plain text. They could be the hash of a "
                    + "transaction or permission; signing may authorize something this screen cannot show."
                    + (m.length() == 32 ? " It is exactly 32 bytes, the size of a hash." : "")));
            rows.add(new Row("Data (hex)", Numeric.toHexString(m.bytes())));
            addOrigin(rows, request);
            details.add(0, new Row(signerLabel, Keys.toChecksumAddress(signer)));
            rows.add(new Row(NETWORK_LABEL, host));
            return new MessageReview(Category.UNREADABLE, "MESSAGE REVIEW", "Review unreadable data",
                    "Only sign if you know exactly what these bytes are. This phone cannot decode them.",
                    rows, details, "I understand this data is unreadable and I know exactly what it authorizes.",
                    "Sign unreadable data");
        }
        if (m.siwe != null) {
            Siwe s = m.siwe;
            rows.add(new Row("Action", "Sign in"));
            // Shown in its ASCII (punycode) form: "xn--uniswp-…" cannot pass for "uniswap" the way
            // a Cyrillic "а" can.
            rows.add(new Row("Website (as claimed)", (s.scheme != null ? s.scheme + "://" : "") + s.displayDomain()));
            if (s.lookalike()) {
                rows.add(new Row(DANGER, "This site name uses lookalike characters: the message writes it as \""
                        + s.domain + "\", which is really " + s.displayDomain() + ". Phishing sites use letters from "
                        + "other alphabets that look like familiar ones. Do not sign unless you are sure."));
            }
            addOrigin(rows, request);
            if (request.origin != null && !MessageRequest.originHost(request.origin).equals(s.asciiHost())) {
                rows.add(new Row(DANGER, "This sign-in is for " + s.displayDomain() + ", but the request came from "
                        + MessageRequest.originDisplay(request.origin) + ". A site may be phishing you."));
            }
            if (request.origin != null) {
                // The Mac named the site (the row above): say that, rather than "cannot see which site".
                rows.add(new Row(WARNING, "Your Mac reported the site above; this phone can't verify it. Only sign if you "
                        + "opened this site yourself.", "WEBSITE"));
            } else {
                rows.add(new Row(WARNING, "This phone cannot see which site asked. Only sign if you opened "
                        + s.displayDomain() + " yourself and your browser shows that exact address."));
            }
            boolean mine = s.address.toLowerCase(Locale.ROOT).equals(signer);
            rows.add(new Row("Account in message", s.address));
            if (!mine) {
                rows.add(new Row(DANGER, "The message signs in as " + s.address + ", which is NOT this wallet ("
                        + Keys.toChecksumAddress(signer) + "). Do not sign."));
            } else if (!Addresses.isChecksummed(s.address)) {
                rows.add(new Row(WARNING, "The account in the message is not in its checksummed form (mixed capitals), as sign-in messages require."));
            }
            if (s.statement != null) rows.add(new Row("Statement", s.statement));
            rows.add(new Row("URI", s.uri));
            String authority = s.uriAuthority();
            if (authority != null && !authority.equalsIgnoreCase(s.domain) && !authority.equalsIgnoreCase(s.displayDomain())) {
                rows.add(new Row(WARNING, "The site in the URI (" + authority + ") differs from the site the message names ("
                        + s.displayDomain() + ").", "WEBSITE"));
            }
            rows.add(new Row("Network in message", Eip1559Request.networkLabel(s.chainId)));
            if (s.chainId != request.chainId) {
                rows.add(new Row(WARNING, "The message names chain " + s.chainId + " but your Mac is on " + host + "."));
            }
            rows.add(new Row("Nonce", s.nonce));
            rows.add(new Row("Issued at", s.issuedAt));
            rows.add(new Row("Expires", s.expirationTime != null ? s.expirationTime : "No expiry in the message"));
            if (s.notBefore != null) rows.add(new Row("Not before", s.notBefore));
            if (s.requestId != null) rows.add(new Row("Request ID", s.requestId));
            for (int i = 0; i < s.resources.size(); i++) rows.add(new Row("Resource " + (i + 1), s.resources.get(i)));
            details.add(0, new Row(signerLabel, Keys.toChecksumAddress(signer)));
            rows.add(new Row(NETWORK_LABEL, host));
            rows.add(new Row("Note", "Times are as written in the message; this offline phone's clock is not trusted to judge them."));
            details.add(0, new Row("Full message", m.text));
            details.add(1, new Row("Standard", "Sign-In with Ethereum (EIP-4361)"));
            return new MessageReview(Category.SIGN_IN, "SIGN-IN REVIEW", "Review sign-in",
                    "Signing proves you control this account to the site named below. It sends no transaction.",
                    rows, details, "I opened this site myself and verified the site, account, and network shown above.",
                    "Approve & sign");
        }
        rows.add(new Row("Action", "Sign a text message"));
        if (m.siweError != null) {
            rows.add(new Row(DANGER, "This looks like a sign-in request but is not a valid sign-in message ("
                    + m.siweError + "). A malformed sign-in may be an attempt to confuse you."));
        }
        rows.add(new Row("Message", m.text));
        rows.add(new Row("What it means", "Signing does not send a transaction, but a site or contract may treat "
                + "the signature as your agreement to this text."));
        addOrigin(rows, request);
        details.add(0, new Row(signerLabel, Keys.toChecksumAddress(signer)));
        rows.add(new Row(NETWORK_LABEL, host));
        return new MessageReview(Category.MESSAGE, "MESSAGE REVIEW", "Review message",
                "Read the whole message. Only this screen can be trusted.", rows, details,
                "I read the whole message and verified the signing address shown above.", "Approve & sign");
    }

    // ------------------------------------------------------------------ eth_signTypedData_v4

    private static MessageReview typed(MessageRequest request, String signer, String signerLabel) {
        Eip712.TypedData t = request.typedData;
        List<Row> who = new ArrayList<>();
        who.add(new Row("Requested by (domain name)", t.domainName() != null ? visible(t.domainName()) : "Not specified"));
        if (t.domainVersion() != null) who.add(new Row("Domain version", visible(t.domainVersion())));
        BigInteger chain = t.domainChainId();
        String host = Eip1559Request.networkLabel(request.chainId);
        who.add(new Row("Network in message", chain == null ? "Not specified" : chainLabel(chain)));
        who.add(new Row("Contract (verifying contract)", t.domainVerifyingContract() != null
                ? Keys.toChecksumAddress(t.domainVerifyingContract()) : "Not specified"));
        if (t.domainSalt() != null) who.add(new Row("Domain salt", Numeric.toHexString(t.domainSalt())));
        List<Row> chainWarnings = new ArrayList<>();
        if (chain == null) {
            chainWarnings.add(new Row(WARNING, "This message does not name a network. The signature may be valid on every chain."));
        } else if (!chain.equals(BigInteger.valueOf(request.chainId))) {
            chainWarnings.add(new Row(DANGER, "The message is for " + chainLabel(chain) + ", but your Mac is on " + host
                    + ". Do not sign unless you meant to act on that network."));
        }

        List<Row> details = new ArrayList<>();
        details.add(new Row("Message type", t.primaryType));
        flatten(details, "domain", t.domain);
        flatten(details, "message", t.message);
        details.add(new Row("Type definition", t.encodeType(t.primaryType)));
        details.add(new Row("Domain separator", Numeric.toHexString(t.domainSeparator())));
        details.add(new Row("Message hash", Numeric.toHexString(t.messageHash())));
        details.add(new Row("Signing digest", Numeric.toHexString(t.digest())));

        Summary s = permit(t, signer);
        if (s == null) s = permit2(t, signer);
        if (s == null) s = order(t, signer);
        if (s == null) s = generic(t, signer);

        List<Row> rows = new ArrayList<>();
        rows.add(new Row("Action", s.action));
        rows.addAll(chainWarnings);
        rows.addAll(s.rows);
        addOrigin(rows, request);
        rows.addAll(who);
        details.add(0, new Row(signerLabel, Keys.toChecksumAddress(signer)));
        if (s.standard != null) details.add(1, new Row("Standard", s.standard));
        rows.add(new Row(NETWORK_LABEL, host));
        return new MessageReview(s.category, "TYPED DATA REVIEW", s.title, s.subtitle, rows, details, s.prompt, s.signLabel);
    }

    private static final class Summary {
        Category category;
        String title, subtitle, action, prompt, signLabel = "Approve & sign";
        /** The standard's name, for the technical details only (null: none to name). */
        String standard;
        final List<Row> rows = new ArrayList<>();
    }

    /** EIP-2612 Permit, and the older DAI-style Permit(holder, spender, nonce, expiry, allowed). */
    private static Summary permit(Eip712.TypedData t, String signer) {
        if (!"Permit".equals(t.primaryType)) return null;
        Eip712.Struct m = t.message;
        boolean eip2612 = shape(t, "Permit", "owner", "address", "spender", "address", "value", "uint256",
                "nonce", "uint256", "deadline", "uint256");
        boolean dai = shape(t, "Permit", "holder", "address", "spender", "address", "nonce", "uint256",
                "expiry", "uint256", "allowed", "bool");
        if (!eip2612 && !dai) return null;
        Summary s = new Summary();
        s.category = Category.PERMIT;
        s.title = "Review token permission";
        s.subtitle = "Signing lets the spender move your tokens later without asking you again. No transaction is sent now; anyone holding this signature can submit it.";
        s.action = "Token spending permission";
        s.standard = eip2612 ? "EIP-2612 Permit" : "DAI-style Permit";
        s.rows.add(new Row(DANGER, "This grants a token allowance. Only sign if you trust the spender. Token identity, name and decimals are unverified."));
        s.rows.add(new Row("Spender", Keys.toChecksumAddress(m.get("spender").address())));
        s.rows.add(new Row("Token (contract)", tokenLabel(t)));
        String owner = m.get(eip2612 ? "owner" : "holder").address();
        if (eip2612) {
            s.rows.add(new Row("Amount", amountLabel(m.get("value").integer(), 256)));
            s.rows.add(new Row("Signature valid until", timeLabel(m.get("deadline").integer())));
        } else {
            boolean allowed = m.get("allowed").bool();
            s.rows.add(new Row("Amount", allowed ? "UNLIMITED (allowed = true: the whole balance, now and later)" : "Revoke (allowed = false)"));
            BigInteger expiry = m.get("expiry").integer();
            s.rows.add(new Row("Signature valid until", expiry.signum() == 0 ? "No expiry (expiry = 0)" : timeLabel(expiry)));
        }
        s.rows.add(new Row("Owner", Keys.toChecksumAddress(owner)));
        if (!owner.equals(signer)) s.rows.add(new Row(WARNING, "The owner is not this wallet. The permit will not work for your tokens; the request may be malformed or misdirected."));
        s.rows.add(new Row("Nonce", m.get("nonce").integer().toString()));
        s.prompt = "I verified the spender, token contract, amount, deadline, and network shown above.";
        s.signLabel = "Approve permission & sign";
        return s;
    }

    private static Summary permit2(Eip712.TypedData t, String signer) {
        String p = t.primaryType;
        boolean single = "PermitSingle".equals(p) && shape(t, p, "details", "PermitDetails", "spender", "address", "sigDeadline", "uint256");
        boolean batch = "PermitBatch".equals(p) && shape(t, p, "details", "PermitDetails[]", "spender", "address", "sigDeadline", "uint256");
        boolean transfer = "PermitTransferFrom".equals(p) && shape(t, p, "permitted", "TokenPermissions", "spender", "address", "nonce", "uint256", "deadline", "uint256");
        boolean batchTransfer = "PermitBatchTransferFrom".equals(p) && shape(t, p, "permitted", "TokenPermissions[]", "spender", "address", "nonce", "uint256", "deadline", "uint256");
        boolean witness = ("PermitWitnessTransferFrom".equals(p) || "PermitBatchWitnessTransferFrom".equals(p))
                && t.types.get(p).size() == 5
                && prefixShape(t, p, "permitted", p.startsWith("PermitBatch") ? "TokenPermissions[]" : "TokenPermissions",
                        "spender", "address", "nonce", "uint256", "deadline", "uint256");
        boolean allowance = single || batch;
        if (allowance && !shape(t, "PermitDetails", "token", "address", "amount", "uint160", "expiration", "uint48", "nonce", "uint48")) return null;
        if ((transfer || batchTransfer || witness) && !shape(t, "TokenPermissions", "token", "address", "amount", "uint256")) return null;
        if (!allowance && !transfer && !batchTransfer && !witness) return null;

        Eip712.Struct m = t.message;
        Summary s = new Summary();
        s.category = Category.PERMIT2;
        s.signLabel = "Approve permission & sign";
        if (allowance) {
            s.title = "Review token allowance";
            s.subtitle = "Permit2 allowance: the spender may move these tokens from your wallet until the allowance expires, without asking you again.";
            s.action = "Token allowance via Permit2 (" + p + ")";
        } else {
            s.title = "Review token transfer permission";
            s.subtitle = "Permit2 signature transfer: the spender may take these tokens once, any time before the deadline.";
            s.action = "One-time token transfer via Permit2 (" + p + ")";
        }
        s.rows.add(new Row(DANGER, "This signature lets the spender move your tokens. Only sign if you trust the spender. Token identity and decimals are unverified."));
        s.rows.add(new Row("Spender", Keys.toChecksumAddress(m.get("spender").address())));
        if (allowance) {
            List<Eip712.Struct> items = new ArrayList<>();
            if (single) items.add(m.get("details").struct());
            else for (Eip712.Value v : m.get("details").elements()) items.add(v.struct());
            for (int i = 0; i < items.size(); i++) {
                String n = items.size() > 1 ? " " + (i + 1) : "";
                Eip712.Struct d = items.get(i);
                s.rows.add(new Row("Token" + n, Keys.toChecksumAddress(d.get("token").address())));
                s.rows.add(new Row("Amount" + n, amountLabel(d.get("amount").integer(), 160)));
                BigInteger exp = d.get("expiration").integer();
                s.rows.add(new Row("Allowance expires" + n, exp.signum() == 0
                        ? "0 (Permit2 treats this as expiring in the block it is used)"
                        : exp.equals(UINT48_MAX) ? "Never (no expiry)" : timeLabel(exp)));
                s.rows.add(new Row("Permit2 nonce" + n, d.get("nonce").integer().toString()));
            }
            s.rows.add(new Row("Signature valid until", timeLabel(m.get("sigDeadline").integer())));
        } else {
            List<Eip712.Struct> items = new ArrayList<>();
            Eip712.Value permitted = m.get("permitted");
            if (permitted.kind == Eip712.Kind.STRUCT) items.add(permitted.struct());
            else for (Eip712.Value v : permitted.elements()) items.add(v.struct());
            for (int i = 0; i < items.size(); i++) {
                String n = items.size() > 1 ? " " + (i + 1) : "";
                s.rows.add(new Row("Token" + n, Keys.toChecksumAddress(items.get(i).get("token").address())));
                s.rows.add(new Row("Amount" + n, amountLabel(items.get(i).get("amount").integer(), 256)));
            }
            s.rows.add(new Row("Signature valid until", timeLabel(m.get("deadline").integer())));
            s.rows.add(new Row("Nonce", m.get("nonce").integer().toString()));
            if (witness) {
                Eip712.Field extra = t.types.get(p).get(4);
                s.rows.add(new Row(WARNING, "Also signs extra \"" + extra.name + "\" data (" + extra.type
                        + ") that the spender's contract interprets. Check it under Details."));
            }
        }
        boolean canonical = "Permit2".equals(t.domainName()) && PERMIT2_ADDRESS.equals(t.domainVerifyingContract());
        if (!canonical) {
            s.rows.add(new Row(WARNING, "Shaped like Permit2 but the domain is not the canonical Permit2 contract ("
                    + Keys.toChecksumAddress(PERMIT2_ADDRESS) + " named \"Permit2\")."));
        }
        s.prompt = "I verified the spender, every token and amount, the expiry dates, and the network shown above.";
        return s;
    }

    /** Seaport and anything else that looks like a marketplace order. */
    private static Summary order(Eip712.TypedData t, String signer) {
        String p = t.primaryType;
        boolean seaport = "Seaport".equals(t.domainName()) || "OrderComponents".equals(p) || "BulkOrder".equals(p)
                || t.types.containsKey("OfferItem") || t.types.containsKey("ConsiderationItem");
        boolean orderLike = p.toLowerCase(Locale.ROOT).contains("order");
        if (!seaport && !orderLike) return null;
        Summary s = new Summary();
        s.category = Category.ORDER;
        s.title = "Review order";
        s.subtitle = "This signs an order. Anyone who holds the signature can execute the trade without asking you again, until it expires or is cancelled on-chain.";
        s.action = seaport ? "Marketplace order (Seaport-style " + p + ")" : "Order (" + p + ")";
        s.rows.add(new Row(DANGER, "This signs an order that can transfer your NFTs or tokens. This phone cannot value the assets or check the price. Check every item under Details."));
        Eip712.Value offer = t.message.get("offer");
        Eip712.Value consideration = t.message.get("consideration");
        if (offer != null && offer.kind == Eip712.Kind.ARRAY) s.rows.add(new Row("You offer", offer.elements().size() + " item(s): see Details"));
        if (consideration != null && consideration.kind == Eip712.Kind.ARRAY) s.rows.add(new Row("You receive / fees", consideration.elements().size() + " item(s): see Details"));
        Eip712.Value offerer = t.message.get("offerer");
        if (offerer != null && offerer.kind == Eip712.Kind.ADDRESS) {
            s.rows.add(new Row("Offerer", Keys.toChecksumAddress(offerer.address())));
            if (!offerer.address().equals(signer)) s.rows.add(new Row(WARNING, "The offerer is not this wallet."));
        }
        Eip712.Value end = t.message.get("endTime");
        if (end != null && (end.kind == Eip712.Kind.UINT)) s.rows.add(new Row("Order valid until", timeLabel(end.integer())));
        addTopLevel(s.rows, t);
        s.prompt = "I checked every offered and requested item under Details and I intend to create this order.";
        s.signLabel = "Approve order & sign";
        return s;
    }

    private static Summary generic(Eip712.TypedData t, String signer) {
        Summary s = new Summary();
        s.category = Category.TYPED_DATA;
        s.title = "Review typed data";
        s.subtitle = "A signed statement for the contract shown below. It may authorize actions; read every field under Details.";
        s.action = "Sign structured data (" + t.primaryType + ")";
        List<String> parties = new ArrayList<>();
        boolean unlimited = scan(t.message, "message", parties);
        if (!parties.isEmpty()) {
            s.rows.add(new Row(WARNING, "Names a spender or operator (" + String.join(", ", parties)
                    + "). It may grant permission over your assets."));
        }
        if (unlimited) s.rows.add(new Row(WARNING, "Contains a maximum-value number, which often means an UNLIMITED allowance."));
        addTopLevel(s.rows, t);
        s.prompt = "I verified who is asking, the network, and every field of this message under Details.";
        return s;
    }

    /** Top-level message fields, one line each; nested values point to Details. */
    private static void addTopLevel(List<Row> rows, Eip712.TypedData t) {
        for (Map.Entry<String, Eip712.Value> e : t.message.fields.entrySet()) {
            Eip712.Value v = e.getValue();
            String value = v.kind == Eip712.Kind.STRUCT ? v.type + ": see Details"
                    : v.kind == Eip712.Kind.ARRAY ? v.elements().size() + " × " + Eip712.baseType(v.type) + ": see Details"
                    : format(v);
            rows.add(new Row(e.getKey(), value));
        }
    }

    private static boolean scan(Eip712.Struct s, String path, List<String> parties) {
        boolean max = false;
        for (Map.Entry<String, Eip712.Value> e : s.fields.entrySet()) {
            max |= scanValue(e.getValue(), path + "." + e.getKey(), e.getKey(), parties);
        }
        return max;
    }

    private static boolean scanValue(Eip712.Value v, String path, String name, List<String> parties) {
        switch (v.kind) {
            case STRUCT: return scan(v.struct(), path, parties);
            case ARRAY: {
                boolean max = false;
                for (int i = 0; i < v.elements().size(); i++) max |= scanValue(v.elements().get(i), path + "[" + i + "]", name, parties);
                return max;
            }
            case ADDRESS: {
                String lower = name.toLowerCase(Locale.ROOT);
                if ((lower.contains("spender") || lower.contains("operator") || lower.equals("delegate")
                        || lower.equals("delegatee") || lower.equals("approved")) && parties.size() < 4) {
                    parties.add(path.substring("message.".length()) + " " + Keys.toChecksumAddress(v.address()));
                }
                return false;
            }
            case UINT: return v.integer().equals(UINT256_MAX) || (v.type.equals("uint160") && v.integer().equals(UINT160_MAX));
            default: return false;
        }
    }

    // ------------------------------------------------------------------ helpers

    /** True if {@code type} declares exactly these (name, type) pairs in this order. */
    private static boolean shape(Eip712.TypedData t, String type, String... pairs) {
        List<Eip712.Field> fields = t.types.get(type);
        return fields != null && fields.size() * 2 == pairs.length && prefixShape(t, type, pairs);
    }

    private static boolean prefixShape(Eip712.TypedData t, String type, String... pairs) {
        List<Eip712.Field> fields = t.types.get(type);
        if (fields == null || fields.size() * 2 < pairs.length) return false;
        for (int i = 0; i < pairs.length / 2; i++) {
            if (!fields.get(i).name.equals(pairs[2 * i]) || !fields.get(i).type.equals(pairs[2 * i + 1])) return false;
        }
        return true;
    }

    private static String tokenLabel(Eip712.TypedData t) {
        String contract = t.domainVerifyingContract();
        if (contract == null) return "NOT SPECIFIED: the domain names no token contract";
        String name = t.domainName();
        return Keys.toChecksumAddress(contract) + (name != null ? " (calls itself \"" + visible(name) + "\"; unverified)" : "");
    }

    static String chainLabel(BigInteger chain) {
        if (chain.bitLength() > 63) return "chain ID " + chain;
        return Eip1559Request.networkLabel(chain.longValue());
    }

    static String amountLabel(BigInteger amount, int bits) {
        if (amount.equals(UINT256_MAX) || (bits == 160 && amount.equals(UINT160_MAX))) {
            return "UNLIMITED (maximum possible amount): every token you hold, now and later";
        }
        return amount + " raw units (token decimals unverified)";
    }

    static String timeLabel(BigInteger seconds) {
        if (seconds.equals(UINT256_MAX) || seconds.equals(UINT48_MAX)) return "No expiry (maximum value " + seconds + ")";
        if (seconds.compareTo(LAST_DISPLAYABLE_SECOND) > 0) return "No practical expiry (" + seconds + ")";
        return UTC.format(Instant.ofEpochSecond(seconds.longValue())) + " (" + seconds + ")";
    }

    /** Detail rows for every leaf of a struct, labelled by path. */
    private static void flatten(List<Row> out, String path, Eip712.Struct s) {
        if (s.fields.isEmpty()) out.add(new Row(path + " · " + s.type, "(no fields)"));
        for (Map.Entry<String, Eip712.Value> e : s.fields.entrySet()) flattenValue(out, path + "." + e.getKey(), e.getValue());
    }

    private static void flattenValue(List<Row> out, String path, Eip712.Value v) {
        if (v.kind == Eip712.Kind.STRUCT) {
            flatten(out, path, v.struct());
        } else if (v.kind == Eip712.Kind.ARRAY) {
            if (v.elements().isEmpty()) out.add(new Row(path + " · " + v.type, "(empty list)"));
            for (int i = 0; i < v.elements().size(); i++) flattenValue(out, path + "[" + i + "]", v.elements().get(i));
        } else {
            out.add(new Row(path + " · " + v.type, format(v)));
        }
    }

    static String format(Eip712.Value v) {
        switch (v.kind) {
            case BOOL: return Boolean.toString(v.bool());
            case ADDRESS: return Keys.toChecksumAddress(v.address());
            case UINT:
            case INT: {
                String n = v.integer().toString();
                if (v.integer().equals(UINT256_MAX)) return n + " (maximum possible value)";
                return n;
            }
            case FIXED_BYTES:
            case BYTES: return Numeric.toHexString(v.bytes());
            case STRING: return "\"" + visible(v.text()) + "\"";
            default: return v.type;
        }
    }

    /**
     * Text with every non-printable or formatting code point (newlines, bidi overrides,
     * zero-width characters, …) shown as a visible escape, so a string cannot visually hide or
     * reorder what it contains.
     */
    static String visible(String text) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            i += Character.charCount(cp);
            if (cp == '\n') out.append("\\n");
            else if (cp == '\t') out.append("\\t");
            else if (cp == '\\') out.append("\\\\");
            else if (!PersonalMessage.printable(cp)) out.append(String.format(Locale.ROOT, "\\u{%04X}", cp));
            else out.appendCodePoint(cp);
        }
        return out.toString();
    }
}
