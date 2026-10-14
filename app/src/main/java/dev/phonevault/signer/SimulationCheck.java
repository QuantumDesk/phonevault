package dev.phonevault.signer;

import org.web3j.crypto.Keys;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Compares the Mac's simulation claim ({@link HostSimulation}) with what the phone itself decoded
 * from the transaction, and builds the separate "the Mac says" box of the approval screen.
 *
 * <p>The phone derives, from the SAME parsed request it signs, the balance changes the decoded call
 * implies for the signing wallet: a range per asset (exact for a transfer, a bound for a swap's
 * "at least"/"at most"), the native coin widened by the fee (gas limit × max fee per gas on
 * Ethereum, Sepolia and Polygon; on rollups the L1 data fee has no offline bound, so only the
 * upper end is checked there). The claim CONTRADICTS the decoding when:
 * <ul>
 *   <li>a decoded asset's claimed change (absent = 0) is outside its range — e.g. the phone decoded
 *       "send 100 USDC" and the Mac claims −0 USDC, −1 USDC or +100 USDC;</li>
 *   <li>the Mac claims a gain of an asset the decoded call gives no way to gain (the phone sees
 *       only outflow);</li>
 *   <li>the Mac names a token from the phone's own list with a different symbol or decimals.</li>
 * </ul>
 * A claimed LOSS of an asset the decoding does not move is not a contradiction (a contract may
 * use an earlier allowance) but is flagged as unexplained. Fungible amounts get a tolerance of
 * {@link #ROUNDING} base units for rebasing tokens' rounding.
 *
 * <p>Nothing here influences signing: the result is display rows only.
 */
final class SimulationCheck {
    static final String BOX_TITLE = "THE MAC'S SIMULATION · NOT VERIFIED BY THIS PHONE";
    static final String MISMATCH = "The Mac's simulation does not match what this transaction does — trust the phone's review above.";
    static final BigInteger ROUNDING = BigInteger.valueOf(2);

    /** The rendered box: title, rows (DANGER/WARNING labels render red), and the verdict. */
    static final class Result {
        final String title;
        final List<MessageReview.Row> rows;
        final boolean contradicts;
        final List<String> contradictions;
        final List<String> unexplained;

        Result(List<MessageReview.Row> rows, List<String> contradictions, List<String> unexplained) {
            this.title = BOX_TITLE;
            this.rows = Collections.unmodifiableList(rows);
            this.contradictions = Collections.unmodifiableList(contradictions);
            this.unexplained = Collections.unmodifiableList(unexplained);
            this.contradicts = !contradictions.isEmpty();
        }

        String text() {
            StringBuilder out = new StringBuilder(title).append('\n');
            for (MessageReview.Row row : rows) out.append(row).append('\n');
            return out.toString();
        }
    }

    /** What the phone's decoding says may happen to one asset: lo ≤ change ≤ hi (null = unbounded). */
    static final class Range {
        BigInteger lo;
        BigInteger hi;
        final boolean fungible;

        Range(BigInteger lo, BigInteger hi, boolean fungible) {
            this.lo = lo;
            this.hi = hi;
            this.fungible = fungible;
        }

        static Range exactly(BigInteger v, boolean fungible) { return new Range(v, v, fungible); }

        void add(Range o) {
            lo = lo == null || o.lo == null ? null : lo.add(o.lo);
            hi = hi == null || o.hi == null ? null : hi.add(o.hi);
        }

        boolean contains(BigInteger v) {
            BigInteger slack = fungible ? ROUNDING : BigInteger.ZERO;
            return (lo == null || v.compareTo(lo.subtract(slack)) >= 0) && (hi == null || v.compareTo(hi.add(slack)) <= 0);
        }
    }

    /** The decoded call's implications: ranges per asset key, and assets it may hand back. */
    static final class Expectation {
        final Map<String, Range> ranges = new LinkedHashMap<>();
        /** Assets (by plain asset key, any token ID) the wallet may gain beyond {@link #ranges}. */
        final Set<String> mayGain = new HashSet<>();

        void add(String key, Range r) {
            Range old = ranges.get(key);
            if (old == null) ranges.put(key, r);
            else old.add(r);
        }
    }

    private SimulationCheck() {}

    /** Null when the request carries no claim. {@code signer} is the reviewed address (any case). */
    static Result review(Eip1559Request r, String signer, TokenList tokens) {
        HostSimulation sim = r.hostSimulation;
        if (sim == null) return null;
        if (tokens == null) tokens = TokenList.empty();
        String s = signer == null ? null : signer.toLowerCase(Locale.ROOT);
        Labels labels = new Labels(r, tokens);

        List<String> contradictions = new ArrayList<>();
        List<String> unexplained = new ArrayList<>();
        Map<String, HostSimulation.Change> claimed = new LinkedHashMap<>();
        for (HostSimulation.Change c : sim.changes) claimed.put(c.key(), c);

        // 1. the Mac's labels for assets the phone names itself
        for (HostSimulation.Change c : sim.changes) {
            String problem = labelProblem(r, tokens, c);
            if (problem != null) contradictions.add(problem);
        }

        // 2. the balance changes the phone's decoding implies (one or two readings; see expectations)
        List<Expectation> readings = expectations(r, s, tokens);
        List<String> best = null;
        List<String> bestUnexplained = null;
        for (Expectation e : readings) {
            List<String> problems = new ArrayList<>();
            List<String> extra = new ArrayList<>();
            compare(e, claimed, labels, problems, extra);
            if (best == null || problems.size() < best.size()) { best = problems; bestUnexplained = extra; }
        }
        contradictions.addAll(best);
        unexplained.addAll(bestUnexplained);

        // 3. the box
        List<MessageReview.Row> rows = new ArrayList<>();
        StringBuilder lines = new StringBuilder();
        for (HostSimulation.Change c : sim.changes) {
            if (lines.length() > 0) lines.append('\n');
            lines.append(labels.change(c));
        }
        rows.add(new MessageReview.Row("The Mac says your balance changes by",
                lines.length() == 0 ? "Nothing (no balance changes reported, not even the fee)" : lines.toString()));
        rows.add(new MessageReview.Row("Simulated by the Mac", "On " + sim.node + " at block " + sim.block
                + ". This phone is offline: it cannot check any of these numbers. They are not part of what you sign."));
        if (!contradictions.isEmpty()) {
            StringBuilder why = new StringBuilder(MISMATCH);
            for (String c : contradictions) why.append("\n• ").append(c);
            rows.add(new MessageReview.Row(MessageReview.DANGER, why.toString(), "MAC SIMULATION MISMATCH"));
        }
        if (!unexplained.isEmpty()) {
            StringBuilder why = new StringBuilder("The Mac also reports changes that the phone's decoding of this call does not explain. "
                    + "A contract can move tokens through an earlier approval; if you did not expect this, reject.");
            for (String u : unexplained) why.append("\n• ").append(u);
            rows.add(new MessageReview.Row(MessageReview.WARNING, why.toString(), "UNEXPLAINED CHANGES"));
        }
        return new Result(rows, contradictions, unexplained);
    }

    // ------------------------------------------------------------------ expectations

    /** One reading, or two for approve/transferFrom on a contract that could be ERC-20 or ERC-721. */
    static List<Expectation> expectations(Eip1559Request r, String s, TokenList tokens) {
        List<Expectation> out = new ArrayList<>();
        if (r.kind == Eip1559Request.Kind.NATIVE_TRANSFER) {
            Expectation e = base(r);
            if (!r.to.equals(s)) e.add(HostSimulation.NATIVE, Range.exactly(r.value.negate(), true));
            // native coin sent to a token contract the phone lists (e.g. WETH's deposit) may come back as that token
            if (tokens.lookup(r.chainId, r.to) != null) e.mayGain.add(r.to);
            out.add(e);
        } else if (r.kind == Eip1559Request.Kind.SWAP) {
            out.add(swap(r, s));
        } else if (r.kind == Eip1559Request.Kind.NFT_CALL) {
            out.add(nft(r, s));
        } else {
            Erc20Call call = r.tokenCall;
            boolean listedToken = tokens.lookup(r.chainId, r.to) != null;
            boolean listedNft = NftCollections.lookup(r.chainId, r.to) != null;
            boolean ambiguous = call.function == Erc20Call.Function.APPROVE || call.function == Erc20Call.Function.TRANSFER_FROM;
            if (!listedNft || !ambiguous) out.add(erc20(r, s));
            if (ambiguous && (listedNft || !listedToken)) out.add(erc721(r, s));
        }
        return out;
    }

    /** Every reading starts with the fee: the native coin may only go down, by at most the fee bound. */
    private static Expectation base(Eip1559Request r) {
        Expectation e = new Expectation();
        e.add(HostSimulation.NATIVE, Range.exactly(BigInteger.ZERO, true));
        return e;
    }

    private static BigInteger flow(String from, String to, String s, BigInteger amount) {
        BigInteger v = BigInteger.ZERO;
        if (to.equals(s)) v = v.add(amount);
        if (from.equals(s)) v = v.subtract(amount);
        return v;
    }

    private static Expectation erc20(Eip1559Request r, String s) {
        Expectation e = base(r);
        Erc20Call call = r.tokenCall;
        BigInteger change;
        switch (call.function) {
            case TRANSFER: change = flow(s, call.party, s, call.amount); break;
            case TRANSFER_FROM: change = flow(call.from, call.party, s, call.amount); break;
            default: change = BigInteger.ZERO; // approve / increaseAllowance move nothing
        }
        e.add(r.to, Range.exactly(change, true));
        return e;
    }

    private static Expectation erc721(Eip1559Request r, String s) {
        Expectation e = base(r);
        Erc20Call call = r.tokenCall;
        BigInteger change = call.function == Erc20Call.Function.TRANSFER_FROM ? flow(call.from, call.party, s, BigInteger.ONE) : BigInteger.ZERO;
        e.add(HostSimulation.Change.key(r.to, call.amount), Range.exactly(change, false));
        return e;
    }

    private static Expectation nft(Eip1559Request r, String s) {
        Expectation e = base(r);
        NftCall call = r.nftCall;
        for (int i = 0; i < call.tokenIds.size(); i++) {
            BigInteger amount = call.function.erc1155() ? call.amounts.get(i) : BigInteger.ONE;
            e.add(HostSimulation.Change.key(r.to, call.tokenIds.get(i)), Range.exactly(flow(call.from, call.party, s, amount), false));
        }
        return e;
    }

    private static Expectation swap(Eip1559Request r, String s) {
        Expectation e = base(r);
        SwapPlan plan = r.swap;
        for (SwapPlan.Amount a : plan.gives) {
            BigInteger v = a.value.negate();
            e.add(asset(a.asset), a.bound == SwapPlan.Bound.EXACT ? Range.exactly(v, true) : new Range(v, BigInteger.ZERO, true));
        }
        for (SwapPlan.Amount a : plan.receives) {
            e.add(asset(a.asset), a.bound == SwapPlan.Bound.EXACT ? Range.exactly(a.value, true) : new Range(a.value, null, true));
        }
        // a payout or fee addressed to this wallet by its own address (not the router's flag)
        for (SwapPlan.Payment p : plan.payments) if (p.recipient.equals(s)) e.mayGain.add(asset(p.amount.asset));
        return e;
    }

    private static String asset(String swapAsset) {
        return SwapPlan.NATIVE.equals(swapAsset) ? HostSimulation.NATIVE : swapAsset;
    }

    // ------------------------------------------------------------------ comparison

    private static void compare(Expectation e, Map<String, HostSimulation.Change> claimed, Labels labels,
                                List<String> problems, List<String> extra) {
        for (Map.Entry<String, Range> entry : e.ranges.entrySet()) {
            String key = entry.getKey();
            Range range = entry.getValue();
            if (HostSimulation.NATIVE.equals(key)) widenForFee(range, labels.request);
            HostSimulation.Change c = claimed.get(key);
            BigInteger got = c == null ? BigInteger.ZERO : c.delta;
            if (!range.contains(got)) problems.add(labels.mismatch(key, range, got));
        }
        for (HostSimulation.Change c : claimed.values()) {
            if (e.ranges.containsKey(c.key())) continue;
            if (c.delta.signum() > 0 && !e.mayGain.contains(c.asset)) {
                problems.add("The Mac claims you gain " + labels.change(c).substring(1)
                        + ", but this transaction, as decoded by the phone, gives nothing of it back.");
            } else if (c.delta.signum() < 0) {
                extra.add(labels.change(c));
            }
        }
    }

    /** gas limit × max fee bounds the fee on Ethereum, Sepolia and Polygon; rollups add an unbounded L1 fee. */
    private static void widenForFee(Range native_, Eip1559Request r) {
        if (r.chainId == 1 || r.chainId == 11155111 || r.chainId == 137) {
            native_.lo = native_.lo == null ? null : native_.lo.subtract(r.gasLimit.multiply(r.maxFeePerGas));
        } else {
            native_.lo = null;
        }
    }

    private static String labelProblem(Eip1559Request r, TokenList tokens, HostSimulation.Change c) {
        if (c.nativeCoin()) {
            if (c.symbol != null && !c.symbol.equals(r.nativeSymbol())) {
                return "The Mac calls the native coin \"" + c.symbol + "\"; on this network it is " + r.nativeSymbol() + ".";
            }
            if (c.decimals != null && c.decimals != 18) return "The Mac gives the native coin " + c.decimals + " decimals; it has 18.";
            return null;
        }
        TokenList.Token t = tokens.lookup(r.chainId, c.asset);
        if (t == null || c.nft()) return null;
        if (c.symbol != null && !c.symbol.equals(t.symbol)) {
            return "The Mac calls token " + Keys.toChecksumAddress(c.asset) + " \"" + c.symbol + "\"; the phone's list says " + t.symbol + ".";
        }
        if (c.decimals != null && c.decimals != t.decimals) {
            return "The Mac gives " + t.symbol + " " + c.decimals + " decimals; the phone's list says " + t.decimals + ".";
        }
        return null;
    }

    // ------------------------------------------------------------------ wording

    /** Amount wording: the phone's own names for what it lists; the Mac's label only in quotes. */
    static final class Labels {
        final Eip1559Request request;
        final TokenList tokens;

        Labels(Eip1559Request request, TokenList tokens) {
            this.request = request;
            this.tokens = tokens;
        }

        String change(HostSimulation.Change c) {
            String sign = c.delta.signum() < 0 ? "−" : "+";
            return sign + amount(c.asset, c.tokenId, c.delta.abs(), c);
        }

        String amount(String asset, BigInteger tokenId, BigInteger magnitude, HostSimulation.Change claim) {
            if (HostSimulation.NATIVE.equals(asset)) return Units.format(magnitude, 18, true) + " " + request.nativeSymbol();
            String contract = Keys.toChecksumAddress(asset);
            if (tokenId != null) {
                NftCollections.Collection col = NftCollections.lookup(request.chainId, asset);
                String name = col != null ? col.name : "NFT contract " + contract;
                return magnitude + " × " + name + " #" + tokenId;
            }
            TokenList.Token t = tokens.lookup(request.chainId, asset);
            if (t != null) return Units.format(magnitude, t.decimals, true) + " " + t.symbol;
            UniswapRouters.Router router = request.swap != null ? request.swap.router : null;
            if (router != null && router.wrappedNative.equals(asset)) return Units.format(magnitude, 18, true) + " " + router.wrappedSymbol;
            String macLabel = claim != null && claim.symbol != null
                    ? " (the Mac calls it \"" + claim.symbol + "\"" + (claim.decimals != null ? ", " + claim.decimals + " decimals" : "") + "; unverified)"
                    : "";
            return Erc20Call.baseUnits(magnitude) + " of unknown token " + contract + macLabel;
        }

        /** "+100 USDC", "−1 × Bored Ape Yacht Club #1", or "no change" for an asset key. */
        String signed(String key, BigInteger v) {
            if (v.signum() == 0) return "no change";
            return (v.signum() < 0 ? "−" : "+") + magnitude(key, v.abs());
        }

        String magnitude(String key, BigInteger v) {
            int hash = key.indexOf('#');
            if (hash < 0) return amount(key, null, v, null);
            return amount(key.substring(0, hash), new BigInteger(key.substring(hash + 1)), v, null);
        }

        /** What an asset key is called on this screen. */
        String name(String key) {
            if (HostSimulation.NATIVE.equals(key)) return request.nativeSymbol();
            int hash = key.indexOf('#');
            String asset = hash < 0 ? key : key.substring(0, hash);
            if (hash >= 0) {
                NftCollections.Collection col = NftCollections.lookup(request.chainId, asset);
                return (col != null ? col.name : "NFT contract " + Keys.toChecksumAddress(asset)) + " " + key.substring(hash);
            }
            TokenList.Token t = tokens.lookup(request.chainId, asset);
            if (t != null) return t.symbol;
            UniswapRouters.Router router = request.swap != null ? request.swap.router : null;
            if (router != null && router.wrappedNative.equals(asset)) return router.wrappedSymbol;
            return "unknown token " + Keys.toChecksumAddress(asset);
        }

        /** The phone's expectation in words. */
        String describe(String key, Range range) {
            boolean nativeKey = HostSimulation.NATIVE.equals(key);
            if (range.lo != null && range.lo.equals(range.hi)) return signed(key, range.lo);
            if (range.hi != null && range.hi.signum() <= 0) { // a decrease: at least −hi, at most −lo
                BigInteger least = range.hi.negate();
                BigInteger most = range.lo == null ? null : range.lo.negate();
                if (least.signum() == 0) {
                    if (nativeKey) return most == null ? "only the network fee" : "at most −" + magnitude(key, most) + " (the network fee)";
                    return most == null ? "no gain" : "a decrease of at most " + magnitude(key, most);
                }
                if (most == null) return "−" + magnitude(key, least) + (nativeKey ? " plus the network fee" : " or more");
                return "−" + magnitude(key, least) + " to −" + magnitude(key, most) + (nativeKey ? " (with the maximum network fee)" : "");
            }
            if (range.lo != null && range.lo.signum() >= 0) {
                return range.hi == null ? "at least +" + magnitude(key, range.lo) : "+" + magnitude(key, range.lo) + " to +" + magnitude(key, range.hi);
            }
            if (range.lo == null) return "at most " + signed(key, range.hi);
            if (range.hi == null) return "at least " + signed(key, range.lo);
            return "between " + signed(key, range.lo) + " and " + signed(key, range.hi);
        }

        String mismatch(String key, Range range, BigInteger got) {
            return "For " + name(key) + " the phone decoded " + describe(key, range) + "; the Mac claims " + signed(key, got) + ".";
        }
    }
}
