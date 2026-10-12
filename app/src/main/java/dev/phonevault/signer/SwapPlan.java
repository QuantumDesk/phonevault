package dev.phonevault.signer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What a decoded Uniswap router call does with value, in the terms the review shows: what this
 * wallet gives, what it gets back (at least / exactly), what goes to any other address (fees,
 * other recipients), Permit2 permissions it activates, and its deadline.
 *
 * <p>Built by {@link UniversalRouter} and {@link SwapDecoder} with a small conservative model of
 * the router's own balances ({@link Sim}): every amount is either known exactly or known as a
 * lower bound. Any step the model cannot follow exactly — spending a balance it cannot show is
 * there, leaving native coin unused, an unsettled V4 delta — makes the decoder refuse the whole
 * transaction ({@link Refusal}), so nothing is signed that the review could not explain.
 */
final class SwapPlan {
    /** Asset key for the chain's native coin (Uniswap's address(0) "ETH"). */
    static final String NATIVE = "0x0000000000000000000000000000000000000000";
    /** Uniswap's CONTRACT_BALANCE flag in the Universal Router (2^255). */
    static final BigInteger CONTRACT_BALANCE = BigInteger.ONE.shiftLeft(255);
    /** Uniswap's recipient flags: MSG_SENDER = address(1), ADDRESS_THIS = address(2). */
    static final String MSG_SENDER = "0x0000000000000000000000000000000000000001";
    static final String ADDRESS_THIS = "0x0000000000000000000000000000000000000002";

    /** The refusal text the review shows whenever a router call cannot be fully explained. */
    static final String CANNOT_EXPLAIN = "This swap uses features the phone can't explain; nothing was signed.";

    enum Bound { EXACT, AT_MOST, AT_LEAST }

    static final class Amount {
        final String asset;
        final BigInteger value;
        final Bound bound;

        Amount(String asset, BigInteger value, Bound bound) {
            this.asset = asset;
            this.value = value;
            this.bound = bound;
        }
    }

    /** Value sent to an address other than "this wallet" by flag (it may still equal the signer). */
    static final class Payment {
        final String recipient;
        final Amount amount;
        /** Non-null for a portion fee: the portion in basis points (or 1e18-precision portion as text). */
        final String portion;

        Payment(String recipient, Amount amount, String portion) {
            this.recipient = recipient;
            this.amount = amount;
            this.portion = portion;
        }

        boolean fee() { return portion != null; }
    }

    /** A Permit2 allowance the transaction activates (PERMIT2_PERMIT). */
    static final class Permit {
        final String token;
        final BigInteger amount;
        final BigInteger expiration;
        final String spender;

        Permit(String token, BigInteger amount, BigInteger expiration, String spender) {
            this.token = token;
            this.amount = amount;
            this.expiration = expiration;
            this.spender = spender;
        }
    }

    static final class Refusal extends RequestRefusal {
        Refusal(String detail) { super("Swap refused", CANNOT_EXPLAIN + " (" + detail + ")"); }
    }

    final UniswapRouters.Router router;
    final String function;
    final List<Amount> gives;
    final List<Amount> receives;
    final List<Payment> payments;
    final List<Permit> permits;
    final List<String> steps;
    final List<String> notes;
    /** Assets that may stay in the router after the call (anyone could take them). */
    final List<String> leftovers;
    /** Bytes appended after the call's ABI data (ignored by the router); empty when none. */
    final byte[] trailing;
    /** Unix seconds, or null when the call carries no deadline. */
    final BigInteger deadline;
    /** True when tokens are pulled through Permit2 (Universal Router) rather than a direct ERC-20 approval. */
    final boolean usesPermit2;
    final BigInteger nativeValue;

    SwapPlan(UniswapRouters.Router router, String function, Sim sim, BigInteger deadline, BigInteger nativeValue) {
        this.router = router;
        this.function = function;
        this.gives = Collections.unmodifiableList(new ArrayList<>(sim.gives.values()));
        this.receives = Collections.unmodifiableList(new ArrayList<>(sim.receives.values()));
        this.payments = Collections.unmodifiableList(new ArrayList<>(sim.payments));
        this.permits = Collections.unmodifiableList(new ArrayList<>(sim.permits));
        this.steps = Collections.unmodifiableList(new ArrayList<>(sim.steps));
        this.notes = Collections.unmodifiableList(new ArrayList<>(sim.notes));
        this.leftovers = Collections.unmodifiableList(new ArrayList<>(sim.leftovers));
        this.trailing = sim.trailing.clone();
        this.deadline = deadline;
        this.usesPermit2 = sim.usesPermit2;
        this.nativeValue = nativeValue;
    }

    // ------------------------------------------------------------------ the balance model

    /** What the model knows about one amount: exactly {@code exact}, or at least {@code min}. */
    static final class Bal {
        final BigInteger exact;
        final BigInteger min;

        private Bal(BigInteger exact, BigInteger min) {
            this.exact = exact;
            this.min = min;
        }

        static Bal exactly(BigInteger v) { return new Bal(v, v); }
        static Bal atLeast(BigInteger v) { return new Bal(null, v); }

        boolean known() { return exact != null; }
        boolean surelyZero() { return exact != null && exact.signum() == 0; }

        Bal plus(Bal o) {
            return exact != null && o.exact != null ? exactly(exact.add(o.exact)) : atLeast(min.add(o.min));
        }

        Amount as(String asset) { return new Amount(asset, known() ? exact : min, known() ? Bound.EXACT : Bound.AT_LEAST); }
    }

    /** The router's balances, this wallet's flows and the steps, as a call is decoded. */
    static final class Sim {
        final UniswapRouters.Router router;
        final Map<String, Bal> held = new LinkedHashMap<>();
        final Map<String, Amount> gives = new LinkedHashMap<>();
        final Map<String, Amount> receives = new LinkedHashMap<>();
        final List<Payment> payments = new ArrayList<>();
        final List<Permit> permits = new ArrayList<>();
        final List<String> steps = new ArrayList<>();
        final List<String> notes = new ArrayList<>();
        final List<String> leftovers = new ArrayList<>();
        boolean usesPermit2;
        byte[] trailing = new byte[0];

        Sim(UniswapRouters.Router router, BigInteger nativeValue) {
            this.router = router;
            if (nativeValue.signum() > 0) {
                held.put(NATIVE, Bal.exactly(nativeValue));
                give(NATIVE, nativeValue, Bound.EXACT);
            }
        }

        /** This wallet pays {@code value} of {@code asset} (exactly or at most). */
        void give(String asset, BigInteger value, Bound bound) {
            Amount old = gives.get(asset);
            if (old == null) gives.put(asset, new Amount(asset, value, bound));
            else gives.put(asset, new Amount(asset, old.value.add(value),
                    old.bound == Bound.EXACT && bound == Bound.EXACT ? Bound.EXACT : Bound.AT_MOST));
        }

        /** Delivers {@code amount} to a mapped recipient: this wallet, the router itself, or an address. */
        void deliver(String recipient, String asset, Bal amount) throws Refusal {
            if (NATIVE.equals(recipient)) throw new Refusal("a payout to the zero address");
            if (MSG_SENDER.equals(recipient)) {
                receive(asset, amount);
            } else if (ADDRESS_THIS.equals(recipient) || router.address.equals(recipient)) {
                hold(asset, amount);
            } else {
                payments.add(new Payment(recipient, amount.as(asset), null));
            }
        }

        void receive(String asset, Bal amount) {
            Amount old = receives.get(asset);
            Amount add = amount.as(asset);
            if (old == null) receives.put(asset, add);
            else receives.put(asset, new Amount(asset, old.value.add(add.value),
                    old.bound == Bound.EXACT && add.bound == Bound.EXACT ? Bound.EXACT : Bound.AT_LEAST));
        }

        void hold(String asset, Bal amount) {
            Bal old = held.get(asset);
            held.put(asset, old == null ? amount : old.plus(amount));
        }

        /** Everything the router holds of {@code asset}; refused if this transaction never put any there. */
        Bal takeAll(String asset, String why) throws Refusal {
            Bal b = held.remove(asset);
            if (b == null) throw new Refusal(why + " uses a router balance this transaction never funded");
            return b;
        }

        /**
         * A "send everything the router holds" payout (SWEEP, UNWRAP, refund). When this transaction
         * never funded {@code asset} the payout is a harmless no-op if its minimum is 0 (returns null);
         * with a positive minimum it would depend on other people's leftovers, so it is refused.
         */
        Bal sweep(String asset, BigInteger min, String why) throws Refusal {
            Bal b = held.remove(asset);
            if (b == null) {
                if (min.signum() > 0) throw new Refusal(why + " expects a router balance this transaction never funded");
                steps.add(why + ": nothing of " + asset + " is expected in the router (a safety sweep; no-op)");
                return null;
            }
            if (b.known()) return b;
            return Bal.atLeast(b.min.max(min));
        }

        /** Exactly {@code amount} from the router's balance; refused unless it is provably there. */
        void take(String asset, BigInteger amount, String why) throws Refusal {
            Bal b = held.get(asset);
            if (b == null) throw new Refusal(why + " spends a router balance this transaction never funded");
            if (b.known()) {
                if (b.exact.compareTo(amount) < 0) throw new Refusal(why + " spends more than the router holds");
                held.put(asset, Bal.exactly(b.exact.subtract(amount)));
            } else {
                if (b.min.compareTo(amount) < 0) throw new Refusal(why + " may spend more than the router is known to hold");
                held.put(asset, Bal.atLeast(b.min.subtract(amount)));
            }
            if (held.get(asset).surelyZero()) held.remove(asset);
        }

        /** Up to {@code max} from the router's balance (exact-output input); the rest stays as an unknown remainder. */
        void takeUpTo(String asset, BigInteger max, String why) throws Refusal {
            Bal b = held.get(asset);
            if (b == null) throw new Refusal(why + " spends a router balance this transaction never funded");
            BigInteger have = b.known() ? b.exact : b.min;
            if (have.compareTo(max) < 0) throw new Refusal(why + " may need more than the router is known to hold");
            held.put(asset, Bal.atLeast(have.subtract(max)));
        }

        /** Portion fee: {@code numerator/denominator} of the router's balance goes to {@code recipient}. */
        void portion(String asset, String recipient, BigInteger numerator, BigInteger denominator, String label) throws Refusal {
            if (numerator.compareTo(denominator) > 0) throw new Refusal("a fee larger than 100%");
            Bal b = held.get(asset);
            if (b == null) throw new Refusal("a fee taken from a router balance this transaction never funded");
            BigInteger feeMin = b.min.multiply(numerator).divide(denominator);
            if (MSG_SENDER.equals(recipient) || ADDRESS_THIS.equals(recipient) || router.address.equals(recipient)) {
                throw new Refusal("a portion paid back to the wallet or router");
            }
            payments.add(new Payment(recipient, new Amount(asset, feeMin, Bound.AT_LEAST), label));
            // what stays is at least min − ceil(min × portion); exact amounts become lower bounds
            BigInteger keep = b.min.subtract(b.min.multiply(numerator).add(denominator).subtract(BigInteger.ONE).divide(denominator));
            held.put(asset, Bal.atLeast(keep.max(BigInteger.ZERO)));
        }

        /** Final checks: unused native coin is refused; other possible leftovers become a warning. */
        void finish() throws Refusal {
            for (Map.Entry<String, Bal> e : held.entrySet()) {
                Bal b = e.getValue();
                if (b.surelyZero()) continue;
                if (NATIVE.equals(e.getKey()) && b.known()) {
                    throw new Refusal("it sends " + b.exact + " wei of native coin that the swap does not use");
                }
                leftovers.add(e.getKey());
            }
            if (receives.isEmpty() && payments.isEmpty()) throw new Refusal("nothing is delivered to anyone");
        }
    }

    /** Formats assets for the review: token list first, then the router's own wrapped-native pin. */
    static final class TokenNames {
        final long chainId;
        final TokenList tokens;
        final UniswapRouters.Router router;
        final String nativeSymbol;

        TokenNames(long chainId, TokenList tokens, UniswapRouters.Router router, String nativeSymbol) {
            this.chainId = chainId;
            this.tokens = tokens == null ? TokenList.empty() : tokens;
            this.router = router;
            this.nativeSymbol = nativeSymbol;
        }

        /** True when the phone knows the symbol and decimals. */
        boolean known(String asset) {
            return NATIVE.equals(asset) || tokens.lookup(chainId, asset) != null
                    || (router != null && router.wrappedNative.equals(asset));
        }

        String symbolOrContract(String asset) {
            if (NATIVE.equals(asset)) return nativeSymbol;
            TokenList.Token t = tokens.lookup(chainId, asset);
            if (t != null) return t.symbol;
            if (router != null && router.wrappedNative.equals(asset)) return router.wrappedSymbol;
            return "unknown token " + org.web3j.crypto.Keys.toChecksumAddress(asset);
        }

        /** Symbol, or a short address for an unknown token (titles). */
        String symbolOrShort(String asset) {
            return known(asset) ? symbolOrContract(asset) : LookAlike.shortForm(asset);
        }

        String amount(String asset, BigInteger raw) {
            if (NATIVE.equals(asset)) return Erc20Call.formatUnits(raw, 18) + " " + nativeSymbol;
            TokenList.Token t = tokens.lookup(chainId, asset);
            if (t != null) return Erc20Call.formatUnits(raw, t.decimals) + " " + t.symbol;
            if (router != null && router.wrappedNative.equals(asset)) return Erc20Call.formatUnits(raw, 18) + " " + router.wrappedSymbol;
            return Erc20Call.baseUnits(raw) + " of unknown token " + org.web3j.crypto.Keys.toChecksumAddress(asset);
        }
    }
}
