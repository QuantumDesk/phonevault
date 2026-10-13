package dev.phonevault.signer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Decoder for Uniswap Universal Router {@code execute(bytes commands, bytes[] inputs[, uint256
 * deadline])} on the pinned 2.0 / 2.1 routers ({@link UniswapRouters}). Only these commands are
 * explained; any other command, the allow-revert flag, or an input this decoder cannot follow is
 * refused with {@link SwapPlan#CANNOT_EXPLAIN}:
 *
 * <pre>
 * 0x00 V3_SWAP_EXACT_IN   0x01 V3_SWAP_EXACT_OUT  0x02 PERMIT2_TRANSFER_FROM (to the router only)
 * 0x04 SWEEP              0x05 TRANSFER           0x06 PAY_PORTION
 * 0x07 PAY_PORTION_FULL_PRECISION (2.1 only)      0x08 V2_SWAP_EXACT_IN  0x09 V2_SWAP_EXACT_OUT
 * 0x0a PERMIT2_PERMIT (spender must be this router) 0x0b WRAP_ETH (to the router) 0x0c UNWRAP_WETH
 * 0x10 V4_SWAP with SWAP_EXACT_IN(_SINGLE), SWAP_EXACT_OUT(_SINGLE), SETTLE, SETTLE_ALL, TAKE,
 *      TAKE_ALL, TAKE_PORTION
 * </pre>
 *
 * Input layouts follow the deployed sources (universal-router tags 2.0.0 / 2.1.2 Dispatcher.sol,
 * v4-periphery V4Router.sol / IV4Router.sol at the router's pinned submodule commit). Every input
 * must be canonical ABI ({@link Abi}), so the router's assembly decoding reads the same values.
 */
final class UniversalRouter {
    private UniversalRouter() {}

    static final String EXECUTE_WITH_DEADLINE = "3593564c"; // execute(bytes,bytes[],uint256)
    static final String EXECUTE = "24856bc3";               // execute(bytes,bytes[])
    static final int MAX_COMMANDS = 16;
    static final int MAX_V4_ACTIONS = 16;
    static final int MAX_PATH_HOPS = 4;
    /**
     * Bytes allowed after execute()'s ABI data. Solidity never reads them; apps append tracking
     * tags there (the Uniswap web app adds 22 bytes starting with "unix"). Shown on the review.
     */
    static final int MAX_TRAILING = 64;
    /** Zero padding allowed after a small V4 parameter block (some encoders add an unused zero word). */
    static final int MAX_V4_PADDING = 64;

    static final BigInteger UINT160_MAX = BigInteger.ONE.shiftLeft(160).subtract(BigInteger.ONE);
    static final BigInteger UINT48_MAX = BigInteger.ONE.shiftLeft(48).subtract(BigInteger.ONE);
    private static final BigInteger BIPS = BigInteger.valueOf(10_000);
    private static final BigInteger E18 = BigInteger.TEN.pow(18);

    static boolean handles(String selector) {
        return EXECUTE_WITH_DEADLINE.equals(selector) || EXECUTE.equals(selector);
    }

    static SwapPlan decode(UniswapRouters.Router router, byte[] call, BigInteger value) throws SwapPlan.Refusal {
        if (router == null || !router.version.universal()) throw new SwapPlan.Refusal("not a pinned Universal Router");
        boolean v21 = router.version == UniswapRouters.Version.UR_2_1;
        String selector = Abi.selector(call);
        List<Object> args;
        byte[] trailing;
        BigInteger deadline = null;
        try {
            byte[] body = java.util.Arrays.copyOfRange(call, 4, call.length);
            Abi.Decoded d;
            if (EXECUTE_WITH_DEADLINE.equals(selector)) {
                d = Abi.decodeWithTrailing(body, MAX_TRAILING, false, Abi.BYTES, Abi.array(Abi.BYTES), Abi.UINT256);
                args = d.values;
                deadline = Abi.uint(args.get(2));
            } else if (EXECUTE.equals(selector)) {
                d = Abi.decodeWithTrailing(body, MAX_TRAILING, false, Abi.BYTES, Abi.array(Abi.BYTES));
                args = d.values;
            } else {
                throw new SwapPlan.Refusal("unknown Universal Router function");
            }
            trailing = d.trailing;
        } catch (Abi.AbiException e) {
            throw new SwapPlan.Refusal("execute() is not canonically encoded: " + e.getMessage());
        }
        byte[] commands = Abi.bytes(args.get(0));
        List<Object> inputs = Abi.list(args.get(1));
        if (commands.length == 0) throw new SwapPlan.Refusal("no commands");
        if (commands.length > MAX_COMMANDS) throw new SwapPlan.Refusal("more than " + MAX_COMMANDS + " commands");
        if (commands.length != inputs.size()) throw new SwapPlan.Refusal("commands and inputs differ in number");

        SwapPlan.Sim sim = new SwapPlan.Sim(router, value);
        sim.trailing = trailing;
        for (int i = 0; i < commands.length; i++) {
            int command = commands[i] & 0xff;
            byte[] input = Abi.bytes(inputs.get(i));
            if ((command & 0x80) != 0) throw new SwapPlan.Refusal("command " + (i + 1) + " may fail silently (allow-revert flag)");
            try {
                command(sim, router, v21, command, input);
            } catch (Abi.AbiException e) {
                throw new SwapPlan.Refusal("command " + (i + 1) + " (" + name(command) + ") is not canonically encoded: " + e.getMessage());
            }
        }
        sim.finish();
        if (deadline == null) sim.notes.add("No deadline: this transaction stays valid until it is mined or replaced.");
        return new SwapPlan(router, "execute(" + (deadline != null ? "bytes,bytes[],uint256" : "bytes,bytes[]") + ")",
                sim, deadline, value);
    }

    static String name(int command) {
        switch (command) {
            case 0x00: return "V3_SWAP_EXACT_IN";
            case 0x01: return "V3_SWAP_EXACT_OUT";
            case 0x02: return "PERMIT2_TRANSFER_FROM";
            case 0x03: return "PERMIT2_PERMIT_BATCH";
            case 0x04: return "SWEEP";
            case 0x05: return "TRANSFER";
            case 0x06: return "PAY_PORTION";
            case 0x07: return "PAY_PORTION_FULL_PRECISION";
            case 0x08: return "V2_SWAP_EXACT_IN";
            case 0x09: return "V2_SWAP_EXACT_OUT";
            case 0x0a: return "PERMIT2_PERMIT";
            case 0x0b: return "WRAP_ETH";
            case 0x0c: return "UNWRAP_WETH";
            case 0x0d: return "PERMIT2_TRANSFER_FROM_BATCH";
            case 0x0e: return "BALANCE_CHECK_ERC20";
            case 0x10: return "V4_SWAP";
            case 0x11: return "V3_POSITION_MANAGER_PERMIT";
            case 0x12: return "V3_POSITION_MANAGER_CALL";
            case 0x13: return "V4_INITIALIZE_POOL";
            case 0x14: return "V4_POSITION_MANAGER_CALL";
            case 0x21: return "EXECUTE_SUB_PLAN";
            default: return String.format(java.util.Locale.ROOT, "command 0x%02x", command);
        }
    }

    private static void command(SwapPlan.Sim sim, UniswapRouters.Router router, boolean v21, int command, byte[] input)
            throws Abi.AbiException, SwapPlan.Refusal {
        switch (command) {
            case 0x00:
            case 0x01: {
                List<Object> a = v21
                        ? Abi.decode(input, Abi.ADDRESS, Abi.UINT256, Abi.UINT256, Abi.BYTES, Abi.BOOL, Abi.array(Abi.UINT256))
                        : Abi.decode(input, Abi.ADDRESS, Abi.UINT256, Abi.UINT256, Abi.BYTES, Abi.BOOL);
                List<String> path = v3Path(Abi.bytes(a.get(3)));
                if (v21) hopLimits(sim, Abi.list(a.get(5)), path.size() - 1);
                boolean exactIn = command == 0x00;
                if (!exactIn) java.util.Collections.reverse(path); // exact-output paths are encoded output-first
                swap(sim, "Uniswap v3", exactIn, Abi.address(a.get(0)), Abi.uint(a.get(1)), Abi.uint(a.get(2)), path, Abi.bool(a.get(4)));
                return;
            }
            case 0x08:
            case 0x09: {
                List<Object> a = v21
                        ? Abi.decode(input, Abi.ADDRESS, Abi.UINT256, Abi.UINT256, Abi.array(Abi.ADDRESS), Abi.BOOL, Abi.array(Abi.UINT256))
                        : Abi.decode(input, Abi.ADDRESS, Abi.UINT256, Abi.UINT256, Abi.array(Abi.ADDRESS), Abi.BOOL);
                List<String> path = new ArrayList<>();
                for (Object o : Abi.list(a.get(3))) path.add(token(Abi.address(o)));
                if (path.size() < 2 || path.size() > MAX_PATH_HOPS + 1) throw new SwapPlan.Refusal("a V2 path of " + path.size() + " tokens");
                if (v21) hopLimits(sim, Abi.list(a.get(5)), path.size() - 1);
                boolean exactIn = command == 0x08;
                if (exactIn && Abi.uint(a.get(1)).signum() == 0) throw new SwapPlan.Refusal("a V2 swap of tokens already sent to the pool");
                swap(sim, "Uniswap v2", exactIn, Abi.address(a.get(0)), Abi.uint(a.get(1)), Abi.uint(a.get(2)), path, Abi.bool(a.get(4)));
                return;
            }
            case 0x02: {
                List<Object> a = Abi.decode(input, Abi.ADDRESS, Abi.ADDRESS, Abi.uint(160));
                String token = token(Abi.address(a.get(0)));
                String to = Abi.address(a.get(1));
                if (!SwapPlan.ADDRESS_THIS.equals(to) && !router.address.equals(to)) {
                    throw new SwapPlan.Refusal("PERMIT2_TRANSFER_FROM sends tokens somewhere other than the router");
                }
                BigInteger amount = Abi.uint(a.get(2));
                sim.give(token, amount, SwapPlan.Bound.EXACT);
                sim.usesPermit2 = true;
                sim.hold(token, SwapPlan.Bal.inputExactly(amount));
                sim.steps.add("Move " + amount + " base units of " + token + " from this wallet to the router (Permit2)");
                return;
            }
            case 0x0a: {
                List<Object> a = Abi.decode(input,
                        Abi.tuple(Abi.tuple(Abi.ADDRESS, Abi.uint(160), Abi.uint(48), Abi.uint(48)), Abi.ADDRESS, Abi.UINT256), Abi.BYTES);
                List<Object> single = Abi.list(a.get(0));
                List<Object> details = Abi.list(single.get(0));
                String spender = Abi.address(single.get(1));
                if (!router.address.equals(spender)) throw new SwapPlan.Refusal("a Permit2 permit for a spender other than this router");
                String token = token(Abi.address(details.get(0)));
                byte[] signature = Abi.bytes(a.get(1));
                if (signature.length != 65 && signature.length != 64) throw new SwapPlan.Refusal("a Permit2 permit with a " + signature.length + "-byte signature");
                sim.permits.add(new SwapPlan.Permit(token, Abi.uint(details.get(1)), Abi.uint(details.get(2)), spender));
                sim.steps.add("Activate a Permit2 allowance (signed earlier) for the router to spend " + token
                        + "; signature deadline " + Abi.uint(single.get(2)));
                return;
            }
            case 0x0b: {
                List<Object> a = Abi.decode(input, Abi.ADDRESS, Abi.UINT256);
                String to = Abi.address(a.get(0));
                if (!SwapPlan.ADDRESS_THIS.equals(to) && !router.address.equals(to)) throw new SwapPlan.Refusal("WRAP_ETH to another address");
                BigInteger amount = Abi.uint(a.get(1));
                SwapPlan.Bal wrapped;
                if (SwapPlan.CONTRACT_BALANCE.equals(amount)) {
                    wrapped = sim.takeAll(SwapPlan.NATIVE, "WRAP_ETH");
                } else {
                    SwapPlan.Bal source = sim.held.get(SwapPlan.NATIVE); // null is refused by take()
                    sim.take(SwapPlan.NATIVE, amount, "WRAP_ETH");
                    wrapped = source.exactlyLike(amount); // the wallet's own coin stays "input" when wrapped
                }
                sim.hold(router.wrappedNative, wrapped);
                sim.steps.add("Wrap the native coin sent with this transaction into " + router.wrappedSymbol);
                return;
            }
            case 0x0c: {
                List<Object> a = Abi.decode(input, Abi.ADDRESS, Abi.UINT256);
                BigInteger min = Abi.uint(a.get(1));
                String to = Abi.address(a.get(0));
                SwapPlan.Bal all = sim.sweep(router.wrappedNative, min, "UNWRAP_WETH");
                if (all == null) return;
                if (SwapPlan.ADDRESS_THIS.equals(to) || router.address.equals(to)) {
                    sim.hold(SwapPlan.NATIVE, all);
                } else {
                    sim.deliver(to, SwapPlan.NATIVE, all);
                }
                sim.steps.add("Unwrap all of the router's " + router.wrappedSymbol + " (at least " + min + " wei) and send it to " + who(to));
                return;
            }
            case 0x04: {
                List<Object> a = Abi.decode(input, Abi.ADDRESS, Abi.ADDRESS, Abi.uint(160));
                String asset = Abi.address(a.get(0));
                String to = Abi.address(a.get(1));
                if (SwapPlan.ADDRESS_THIS.equals(to) || router.address.equals(to)) throw new SwapPlan.Refusal("SWEEP to the router itself");
                BigInteger min = Abi.uint(a.get(2));
                SwapPlan.Bal all = sim.sweep(asset, min, "SWEEP");
                if (all == null) return;
                sim.deliver(to, asset, all);
                sim.steps.add("Send all of the router's " + asset + " (at least " + min + ") to " + who(to));
                return;
            }
            case 0x05: {
                List<Object> a = Abi.decode(input, Abi.ADDRESS, Abi.ADDRESS, Abi.UINT256);
                String asset = Abi.address(a.get(0));
                String to = Abi.address(a.get(1));
                if (SwapPlan.ADDRESS_THIS.equals(to) || router.address.equals(to)) throw new SwapPlan.Refusal("TRANSFER to the router itself");
                BigInteger amount = Abi.uint(a.get(2));
                if (SwapPlan.CONTRACT_BALANCE.equals(amount)) {
                    if (SwapPlan.NATIVE.equals(asset)) throw new SwapPlan.Refusal("TRANSFER of the whole native balance");
                    sim.deliver(to, asset, sim.takeAll(asset, "TRANSFER"));
                } else {
                    SwapPlan.Bal source = sim.held.get(asset); // null is refused by take()
                    sim.take(asset, amount, "TRANSFER");
                    sim.deliver(to, asset, source.exactlyLike(amount));
                }
                sim.steps.add("Pay " + amount + " of " + asset + " from the router to " + who(to));
                return;
            }
            case 0x06: {
                List<Object> a = Abi.decode(input, Abi.ADDRESS, Abi.ADDRESS, Abi.UINT256);
                BigInteger bips = Abi.uint(a.get(2));
                if (bips.compareTo(BIPS) > 0) throw new SwapPlan.Refusal("PAY_PORTION above 100%");
                String label = percent(bips, BIPS);
                sim.portion(Abi.address(a.get(0)), Abi.address(a.get(1)), bips, BIPS, label);
                sim.steps.add("Pay " + label + " of the router's " + Abi.address(a.get(0)) + " to " + who(Abi.address(a.get(1))));
                return;
            }
            case 0x07: {
                if (!v21) throw new SwapPlan.Refusal("command 0x07 does not exist on this router");
                List<Object> a = Abi.decode(input, Abi.ADDRESS, Abi.ADDRESS, Abi.UINT256);
                BigInteger portion = Abi.uint(a.get(2));
                if (portion.compareTo(E18) > 0) throw new SwapPlan.Refusal("PAY_PORTION_FULL_PRECISION above 100%");
                String label = percent(portion, E18);
                sim.portion(Abi.address(a.get(0)), Abi.address(a.get(1)), portion, E18, label);
                sim.steps.add("Pay " + label + " of the router's " + Abi.address(a.get(0)) + " to " + who(Abi.address(a.get(1))));
                return;
            }
            case 0x10:
                v4(sim, v21, input);
                return;
            default:
                throw new SwapPlan.Refusal("command " + name(command) + " is not supported");
        }
    }

    // ------------------------------------------------------------------ V2/V3 swaps

    /** path is input-first. */
    private static void swap(SwapPlan.Sim sim, String venue, boolean exactIn, String recipient, BigInteger amount,
                             BigInteger limit, List<String> path, boolean payerIsUser) throws SwapPlan.Refusal {
        String in = path.get(0), out = path.get(path.size() - 1);
        if (in.equals(out)) throw new SwapPlan.Refusal("a swap whose input and output are the same token");
        if (exactIn) {
            if (SwapPlan.CONTRACT_BALANCE.equals(amount)) {
                if (payerIsUser) throw new SwapPlan.Refusal("a wallet-paid swap of 'the router's balance'");
                sim.takeAll(in, venue + " swap");
            } else if (payerIsUser) {
                if (amount.signum() == 0) throw new SwapPlan.Refusal("a swap of nothing");
                sim.give(in, amount, SwapPlan.Bound.EXACT);
                sim.usesPermit2 = true;
            } else {
                sim.take(in, amount, venue + " swap");
            }
            sim.deliver(recipient, out, SwapPlan.Bal.atLeast(limit));
        } else {
            if (amount.signum() == 0 || amount.compareTo(SwapPlan.CONTRACT_BALANCE) >= 0) throw new SwapPlan.Refusal("an exact-output swap of " + amount);
            if (payerIsUser) {
                sim.give(in, limit, SwapPlan.Bound.AT_MOST);
                sim.usesPermit2 = true;
            } else {
                sim.takeUpTo(in, limit, venue + " swap");
            }
            sim.deliver(recipient, out, SwapPlan.Bal.exactly(amount));
        }
        sim.steps.add(venue + (exactIn ? " exact-input" : " exact-output") + " swap " + in + " → " + out + " ("
                + (path.size() - 1) + " hop" + (path.size() > 2 ? "s" : "") + "), "
                + (exactIn ? "amount in " + amount + ", minimum out " + limit : "amount out " + amount + ", maximum in " + limit)
                + ", paid by " + (payerIsUser ? "this wallet (Permit2)" : "the router") + ", output to " + who(recipient));
    }

    /** A packed v3 path: token (20) ‖ fee (3) ‖ token (20) …; returned as the token list, encoded order. */
    static List<String> v3Path(byte[] p) throws SwapPlan.Refusal {
        if (p.length < 43 || (p.length - 20) % 23 != 0) throw new SwapPlan.Refusal("a malformed v3 path");
        int hops = (p.length - 20) / 23;
        if (hops > MAX_PATH_HOPS) throw new SwapPlan.Refusal("a v3 path of " + hops + " hops");
        List<String> tokens = new ArrayList<>();
        for (int i = 0; i <= hops; i++) {
            byte[] t = java.util.Arrays.copyOfRange(p, 23 * i, 23 * i + 20);
            tokens.add(token("0x" + Abi.toHex(t)));
        }
        return tokens;
    }

    private static void hopLimits(SwapPlan.Sim sim, List<Object> limits, int hops) throws SwapPlan.Refusal {
        if (!limits.isEmpty() && limits.size() != hops) throw new SwapPlan.Refusal("per-hop price limits that do not match the path");
        if (!limits.isEmpty()) sim.steps.add("Per-hop minimum prices set for " + limits.size() + " hop(s) (extra protection)");
    }

    // ------------------------------------------------------------------ V4

    private static final int SWAP_EXACT_IN_SINGLE = 0x06, SWAP_EXACT_IN = 0x07, SWAP_EXACT_OUT_SINGLE = 0x08,
            SWAP_EXACT_OUT = 0x09, SETTLE = 0x0b, SETTLE_ALL = 0x0c, TAKE = 0x0e, TAKE_ALL = 0x0f, TAKE_PORTION = 0x10;

    private static Abi.Type poolKey() {
        return Abi.tuple(Abi.ADDRESS, Abi.ADDRESS, Abi.uint(24), Abi.int_(24), Abi.ADDRESS);
    }

    private static Abi.Type pathKey() {
        return Abi.tuple(Abi.ADDRESS, Abi.uint(24), Abi.int_(24), Abi.ADDRESS, Abi.BYTES);
    }

    private static void v4(SwapPlan.Sim sim, boolean v21, byte[] input) throws Abi.AbiException, SwapPlan.Refusal {
        List<Object> outer = Abi.decode(input, Abi.BYTES, Abi.array(Abi.BYTES));
        byte[] actions = Abi.bytes(outer.get(0));
        List<Object> params = Abi.list(outer.get(1));
        if (actions.length == 0 || actions.length > MAX_V4_ACTIONS) throw new SwapPlan.Refusal("a V4 swap with " + actions.length + " actions");
        if (actions.length != params.size()) throw new SwapPlan.Refusal("V4 actions and parameters differ in number");
        Map<String, SwapPlan.Bal> debt = new LinkedHashMap<>(), credit = new LinkedHashMap<>();
        for (int i = 0; i < actions.length; i++) {
            int action = actions[i] & 0xff;
            byte[] p = Abi.bytes(params.get(i));
            switch (action) {
                case SWAP_EXACT_IN_SINGLE:
                case SWAP_EXACT_OUT_SINGLE: {
                    Abi.Type t = v21
                            ? Abi.tuple(poolKey(), Abi.BOOL, Abi.uint(128), Abi.uint(128), Abi.UINT256, Abi.BYTES)
                            : Abi.tuple(poolKey(), Abi.BOOL, Abi.uint(128), Abi.uint(128), Abi.BYTES);
                    List<Object> s = Abi.list(Abi.decode(p, t).get(0));
                    List<Object> key = Abi.list(s.get(0));
                    hooks(sim, Abi.address(key.get(4)), Abi.bytes(s.get(v21 ? 5 : 4)));
                    boolean zeroForOne = Abi.bool(s.get(1));
                    String c0 = Abi.address(key.get(0)), c1 = Abi.address(key.get(1));
                    if (c0.compareTo(c1) >= 0) throw new SwapPlan.Refusal("a V4 pool key with unsorted currencies");
                    String in = zeroForOne ? c0 : c1, out = zeroForOne ? c1 : c0;
                    v4Swap(sim, debt, credit, action == SWAP_EXACT_IN_SINGLE, in, out, Abi.uint(s.get(2)), Abi.uint(s.get(3)), 1);
                    break;
                }
                case SWAP_EXACT_IN:
                case SWAP_EXACT_OUT: {
                    Abi.Type t = v21
                            ? Abi.tuple(Abi.ADDRESS, Abi.array(pathKey()), Abi.array(Abi.UINT256), Abi.uint(128), Abi.uint(128))
                            : Abi.tuple(Abi.ADDRESS, Abi.array(pathKey()), Abi.uint(128), Abi.uint(128));
                    List<Object> s = Abi.list(Abi.decode(p, t).get(0));
                    List<Object> path = Abi.list(s.get(1));
                    if (path.isEmpty() || path.size() > MAX_PATH_HOPS) throw new SwapPlan.Refusal("a V4 path of " + path.size() + " hops");
                    if (v21) hopLimits(sim, Abi.list(s.get(2)), path.size());
                    for (Object o : path) {
                        List<Object> k = Abi.list(o);
                        hooks(sim, Abi.address(k.get(3)), Abi.bytes(k.get(4)));
                    }
                    String given = Abi.address(s.get(0));
                    // exact-in: currencyIn then path[i].intermediateCurrency forward;
                    // exact-out: currencyOut, walking path from the end; the input is path[0].intermediateCurrency
                    String in, out;
                    if (action == SWAP_EXACT_IN) {
                        in = given;
                        out = Abi.address(Abi.list(path.get(path.size() - 1)).get(0));
                    } else {
                        out = given;
                        in = Abi.address(Abi.list(path.get(0)).get(0));
                    }
                    int a = v21 ? 3 : 2;
                    v4Swap(sim, debt, credit, action == SWAP_EXACT_IN, in, out, Abi.uint(s.get(a)), Abi.uint(s.get(a + 1)), path.size());
                    break;
                }
                case SETTLE_ALL: {
                    List<Object> s = Abi.decodeWithTrailing(p, MAX_V4_PADDING, true, Abi.ADDRESS, Abi.UINT256).values;
                    String c = Abi.address(s.get(0));
                    BigInteger max = Abi.uint(s.get(1));
                    SwapPlan.Bal owed = debt.remove(c);
                    if (owed == null) throw new SwapPlan.Refusal("V4 SETTLE_ALL for a currency with no debt");
                    if (owed.known()) {
                        if (owed.exact.compareTo(max) > 0) throw new SwapPlan.Refusal("V4 SETTLE_ALL whose maximum is below the amount owed");
                        payExact(sim, c, owed.exact, true);
                    } else {
                        // exact-output debt: at most the swap's maximum, capped again by SETTLE_ALL's maximum
                        BigInteger cap = owed.min.min(max);
                        payUpTo(sim, c, cap);
                    }
                    sim.steps.add("V4: pay what the swap needs in " + c + " (at most " + max + ")");
                    break;
                }
                case SETTLE: {
                    List<Object> s = Abi.decodeWithTrailing(p, MAX_V4_PADDING, true, Abi.ADDRESS, Abi.UINT256, Abi.BOOL).values;
                    String c = Abi.address(s.get(0));
                    BigInteger amount = Abi.uint(s.get(1));
                    boolean payerIsUser = Abi.bool(s.get(2));
                    SwapPlan.Bal paid;
                    if (SwapPlan.CONTRACT_BALANCE.equals(amount)) {
                        if (payerIsUser && !SwapPlan.NATIVE.equals(c)) throw new SwapPlan.Refusal("V4 SETTLE of 'the router's balance' paid by the wallet");
                        paid = sim.takeAll(c, "V4 SETTLE");
                    } else if (amount.signum() == 0) {
                        SwapPlan.Bal owed = debt.get(c);
                        if (owed == null || !owed.known()) throw new SwapPlan.Refusal("V4 SETTLE of an open debt the phone cannot size");
                        payExact(sim, c, owed.exact, payerIsUser);
                        paid = owed;
                    } else {
                        payExact(sim, c, amount, payerIsUser);
                        paid = SwapPlan.Bal.exactly(amount);
                    }
                    applyCredit(debt, credit, c, paid);
                    sim.steps.add("V4: pay " + (amount.signum() == 0 ? "the open debt" : SwapPlan.CONTRACT_BALANCE.equals(amount)
                            ? "the router's whole balance" : amount.toString()) + " of " + c + " into the pool manager");
                    break;
                }
                case TAKE_ALL: {
                    List<Object> s = Abi.decodeWithTrailing(p, MAX_V4_PADDING, true, Abi.ADDRESS, Abi.UINT256).values;
                    String c = Abi.address(s.get(0));
                    SwapPlan.Bal got = credit.remove(c);
                    if (got == null) throw new SwapPlan.Refusal("V4 TAKE_ALL for a currency with no credit");
                    sim.receive(c, raise(got, Abi.uint(s.get(1))));
                    sim.steps.add("V4: send all of " + c + " to this wallet (at least " + Abi.uint(s.get(1)) + ")");
                    break;
                }
                case TAKE: {
                    List<Object> s = Abi.decodeWithTrailing(p, MAX_V4_PADDING, true, Abi.ADDRESS, Abi.ADDRESS, Abi.UINT256).values;
                    String c = Abi.address(s.get(0));
                    String to = Abi.address(s.get(1));
                    BigInteger amount = Abi.uint(s.get(2));
                    SwapPlan.Bal have = credit.get(c);
                    if (have == null) throw new SwapPlan.Refusal("V4 TAKE for a currency with no credit");
                    SwapPlan.Bal taken;
                    if (amount.signum() == 0) {
                        credit.remove(c);
                        taken = have;
                    } else {
                        if (!have.known() || have.exact.compareTo(amount) < 0) throw new SwapPlan.Refusal("V4 TAKE of a partial amount the phone cannot track");
                        taken = SwapPlan.Bal.exactly(amount);
                        if (have.exact.equals(amount)) credit.remove(c);
                        else credit.put(c, SwapPlan.Bal.exactly(have.exact.subtract(amount)));
                    }
                    sim.deliver(to, c, taken);
                    sim.steps.add("V4: send " + (amount.signum() == 0 ? "all" : amount.toString()) + " of " + c + " to " + who(to));
                    break;
                }
                case TAKE_PORTION: {
                    List<Object> s = Abi.decodeWithTrailing(p, MAX_V4_PADDING, true, Abi.ADDRESS, Abi.ADDRESS, Abi.UINT256).values;
                    String c = Abi.address(s.get(0));
                    String to = Abi.address(s.get(1));
                    BigInteger bips = Abi.uint(s.get(2));
                    if (bips.compareTo(BIPS) > 0) throw new SwapPlan.Refusal("V4 TAKE_PORTION above 100%");
                    SwapPlan.Bal have = credit.get(c);
                    if (have == null) throw new SwapPlan.Refusal("V4 TAKE_PORTION for a currency with no credit");
                    if (SwapPlan.NATIVE.equals(to)) throw new SwapPlan.Refusal("a fee paid to the zero address");
                    if (SwapPlan.MSG_SENDER.equals(to) || SwapPlan.ADDRESS_THIS.equals(to) || sim.router.address.equals(to)) {
                        throw new SwapPlan.Refusal("V4 TAKE_PORTION back to the wallet or router");
                    }
                    String label = percent(bips, BIPS);
                    sim.payments.add(new SwapPlan.Payment(to, new SwapPlan.Amount(c, have.min.multiply(bips).divide(BIPS), SwapPlan.Bound.AT_LEAST), label));
                    BigInteger keep = have.min.subtract(have.min.multiply(bips).add(BIPS).subtract(BigInteger.ONE).divide(BIPS));
                    credit.put(c, SwapPlan.Bal.atLeast(keep.max(BigInteger.ZERO)));
                    sim.steps.add("V4: pay " + label + " of " + c + " to " + who(to));
                    break;
                }
                default:
                    throw new SwapPlan.Refusal("V4 action " + String.format(java.util.Locale.ROOT, "0x%02x", action) + " is not supported");
            }
        }
        if (!debt.isEmpty()) throw new SwapPlan.Refusal("a V4 swap that leaves a debt unpaid");
        if (!credit.isEmpty()) throw new SwapPlan.Refusal("a V4 swap that leaves output untaken");
    }

    private static void v4Swap(SwapPlan.Sim sim, Map<String, SwapPlan.Bal> debt, Map<String, SwapPlan.Bal> credit,
                               boolean exactIn, String in, String out, BigInteger amount, BigInteger limit, int hops)
            throws SwapPlan.Refusal {
        if (in.equals(out)) throw new SwapPlan.Refusal("a V4 swap whose input and output are the same currency");
        if (exactIn) {
            if (amount.signum() == 0) {
                // OPEN_DELTA: swap whatever this transaction already paid in (a prior SETTLE)
                SwapPlan.Bal prepaid = credit.remove(in);
                if (prepaid == null) throw new SwapPlan.Refusal("a V4 swap of an open credit that does not exist");
            } else {
                applyDebt(debt, credit, in, SwapPlan.Bal.exactly(amount));
            }
            applyCredit(debt, credit, out, SwapPlan.Bal.atLeast(limit));
        } else {
            if (amount.signum() == 0) throw new SwapPlan.Refusal("a V4 exact-output swap of an open delta");
            // the debt is at most `limit`; recorded as a lower bound of `limit` used only as the cap
            if (debt.containsKey(in) || credit.containsKey(in)) throw new SwapPlan.Refusal("a V4 exact-output swap mixed with other flows of its input");
            debt.put(in, SwapPlan.Bal.atLeast(limit));
            applyCredit(debt, credit, out, SwapPlan.Bal.exactly(amount));
        }
        sim.steps.add("V4 " + (exactIn ? "exact-input" : "exact-output") + " swap " + in + " → " + out + " (" + hops + " hop"
                + (hops > 1 ? "s" : "") + "), " + (exactIn ? "amount in " + (amount.signum() == 0 ? "everything paid in" : amount)
                + ", minimum out " + limit : "amount out " + amount + ", maximum in " + limit));
    }

    private static void applyDebt(Map<String, SwapPlan.Bal> debt, Map<String, SwapPlan.Bal> credit, String c, SwapPlan.Bal d)
            throws SwapPlan.Refusal {
        SwapPlan.Bal have = credit.get(c);
        if (have != null) {
            if (!have.known() || !d.known()) throw new SwapPlan.Refusal("V4 amounts the phone cannot net exactly");
            BigInteger net = have.exact.subtract(d.exact);
            credit.remove(c);
            if (net.signum() > 0) credit.put(c, SwapPlan.Bal.exactly(net));
            else if (net.signum() < 0) addTo(debt, c, SwapPlan.Bal.exactly(net.negate()));
            return;
        }
        addTo(debt, c, d);
    }

    private static void applyCredit(Map<String, SwapPlan.Bal> debt, Map<String, SwapPlan.Bal> credit, String c, SwapPlan.Bal x)
            throws SwapPlan.Refusal {
        SwapPlan.Bal owed = debt.get(c);
        if (owed != null) {
            if (!owed.known() || !x.known()) throw new SwapPlan.Refusal("V4 amounts the phone cannot net exactly");
            BigInteger net = x.exact.subtract(owed.exact);
            debt.remove(c);
            if (net.signum() > 0) credit.put(c, SwapPlan.Bal.exactly(net));
            else if (net.signum() < 0) debt.put(c, SwapPlan.Bal.exactly(net.negate()));
            return;
        }
        addTo(credit, c, x);
    }

    private static void addTo(Map<String, SwapPlan.Bal> map, String c, SwapPlan.Bal x) {
        SwapPlan.Bal old = map.get(c);
        map.put(c, old == null ? x : old.plus(x));
    }

    /** Pays an exact amount into the pool manager: native coin always from the router, tokens per payer. */
    private static void payExact(SwapPlan.Sim sim, String c, BigInteger amount, boolean payerIsUser) throws SwapPlan.Refusal {
        if (SwapPlan.NATIVE.equals(c)) {
            sim.take(SwapPlan.NATIVE, amount, "V4 settle in native coin");
        } else if (payerIsUser) {
            sim.give(c, amount, SwapPlan.Bound.EXACT);
            sim.usesPermit2 = true;
        } else {
            sim.take(c, amount, "V4 settle");
        }
    }

    /** SETTLE_ALL of an exact-output debt: the wallet (or the router's native coin) pays at most {@code cap}. */
    private static void payUpTo(SwapPlan.Sim sim, String c, BigInteger cap) throws SwapPlan.Refusal {
        if (SwapPlan.NATIVE.equals(c)) {
            sim.takeUpTo(SwapPlan.NATIVE, cap, "V4 settle in native coin");
        } else {
            sim.give(c, cap, SwapPlan.Bound.AT_MOST);
            sim.usesPermit2 = true;
        }
    }

    private static void hooks(SwapPlan.Sim sim, String hooks, byte[] hookData) {
        if (!hooks.matches("0x0{40}")) {
            String note = "A pool in this swap runs extra contract code (hook " + org.web3j.crypto.Keys.toChecksumAddress(hooks)
                    + ") that the phone cannot check. Your minimum-received limit still applies.";
            if (!sim.notes.contains(note)) sim.notes.add(note);
        }
        if (hookData.length > 0) sim.steps.add("Passes " + hookData.length + " bytes of data to a pool hook");
    }

    // ------------------------------------------------------------------ helpers

    private static SwapPlan.Bal raise(SwapPlan.Bal b, BigInteger min) {
        if (b.known()) return b; // an exact amount already implies (or fails) the minimum
        return b.atLeastLike(b.min.max(min));
    }

    private static String token(String address) throws SwapPlan.Refusal {
        if (SwapPlan.NATIVE.equals(address)) throw new SwapPlan.Refusal("the zero address used as a token");
        return address;
    }

    static String who(String recipient) {
        if (SwapPlan.MSG_SENDER.equals(recipient)) return "this wallet";
        if (SwapPlan.ADDRESS_THIS.equals(recipient)) return "the router";
        return org.web3j.crypto.Keys.toChecksumAddress(recipient);
    }

    static String percent(BigInteger part, BigInteger whole) {
        return new java.math.BigDecimal(part).multiply(java.math.BigDecimal.valueOf(100))
                .divide(new java.math.BigDecimal(whole), 6, java.math.RoundingMode.DOWN).stripTrailingZeros().toPlainString() + "%";
    }
}
