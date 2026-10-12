package dev.phonevault.signer;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;

/**
 * Entry point for router calls: a transaction whose {@code to} is a pinned Uniswap router
 * ({@link UniswapRouters}) is decoded into a {@link SwapPlan}; anything the decoders cannot fully
 * follow is refused with {@link SwapPlan#CANNOT_EXPLAIN}.
 *
 * <p>SwapRouter02 (Uniswap/swap-router-contracts, V3SwapRouter + PeripheryPaymentsExtended):
 * {@code exactInputSingle}, {@code exactInput}, {@code exactOutputSingle}, {@code exactOutput},
 * {@code unwrapWETH9}, {@code refundETH}, {@code sweepToken}, and {@code multicall(uint256
 * deadline, bytes[])} / {@code multicall(bytes[])} over those (no nesting). Its V2 functions,
 * fee variants, {@code multicall(bytes32,…)} and everything else are refused. Semantics followed:
 * {@code amountIn == 0} spends the router's own balance; a WETH9 input is paid from the native
 * coin sent with the call when that covers it; recipients address(1)/address(2) are mapped only
 * inside the swap functions (unwrap/sweep send to the literal address, so 1/2 there are refused);
 * a non-zero {@code sqrtPriceLimitX96} (partial fills) is refused.
 */
final class SwapDecoder {
    private SwapDecoder() {}

    static final String MULTICALL_DEADLINE = "5ae401dc";   // multicall(uint256,bytes[])
    static final String MULTICALL = "ac9650d8";            // multicall(bytes[])
    static final String EXACT_INPUT_SINGLE = "04e45aaf";   // exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))
    static final String EXACT_INPUT = "b858183f";          // exactInput((bytes,address,uint256,uint256))
    static final String EXACT_OUTPUT_SINGLE = "5023b4df";  // exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))
    static final String EXACT_OUTPUT = "09b81346";         // exactOutput((bytes,address,uint256,uint256))
    static final String UNWRAP_WETH9_TO = "49404b7c";      // unwrapWETH9(uint256,address)
    static final String UNWRAP_WETH9 = "49616997";         // unwrapWETH9(uint256)
    static final String REFUND_ETH = "12210e8a";           // refundETH()
    static final String SWEEP_TOKEN_TO = "df2ab5bb";       // sweepToken(address,uint256,address)
    static final String SWEEP_TOKEN = "e90a182f";          // sweepToken(address,uint256)
    static final int MAX_MULTICALL = 8;

    /** Decodes a call to a pinned router; refuses (with the reason) anything it cannot explain. */
    static SwapPlan decode(UniswapRouters.Router router, String data, BigInteger value) throws SwapPlan.Refusal {
        byte[] call;
        try {
            call = Abi.hex(data);
        } catch (Abi.AbiException e) {
            throw new SwapPlan.Refusal(e.getMessage());
        }
        if (router.version.universal()) return UniversalRouter.decode(router, call, value);
        return swapRouter02(router, call, value);
    }

    static SwapPlan swapRouter02(UniswapRouters.Router router, byte[] call, BigInteger value) throws SwapPlan.Refusal {
        String selector = Abi.selector(call);
        SwapPlan.Sim sim = new SwapPlan.Sim(router, value);
        BigInteger deadline = null;
        String function;
        try {
            List<Object> calls;
            byte[] body = java.util.Arrays.copyOfRange(call, 4, call.length);
            if (MULTICALL_DEADLINE.equals(selector)) {
                Abi.Decoded d = Abi.decodeWithTrailing(body, UniversalRouter.MAX_TRAILING, false, Abi.UINT256, Abi.array(Abi.BYTES));
                deadline = Abi.uint(d.values.get(0));
                calls = Abi.list(d.values.get(1));
                sim.trailing = d.trailing;
                function = "multicall(uint256,bytes[])";
            } else if (MULTICALL.equals(selector)) {
                Abi.Decoded d = Abi.decodeWithTrailing(body, UniversalRouter.MAX_TRAILING, false, Abi.array(Abi.BYTES));
                calls = Abi.list(d.values.get(0));
                sim.trailing = d.trailing;
                function = "multicall(bytes[])";
            } else {
                calls = Collections.singletonList(call);
                function = null;
            }
            if (calls.isEmpty() || calls.size() > MAX_MULTICALL) throw new SwapPlan.Refusal("a multicall of " + calls.size() + " calls");
            for (Object o : calls) {
                byte[] inner = o instanceof byte[] ? (byte[]) o : Abi.bytes(o);
                String name = sr02Call(sim, router, inner);
                if (function == null) function = name;
            }
        } catch (Abi.AbiException e) {
            throw new SwapPlan.Refusal("SwapRouter02 call is not canonically encoded: " + e.getMessage());
        }
        sim.finish();
        if (deadline == null) sim.notes.add("No deadline: this transaction stays valid until it is mined or replaced.");
        return new SwapPlan(router, function, sim, deadline, value);
    }

    private static Abi.Type singleParams() {
        return Abi.tuple(Abi.ADDRESS, Abi.ADDRESS, Abi.uint(24), Abi.ADDRESS, Abi.UINT256, Abi.UINT256, Abi.uint(160));
    }

    private static Abi.Type pathParams() {
        return Abi.tuple(Abi.BYTES, Abi.ADDRESS, Abi.UINT256, Abi.UINT256);
    }

    private static String sr02Call(SwapPlan.Sim sim, UniswapRouters.Router router, byte[] call)
            throws Abi.AbiException, SwapPlan.Refusal {
        String selector = Abi.selector(call);
        if (selector == null) throw new SwapPlan.Refusal("an empty call inside multicall");
        switch (selector) {
            case EXACT_INPUT_SINGLE:
            case EXACT_OUTPUT_SINGLE: {
                List<Object> p = Abi.list(Abi.decodeCall(call, singleParams()).get(0));
                if (Abi.uint(p.get(6)).signum() != 0) throw new SwapPlan.Refusal("a price-limited swap (may fill only partly)");
                boolean exactIn = EXACT_INPUT_SINGLE.equals(selector);
                String in = Abi.address(p.get(0)), out = Abi.address(p.get(1));
                sr02Swap(sim, router, exactIn, in, out, Abi.address(p.get(3)), Abi.uint(p.get(4)), Abi.uint(p.get(5)), 1);
                return exactIn ? "exactInputSingle" : "exactOutputSingle";
            }
            case EXACT_INPUT:
            case EXACT_OUTPUT: {
                List<Object> p = Abi.list(Abi.decodeCall(call, pathParams()).get(0));
                boolean exactIn = EXACT_INPUT.equals(selector);
                List<String> path = UniversalRouter.v3Path(Abi.bytes(p.get(0)));
                if (!exactIn) Collections.reverse(path);
                sr02Swap(sim, router, exactIn, path.get(0), path.get(path.size() - 1), Abi.address(p.get(1)),
                        Abi.uint(p.get(2)), Abi.uint(p.get(3)), path.size() - 1);
                return exactIn ? "exactInput" : "exactOutput";
            }
            case UNWRAP_WETH9_TO:
            case UNWRAP_WETH9: {
                boolean to = UNWRAP_WETH9_TO.equals(selector);
                List<Object> a = to ? Abi.decodeCall(call, Abi.UINT256, Abi.ADDRESS) : Abi.decodeCall(call, Abi.UINT256);
                String recipient = to ? literal(Abi.address(a.get(1))) : SwapPlan.MSG_SENDER;
                BigInteger min = Abi.uint(a.get(0));
                SwapPlan.Bal all = sim.sweep(router.wrappedNative, min, "unwrapWETH9");
                if (all != null) sim.deliver(recipient, SwapPlan.NATIVE, all);
                sim.steps.add("Unwrap all of the router's " + router.wrappedSymbol + " (at least " + min + " wei) and send it to "
                        + UniversalRouter.who(recipient));
                return "unwrapWETH9";
            }
            case REFUND_ETH: {
                if (call.length != 4) throw new SwapPlan.Refusal("refundETH() with arguments");
                SwapPlan.Bal left = sim.held.remove(SwapPlan.NATIVE);
                if (left != null) sim.deliver(SwapPlan.MSG_SENDER, SwapPlan.NATIVE, left);
                sim.steps.add("Return any unused native coin to this wallet");
                return "refundETH";
            }
            case SWEEP_TOKEN_TO:
            case SWEEP_TOKEN: {
                boolean to = SWEEP_TOKEN_TO.equals(selector);
                List<Object> a = to ? Abi.decodeCall(call, Abi.ADDRESS, Abi.UINT256, Abi.ADDRESS)
                        : Abi.decodeCall(call, Abi.ADDRESS, Abi.UINT256);
                String token = Abi.address(a.get(0));
                String recipient = to ? literal(Abi.address(a.get(2))) : SwapPlan.MSG_SENDER;
                BigInteger min = Abi.uint(a.get(1));
                SwapPlan.Bal all = sim.sweep(token, min, "sweepToken");
                if (all != null) sim.deliver(recipient, token, all);
                sim.steps.add("Send all of the router's " + token + " (at least " + min + ") to " + UniversalRouter.who(recipient));
                return "sweepToken";
            }
            default:
                throw new SwapPlan.Refusal("SwapRouter02 function 0x" + selector + " is not supported");
        }
    }

    private static void sr02Swap(SwapPlan.Sim sim, UniswapRouters.Router router, boolean exactIn, String in, String out,
                                 String recipient, BigInteger amount, BigInteger limit, int hops) throws SwapPlan.Refusal {
        if (in.equals(out)) throw new SwapPlan.Refusal("a swap whose input and output are the same token");
        if (SwapPlan.NATIVE.equals(in) || SwapPlan.NATIVE.equals(out)) throw new SwapPlan.Refusal("the zero address used as a token");
        SwapPlan.Bal native_ = sim.held.get(SwapPlan.NATIVE);
        boolean nativePays = router.wrappedNative.equals(in) && native_ != null;
        if (exactIn) {
            if (amount.signum() == 0) {
                sim.takeAll(in, "a swap of the router's balance");
            } else if (nativePays) {
                // pay(): WETH9 is wrapped from the router's native balance when it covers the amount
                sim.take(SwapPlan.NATIVE, amount, "paying " + router.wrappedSymbol + " from the native coin sent");
            } else {
                sim.give(in, amount, SwapPlan.Bound.EXACT);
            }
            sim.deliver(recipient, out, SwapPlan.Bal.atLeast(limit));
        } else {
            if (amount.signum() == 0) throw new SwapPlan.Refusal("an exact-output swap of nothing");
            if (nativePays) sim.takeUpTo(SwapPlan.NATIVE, limit, "paying " + router.wrappedSymbol + " from the native coin sent");
            else sim.give(in, limit, SwapPlan.Bound.AT_MOST);
            sim.deliver(recipient, out, SwapPlan.Bal.exactly(amount));
        }
        sim.steps.add("Uniswap v3 " + (exactIn ? "exact-input" : "exact-output") + " swap " + in + " → " + out + " (" + hops
                + " hop" + (hops > 1 ? "s" : "") + "), " + (exactIn ? "amount in " + (amount.signum() == 0 ? "the router's balance" : amount)
                + ", minimum out " + limit : "amount out " + amount + ", maximum in " + limit) + ", output to " + UniversalRouter.who(recipient));
    }

    /** unwrap/sweep do not map address(1)/address(2): those would burn the funds, so they are refused. */
    private static String literal(String recipient) throws SwapPlan.Refusal {
        if (SwapPlan.MSG_SENDER.equals(recipient) || SwapPlan.ADDRESS_THIS.equals(recipient) || SwapPlan.NATIVE.equals(recipient)) {
            throw new SwapPlan.Refusal("a payout to the special address " + recipient);
        }
        return recipient;
    }
}
