package dev.phonevault.signer;

import org.web3j.crypto.Keys;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static dev.phonevault.signer.TransactionReview.DANGER;
import static dev.phonevault.signer.TransactionReview.WARNING;
import static dev.phonevault.signer.TransactionReview.row;

/**
 * The swap review: "You give 100 USDC · You get at least 0.0312 ETH · Recipient: this wallet ✓ ·
 * Expires …", built from the {@link SwapPlan} decoded out of the same {@link Eip1559Request} that
 * is signed. Token names come only from the built-in {@link TokenList} (and the router's pinned
 * wrapped-native token); anything else is shown as an unknown token in raw base units with a
 * warning.
 */
final class SwapReview {
    private SwapReview() {}

    static final String THIS_WALLET = "This wallet ✓";

    static TransactionReview build(Eip1559Request r, String signerAddress, TokenList tokens, AddressSafety safety, String fromLabel) {
        SwapPlan plan = r.swap;
        String signer = signerAddress == null ? null : signerAddress.toLowerCase(Locale.ROOT);
        SwapPlan.TokenNames names = new SwapPlan.TokenNames(r.chainId, tokens, plan.router, r.nativeSymbol());
        List<MessageReview.Row> rows = new ArrayList<>();
        List<MessageReview.Row> details = new ArrayList<>();
        List<TransactionReview.Party> parties = new ArrayList<>();

        // Payouts to a literal address equal to this wallet count as "this wallet" (merged per token).
        java.util.Map<String, SwapPlan.Amount> merged = new java.util.LinkedHashMap<>();
        for (SwapPlan.Amount a : plan.receives) merge(merged, a);
        List<SwapPlan.Payment> others = new ArrayList<>();
        for (SwapPlan.Payment p : plan.payments) {
            if (!p.fee() && signer != null && p.recipient.equals(signer)) merge(merged, p.amount);
            else others.add(p);
        }
        // A no-minimum payout counts as "unused input coming back" (exact-output swaps, native value
        // the swap did not need) only when the decoder traced every part of it to this wallet's own
        // input that no swap touched. A payout that includes ANY swap output with no minimum stays a
        // "You get at least 0" with its No-minimum DANGER, even in a coin this wallet also paid in.
        List<SwapPlan.Amount> receives = new ArrayList<>();
        List<SwapPlan.Amount> refunds = new ArrayList<>();
        for (SwapPlan.Amount a : merged.values()) {
            boolean refund = a.unusedInput && a.bound == SwapPlan.Bound.AT_LEAST && a.value.signum() == 0 && gave(plan, a.asset);
            (refund ? refunds : receives).add(a);
        }
        List<SwapPlan.Amount> gives = new ArrayList<>();
        for (SwapPlan.Amount g : plan.gives) {
            boolean refunded = false;
            for (SwapPlan.Amount f : refunds) if (sameCoin(plan, f.asset, g.asset)) refunded = true;
            gives.add(refunded ? new SwapPlan.Amount(g.asset, g.value, SwapPlan.Bound.AT_MOST) : g);
        }

        String give = join(gives, names, "You give ");
        String get = join(receives, names, "You get ");
        boolean otherRecipient = false;
        for (SwapPlan.Payment p : others) if (!p.fee() || bigFee(p)) otherRecipient = true;

        String headline = (give.isEmpty() ? "" : give) + (get.isEmpty() ? "" : (give.isEmpty() ? "" : " · ") + get)
                + " · Recipient: " + (otherRecipient ? "OTHER ADDRESS ✗" : receives.isEmpty() ? "—" : "this wallet ✓")
                + (plan.deadline != null ? " · Expires " + shortTime(plan.deadline) : " · No deadline");
        rows.add(row("Action", "Swap on Uniswap (" + plan.router.version.label + ")"));
        rows.add(row("Summary", headline));
        for (SwapPlan.Amount a : gives) rows.add(row("You give", amount(a, names)));
        for (SwapPlan.Amount a : refunds) {
            rows.add(row("Unused input", "Any " + names.symbolOrContract(a.asset) + " the swap does not need comes back to this wallet"));
        }
        for (SwapPlan.Amount a : receives) {
            rows.add(row(a.bound == SwapPlan.Bound.EXACT ? "You get exactly" : "You get at least", names.amount(a.asset, a.value)));
            if (a.bound == SwapPlan.Bound.AT_LEAST && a.value.signum() == 0) {
                rows.add(row(DANGER, "No minimum: this swap accepts getting nothing back in " + names.symbolOrContract(a.asset)
                        + ". It has no protection against a bad price."));
            }
        }
        if (receives.isEmpty() && !otherRecipient) rows.add(row(WARNING, "Nothing from this swap comes back to this wallet."));

        if (!otherRecipient) {
            rows.add(row("Recipient", receives.isEmpty() ? "—" : THIS_WALLET));
        }
        for (SwapPlan.Payment p : others) {
            String to = Keys.toChecksumAddress(p.recipient);
            if (p.fee() && !bigFee(p)) {
                String fee = "Fee: " + p.portion + " of the " + names.symbolOrContract(p.amount.asset) + " output"
                        + (p.amount.value.signum() > 0 ? " (at least " + names.amount(p.amount.asset, p.amount.value) + ")" : "")
                        + " goes to " + to;
                boolean high = portionAbove(p.portion, WARNING_FEE_PERCENT);
                rows.add(row(high ? WARNING : "Fee", fee + (high ? ". That is more than 1%, unusually high." : "")));
            } else if (p.fee()) {
                // A "fee" above 3% is not a fee: it is shown and counted like any other payout to another address.
                rows.add(row(DANGER, "OTHER ADDRESS ✗ " + p.portion + " of the " + names.symbolOrContract(p.amount.asset)
                        + " output" + (p.amount.value.signum() > 0 ? " (at least " + names.amount(p.amount.asset, p.amount.value) + ")" : "")
                        + " goes to " + to + " as a \"fee\". That is more than 3%, far above any normal interface fee. "
                        + "Do not sign unless you meant to give that much away."));
                rows.add(row("Recipient", to));
                if (safety != null) rows.addAll(safety.rows(signer, p.recipient, RecipientHistory.Role.SEND));
                parties.add(new TransactionReview.Party(p.recipient, RecipientHistory.Role.SEND));
            } else {
                rows.add(row(DANGER, "OTHER ADDRESS ✗ " + amount(p.amount, names) + " goes to " + to
                        + ", not to this wallet. Sign only if you meant to send the swapped tokens there."));
                rows.add(row("Recipient", to));
                if (safety != null) rows.addAll(safety.rows(signer, p.recipient, RecipientHistory.Role.SEND));
                parties.add(new TransactionReview.Party(p.recipient, RecipientHistory.Role.SEND));
            }
        }

        rows.add(row(plan.deadline != null ? "Expires" : WARNING, plan.deadline != null
                ? MessageReview.timeLabel(plan.deadline) + " (as written in the transaction; this phone's clock is not used)"
                : "No deadline: this swap can be executed at any later time, at whatever the price is then (the minimum still applies)."));

        // unknown tokens: raw base units, never a guessed symbol
        List<String> seen = new ArrayList<>();
        List<SwapPlan.Amount> all = new ArrayList<>(gives);
        all.addAll(receives);
        for (SwapPlan.Payment p : others) all.add(p.amount);
        for (SwapPlan.Amount a : all) {
            if (names.known(a.asset) || seen.contains(a.asset)) continue;
            seen.add(a.asset);
            rows.add(row(WARNING, "Unknown token " + Keys.toChecksumAddress(a.asset) + ": it is not in the token list built "
                    + "into this phone, so its name and decimals can't be verified; its amount is shown in raw base units."));
        }
        if (!tokens.available()) {
            rows.add(row(WARNING, "The token list built into this app failed its integrity check, so no token is recognized. ("
                    + tokens.problem() + ")"));
        }

        for (SwapPlan.Permit p : plan.permits) {
            boolean unlimited = p.amount.equals(UniversalRouter.UINT160_MAX);
            rows.add(row(unlimited ? WARNING : "Permit2 permission", "Also activates a Permit2 allowance you signed earlier: the "
                    + plan.router.version.label + " may spend " + (unlimited ? "UNLIMITED " + names.symbolOrContract(p.token)
                    : names.amount(p.token, p.amount)) + " from this wallet "
                    + (p.expiration.equals(UniversalRouter.UINT48_MAX) ? "with NO expiry" : "until " + MessageReview.timeLabel(p.expiration)) + "."));
        }
        if (plan.usesPermit2) {
            rows.add(row("Paid through", "Permit2: the router pulls your tokens using the Permit2 allowance this wallet gave it."));
        } else if (!plan.router.version.universal() && hasTokenGive(plan)) {
            rows.add(row("Paid through", "Your token approval for SwapRouter02 (the router pulls the tokens directly)."));
        }
        for (String note : plan.notes) if (!note.startsWith("No deadline")) rows.add(row(WARNING, note));
        if (plan.trailing.length > 0) {
            rows.add(row("Extra data", plan.trailing.length + " byte" + (plan.trailing.length == 1 ? " is" : "s are")
                    + " appended after the call. The router never reads them (apps add tracking tags there); shown under Details."));
            details.add(row("Appended bytes (ignored by the router)", "0x" + Abi.toHex(plan.trailing)));
        }
        for (String left : plan.leftovers) {
            rows.add(row(WARNING, "Some " + names.symbolOrContract(left) + " may be left in the router after this "
                    + "transaction, where anyone can take it."));
        }

        rows.add(row("Router", "Uniswap " + plan.router.version.label + " · " + Keys.toChecksumAddress(plan.router.address)
                + " (pinned in this phone)"));
        if (r.value.signum() > 0) rows.add(row("Native value sent", r.valueEth() + " (used by the swap)"));
        else rows.add(row("Native value sent", "0 " + r.nativeSymbol() + " (only the fee below)"));
        TransactionReview.addCommon(rows, r, signer, fromLabel);
        TransactionReview.addMaximumFee(rows, r);

        details.add(row("Function", plan.function + " · selector 0x" + r.data.substring(2, 10)));
        for (int i = 0; i < plan.steps.size(); i++) details.add(row("Step " + (i + 1), readable(plan.steps.get(i), names)));
        TransactionReview.addFeeDetails(details, r);
        details.add(row("Contract data", r.data));

        String title = "Swap";
        if (!gives.isEmpty() && !receives.isEmpty()) {
            title = "Swap " + names.symbolOrShort(gives.get(0).asset) + " → " + names.symbolOrShort(receives.get(0).asset);
        }
        if (otherRecipient) title = "Swap to OTHER ADDRESS";
        String locked = headline + " · " + r.networkLabel() + ". Unlock to review every field before anything is signed.";
        return new TransactionReview(title, rows, details,
                "I verified what I give, the minimum I get, the recipient, the deadline, the network, and the maximum fee shown above.",
                otherRecipient ? "Swap to other address & sign" : "Approve swap & sign", locked, null, parties);
    }

    private static boolean gave(SwapPlan plan, String asset) {
        for (SwapPlan.Amount g : plan.gives) if (sameCoin(plan, g.asset, asset)) return true;
        return false;
    }

    private static boolean sameCoin(SwapPlan plan, String a, String b) {
        if (a.equals(b)) return true;
        String w = plan.router.wrappedNative;
        return (a.equals(SwapPlan.NATIVE) && b.equals(w)) || (a.equals(w) && b.equals(SwapPlan.NATIVE));
    }

    private static void merge(java.util.Map<String, SwapPlan.Amount> map, SwapPlan.Amount a) {
        SwapPlan.Amount old = map.get(a.asset);
        if (old == null) { map.put(a.asset, a); return; }
        map.put(a.asset, new SwapPlan.Amount(a.asset, old.value.add(a.value),
                old.bound == SwapPlan.Bound.EXACT && a.bound == SwapPlan.Bound.EXACT ? SwapPlan.Bound.EXACT : SwapPlan.Bound.AT_LEAST));
    }

    /** Step text with lower-case token addresses replaced by their symbol (or EIP-55 address when unknown). */
    static String readable(String step, SwapPlan.TokenNames names) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("0x[0-9a-f]{40}").matcher(step);
        StringBuffer out = new StringBuffer();
        while (m.find()) {
            String a = m.group();
            m.appendReplacement(out, java.util.regex.Matcher.quoteReplacement(names.known(a) ? names.symbolOrContract(a) : Keys.toChecksumAddress(a)));
        }
        m.appendTail(out);
        return out.toString();
    }

    private static boolean hasTokenGive(SwapPlan plan) {
        for (SwapPlan.Amount a : plan.gives) if (!SwapPlan.NATIVE.equals(a.asset)) return true;
        return false;
    }

    static String amount(SwapPlan.Amount a, SwapPlan.TokenNames names) {
        String v = names.amount(a.asset, a.value);
        switch (a.bound) {
            case AT_MOST: return "at most " + v;
            case AT_LEAST: return "at least " + v;
            default: return v;
        }
    }

    private static String join(List<SwapPlan.Amount> list, SwapPlan.TokenNames names, String prefix) {
        if (list.isEmpty()) return "";
        StringBuilder b = new StringBuilder(prefix);
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) b.append(" + ");
            b.append(amount(list.get(i), names));
        }
        return b.toString();
    }

    /** "2026-10-11 14:32 UTC" (from the transaction; the phone's clock is not used). */
    static String shortTime(BigInteger seconds) {
        String full = MessageReview.timeLabel(seconds);
        // "yyyy-MM-dd HH:mm:ss UTC (n)" → "yyyy-MM-dd HH:mm UTC"
        if (full.matches("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} UTC.*")) return full.substring(0, 16) + " UTC";
        return full;
    }

    /** A portion fee above this is WARNING ("unusually high"). */
    static final java.math.BigDecimal WARNING_FEE_PERCENT = java.math.BigDecimal.ONE;
    /** A portion fee above this is treated as a payout to another address (DANGER, "OTHER ADDRESS"). */
    static final java.math.BigDecimal DANGER_FEE_PERCENT = java.math.BigDecimal.valueOf(3);

    static boolean bigFee(SwapPlan.Payment p) {
        return p.fee() && portionAbove(p.portion, DANGER_FEE_PERCENT);
    }

    /** True when the "0.25%"-style label exceeds {@code limit} percent; an unparseable label counts as above. */
    private static boolean portionAbove(String percent, java.math.BigDecimal limit) {
        try {
            return new java.math.BigDecimal(percent.replace("%", "")).compareTo(limit) > 0;
        } catch (NumberFormatException e) {
            return true;
        }
    }
}
