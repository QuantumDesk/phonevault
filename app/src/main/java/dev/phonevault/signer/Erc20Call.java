package dev.phonevault.signer;

import org.json.JSONException;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.util.Locale;

/**
 * Strict decoder for the four ERC-20 calls the phone reviews. The calldata must be exactly the
 * selector plus the canonical ABI words for that function: nothing missing, nothing trailing,
 * address words zero-padded, no zero addresses. Anything else is refused, never guessed at.
 *
 * <p>A selector and well-formed arguments do not prove the contract is a token or behaves like
 * one; {@link TransactionReview} says so for contracts that are not in the built-in
 * {@link TokenList}.
 */
final class Erc20Call {
    enum Function {
        TRANSFER("a9059cbb", "transfer(address,uint256)", 2),
        APPROVE("095ea7b3", "approve(address,uint256)", 2),
        TRANSFER_FROM("23b872dd", "transferFrom(address,address,uint256)", 3),
        INCREASE_ALLOWANCE("39509351", "increaseAllowance(address,uint256)", 2);

        final String selector;
        final String signature;
        final int words;

        Function(String selector, String signature, int words) {
            this.selector = selector;
            this.signature = signature;
            this.words = words;
        }

        int dataBytes() { return 4 + 32 * words; }

        /** approve / increaseAllowance grant a spender permission instead of moving tokens now. */
        boolean grantsAllowance() { return this == APPROVE || this == INCREASE_ALLOWANCE; }
    }

    /** Allowances at or above 2^255 are shown as UNLIMITED (covers 2^256 − 1 and "half-max" patterns). */
    static final BigInteger UNLIMITED_THRESHOLD = BigInteger.ONE.shiftLeft(255);

    static final String SUPPORTED = "Only canonical transfer(address,uint256), approve(address,uint256), "
            + "transferFrom(address,address,uint256) and increaseAllowance(address,uint256) calldata is supported";

    final Function function;
    /** transferFrom's source address (lower-case 0x); null for the other functions. */
    final String from;
    /** Recipient (transfer, transferFrom) or spender (approve, increaseAllowance), lower-case 0x. */
    final String party;
    final BigInteger amount;

    private Erc20Call(Function function, String from, String party, BigInteger amount) {
        this.function = function;
        this.from = from;
        this.party = party;
        this.amount = amount;
    }

    /** True for the four ERC-20 selectors this decoder accepts. */
    static boolean handles(String selector) {
        for (Function f : Function.values()) if (f.selector.equals(selector)) return true;
        return false;
    }

    static Erc20Call decode(String data) throws JSONException {
        if (data == null || !data.matches("0x[0-9a-fA-F]*") || ((data.length() - 2) & 1) != 0)
            throw new JSONException("data must be even-length 0x-prefixed hex");
        String clean = Numeric.cleanHexPrefix(data).toLowerCase(Locale.ROOT);
        if (clean.length() < 8) throw new JSONException(SUPPORTED);
        String selector = clean.substring(0, 8);
        Function function = null;
        for (Function f : Function.values()) if (f.selector.equals(selector)) function = f;
        if (function == null) throw new JSONException(SUPPORTED);
        int bytes = clean.length() / 2;
        if (bytes != function.dataBytes()) {
            throw new JSONException(function.signature + " calldata must be exactly " + function.dataBytes()
                    + " bytes; got " + bytes + (bytes > function.dataBytes() ? " (trailing bytes)" : " (truncated)"));
        }
        String[] word = new String[function.words];
        for (int i = 0; i < function.words; i++) word[i] = clean.substring(8 + 64 * i, 8 + 64 * (i + 1));
        BigInteger amount = new BigInteger(word[function.words - 1], 16);
        if (function == Function.TRANSFER_FROM) {
            return new Erc20Call(function, address(word[0], "transferFrom source"),
                    address(word[1], "recipient"), amount);
        }
        return new Erc20Call(function, null,
                address(word[0], function.grantsAllowance() ? "approved address" : "recipient"), amount);
    }

    private static String address(String word, String what) throws JSONException {
        if (!word.startsWith("000000000000000000000000")) throw new JSONException(what + " has non-zero ABI padding");
        String address = "0x" + word.substring(24);
        if (Addresses.isZero(address)) throw new JSONException("Zero " + what + " is not allowed");
        return address;
    }

    boolean unlimited() { return function.grantsAllowance() && amount.compareTo(UNLIMITED_THRESHOLD) >= 0; }

    /** Base units with digit grouping, for unknown tokens: "1,000,000 base units". */
    static String baseUnits(BigInteger raw) {
        return Units.format(raw, 0, true) + (BigInteger.ONE.equals(raw) ? " base unit" : " base units");
    }
}
