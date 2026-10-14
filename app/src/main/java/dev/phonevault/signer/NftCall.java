package dev.phonevault.signer;

import org.json.JSONException;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Strict decoder for the NFT calls whose selectors are unambiguous (no ERC-20 function shares
 * them): ERC-721/1155 {@code setApprovalForAll}, ERC-721 {@code safeTransferFrom} (with and
 * without data) and ERC-1155 {@code safeTransferFrom}/{@code safeBatchTransferFrom}. Canonical ABI
 * only ({@link Abi}); zero recipient/operator refused; a call carrying native value is refused.
 *
 * <p>ERC-721 {@code approve(address,uint256)} and {@code transferFrom(address,address,uint256)}
 * share their selectors with ERC-20; they are decoded by {@link Erc20Call} and interpreted by
 * {@link NftReview} using the built-in lists.
 */
final class NftCall {
    static final int MAX_BATCH = 64;
    static final int MAX_DATA = 1024;

    enum Function {
        SET_APPROVAL_FOR_ALL("a22cb465", "setApprovalForAll(address,bool)"),
        SAFE_TRANSFER_721("42842e0e", "safeTransferFrom(address,address,uint256)"),
        SAFE_TRANSFER_721_DATA("b88d4fde", "safeTransferFrom(address,address,uint256,bytes)"),
        SAFE_TRANSFER_1155("f242432a", "safeTransferFrom(address,address,uint256,uint256,bytes)"),
        SAFE_BATCH_TRANSFER_1155("2eb2c2d6", "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)");

        final String selector;
        final String signature;

        Function(String selector, String signature) {
            this.selector = selector;
            this.signature = signature;
        }

        boolean erc1155() { return this == SAFE_TRANSFER_1155 || this == SAFE_BATCH_TRANSFER_1155; }
    }

    final Function function;
    /** Source of a transfer (lower-case); null for setApprovalForAll. */
    final String from;
    /** Recipient of a transfer, or the operator of setApprovalForAll (lower-case). */
    final String party;
    /** setApprovalForAll's flag. */
    final boolean approved;
    final List<BigInteger> tokenIds;
    /** ERC-1155 amounts, parallel to tokenIds; empty for ERC-721. */
    final List<BigInteger> amounts;
    /** Extra data passed to the receiver's hook; empty when none. */
    final byte[] data;

    private NftCall(Function function, String from, String party, boolean approved,
                    List<BigInteger> tokenIds, List<BigInteger> amounts, byte[] data) {
        this.function = function;
        this.from = from;
        this.party = party;
        this.approved = approved;
        this.tokenIds = Collections.unmodifiableList(tokenIds);
        this.amounts = Collections.unmodifiableList(amounts);
        this.data = data;
    }

    static boolean handles(String selector) {
        for (Function f : Function.values()) if (f.selector.equals(selector)) return true;
        return false;
    }

    static NftCall decode(String hex) throws JSONException {
        try {
            byte[] call = Abi.hex(hex);
            String selector = Abi.selector(call);
            Function function = null;
            for (Function f : Function.values()) if (f.selector.equals(selector)) function = f;
            if (function == null) throw new JSONException("Not an NFT call");
            List<Object> v;
            switch (function) {
                case SET_APPROVAL_FOR_ALL:
                    v = Abi.decodeCall(call, Abi.ADDRESS, Abi.BOOL);
                    return new NftCall(function, null, nonZero(v.get(0), "operator"), Abi.bool(v.get(1)),
                            new ArrayList<>(), new ArrayList<>(), new byte[0]);
                case SAFE_TRANSFER_721:
                    v = Abi.decodeCall(call, Abi.ADDRESS, Abi.ADDRESS, Abi.UINT256);
                    return transfer(function, v, Collections.singletonList(Abi.uint(v.get(2))), new ArrayList<>(), new byte[0]);
                case SAFE_TRANSFER_721_DATA:
                    v = Abi.decodeCall(call, Abi.ADDRESS, Abi.ADDRESS, Abi.UINT256, Abi.BYTES);
                    return transfer(function, v, Collections.singletonList(Abi.uint(v.get(2))), new ArrayList<>(), data(v.get(3)));
                case SAFE_TRANSFER_1155:
                    v = Abi.decodeCall(call, Abi.ADDRESS, Abi.ADDRESS, Abi.UINT256, Abi.UINT256, Abi.BYTES);
                    return transfer(function, v, Collections.singletonList(Abi.uint(v.get(2))),
                            Collections.singletonList(Abi.uint(v.get(3))), data(v.get(4)));
                default: {
                    v = Abi.decodeCall(call, Abi.ADDRESS, Abi.ADDRESS, Abi.array(Abi.UINT256), Abi.array(Abi.UINT256), Abi.BYTES);
                    List<BigInteger> ids = new ArrayList<>(), amounts = new ArrayList<>();
                    for (Object o : Abi.list(v.get(2))) ids.add(Abi.uint(o));
                    for (Object o : Abi.list(v.get(3))) amounts.add(Abi.uint(o));
                    if (ids.isEmpty()) throw new JSONException("safeBatchTransferFrom with no tokens");
                    if (ids.size() > MAX_BATCH) throw new JSONException("safeBatchTransferFrom with more than " + MAX_BATCH + " tokens");
                    if (ids.size() != amounts.size()) throw new JSONException("safeBatchTransferFrom ids and amounts differ in length");
                    return transfer(function, v, ids, amounts, data(v.get(4)));
                }
            }
        } catch (Abi.AbiException e) {
            throw new JSONException("NFT call is not canonically encoded: " + e.getMessage());
        }
    }

    private static NftCall transfer(Function f, List<Object> v, List<BigInteger> ids, List<BigInteger> amounts, byte[] data)
            throws JSONException {
        return new NftCall(f, nonZero(v.get(0), "sender"), nonZero(v.get(1), "recipient"), false,
                new ArrayList<>(ids), new ArrayList<>(amounts), data);
    }

    private static byte[] data(Object o) throws JSONException {
        byte[] b = Abi.bytes(o);
        if (b.length > MAX_DATA) throw new JSONException("NFT transfer data longer than " + MAX_DATA + " bytes");
        return b;
    }

    private static String nonZero(Object address, String what) throws JSONException {
        String a = Abi.address(address);
        if (Addresses.isZero(a)) throw new JSONException("Zero " + what + " is not allowed");
        return a;
    }
}
