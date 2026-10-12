package dev.phonevault.signer;

import org.json.JSONException;

/**
 * A request the phone refuses on safety grounds before any review exists (EIP-7702 delegation,
 * a contract call it cannot explain, a swap with features it cannot follow). Like every parse
 * error it is answered to the host with {@code status: "error"}; unlike a malformed frame, the
 * phone also shows the reason on screen so the user learns why nothing was signed.
 */
class RequestRefusal extends JSONException {
    final String title;

    RequestRefusal(String title, String message) {
        super(message);
        this.title = title;
    }

    static final String DELEGATION_TITLE = "Delegation refused";
    static final String DELEGATION = "Account delegation (EIP-7702) is not supported: it can hand control of this "
            + "wallet to a contract. Nothing was signed.";
    static final String UNKNOWN_CALL_TITLE = "Contract call refused";

    static RequestRefusal delegation(String detail) {
        return new RequestRefusal(DELEGATION_TITLE, DELEGATION + (detail == null ? "" : " (" + detail + ")"));
    }

    /** Non-empty calldata the phone cannot fully decode: refused, never shown raw for blind approval. */
    static RequestRefusal unknownCall(String contract, String selector) {
        return new RequestRefusal(UNKNOWN_CALL_TITLE, "This contract call can't be explained by the phone, so it was refused "
                + "and nothing was signed (contract " + contract + ", function selector 0x" + selector + "). "
                + Erc20Call.SUPPORTED + ", plus the NFT calls and pinned Uniswap routers the phone can explain.");
    }
}
