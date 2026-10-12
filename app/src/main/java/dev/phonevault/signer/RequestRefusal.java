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

    static final String WRONG_ACCOUNT_TITLE = "Switch to the right account on the phone";

    /**
     * The host named a signer ({@code from}) that is not the phone's active account. Refused, never
     * re-routed: the user switches accounts on the phone (☰ → Accounts) and the host asks again.
     */
    static RequestRefusal wrongAccount(String requested, String activeName, String activeAddress) {
        return new RequestRefusal(WRONG_ACCOUNT_TITLE, "This request is for "
                + org.web3j.crypto.Keys.toChecksumAddress(requested) + ", but the active account on this phone is "
                + activeName + " (" + org.web3j.crypto.Keys.toChecksumAddress(activeAddress) + "). Switch to the right "
                + "account on the phone (☰ → Accounts, or open the passphrase wallet it belongs to), then send the "
                + "request again. Nothing was signed.");
    }

    /** Throws {@link #wrongAccount} unless {@code from} is absent or equals the active address. */
    static void requireFrom(String from, String activeName, String activeAddress) throws RequestRefusal {
        if (from == null) return;
        if (activeAddress == null || !from.equalsIgnoreCase(activeAddress)) {
            throw wrongAccount(from, activeName, activeAddress == null ? "0x0000000000000000000000000000000000000000" : activeAddress);
        }
    }

    /** Non-empty calldata the phone cannot fully decode: refused, never shown raw for blind approval. */
    static RequestRefusal unknownCall(String contract, String selector) {
        return new RequestRefusal(UNKNOWN_CALL_TITLE, "This contract call can't be explained by the phone, so it was refused "
                + "and nothing was signed (contract " + contract + ", function selector 0x" + selector + "). "
                + Erc20Call.SUPPORTED + ", plus the NFT calls and pinned Uniswap routers the phone can explain.");
    }
}
