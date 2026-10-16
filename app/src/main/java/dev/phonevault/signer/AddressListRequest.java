package dev.phonevault.signer;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;

/**
 * USB {@code listAddresses}: the Mac asks for the first public addresses of the standard wallet
 * under one account numbering, to find out which numbering another wallet used (migration). The
 * phone shows them and answers only after the user taps Share; nothing is remembered, so the next
 * request asks again. Public addresses only: no key, no xpub, no passphrase wallet.
 *
 * <pre>
 * {"id","method":"listAddresses","scheme":"standard|ledger-live","count":"1".."10"}
 *   → {"id","status":"ok","scheme":"ledger-live","addresses":"0xAb…,0xCd…"}   (EIP-55, comma-separated, in order)
 * </pre>
 * Declining answers {"id","status":"rejected"}. Schema-exact like every request: all values are
 * strings, no missing or unknown fields, the scheme from the allowlist, count canonical decimal.
 */
final class AddressListRequest {
    static final String METHOD = "listAddresses";

    final String id;
    final AccountScheme scheme;
    final int count;

    private AddressListRequest(String id, AccountScheme scheme, int count) {
        this.id = id;
        this.scheme = scheme;
        this.count = count;
    }

    static boolean handles(String method) { return METHOD.equals(method); }

    static AddressListRequest parse(JSONObject json) throws JSONException {
        Eip1559Request.requireExactFields(json, "id", "method", "scheme", "count");
        if (!METHOD.equals(json.getString("method"))) throw new JSONException("Unsupported method");
        String id = Eip1559Request.validatedId(json.getString("id"));
        Object schemeValue = json.get("scheme"), countValue = json.get("count");
        if (!(schemeValue instanceof String) || !(countValue instanceof String)) throw new JSONException("scheme and count must be strings");
        AccountScheme scheme;
        try {
            scheme = AccountScheme.fromWire((String) schemeValue);
        } catch (IllegalArgumentException e) {
            throw new JSONException(e.getMessage());
        }
        String count = (String) countValue;
        if (!count.matches("[1-9]|10")) throw new JSONException("count must be \"1\" to \"" + SeedVault.MAX_LISTED_ADDRESSES + "\"");
        return new AddressListRequest(id, scheme, Integer.parseInt(count));
    }

    /** The approved answer: exactly {@link #count} checksummed addresses, in account order. */
    JSONObject response(List<String> addresses) {
        if (addresses == null || addresses.size() != count) throw new IllegalStateException("address list does not match the request");
        for (String a : addresses) {
            if (!Addresses.isEvm(a)) throw new IllegalStateException("not an address");
        }
        return Pages.json("id", id, "status", "ok", "scheme", scheme.wire, "addresses", String.join(",", addresses));
    }

    /** What the locked gate shows. */
    String lockedSummary() {
        return "Your Mac asks for " + count + (count == 1 ? " address" : " addresses") + " of your wallet ("
                + scheme.label + " account numbering). Unlock to review.";
    }
}
