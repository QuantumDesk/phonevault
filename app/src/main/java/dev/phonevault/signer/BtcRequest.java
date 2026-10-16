package dev.phonevault.signer;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Base64;

/**
 * The three Bitcoin USB methods, parsed schema-exact like every other request (all values are
 * strings; missing, unknown or duplicate fields are refused by {@link AccessoryTransport} and here):
 *
 * <pre>
 * {"id","method":"btcGetAccount","network":"bitcoin|testnet|signet","type":"p2wpkh|p2tr|p2sh-p2wpkh|p2pkh","account":"1".."20"}
 *   → {"id","status":"ok","fingerprint":"73c5da0a","path":"m/84'/0'/0'","xpub":"xpub…|tpub…","descriptor":"wpkh([73c5da0a/84h/0h/0h]xpub…/&lt;0;1&gt;/*)#…"}
 *     (p2tr: m/86'… tr(…); p2sh-p2wpkh: m/49'… sh(wpkh(…)); p2pkh: m/44'… pkh(…); always xpub/tpub, never ypub)
 * {"id","method":"btcShowAddress","network","type","account","change":"0|1","index":"0".."9999"}
 *   → {"id","status":"ok","address":"bc1…|3…|1…"}      (after the user compared it and tapped Done)
 * {"id","method":"btcSignPsbt","network","psbt":"&lt;base64 BIP-174 v0&gt;"}
 *   → {"id","status":"approved","psbt":"&lt;base64, partial_sigs / tap_key_sig added, nothing finalized&gt;"}
 * </pre>
 * Declining answers {"id","status":"rejected"}; anything refused answers {"id","status":"error","error"}.
 * "account" is 1-based like getAddress's: account "1" is m/84'/0'/0'.
 */
final class BtcRequest {
    static final String GET_ACCOUNT = "btcGetAccount", SHOW_ADDRESS = "btcShowAddress", SIGN_PSBT = "btcSignPsbt";

    enum Kind { GET_ACCOUNT, SHOW_ADDRESS, SIGN_PSBT }

    final String id;
    final Kind kind;
    final BtcNetwork network;
    final BtcWallet.Type type;  // null for SIGN_PSBT
    final int account;          // 0-based; -1 for SIGN_PSBT
    final int change, index;    // SHOW_ADDRESS only
    final Psbt psbt;            // SIGN_PSBT only

    private BtcRequest(String id, Kind kind, BtcNetwork network, BtcWallet.Type type, int account, int change, int index, Psbt psbt) {
        this.id = id;
        this.kind = kind;
        this.network = network;
        this.type = type;
        this.account = account;
        this.change = change;
        this.index = index;
        this.psbt = psbt;
    }

    static boolean handles(String method) {
        return GET_ACCOUNT.equals(method) || SHOW_ADDRESS.equals(method) || SIGN_PSBT.equals(method);
    }

    static BtcRequest parse(JSONObject json) throws JSONException {
        String method = json.optString("method");
        Kind kind;
        if (GET_ACCOUNT.equals(method)) {
            Eip1559Request.requireExactFields(json, "id", "method", "network", "type", "account");
            kind = Kind.GET_ACCOUNT;
        } else if (SHOW_ADDRESS.equals(method)) {
            Eip1559Request.requireExactFields(json, "id", "method", "network", "type", "account", "change", "index");
            kind = Kind.SHOW_ADDRESS;
        } else if (SIGN_PSBT.equals(method)) {
            Eip1559Request.requireExactFields(json, "id", "method", "network", "psbt");
            kind = Kind.SIGN_PSBT;
        } else {
            throw new JSONException("Unsupported method");
        }
        String id = Eip1559Request.validatedId(json.getString("id"));
        BtcNetwork network;
        try {
            network = BtcNetwork.fromWire(json.getString("network"));
        } catch (IllegalArgumentException e) {
            throw new JSONException(e.getMessage());
        }
        if (kind == Kind.SIGN_PSBT) {
            return new BtcRequest(id, kind, network, null, -1, -1, -1, decodePsbt(json.getString("psbt")));
        }
        BtcWallet.Type type;
        try {
            type = BtcWallet.Type.fromWire(json.getString("type"));
        } catch (IllegalArgumentException e) {
            throw new JSONException(e.getMessage());
        }
        String account = json.getString("account");
        if (!account.matches("[1-9]|1[0-9]|20")) throw new JSONException("account must be \"1\" to \"20\"");
        int change = -1, index = -1;
        if (kind == Kind.SHOW_ADDRESS) {
            String c = json.getString("change"), i = json.getString("index");
            if (!c.matches("[01]")) throw new JSONException("change must be \"0\" or \"1\"");
            if (!i.matches("0|[1-9][0-9]{0,8}") || Integer.parseInt(i) > BtcWallet.MAX_ADDRESS_INDEX) {
                throw new JSONException("index must be \"0\" to \"" + BtcWallet.MAX_ADDRESS_INDEX + "\"");
            }
            change = Integer.parseInt(c);
            index = Integer.parseInt(i);
        }
        return new BtcRequest(id, kind, network, type, Integer.parseInt(account) - 1, change, index, null);
    }

    /** Strict base64 (canonical, padded), at most {@link Psbt#MAX_BYTES} decoded, then a structural BIP-174 parse. */
    static Psbt decodePsbt(String b64) throws JSONException {
        if (b64.length() > (Psbt.MAX_BYTES + 2) / 3 * 4) {
            throw BtcPsbtReview.refuse("The PSBT is larger than " + (Psbt.MAX_BYTES / 1024) + " KiB.");
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            throw new JSONException("psbt must be standard base64");
        }
        if (!Base64.getEncoder().encodeToString(raw).equals(b64)) throw new JSONException("psbt must be canonical, padded base64");
        try {
            return Psbt.parse(raw);
        } catch (IllegalArgumentException e) {
            throw BtcPsbtReview.refuse("This is not a valid PSBT (" + e.getMessage() + ").");
        }
    }

    /** The lock-screen line for a request that waits for unlock. Parses only; derives nothing. */
    static String lockedSummary(JSONObject json) throws JSONException {
        BtcRequest r = parse(json);
        switch (r.kind) {
            case GET_ACCOUNT:
                return "Your Mac asks to see your " + r.network.label + " " + BtcWallet.accountLabel(r.type, r.account)
                        + " (watch-only). Unlock to continue.";
            case SHOW_ADDRESS:
                return "Your Mac asks the phone to show a " + r.network.label + " receiving address. Unlock to continue.";
            default:
                return BtcPsbtReview.lockedSummary(r.psbt, r.network);
        }
    }

    // ------------------------------------------------------------------ responses

    static JSONObject accountResponse(String id, BtcWallet wallet, BtcWallet.Type type, int account) throws JSONException {
        return new JSONObject()
                .put("id", id)
                .put("status", "ok")
                .put("fingerprint", wallet.fingerprintHex())
                .put("path", wallet.accountPathString(type, account))
                .put("xpub", wallet.xpub(type, account))
                .put("descriptor", wallet.descriptor(type, account));
    }

    static JSONObject addressResponse(String id, String address) throws JSONException {
        return new JSONObject().put("id", id).put("status", "ok").put("address", address);
    }

    static JSONObject signedResponse(String id, byte[] psbt) throws JSONException {
        return new JSONObject().put("id", id).put("status", "approved").put("psbt", Base64.getEncoder().encodeToString(psbt));
    }
}
