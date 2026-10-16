package dev.phonevault.signer;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Set;
import java.util.TreeSet;

/**
 * Which Bitcoin accounts the user agreed to share (watch-only) with a connected computer, per
 * (network, type, account), so btcGetAccount asks once. Bound to the standard wallet's id (its
 * account-0 EVM address, as {@link AccountBook}); a record for another wallet is discarded.
 * Holds no key material and no xpub: only the decision. Losing or editing it can only make the
 * phone ask again or skip a privacy question, never change what is signed.
 */
final class BtcSharing {
    private static final int VERSION = 1;

    final String walletId;
    private final Set<String> shared = new TreeSet<>();

    private BtcSharing(String walletId) { this.walletId = walletId; }

    static String key(BtcNetwork network, BtcWallet.Type type, int account) {
        return network.wire + "/" + type.wire + "/" + (account + 1);
    }

    static BtcSharing load(String stored, String walletId) {
        BtcSharing s = new BtcSharing(AccountBook.address(walletId));
        if (stored == null || stored.isEmpty()) return s;
        try {
            JSONObject json = new JSONObject(stored);
            if (json.getInt("v") != VERSION || !s.walletId.equals(json.getString("wallet"))) return s;
            JSONArray list = json.getJSONArray("shared");
            for (int i = 0; i < list.length() && i < BtcNetwork.values().length * BtcWallet.Type.values().length * BtcWallet.ACCOUNTS; i++) {
                String k = list.getString(i);
                if (k.matches("(bitcoin|testnet|signet)/(p2wpkh|p2tr|p2sh-p2wpkh|p2pkh)/([1-9]|1[0-9]|20)")) s.shared.add(k);
            }
        } catch (JSONException corrupt) {
            s.shared.clear();
        }
        return s;
    }

    boolean isShared(BtcNetwork network, BtcWallet.Type type, int account) { return shared.contains(key(network, type, account)); }

    void share(BtcNetwork network, BtcWallet.Type type, int account) { shared.add(key(network, type, account)); }

    /** The shared accounts, as stored keys ("network/type/account", account 1-based), sorted. */
    java.util.List<String> keys() { return new java.util.ArrayList<>(shared); }

    /** Stop answering btcGetAccount for this key without asking (the phone asks again next time). */
    boolean revoke(String key) { return shared.remove(key); }

    void revokeAll() { shared.clear(); }

    /** "Bitcoin TESTNET · Account 1 · Native SegWit" for a stored key. */
    static String label(String key) {
        String[] p = key.split("/");
        return BtcNetwork.fromWire(p[0]).label + " · " + BtcWallet.accountLabel(BtcWallet.Type.fromWire(p[1]), Integer.parseInt(p[2]) - 1);
    }

    String encode() {
        try {
            JSONArray list = new JSONArray();
            for (String k : shared) list.put(k);
            return new JSONObject().put("v", VERSION).put("wallet", walletId).put("shared", list).toString();
        } catch (JSONException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
