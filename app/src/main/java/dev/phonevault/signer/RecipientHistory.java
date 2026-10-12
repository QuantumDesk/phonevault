package dev.phonevault.signer;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The addresses this phone has signed transfers to (and spenders/operators it has approved), per
 * wallet, with the first date and a count. It exists to catch address poisoning: a review says
 * "First time sending to this address" or "Sent here 3 times before", and {@link LookAlike} flags
 * a new address that imitates one of these.
 *
 * <p>Recorded on the phone after a signature is created (the phone cannot see whether the
 * transaction was broadcast, so "sent" means "signed on this phone"). Stored in app-private
 * storage next to the wallet's preferences, protected at rest by Android's file-based encryption;
 * nothing here comes from the host and nothing here changes what is signed.
 */
final class RecipientHistory {
    static final String FILE = "recipient-history.json";
    static final int MAX_PER_WALLET = 1000;

    enum Role { SEND, APPROVE }

    static final class Entry {
        final String address;
        final long firstSeen;
        final int sends;
        final int approvals;

        Entry(String address, long firstSeen, int sends, int approvals) {
            this.address = address;
            this.firstSeen = firstSeen;
            this.sends = sends;
            this.approvals = approvals;
        }
    }

    private final AddressBook.Store store;
    private final Map<String, Map<String, Entry>> wallets = new LinkedHashMap<>();
    private String problem;

    RecipientHistory(AddressBook.Store store) {
        this.store = store;
        load();
    }

    synchronized String problem() { return problem; }

    private void load() {
        try {
            byte[] bytes = store.read(FILE);
            if (bytes == null) return;
            JSONObject root = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
            if (root.getInt("version") != 1) throw new JSONException("unsupported version");
            JSONObject all = root.getJSONObject("wallets");
            java.util.Iterator<String> keys = all.keys();
            while (keys.hasNext()) {
                String wallet = AddressBook.normalize(keys.next());
                JSONArray list = all.getJSONArray(wallet);
                Map<String, Entry> entries = new LinkedHashMap<>();
                for (int i = 0; i < list.length() && i < MAX_PER_WALLET; i++) {
                    JSONObject e = list.getJSONObject(i);
                    String address = AddressBook.normalize(e.getString("address"));
                    int sends = e.getInt("sends"), approvals = e.getInt("approvals");
                    if (sends < 0 || approvals < 0) throw new JSONException("negative count");
                    entries.put(address, new Entry(address, e.getLong("first"), sends, approvals));
                }
                wallets.put(wallet, entries);
            }
        } catch (IOException | JSONException | IllegalArgumentException e) {
            wallets.clear();
            problem = "the saved address history could not be read (" + e.getMessage() + ")";
        }
    }

    /** What this wallet has signed for {@code address}, or null if never. */
    synchronized Entry lookup(String wallet, String address) {
        Map<String, Entry> entries = wallets.get(wallet.toLowerCase(Locale.ROOT));
        return entries == null ? null : entries.get(address.toLowerCase(Locale.ROOT));
    }

    /** Every address this wallet has signed for. */
    synchronized List<Entry> entries(String wallet) {
        Map<String, Entry> entries = wallets.get(wallet.toLowerCase(Locale.ROOT));
        return entries == null ? Collections.<Entry>emptyList() : new ArrayList<>(entries.values());
    }

    /**
     * Counts one signed transfer (SEND) or permission (APPROVE) to {@code address}. Best effort:
     * a storage failure is returned, never thrown, because the signature already exists.
     */
    synchronized String record(String wallet, String address, Role role, long now) {
        if (problem != null) return problem;
        String w = AddressBook.normalize(wallet), a = AddressBook.normalize(address);
        Map<String, Entry> entries = wallets.get(w);
        if (entries == null) wallets.put(w, entries = new LinkedHashMap<>());
        Entry old = entries.get(a);
        entries.put(a, new Entry(a, old == null ? now : old.firstSeen,
                (old == null ? 0 : old.sends) + (role == Role.SEND ? 1 : 0),
                (old == null ? 0 : old.approvals) + (role == Role.APPROVE ? 1 : 0)));
        while (entries.size() > MAX_PER_WALLET) {
            // drop the entry first seen longest ago
            String oldest = null;
            long when = Long.MAX_VALUE;
            for (Entry e : entries.values()) if (e.firstSeen < when) { when = e.firstSeen; oldest = e.address; }
            entries.remove(oldest);
        }
        try {
            save();
            return null;
        } catch (IOException e) {
            return "address history not saved: " + e.getMessage();
        }
    }

    private void save() throws IOException {
        try {
            JSONObject all = new JSONObject();
            for (Map.Entry<String, Map<String, Entry>> w : wallets.entrySet()) {
                JSONArray list = new JSONArray();
                for (Entry e : w.getValue().values()) {
                    list.put(new JSONObject().put("address", e.address).put("first", e.firstSeen)
                            .put("sends", e.sends).put("approvals", e.approvals));
                }
                all.put(w.getKey(), list);
            }
            store.write(FILE, new JSONObject().put("version", 1).put("wallets", all).toString().getBytes(StandardCharsets.UTF_8));
        } catch (JSONException impossible) {
            throw new IOException(impossible);
        }
    }
}
