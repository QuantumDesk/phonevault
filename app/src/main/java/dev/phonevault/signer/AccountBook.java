package dev.phonevault.signer;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * The accounts the user has opened in one wallet (m/44'/60'/0'/0/i, i = 0…{@link
 * SeedVault#MAX_ACCOUNT_INDEX}): index, public address, an optional label typed on the phone, a
 * hidden flag, and which one is active. Non-secret metadata only — no key, no seed, no passphrase.
 *
 * <p>Derivation is deterministic, so an account is never deleted, only hidden: "Add account"
 * always opens the next unused index, and a hidden account comes back with the same address.
 *
 * <p>The standard wallet's book is persisted ({@link #encode}) and bound to the wallet's
 * account-0 address ({@link #walletId}): a stored book for a different wallet (after replace or
 * restore) is discarded on load. A passphrase wallet's book lives in memory only and is dropped
 * on lock, so the phone keeps no trace that a passphrase wallet exists.
 *
 * <p>Pure Java (org.json is part of Android; a test dependency on the JVM) so the rules are unit-tested.
 */
final class AccountBook {
    static final int MAX_ACCOUNTS = SeedVault.MAX_ACCOUNT_INDEX + 1;
    static final int MAX_LABEL = 24;
    private static final int VERSION = 1;

    static final class Account {
        final int index;
        /** Lowercase 0x address. */
        final String address;
        String label;
        boolean hidden;

        Account(int index, String address, String label, boolean hidden) {
            this.index = index;
            this.address = address;
            this.label = label;
            this.hidden = hidden;
        }

        /** "Account 2" for index 1, or the user's label. */
        String name() { return label != null ? label : defaultName(index); }
    }

    /** Lowercase account-0 address of the wallet these accounts belong to. */
    final String walletId;
    private final List<Account> accounts = new ArrayList<>();
    private int active;

    private AccountBook(String walletId) { this.walletId = walletId; }

    /** A wallet's book with only account 0, active. */
    static AccountBook fresh(String account0Address) {
        String id = address(account0Address);
        AccountBook book = new AccountBook(id);
        book.accounts.add(new Account(0, id, null, false));
        book.active = 0;
        return book;
    }

    static String defaultName(int index) { return "Account " + (index + 1); }

    /**
     * The stored book if it belongs to {@code account0Address}; otherwise (none stored, unreadable,
     * or another wallet's) a fresh one. Never throws: the metadata is a convenience, the addresses
     * are re-derived from the seed before use.
     */
    static AccountBook load(String stored, String account0Address) {
        String id = address(account0Address);
        if (stored == null || stored.isEmpty()) return fresh(id);
        try {
            JSONObject json = new JSONObject(stored);
            if (json.getInt("v") != VERSION || !id.equals(json.getString("wallet"))) return fresh(id);
            AccountBook book = new AccountBook(id);
            JSONArray list = json.getJSONArray("accounts");
            boolean[] seen = new boolean[MAX_ACCOUNTS];
            for (int i = 0; i < list.length() && i < MAX_ACCOUNTS; i++) {
                JSONObject a = list.getJSONObject(i);
                int index = a.getInt("i");
                if (index < 0 || index >= MAX_ACCOUNTS || seen[index]) return fresh(id);
                seen[index] = true;
                String addr = address(a.getString("a"));
                String label = a.has("l") ? cleanLabel(a.getString("l")) : null;
                book.accounts.add(new Account(index, addr, label, a.optBoolean("h", false)));
            }
            if (!seen[0] || !id.equals(book.get(0).address)) return fresh(id);
            Collections.sort(book.accounts, (x, y) -> Integer.compare(x.index, y.index));
            int active = json.getInt("active");
            Account chosen = book.get(active);
            book.active = chosen != null && !chosen.hidden ? active : 0;
            book.get(book.active).hidden = false;
            return book;
        } catch (JSONException | IllegalArgumentException | NullPointerException corrupt) {
            return fresh(id);
        }
    }

    /**
     * The active index a stored book names, before it can be bound (binding needs the account-0
     * address, which only the seed gives). 0 when absent or unreadable; the caller re-checks with
     * {@link #load} once it has derived the wallet.
     */
    static int storedActiveIndex(String stored) {
        if (stored == null || stored.isEmpty()) return 0;
        try {
            int index = new JSONObject(stored).getInt("active");
            return index >= 0 && index < MAX_ACCOUNTS ? index : 0;
        } catch (JSONException corrupt) {
            return 0;
        }
    }

    String encode() {
        try {
            JSONArray list = new JSONArray();
            for (Account a : accounts) {
                JSONObject o = new JSONObject().put("i", a.index).put("a", a.address);
                if (a.label != null) o.put("l", a.label);
                if (a.hidden) o.put("h", true);
                list.put(o);
            }
            return new JSONObject().put("v", VERSION).put("wallet", walletId).put("active", active)
                    .put("accounts", list).toString();
        } catch (JSONException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    int activeIndex() { return active; }
    Account active() { return get(active); }

    Account get(int index) {
        for (Account a : accounts) if (a.index == index) return a;
        return null;
    }

    /** Every opened account, by index (hidden ones included; the UI filters). */
    List<Account> all() { return Collections.unmodifiableList(accounts); }

    List<Account> visible() {
        List<Account> out = new ArrayList<>();
        for (Account a : accounts) if (!a.hidden) out.add(a);
        return out;
    }

    int hiddenCount() { return accounts.size() - visible().size(); }

    /** The index "Add account" opens next, or -1 at the cap. Hidden accounts keep their index. */
    int nextIndex() {
        int max = -1;
        for (Account a : accounts) max = Math.max(max, a.index);
        return max + 1 < MAX_ACCOUNTS ? max + 1 : -1;
    }

    /** Record a newly derived account. Its index must be {@link #nextIndex()}. */
    Account add(int index, String derivedAddress) {
        if (index != nextIndex() || index < 0) throw new IllegalArgumentException("account " + index + " is not the next one");
        Account a = new Account(index, address(derivedAddress), null, false);
        accounts.add(a);
        return a;
    }

    /**
     * Make {@code index} active. The caller has just derived its key from the seed and passes the
     * address it produced; a mismatch with the stored address means the metadata is stale.
     */
    void select(int index, String derivedAddress) {
        Account a = get(index);
        if (a == null) throw new IllegalArgumentException("no account " + index);
        if (!a.address.equals(address(derivedAddress))) throw new IllegalStateException("stored address for account " + index + " does not match the seed");
        a.hidden = false;
        active = index;
    }

    /** Label shown on the phone (and nowhere else). Empty or blank resets to "Account N". */
    void rename(int index, String label) {
        Account a = get(index);
        if (a == null) throw new IllegalArgumentException("no account " + index);
        a.label = cleanLabel(label);
    }

    /** Hide from the list. The active account cannot be hidden (switch first). */
    void hide(int index) {
        Account a = get(index);
        if (a == null) throw new IllegalArgumentException("no account " + index);
        if (index == active) throw new IllegalStateException("Switch to another account before hiding this one");
        a.hidden = true;
    }

    void unhide(int index) {
        Account a = get(index);
        if (a == null) throw new IllegalArgumentException("no account " + index);
        a.hidden = false;
    }

    /** Printable ASCII, trimmed, at most {@link #MAX_LABEL} characters; null when empty. */
    static String cleanLabel(String label) {
        if (label == null) return null;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < label.length() && out.length() < MAX_LABEL; i++) {
            char c = label.charAt(i);
            if (c >= 0x20 && c <= 0x7E) out.append(c);
        }
        String trimmed = out.toString().trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    static String address(String value) {
        if (value == null || !value.matches("0x[0-9a-fA-F]{40}")) throw new IllegalArgumentException("invalid address");
        return value.toLowerCase(Locale.ROOT);
    }

    /** "0x1234…abcd". */
    static String shortAddress(String address) {
        String checksum = org.web3j.crypto.Keys.toChecksumAddress(address);
        return checksum.substring(0, 6) + "…" + checksum.substring(checksum.length() - 4);
    }
}
