package dev.phonevault.signer;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The accounts the user has opened in one wallet (i = 0…{@link SeedVault#MAX_ACCOUNT_INDEX}):
 * index, public address, an optional label typed on the phone, a hidden flag, and which one is
 * active. Non-secret metadata only — no key, no seed, no passphrase.
 *
 * <p>The book also holds the wallet's "Account numbering" ({@link AccountScheme}): which path
 * "Account N" is (Standard m/44'/60'/0'/0/i or Ledger Live m/44'/60'/i'/0/0). Switching numbering
 * ({@link #withScheme}) parks the current list (labels, hidden flags, active account) and brings
 * back the other numbering's parked list, so switching back restores it. Account 1 is the same
 * address under both, so the wallet's identity ({@link #walletId}) never changes.
 *
 * <p>Derivation is deterministic, so an account is never deleted, only hidden: "Add account"
 * always opens the lowest unused index, and a hidden account comes back with the same address.
 *
 * <p>A stored book is untrusted until {@link #dropUnverified} has re-derived every account it lists
 * (both numberings) from the seed and dropped those whose saved address the seed does not give;
 * only a {@link #verified} book names "your own" accounts in a review.
 *
 * <p>The standard wallet's book (with its numbering) is persisted ({@link #encode}) and bound to
 * the wallet's account-0 address ({@link #walletId}): a stored book for a different wallet (after
 * replace or restore) is discarded on load. A passphrase wallet's book (and its own numbering)
 * lives in memory only and is dropped on lock, so the phone keeps no trace that a passphrase
 * wallet exists.
 *
 * <p>Pure Java (org.json is part of Android; a test dependency on the JVM) so the rules are unit-tested.
 */
final class AccountBook {
    static final int MAX_ACCOUNTS = SeedVault.MAX_ACCOUNT_INDEX + 1;
    static final int MAX_LABEL = 24;
    /** v1: Standard numbering only (what earlier apps wrote and read). v2 adds the numbering and a parked list. */
    private static final int VERSION = 1, VERSION_SCHEMES = 2;

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
    /** Which path "Account N" is in this book. */
    final AccountScheme scheme;
    private final List<Account> accounts = new ArrayList<>();
    private int active;
    /** The other numbering's list, kept for switching back (null: none). Same wallet, other scheme. */
    private AccountBook parked;
    /** False for a list read from storage until {@link #dropUnverified} has checked it against the seed. */
    private boolean verified = true;
    /** Why {@link #load} started the list over (shown once after unlock), or null. Not stored. */
    private String resetNotice;

    /** Re-derives account addresses from the seed (lowercase 0x). */
    interface AddressSource { String address(AccountScheme scheme, int index); }

    private AccountBook(String walletId, AccountScheme scheme) {
        this.walletId = walletId;
        this.scheme = scheme;
    }

    /** A wallet's book with only account 0, active, Standard numbering. */
    static AccountBook fresh(String account0Address) {
        return fresh(account0Address, AccountScheme.STANDARD);
    }

    /** A wallet's book with only account 0 (the same address under every numbering), active. */
    static AccountBook fresh(String account0Address, AccountScheme scheme) {
        if (scheme == null) throw new IllegalArgumentException("no account numbering");
        String id = address(account0Address);
        AccountBook book = new AccountBook(id, scheme);
        book.accounts.add(new Account(0, id, null, false));
        book.active = 0;
        return book;
    }

    static String defaultName(int index) { return "Account " + (index + 1); }

    /**
     * This wallet's book under {@code next} numbering: the list parked when the user last left that
     * numbering (labels, hidden accounts, the active one), or a fresh one at Account 1; this book is
     * parked in it. Returns this book when {@code next} is already its numbering. Never changes this
     * book. The caller derives the returned book's active account under {@code next} and checks it
     * with {@link #select} before publishing (a parked address that does not match the seed is
     * never trusted).
     */
    AccountBook withScheme(AccountScheme next) { return withScheme(next, true); }

    /** As {@link #withScheme(AccountScheme)}; {@code reuseParked} false starts {@code next} over at Account 1 (its parked list did not match the seed). */
    AccountBook withScheme(AccountScheme next, boolean reuseParked) {
        if (next == null) throw new IllegalArgumentException("no account numbering");
        if (next == scheme) return this;
        AccountBook other = reuseParked && parked != null && parked.scheme == next ? parked.copy() : fresh(walletId, next);
        AccountBook me = copy();
        me.parked = null;
        other.parked = me;
        return other;
    }

    /** The parked list of the other numbering, or null. */
    AccountBook parked() { return parked; }

    private AccountBook copy() {
        AccountBook c = new AccountBook(walletId, scheme);
        for (Account a : accounts) c.accounts.add(new Account(a.index, a.address, a.label, a.hidden));
        c.active = active;
        c.parked = parked == null ? null : parked.copy();
        c.verified = verified;
        return c;
    }

    /** True when every listed address (this list and the parked one) was derived or checked against the seed. */
    boolean verified() { return verified && (parked == null || parked.verified); }

    /** Why the stored list was unreadable and started over (for a one-time notice), or null. */
    String resetNotice() { return resetNotice; }

    /**
     * Re-derive every listed account from the seed (this list under its numbering, the parked list
     * under its own) and drop each one whose saved address differs: such an address was never this
     * wallet's, so it is neither listed nor named as "your account". When the active account is
     * dropped, Account 1 becomes active. The book is {@link #verified} afterwards. Returns how many
     * accounts were dropped.
     *
     * @throws IllegalStateException when Account 1 does not match (the list belongs to another wallet)
     */
    int dropUnverified(AddressSource seed) {
        int dropped = dropUnverifiedList(seed);
        if (parked != null) dropped += parked.dropUnverifiedList(seed);
        return dropped;
    }

    private int dropUnverifiedList(AddressSource seed) {
        if (!walletId.equals(address(seed.address(scheme, 0)))) throw new IllegalStateException("the account list belongs to another wallet");
        int dropped = 0;
        for (java.util.Iterator<Account> it = accounts.iterator(); it.hasNext(); ) {
            Account a = it.next();
            if (!a.address.equals(address(seed.address(scheme, a.index)))) {
                it.remove();
                dropped++;
            }
        }
        if (get(active) == null) active = 0;
        get(active).hidden = false;
        verified = true;
        return dropped;
    }

    /** {@link #resetNotice} when the stored list was unreadable but its numbering was not. */
    static String resetNoticeFor(AccountScheme kept) {
        return "Your account list was reset; account numbering is still " + kept.label + ".";
    }

    /** {@link #resetNotice} when not even the stored numbering could be read. */
    static final String RESET_UNREADABLE_NOTICE = "Your account list could not be read and was reset to Account 1 with Standard numbering. "
            + "If you used Ledger Live numbering, switch to it again in ☰ → Accounts.";

    /**
     * The one-time home notice after unlock when the saved account list was reset or had accounts
     * that did not match the recovery phrase, or null. The repaired list is saved, so the next
     * unlock shows nothing.
     */
    static String listNotice(String resetNotice, int dropped) {
        if (resetNotice != null) return resetNotice;
        if (dropped == 0) return null;
        return (dropped == 1 ? "1 saved account did not" : dropped + " saved accounts did not")
                + " match your recovery phrase and " + (dropped == 1 ? "was" : "were") + " removed from your account list. "
                + "Add accounts again in ☰ → Accounts; each address is derived from your phrase.";
    }

    private static AccountBook reset(String id, AccountScheme scheme, String notice) {
        AccountBook book = fresh(id, scheme);
        book.resetNotice = notice;
        return book;
    }

    /**
     * The stored book if it belongs to {@code account0Address}; otherwise (none stored, a newer
     * format, or another wallet's) a fresh one. A stored book of this wallet whose list is unreadable
     * starts over at Account 1 under its SAVED numbering, with a {@link #resetNotice}. Never throws.
     * The result is not {@link #verified}: the caller re-derives it with {@link #dropUnverified}
     * before use.
     */
    static AccountBook load(String stored, String account0Address) {
        String id = address(account0Address);
        if (stored == null || stored.isEmpty()) return fresh(id);
        JSONObject json;
        int version;
        String wallet;
        try {
            json = new JSONObject(stored);
            version = json.getInt("v");
            wallet = json.getString("wallet");
        } catch (JSONException unreadable) {
            return reset(id, AccountScheme.STANDARD, RESET_UNREADABLE_NOTICE);
        }
        if ((version != VERSION && version != VERSION_SCHEMES) || !id.equals(wallet)) return fresh(id);
        AccountScheme scheme;
        try {
            scheme = version == VERSION ? AccountScheme.STANDARD : AccountScheme.fromWire(json.getString("scheme"));
        } catch (JSONException | IllegalArgumentException | NullPointerException unreadable) {
            return reset(id, AccountScheme.STANDARD, RESET_UNREADABLE_NOTICE);
        }
        try {
            AccountBook book = decodeList(json, id, scheme);
            if (book == null) return reset(id, scheme, resetNoticeFor(scheme));
            book.verified = false;
            if (version == VERSION_SCHEMES && json.has("parked")) {
                // A parked list that is unreadable or of the same numbering is dropped, never trusted;
                // the book itself stays.
                try {
                    JSONObject p = json.getJSONObject("parked");
                    AccountScheme other = AccountScheme.fromWire(p.getString("scheme"));
                    if (other != scheme) book.parked = decodeList(p, id, other);
                    if (book.parked != null) book.parked.verified = false;
                } catch (JSONException | IllegalArgumentException | NullPointerException corruptParked) {
                    book.parked = null;
                }
            }
            return book;
        } catch (JSONException | IllegalArgumentException | NullPointerException corrupt) {
            return reset(id, scheme, resetNoticeFor(scheme));
        }
    }

    /** One numbering's list ({"active","accounts"}), or null when it is not a valid list of wallet {@code id}. */
    private static AccountBook decodeList(JSONObject json, String id, AccountScheme scheme) throws JSONException {
        AccountBook book = new AccountBook(id, scheme);
        JSONArray list = json.getJSONArray("accounts");
        boolean[] seen = new boolean[MAX_ACCOUNTS];
        for (int i = 0; i < list.length() && i < MAX_ACCOUNTS; i++) {
            JSONObject a = list.getJSONObject(i);
            int index = a.getInt("i");
            if (index < 0 || index >= MAX_ACCOUNTS || seen[index]) return null;
            seen[index] = true;
            String addr = address(a.getString("a"));
            String label = a.has("l") ? cleanLabel(a.getString("l")) : null;
            book.accounts.add(new Account(index, addr, label, a.optBoolean("h", false)));
        }
        if (!seen[0] || !id.equals(book.get(0).address)) return null;
        Collections.sort(book.accounts, (x, y) -> Integer.compare(x.index, y.index));
        int active = json.getInt("active");
        Account chosen = book.get(active);
        book.active = chosen != null && !chosen.hidden ? active : 0;
        book.get(book.active).hidden = false;
        return book;
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

    /**
     * The numbering a stored book names, before it can be bound (as {@link #storedActiveIndex}).
     * Standard when absent or unreadable. {@link #load} keeps this numbering for this wallet's book
     * even when its list is unreadable.
     */
    static AccountScheme storedScheme(String stored) {
        if (stored == null || stored.isEmpty()) return AccountScheme.STANDARD;
        try {
            JSONObject json = new JSONObject(stored);
            return json.optInt("v") == VERSION_SCHEMES ? AccountScheme.fromWire(json.getString("scheme")) : AccountScheme.STANDARD;
        } catch (JSONException | IllegalArgumentException corrupt) {
            return AccountScheme.STANDARD;
        }
    }

    /**
     * The stored form. A Standard book with nothing parked is written as v1 (what earlier apps
     * read); anything else as v2, which an earlier app discards (it then starts its list over at
     * Account 1, Standard numbering, re-derived from the seed).
     */
    String encode() {
        try {
            JSONObject out = encodeList(this).put("wallet", walletId);
            if (scheme == AccountScheme.STANDARD && parked == null) return out.put("v", VERSION).toString();
            out.put("v", VERSION_SCHEMES).put("scheme", scheme.wire);
            if (parked != null) out.put("parked", encodeList(parked).put("scheme", parked.scheme.wire));
            return out.toString();
        } catch (JSONException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static JSONObject encodeList(AccountBook book) throws JSONException {
        JSONArray list = new JSONArray();
        for (Account a : book.accounts) {
            JSONObject o = new JSONObject().put("i", a.index).put("a", a.address);
            if (a.label != null) o.put("l", a.label);
            if (a.hidden) o.put("h", true);
            list.put(o);
        }
        return new JSONObject().put("active", book.active).put("accounts", list);
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

    /**
     * The index "Add account" opens next: the lowest one not listed (an account dropped by
     * {@link #dropUnverified} can be opened again), or -1 at the cap. Hidden accounts keep their index.
     */
    int nextIndex() {
        for (int i = 0; i < MAX_ACCOUNTS; i++) if (get(i) == null) return i;
        return -1;
    }

    /** Record a newly derived account. Its index must be {@link #nextIndex()}. */
    Account add(int index, String derivedAddress) {
        if (index != nextIndex() || index < 0) throw new IllegalArgumentException("account " + index + " is not the next one");
        Account a = new Account(index, address(derivedAddress), null, false);
        accounts.add(a);
        Collections.sort(accounts, (x, y) -> Integer.compare(x.index, y.index));
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
        if (!Addresses.isEvm(value)) throw new IllegalArgumentException("invalid address");
        return Addresses.lowercase(value);
    }
}
