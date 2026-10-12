package dev.phonevault.signer;

import org.web3j.crypto.Keys;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The phone's own knowledge about an address on a review: the contact name from {@link AddressBook},
 * this wallet's history from {@link RecipientHistory}, and a {@link LookAlike} check against both.
 * Everything here comes from the phone's storage; the host contributes only the address being
 * reviewed. Rows labelled DANGER/WARNING render in the danger style; a "COMPARE" row renders as an
 * aligned chunk grid.
 */
final class AddressSafety {
    static final String COMPARE = "COMPARE";
    static final String CONTACT = "Saved contact";
    static final int MAX_LOOKALIKES = 2;
    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyy-MM-dd", Locale.ROOT).withZone(ZoneOffset.UTC);

    static final String OWN_ACCOUNT = "Your account";
    final AddressBook book;
    final RecipientHistory history;
    /**
     * The other accounts of the open wallet(s) on this phone (lowercase address → name), so a send
     * between your own accounts is named and a look-alike of any of them is caught. Display only.
     */
    private volatile Map<String, String> ownAccounts = Collections.emptyMap();

    AddressSafety(AddressBook book, RecipientHistory history) {
        this.book = book;
        this.history = history;
    }

    String contactName(String address) { return book == null ? null : book.name(address); }

    /** Replace the phone's own account list (address → name); null clears it. */
    void setOwnAccounts(Map<String, String> accounts) {
        Map<String, String> copy = new LinkedHashMap<>();
        if (accounts != null) for (Map.Entry<String, String> e : accounts.entrySet()) {
            if (e.getKey() != null) copy.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue());
        }
        ownAccounts = Collections.unmodifiableMap(copy);
    }

    /**
     * Rows for one counterparty: contact name, look-alike DANGER with the comparison grid, then the
     * history line ("First time …" as a WARNING, or "Sent here N times before").
     */
    List<MessageReview.Row> rows(String signer, String address, RecipientHistory.Role role) {
        List<MessageReview.Row> rows = new ArrayList<>();
        String a = address.toLowerCase(Locale.ROOT);
        String name = contactName(a);
        if (name != null) rows.add(new MessageReview.Row(CONTACT, name + " (named on this phone)"));
        Map<String, String> own = ownAccounts;
        String self = signer == null ? null : signer.toLowerCase(Locale.ROOT);
        if (own.containsKey(a) && !a.equals(self)) {
            rows.add(new MessageReview.Row(OWN_ACCOUNT, own.get(a) + " on this phone"));
        }

        // look-alikes: this wallet's own accounts, every address this wallet signed for, and every contact
        Set<String> known = new LinkedHashSet<>();
        if (self != null) known.add(self); // poisoners also imitate your own address ("send to my other account")
        known.addAll(own.keySet());
        if (history != null && signer != null) for (RecipientHistory.Entry e : history.entries(signer)) known.add(e.address);
        if (book != null) for (AddressBook.Contact c : book.list()) known.add(c.address);
        int shown = 0;
        for (String k : known) {
            if (shown >= MAX_LOOKALIKES) break;
            if (!LookAlike.similar(k, a)) continue;
            String kName = contactName(k);
            RecipientHistory.Entry ke = history == null || signer == null ? null : history.lookup(signer, k);
            String how = k.equals(self) ? "(this wallet's own address)"
                    : own.containsKey(k) ? "(your " + own.get(k) + " on this phone)"
                    : ke != null && ke.sends > 0 ? "you sent to before" : ke != null ? "you approved before"
                    : "saved in your address book";
            rows.add(new MessageReview.Row(TransactionReview.DANGER, "Looks like " + LookAlike.shortForm(k)
                    + (kName != null ? " (\"" + kName + "\")" : "") + " " + how + ", but it is a DIFFERENT address ("
                    + LookAlike.differingChunks(k, a) + " of 10 chunks differ). This is how address-poisoning scams work: "
                    + "check every character below. Do not sign unless you are sure."));
            rows.add(new MessageReview.Row(COMPARE, LookAlike.grid(k, a)));
            rows.add(new MessageReview.Row("Known address", Keys.toChecksumAddress(k)));
            rows.add(new MessageReview.Row("This address", Keys.toChecksumAddress(a)));
            shown++;
        }

        if (history == null || signer == null) return rows;
        if (history.problem() != null) {
            rows.add(new MessageReview.Row(TransactionReview.WARNING, "The address history on this phone could not be read, "
                    + "so first-time and look-alike checks against past sends are not available (" + history.problem() + ")."));
            return rows;
        }
        RecipientHistory.Entry e = history.lookup(signer, a);
        if (role == RecipientHistory.Role.SEND) {
            if (e == null || e.sends == 0) {
                rows.add(new MessageReview.Row(TransactionReview.WARNING, "First time sending to this address from this wallet."
                        + (e != null && e.approvals > 0 ? " (You approved it as a spender before.)" : "")
                        + " Check the whole address with the recipient."));
            } else {
                rows.add(new MessageReview.Row("History", "Sent here " + times(e.sends) + " before (first on " + day(e.firstSeen) + ")"));
            }
        } else {
            if (e == null || e.approvals == 0) {
                rows.add(new MessageReview.Row(TransactionReview.WARNING, "First time approving this spender from this wallet."));
            } else {
                rows.add(new MessageReview.Row("History", "Approved this spender " + times(e.approvals) + " before (first on " + day(e.firstSeen) + ")"));
            }
        }
        return rows;
    }

    /** Records the signed counterparties; returns a problem to show, or null. */
    String record(String signer, List<TransactionReview.Party> parties, long now) {
        if (history == null || signer == null) return null;
        String problem = null;
        for (TransactionReview.Party p : parties) {
            String r = history.record(signer, p.address, p.role, now);
            if (r != null) problem = r;
        }
        return problem;
    }

    private static String times(int n) { return n == 1 ? "once" : n + " times"; }

    static String day(long millis) { return DAY.format(Instant.ofEpochMilli(millis)); }
}
