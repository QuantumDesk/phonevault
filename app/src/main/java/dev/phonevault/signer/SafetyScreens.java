package dev.phonevault.signer;

import android.content.Context;
import android.graphics.drawable.GradientDrawable;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.BackgroundColorSpan;
import android.text.style.ForegroundColorSpan;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.List;

/**
 * The address-book screens (☰ → Address book, and "Save as contact" on a transaction receipt)
 * and the styling of the look-alike comparison grid. Kept out of MainActivity: it only borrows the
 * activity's page/present/action helpers through {@link Host}. Names are typed on an on-screen
 * keyboard (the appliance has no system IME). No PIN is needed to add, rename or delete: names
 * only label addresses and never change what is signed.
 */
final class SafetyScreens {
    interface Host {
        Context context();
        LinearLayout page(String eyebrow, String title, String description);
        void present(LinearLayout root, String screen);
        void action(LinearLayout parent, String label, boolean primary, Runnable run);
        void card(LinearLayout parent, String label, String value);
        /** True while the address-book screens may be shown (unlocked, no approval or sensitive flow). */
        boolean ready();
        void showMenu();
        void showHome();
        float bodySize();
        void harden(View view);
        int dp(int value);
    }

    private final Host host;
    private final AddressBook book;
    private final StringBuilder typed = new StringBuilder();
    private boolean shift;
    private String error;

    SafetyScreens(Host host, AddressBook book) {
        this.host = host;
        this.book = book;
    }

    // ------------------------------------------------------------------ list / contact

    void showList() {
        if (!host.ready()) return;
        LinearLayout root = host.page("MENU / ADDRESS BOOK", "Contacts",
                "Names you give addresses on this phone. Reviews show them next to the full address; a connected computer can never set or change them.");
        if (book.problem() != null) host.card(root, "Address book unavailable", book.problem());
        List<AddressBook.Contact> contacts = book.list();
        if (contacts.isEmpty()) {
            host.card(root, "No contacts yet", "After a transfer is signed, the receipt offers \"Save as contact\" for the recipient.");
        }
        for (AddressBook.Contact c : contacts) {
            host.action(root, c.name + " · " + LookAlike.shortForm(c.address) + AddressKeys.networkSuffix(c.address), false, () -> showContact(c.address));
        }
        host.action(root, "Back to menu", true, host::showMenu);
        host.present(root, "address-book");
    }

    void showContact(String address) {
        if (!host.ready()) return;
        String name = book.name(address);
        if (name == null) { showList(); return; }
        LinearLayout root = host.page("ADDRESS BOOK / CONTACT", name, "Saved on this phone on " + AddressSafety.day(added(address)) + ".");
        addressCard(root, "Address", address);
        host.action(root, "Rename", true, () -> startNameEntry(address, name, () -> showContact(address)));
        host.action(root, "Delete contact", false, () -> confirmDelete(address));
        host.action(root, "Back to contacts", false, this::showList);
        host.present(root, "address-book-contact");
    }

    private long added(String address) {
        for (AddressBook.Contact c : book.list()) if (c.address.equalsIgnoreCase(address)) return c.added;
        return 0;
    }

    private void confirmDelete(String address) {
        if (!host.ready()) return;
        String name = book.name(address);
        LinearLayout root = host.page("ADDRESS BOOK / DELETE", "Delete \"" + name + "\"?",
                "The address itself is not affected. Reviews will show it without a name, and this phone's send history for it stays.");
        addressCard(root, "Address", address);
        host.action(root, "Delete", true, () -> {
            try {
                book.remove(address);
                showList();
            } catch (java.io.IOException e) {
                showProblem("Not deleted", e.getMessage(), this::showList);
            }
        });
        host.action(root, "Cancel", false, () -> showContact(address));
        host.present(root, "address-book-delete");
    }

    // ------------------------------------------------------------------ receipt

    /** "Save as contact" buttons for the signed counterparties that have no name yet. */
    void addSaveActions(LinearLayout root, List<TransactionReview.Party> parties) {
        int shown = 0;
        for (TransactionReview.Party p : parties) {
            if (book.name(p.address) != null || shown >= 3) continue;
            String label = (p.role == RecipientHistory.Role.SEND ? "Save recipient " : "Save spender ")
                    + LookAlike.shortForm(p.address) + " as contact";
            host.action(root, label, false, () -> startNameEntry(p.address, "", host::showHome));
            shown++;
        }
    }

    // ------------------------------------------------------------------ name entry

    void startNameEntry(String address, String initial, Runnable after) {
        typed.setLength(0);
        typed.append(initial == null ? "" : initial);
        shift = typed.length() == 0;
        error = null;
        showNameEntry(address, after);
    }

    private void showNameEntry(String address, Runnable after) {
        if (!host.ready()) return;
        LinearLayout root = host.page("ADDRESS BOOK / NAME", typed.length() == 0 ? "Type a name" : typed + "▌",
                "Up to " + AddressBook.MAX_NAME + " letters, digits, spaces, '.', '-' or apostrophes. Only this phone shows it.");
        addressCard(root, "For address", address);
        keyRow(root, "a b c d e f g h i".split(" "), address, after);
        keyRow(root, "j k l m n o p q r".split(" "), address, after);
        keyRow(root, "s t u v w x y z ⌫".split(" "), address, after);
        keyRow(root, "1 2 3 4 5 6 7 8 9 0".split(" "), address, after);
        keyRow(root, new String[] {shift ? "⇧ ON" : "⇧", "space", ".", "-", "'"}, address, after);
        if (error != null) {
            TextView e = VaultTheme.bodyText(host.context(), error, host.bodySize(), VaultTheme.DANGER_INK);
            e.setPadding(0, host.dp(10), 0, host.dp(4));
            root.addView(e);
        }
        host.action(root, "Save name", true, () -> {
            try {
                book.put(address, typed.toString(), System.currentTimeMillis());
                typed.setLength(0);
                after.run();
            } catch (AddressBook.InvalidNameException e) {
                error = e.getMessage();
                showNameEntry(address, after);
            } catch (java.io.IOException e) {
                showProblem("Name not saved", e.getMessage(), after);
            }
        });
        host.action(root, "Cancel", false, () -> { typed.setLength(0); after.run(); });
        host.present(root, "address-book-name");
    }

    private void keyRow(LinearLayout parent, String[] keys, String address, Runnable after) {
        LinearLayout row = new LinearLayout(host.context());
        row.setOrientation(LinearLayout.HORIZONTAL);
        for (String key : keys) {
            String shown = key.length() == 1 && Character.isLetter(key.charAt(0)) && shift ? key.toUpperCase(java.util.Locale.ROOT) : key;
            TextView b = VaultTheme.pixelButton(host.context(), shown, false);
            VaultTheme.size(b, key.length() > 2 ? 14 : 18);
            b.setPadding(0, 0, 0, 0);
            b.setGravity(Gravity.CENTER);
            host.harden(b);
            b.setOnClickListener(v -> {
                if (!host.ready()) return;
                error = null;
                if ("⌫".equals(key)) {
                    if (typed.length() > 0) typed.setLength(typed.length() - 1);
                } else if (key.startsWith("⇧")) {
                    shift = !shift;
                } else if (typed.length() < AddressBook.MAX_NAME) {
                    typed.append("space".equals(key) ? " " : shown);
                    shift = false;
                }
                showNameEntry(address, after);
            });
            float weight = "space".equals(key) ? 3f : 1f;
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, host.dp(48), weight);
            lp.setMargins(host.dp(2), host.dp(3), host.dp(2), host.dp(3));
            row.addView(b, lp);
        }
        parent.addView(row);
    }

    private void showProblem(String title, String message, Runnable back) {
        LinearLayout root = host.page("ADDRESS BOOK", title, message);
        host.action(root, "Continue", true, back);
        host.present(root, "address-book-problem");
    }

    private void addressCard(LinearLayout root, String label, String address) {
        LinearLayout box = VaultTheme.box(host.context());
        box.addView(VaultTheme.bodyText(host.context(), label, 13, VaultTheme.FAINT));
        String c = AddressKeys.display(address);
        String shown = AddressKeys.isBtc(address) ? BtcScript.grouped(c, 5) + AddressKeys.networkSuffix(address).replace(" · ", "\n")
                : ReviewStyle.groupEvmTwoLines(c);
        TextView t = VaultTheme.monoText(host.context(), shown, host.bodySize(), VaultTheme.INK);
        t.setPadding(0, host.dp(6), 0, 0);
        box.addView(t);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = host.dp(12);
        root.addView(box, lp);
    }

    // ------------------------------------------------------------------ review row styling

    /**
     * Review rows: DANGER rows sit on a red-outlined panel; the look-alike COMPARE grid is shown
     * in monospace with every differing chunk line highlighted.
     */
    static void style(Context c, LinearLayout row, String label, TextView valueView, String value) {
        if (MessageReview.DANGER.equalsIgnoreCase(label)) {
            GradientDrawable panel = new GradientDrawable();
            panel.setColor(0x33FF5A5A);
            panel.setStroke(VaultTheme.dp(c, 2), VaultTheme.DANGER_INK);
            panel.setCornerRadius(VaultTheme.dp(c, 6));
            row.setBackground(panel);
            int p = VaultTheme.dp(c, 10);
            row.setPadding(p, p, p, 0);
        } else if (AddressSafety.COMPARE.equals(label)) {
            SpannableString s = new SpannableString(value);
            int at = 0;
            for (String line : value.split("\n", -1)) {
                if (line.contains(LookAlike.DIFFERENT_MARK)) {
                    s.setSpan(new ForegroundColorSpan(VaultTheme.DANGER_INK), at, at + line.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    s.setSpan(new BackgroundColorSpan(0x40FF5A5A), at, at + line.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                }
                at += line.length() + 1;
            }
            valueView.setText(s);
        }
    }
}
