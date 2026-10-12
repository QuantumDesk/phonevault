package dev.phonevault.signer;

import android.content.Context;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.web3j.crypto.Keys;

import java.util.Arrays;
import java.util.List;

/**
 * ☰ → Accounts and ☰ → Passphrase wallet. Screens only: every key derivation, the PIN window and
 * the publish of the new signing identity happen in the host (MainActivity), under its session
 * and state lock, exactly like unlock.
 *
 * <p>The passphrase is typed on this screen's own keyboard (the appliance has no system IME), kept
 * in a fixed-capacity buffer that is overwritten on every exit, handed to the host as a char[] the
 * host owns, and never stored or sent over USB.
 */
final class AccountScreens {
    interface Host {
        Context context();
        LinearLayout page(String eyebrow, String title, String description);
        void present(LinearLayout root, String screen);
        void action(LinearLayout parent, String label, boolean primary, Runnable run);
        void card(LinearLayout parent, String label, String value);
        boolean ready();
        void showHome();
        float bodySize();
        void harden(View view);
        int dp(int value);
        /** The open wallet's accounts (the passphrase wallet's while one is open). */
        AccountBook book();
        /** The open passphrase wallet's fingerprint, or null for the standard wallet. */
        String passphraseFingerprint();
        /** The account signing right now. */
        SigningAccount active();
        /** Derive account {@code index} from the seed (adding it first when {@code add}) and make it active. */
        void activate(int index, boolean add);
        /** A label or hidden flag changed: persist the standard wallet's book (passphrase books are not saved). */
        void bookChanged();
        /** Derive the passphrase wallet's account 1 and call back with (fingerprint, address); takes no ownership. */
        void previewPassphrase(char[] passphrase, PreviewResult result);
        /** Open the passphrase wallet; the host takes ownership of the array. */
        void usePassphrase(char[] passphrase);
        /** Back to the standard wallet. */
        void closePassphrase();
        /** True while a passphrase is being typed or confirmed: USB requests wait, the menu hides. */
        void entryActive(boolean active);
    }

    interface PreviewResult { void preview(String fingerprint, String account0Address); }

    private final Host host;
    /** Typing buffer for a passphrase or a label. Fixed capacity so it never reallocates (and copies). */
    private final StringBuilder typed = new StringBuilder(SeedVault.MAX_PASSPHRASE_LENGTH + 8);
    private boolean shift, symbols, reveal;
    private String error;
    /** A typed passphrase awaiting "Use this wallet". Zeroed on every other exit. */
    private char[] pending;

    AccountScreens(Host host) { this.host = host; }

    /** Drop everything typed (lock, cancel, leaving the screens). */
    void clear() {
        for (int i = 0; i < typed.length(); i++) typed.setCharAt(i, '\0');
        typed.setLength(0);
        if (pending != null) Arrays.fill(pending, '\0');
        pending = null;
        shift = symbols = reveal = false;
        error = null;
    }

    boolean revealing() { return reveal; }

    // ------------------------------------------------------------------ accounts

    void showAccounts() {
        if (!host.ready()) return;
        clear();
        AccountBook book = host.book();
        String fingerprint = host.passphraseFingerprint();
        LinearLayout root = host.page(fingerprint == null ? "ACCOUNTS" : "ACCOUNTS · PASSPHRASE WALLET",
                fingerprint == null ? "Your accounts" : "Passphrase wallet accounts",
                "Each account is its own address from the same recovery phrase (m/44'/60'/0'/0/n). The active account receives, answers the computer and signs.");
        if (fingerprint != null) host.card(root, "Passphrase wallet · fingerprint " + fingerprint,
                "This list is not saved on the phone. It starts at Account 1 each time you open the passphrase wallet; add accounts again to reach them (same addresses every time).");
        SigningAccount active = host.active();
        for (AccountBook.Account a : book.visible()) {
            boolean isActive = active != null && a.index == active.index;
            host.action(root, (isActive ? "● " : "") + a.name() + " · " + AccountBook.shortAddress(a.address), isActive,
                    () -> showAccount(a.index));
        }
        int next = book.nextIndex();
        if (next >= 0) host.action(root, "+ Add " + AccountBook.defaultName(next), false, () -> confirmAdd(next));
        else host.card(root, "Limit reached", "This phone opens up to " + AccountBook.MAX_ACCOUNTS + " accounts per wallet.");
        if (book.hiddenCount() > 0) host.action(root, "Hidden accounts (" + book.hiddenCount() + ")", false, this::showHidden);
        host.action(root, "Back to Wallet", false, host::showHome);
        host.present(root, "accounts");
    }

    private void confirmAdd(int index) {
        if (!host.ready()) return;
        LinearLayout root = host.page("ACCOUNTS / ADD", "Add " + AccountBook.defaultName(index) + "?",
                "The phone derives the next address from your recovery phrase (path m/44'/60'/0'/0/" + index
                        + ") and switches to it. Your existing backup already covers it: nothing new to write down.");
        host.action(root, "Add and switch", true, () -> host.activate(index, true));
        host.action(root, "Cancel", false, this::showAccounts);
        host.present(root, "accounts-add");
    }

    void showAccount(int index) {
        if (!host.ready()) return;
        AccountBook.Account a = host.book().get(index);
        if (a == null) { showAccounts(); return; }
        SigningAccount active = host.active();
        boolean isActive = active != null && active.index == index;
        LinearLayout root = host.page("ACCOUNTS / " + AccountBook.defaultName(index).toUpperCase(java.util.Locale.ROOT),
                a.name(), isActive ? "Active · receiving and signing use this account." : "Not active.");
        host.card(root, "Address", Keys.toChecksumAddress(a.address));
        host.card(root, "Derivation", "m/44'/60'/0'/0/" + index + (host.passphraseFingerprint() == null ? " · standard wallet" : " · passphrase wallet " + host.passphraseFingerprint()));
        if (!isActive) host.action(root, "Use this account", true, () -> host.activate(index, false));
        host.action(root, "Rename", false, () -> startRename(index));
        if (!isActive && !a.hidden) host.action(root, "Hide from the list", false, () -> {
            host.book().hide(index);
            host.bookChanged();
            showAccounts();
        });
        if (a.hidden) host.action(root, "Show in the list again", false, () -> {
            host.book().unhide(index);
            host.bookChanged();
            showAccount(index);
        });
        if (!isActive && !a.hidden) {
            TextView note = VaultTheme.bodyText(host.context(), "Hiding only tidies this list. The address still belongs to your recovery phrase and anything sent to it stays there.", 14, VaultTheme.FAINT);
            note.setPadding(0, host.dp(8), 0, 0);
            root.addView(note);
        }
        host.action(root, "All accounts", false, this::showAccounts);
        host.present(root, "account");
    }

    private void showHidden() {
        if (!host.ready()) return;
        LinearLayout root = host.page("ACCOUNTS / HIDDEN", "Hidden accounts", "Hidden accounts keep their address. Open one to use it or show it again.");
        for (AccountBook.Account a : host.book().all()) {
            if (!a.hidden) continue;
            host.action(root, a.name() + " · " + AccountBook.shortAddress(a.address), false, () -> showAccount(a.index));
        }
        host.action(root, "All accounts", false, this::showAccounts);
        host.present(root, "accounts-hidden");
    }

    private void startRename(int index) {
        clear();
        AccountBook.Account a = host.book().get(index);
        if (a == null) return;
        if (a.label != null) typed.append(a.label);
        shift = typed.length() == 0;
        showRename(index);
    }

    private void showRename(int index) {
        if (!host.ready()) return;
        LinearLayout root = host.page("ACCOUNTS / RENAME " + AccountBook.defaultName(index).toUpperCase(java.util.Locale.ROOT),
                typed.length() == 0 ? AccountBook.defaultName(index) : typed + "▌",
                "Up to " + AccountBook.MAX_LABEL + " characters. Only this phone shows the name; leave it empty for \"" + AccountBook.defaultName(index) + "\".");
        keyboard(root, AccountBook.MAX_LABEL, false, () -> showRename(index));
        host.action(root, "Save name", true, () -> {
            host.book().rename(index, typed.toString());
            host.bookChanged();
            clear();
            showAccount(index);
        });
        host.action(root, "Cancel", false, () -> { clear(); showAccount(index); });
        host.present(root, "account-rename");
    }

    // ------------------------------------------------------------------ passphrase wallet

    void showPassphraseIntro() {
        if (!host.ready()) return;
        clear();
        host.entryActive(false);
        String open = host.passphraseFingerprint();
        LinearLayout root = host.page("PASSPHRASE WALLET", open == null ? "Open a passphrase wallet" : "Passphrase wallet is open",
                "A passphrase (the \"25th word\") added to your 24 words opens a separate wallet with its own accounts.");
        if (open != null) host.card(root, "Open now", "Fingerprint " + open + ". Forgotten when the phone locks.");
        host.card(root, "A wrong passphrase opens a different wallet",
                "There is no \"wrong passphrase\" error, by design: every passphrase opens some wallet, and a typo opens an empty one. Recognise yours by its fingerprint and first address every time.");
        host.card(root, "Not part of your backup",
                "Your 24 words alone do NOT restore a passphrase wallet. Write the passphrase down separately and exactly (capitals, spaces, symbols). If it is lost, so is everything in that wallet.");
        host.card(root, "Never stored",
                "The phone never saves the passphrase and never sends it over USB. It is cleared when the phone locks or restarts; type it again after every unlock.");
        host.action(root, open == null ? "Enter passphrase" : "Open a different passphrase", true, this::startPassphraseEntry);
        if (open != null) host.action(root, "Close · back to standard wallet", false, host::closePassphrase);
        host.action(root, "Back to Wallet", false, host::showHome);
        host.present(root, "passphrase-intro");
    }

    private void startPassphraseEntry() {
        clear();
        host.entryActive(true);
        showPassphraseEntry();
    }

    private void showPassphraseEntry() {
        if (!host.ready()) return;
        int n = typed.length();
        String shown;
        if (n == 0) shown = "Type your passphrase";
        else if (reveal) shown = typed + "▌";
        else { char[] dots = new char[n]; Arrays.fill(dots, '•'); shown = new String(dots) + "▌"; }
        LinearLayout root = host.page("PASSPHRASE WALLET · " + n + (n == 1 ? " CHARACTER" : " CHARACTERS"), shown,
                "Capitals, spaces and symbols all count. Typed here only; never stored, never sent to the computer.");
        keyboard(root, SeedVault.MAX_PASSPHRASE_LENGTH, true, this::showPassphraseEntry);
        if (error != null) {
            TextView e = VaultTheme.bodyText(host.context(), error, host.bodySize(), VaultTheme.DANGER_INK);
            e.setPadding(0, host.dp(10), 0, host.dp(4));
            root.addView(e);
        }
        if (n > 0) host.action(root, "Open passphrase wallet", true, () -> {
            String problem = SeedVault.passphraseProblem(typed);
            if (problem != null) { error = problem; showPassphraseEntry(); return; }
            char[] chars = new char[typed.length()];
            typed.getChars(0, typed.length(), chars, 0);
            for (int i = 0; i < typed.length(); i++) typed.setCharAt(i, '\0');
            typed.setLength(0);
            if (pending != null) Arrays.fill(pending, '\0');
            pending = chars;
            host.previewPassphrase(chars, this::showPreview);
        });
        host.action(root, "Cancel", false, () -> { clear(); host.entryActive(false); showPassphraseIntro(); });
        host.present(root, "passphrase-entry");
    }

    /** Fingerprint + first address of the wallet this passphrase opens: the user recognises it before using it. */
    private void showPreview(String fingerprint, String account0) {
        if (!host.ready() || pending == null) return;
        boolean edgeSpace = pending.length > 0 && (pending[0] == ' ' || pending[pending.length - 1] == ' ');
        LinearLayout root = host.page("PASSPHRASE WALLET · CHECK", "Is this the wallet you expect?",
                "Compare the fingerprint and first address with what you noted when you first used this passphrase.");
        host.card(root, "Fingerprint", fingerprint);
        host.card(root, "Account 1", Keys.toChecksumAddress(account0));
        if (edgeSpace) host.card(root, "Note", "Your passphrase starts or ends with a space. That space is part of it.");
        host.card(root, "Not what you expected?",
                "Then the passphrase was typed differently: this is another, probably empty, wallet. Nothing is wrong with the phone. Re-enter it. New passphrase? Note the fingerprint so you can recognise this wallet next time.");
        host.action(root, "Use this wallet", true, () -> {
            char[] chars = pending;
            pending = null;
            host.usePassphrase(chars); // ownership passes to the host
        });
        host.action(root, "Re-enter passphrase", false, this::startPassphraseEntry);
        host.action(root, "Cancel", false, () -> { clear(); host.entryActive(false); host.showHome(); });
        host.present(root, "passphrase-preview");
    }

    // ------------------------------------------------------------------ keyboard

    private static final String[][] LETTERS = {
            "1 2 3 4 5 6 7 8 9 0".split(" "),
            "q w e r t y u i o p".split(" "),
            "a s d f g h j k l".split(" "),
            "⇧ z x c v b n m ⌫".split(" "),
    };
    private static final String[][] SYMBOLS = {
            "1 2 3 4 5 6 7 8 9 0".split(" "),
            "! @ # $ % ^ & * ( )".split(" "),
            "- _ = + [ ] { } \\ |".split(" "),
            "; : ' \" , . < > / ⌫".split(" "),
    };

    /** Printable-ASCII keyboard; {@code secret} adds Show/Hide. Every printable ASCII character is reachable. */
    private void keyboard(LinearLayout root, int max, boolean secret, Runnable redraw) {
        for (String[] row : symbols ? SYMBOLS : LETTERS) keyRow(root, row, max, redraw);
        String[] bottom = symbols
                ? (secret ? new String[] {"abc", "space", "?", "`", "~", reveal ? "Hide" : "Show"} : new String[] {"abc", "space", "?", "`", "~"})
                : (secret ? new String[] {"#+=", "space", reveal ? "Hide" : "Show"} : new String[] {"#+=", "space"});
        keyRow(root, bottom, max, redraw);
    }

    private void keyRow(LinearLayout parent, String[] keys, int max, Runnable redraw) {
        LinearLayout row = new LinearLayout(host.context());
        row.setOrientation(LinearLayout.HORIZONTAL);
        for (String key : keys) {
            boolean letter = key.length() == 1 && Character.isLetter(key.charAt(0));
            String shown = letter && shift ? key.toUpperCase(java.util.Locale.ROOT) : "⇧".equals(key) && shift ? "⇧ON" : key;
            TextView b = VaultTheme.pixelButton(host.context(), shown, false);
            b.setTextSize(key.length() > 2 ? 13 : 18);
            b.setPadding(0, 0, 0, 0);
            b.setGravity(Gravity.CENTER);
            b.setContentDescription("space".equals(key) ? "space" : shown);
            host.harden(b);
            b.setOnClickListener(v -> {
                if (!host.ready()) return;
                error = null;
                switch (key) {
                    case "⌫": if (typed.length() > 0) { typed.setCharAt(typed.length() - 1, '\0'); typed.setLength(typed.length() - 1); } break;
                    case "⇧": shift = !shift; break;
                    case "#+=": symbols = true; break;
                    case "abc": symbols = false; break;
                    case "Show": reveal = true; break;
                    case "Hide": reveal = false; break;
                    default:
                        if (typed.length() < max) {
                            typed.append("space".equals(key) ? " " : shown);
                            if (letter) shift = false;
                        }
                }
                redraw.run();
            });
            float weight = "space".equals(key) ? 3f : key.length() > 2 && !"space".equals(key) ? 1.6f : 1f;
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, host.dp(48), weight);
            lp.setMargins(host.dp(2), host.dp(3), host.dp(2), host.dp(3));
            row.addView(b, lp);
        }
        parent.addView(row);
    }

    /** For tests and the harness: the keys the keyboard offers, in both modes. */
    static List<String> allKeys() {
        java.util.ArrayList<String> out = new java.util.ArrayList<>();
        for (String[][] layer : new String[][][] {LETTERS, SYMBOLS}) for (String[] row : layer) out.addAll(Arrays.asList(row));
        out.addAll(Arrays.asList("?", "`", "~"));
        return out;
    }
}
