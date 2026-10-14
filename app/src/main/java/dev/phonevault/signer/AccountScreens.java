package dev.phonevault.signer;

import android.content.Context;
import android.graphics.Bitmap;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.web3j.crypto.Keys;

import java.nio.CharBuffer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

/**
 * ☰ → Accounts and ☰ → Passphrase wallet: the screens, the open wallet's account lists and
 * passphrase, and switching the signing account. One private key in memory: the ACTIVE account's.
 * Switching derives the new account from the seed inside the PIN window (withSeedKey →
 * VaultKeyStore.deriveAccount, one decrypt) on the host's crypto thread and publishes it under the
 * host's state lock with the session re-checked, exactly like unlock. The list and passphrase
 * fields below are guarded by that same lock (lock() clears them inside it).
 *
 * <p>The passphrase is typed on this screen's own keyboard (the appliance has no system IME), kept
 * in a fixed-capacity buffer that is overwritten on every exit, then held only in {@link #passphrase}
 * (char[]) while its wallet is open, zeroed on lock and close, and never stored or sent over USB.
 */
final class AccountScreens {
    private static final String TAG = "Vault";
    /** Preferences file and key of the standard wallet's saved account list. */
    static final String ACCOUNT_PREFS = "accounts", ACCOUNT_BOOK_KEY = "account_book_v1";

    interface Host {
        Context context();
        LinearLayout page(String eyebrow, String title, String description);
        void present(LinearLayout root, String screen);
        void action(LinearLayout parent, String label, boolean primary, Runnable run);
        void card(LinearLayout parent, String label, String value);
        /** The account screens may be shown: {@link #accountScreensReady()} and the backup is verified. */
        boolean ready();
        /** Unlocked, wallet loaded, no sensitive flow, approval or replacement (the backup may be unchecked). */
        boolean accountScreensReady();
        /** Leave passphrase entry and go home. */
        void showHome();
        void harden(View view);
        int dp(int value);
        /** The account signing right now. */
        SigningAccount active();
        /** True while a passphrase is being typed or confirmed: USB requests wait, the menu hides. */
        void entryActive(boolean active);
        boolean entryActive();
    }

    interface PreviewResult { void preview(String fingerprint, String account0Address); }

    private final Host host;
    /** The activity's lock, session, crypto thread and wallet publish. */
    private final VaultHost app;
    private final Pages pages;
    private final Object stateLock;
    private final ExecutorService cryptoExecutor;
    /** The standard wallet's accounts (persisted in the "accounts" preferences, bound to walletId). */
    private AccountBook standardBook;
    /** The open passphrase wallet's accounts, memory only; null while the standard wallet is active. */
    private AccountBook passphraseBook;
    private String passphraseFingerprint;
    /**
     * The open passphrase wallet's passphrase, held only so its other accounts can be derived
     * without retyping. Never stored, never sent; zeroed on lock, close and destroy.
     */
    private char[] passphrase;
    /** A typed passphrase handed over by "Use this wallet", until its wallet is open. Zeroed on lock. */
    private char[] pendingPassphrase;
    /** Typing buffer for a passphrase or a label. Fixed capacity so it never reallocates (and copies). */
    private final StringBuilder typed = new StringBuilder(SeedVault.MAX_PASSPHRASE_LENGTH + 8);
    private boolean shift, symbols, reveal;
    private String error;
    /** A typed passphrase awaiting "Use this wallet". Zeroed on every other exit. */
    private char[] pending;

    AccountScreens(Host host, VaultHost app) {
        this.host = host;
        this.app = app;
        this.pages = app.pages();
        this.stateLock = app.stateLock();
        this.cryptoExecutor = app.cryptoExecutor();
    }

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
        AccountBook book = book();
        String fingerprint = passphraseFingerprint();
        LinearLayout root = host.page(fingerprint == null ? "ACCOUNTS" : "ACCOUNTS · PASSPHRASE WALLET",
                fingerprint == null ? "Your accounts" : "Passphrase wallet accounts",
                "Each account is its own address from the same recovery phrase (m/44'/60'/0'/0/n). The active account receives, answers the computer and signs.");
        if (fingerprint != null) host.card(root, "Passphrase wallet · fingerprint " + fingerprint,
                "This list is not saved on the phone. It starts at Account 1 each time you open the passphrase wallet; add accounts again to reach them (same addresses every time).");
        SigningAccount active = host.active();
        for (AccountBook.Account a : book.visible()) {
            boolean isActive = active != null && a.index == active.index;
            host.action(root, (isActive ? "● " : "") + a.name() + " · " + AddressKeys.shortForm(a.address), isActive,
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
        host.action(root, "Add and switch", true, () -> activateAccount(index, true));
        host.action(root, "Cancel", false, this::showAccounts);
        host.present(root, "accounts-add");
    }

    void showAccount(int index) {
        if (!host.ready()) return;
        AccountBook.Account a = book().get(index);
        if (a == null) { showAccounts(); return; }
        SigningAccount active = host.active();
        boolean isActive = active != null && active.index == index;
        LinearLayout root = host.page("ACCOUNTS / " + AccountBook.defaultName(index).toUpperCase(java.util.Locale.ROOT),
                a.name(), isActive ? "Active · receiving and signing use this account." : "Not active.");
        host.card(root, "Address", Keys.toChecksumAddress(a.address));
        host.card(root, "Derivation", "m/44'/60'/0'/0/" + index + (passphraseFingerprint() == null ? " · standard wallet" : " · passphrase wallet " + passphraseFingerprint()));
        if (!isActive) host.action(root, "Use this account", true, () -> activateAccount(index, false));
        host.action(root, "Rename", false, () -> startRename(index));
        if (!isActive && !a.hidden) host.action(root, "Hide from the list", false, () -> {
            book().hide(index);
            bookChanged();
            showAccounts();
        });
        if (a.hidden) host.action(root, "Show in the list again", false, () -> {
            book().unhide(index);
            bookChanged();
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
        for (AccountBook.Account a : book().all()) {
            if (!a.hidden) continue;
            host.action(root, a.name() + " · " + AddressKeys.shortForm(a.address), false, () -> showAccount(a.index));
        }
        host.action(root, "All accounts", false, this::showAccounts);
        host.present(root, "accounts-hidden");
    }

    private void startRename(int index) {
        clear();
        AccountBook.Account a = book().get(index);
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
            book().rename(index, typed.toString());
            bookChanged();
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
        String open = passphraseFingerprint();
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
        if (open != null) host.action(root, "Close · back to standard wallet", false, this::closePassphraseWallet);
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
            TextView e = VaultTheme.bodyText(host.context(), error, VaultTheme.BODY_SIZE, VaultTheme.DANGER_INK);
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
            previewPassphrase(chars, this::showPreview);
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
            usePassphrase(chars); // ownership passes to usePassphrase
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
            VaultTheme.size(b, key.length() > 2 ? 13 : 18);
            b.setPadding(0, 0, 0, 0);
            b.setGravity(Gravity.CENTER);
            b.setContentDescription("space".equals(key) ? "space" : shown);
            host.harden(b);
            b.setOnClickListener(v -> {
                if (!host.ready()) return;
                Haptics.tick(v);
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

    // ------------------------------------------------------------------ the open wallet(s)
    // Guarded by the host's stateLock (read without it only on the UI thread, as before).

    /** The open wallet's accounts (the passphrase wallet's while one is open). */
    AccountBook book() { return passphraseBook != null ? passphraseBook : standardBook; }

    /** The open passphrase wallet's fingerprint, or null for the standard wallet. */
    String passphraseFingerprint() { return passphraseFingerprint; }

    /** A passphrase wallet is open (Bitcoin is refused, the menu says so). */
    boolean passphraseWalletOpen() { return passphraseBook != null; }

    /** Zero and forget the passphrase wallet. Call under stateLock (or where nothing else runs). */
    void clearPassphraseWallet() {
        if (passphrase != null) Arrays.fill(passphrase, '\0');
        if (pendingPassphrase != null) Arrays.fill(pendingPassphrase, '\0');
        passphrase = null;
        pendingPassphrase = null;
        passphraseBook = null;
        passphraseFingerprint = null;
    }

    /** Unlock: the standard wallet's account list as loaded and checked against the seed. Under stateLock. */
    void setStandardBook(AccountBook book) { standardBook = book; }

    /** A wallet was created, restored or replaced: its list starts over at account 1. Under stateLock. */
    AccountBook startStandardBook(String walletId) {
        standardBook = AccountBook.fresh(walletId);
        return standardBook;
    }

    void saveStandardBook(AccountBook book) {
        if (book == null) return;
        if (!host.context().getSharedPreferences(ACCOUNT_PREFS, Context.MODE_PRIVATE).edit().putString(ACCOUNT_BOOK_KEY, book.encode()).commit()) {
            Log.w(TAG, "account list not saved (it is rebuilt from the seed on demand)");
        }
    }

    /** A label or hidden flag changed: the active name follows; persist the standard wallet's book (passphrase books are not saved). */
    private void bookChanged() {
        // Labels change the name shown everywhere; the passphrase wallet's list stays in memory.
        synchronized (stateLock) {
            AccountBook book = book();
            SigningAccount a = host.active();
            if (book != null && a != null && book.get(a.index) != null) {
                app.relabelActiveAccount(new SigningAccount(a.index, book.get(a.index).name(), a.passphrase, a.fingerprint, a.address));
            }
        }
        if (passphraseBook == null) saveStandardBook(standardBook);
    }

    /**
     * Every account of the open wallet(s) (address → name, hidden ones too), so the review names a
     * send to your own other account and catches look-alikes of it. Display only; a list being
     * edited on screen at that instant just yields no names this time.
     */
    Map<String, String> ownAccountNames() {
        Map<String, String> own = new LinkedHashMap<>();
        try {
            AccountBook standard = standardBook, passphraseAccounts = passphraseBook;
            if (standard != null) for (AccountBook.Account a : new ArrayList<>(standard.all())) own.put(a.address, a.name());
            if (passphraseAccounts != null) for (AccountBook.Account a : new ArrayList<>(passphraseAccounts.all())) {
                own.put(a.address, a.name() + " (passphrase wallet)");
            }
        } catch (RuntimeException concurrentEdit) {
            own.clear();
        }
        return own;
    }

    /** Leave passphrase typing: the screen buffer is overwritten, USB requests are answered again. */
    private void endPassphraseEntry() {
        host.entryActive(false);
        clear();
    }

    // ------------------------------------------------------------------ switching the signing account

    /** Derive {@code index} of the open wallet (adding it to the list when {@code add}) and make it the signing account. */
    private void activateAccount(int index, boolean add) {
        if (!host.ready()) return;
        if (app.requestPending()) { pages.showInfo("Finish the request first", "Approve or reject the request on screen before switching accounts.", app::showHome); return; }
        app.withSeedKey("Confirm your PIN to switch account", () -> deriveAndActivate(index, add, false));
    }

    private void deriveAndActivate(int index, boolean add, boolean retried) {
        final int s = app.session();
        final AccountBook book;
        final String fingerprint;
        synchronized (stateLock) { book = book(); fingerprint = passphraseFingerprint; }
        if (book == null || !app.unlocked()) return;
        final String name = book.get(index) != null ? book.get(index).name() : AccountBook.defaultName(index);
        pages.showLoading(add ? "Adding " + name : "Switching to " + name, "Deriving its address from your recovery phrase…");
        cryptoExecutor.execute(() -> {
            try {
                String pass;
                synchronized (stateLock) {
                    if (s != app.session() || !app.unlocked()) return;
                    if (book() != book) throw new IllegalStateException("the wallet changed while switching");
                    // web3j derives from a String passphrase: this copy is short-lived and unreferenced after derivation.
                    pass = passphrase == null ? null : new String(passphrase);
                }
                if ((pass == null) != (fingerprint == null)) throw new IllegalStateException("the wallet changed while switching");
                SeedVault.Derived d = app.vault().deriveAccount(index, pass);
                pass = null;
                String address = d.credentials.getAddress();
                Bitmap qr = app.qrFor(address);
                boolean switched = false;
                synchronized (stateLock) {
                    if (s != app.session() || !app.unlocked() || !app.operational()) return;
                    boolean sameWallet = book() == book && (fingerprint != null
                            ? fingerprint.equals(d.fingerprint) && fingerprint.equals(passphraseFingerprint)
                            : d.account0Address.equals(app.walletId()));
                    if (!sameWallet) throw new IllegalStateException("the wallet changed while switching");
                    if (!app.requestPending() && app.approvalDecision() == null) {
                        if (add && book.get(index) == null) book.add(index, address);
                        book.select(index, address);
                        app.publishAccount(d.credentials, new SigningAccount(index, book.active().name(), fingerprint != null, d.fingerprint, address), address, qr);
                        switched = true;
                    }
                }
                if (switched && fingerprint == null) saveStandardBook(book);
                final boolean done = switched;
                app.activity().runOnUiThread(() -> {
                    if (s != app.session() || !app.unlocked()) return;
                    if (app.approvalDecision() != null) return; // the request's own screen is showing
                    app.setStatus(done ? "Now using " + name + (fingerprint != null ? " (passphrase wallet)" : "")
                            : "Account not switched: a request arrived. Try again after it.");
                    app.showHome();
                    app.drainPendingUsb();
                });
            } catch (Exception e) {
                app.activity().runOnUiThread(() -> {
                    if (s != app.session() || !app.unlocked()) return;
                    if (KeystoreFailures.authLapsed(e) && !retried) {
                        app.forgetConfirmation();
                        app.confirmDevicePin("Confirm your PIN to switch account", () -> deriveAndActivate(index, add, true), app::showHome);
                        return;
                    }
                    Log.w(TAG, "account switch failed: " + KeystoreFailures.chain(e));
                    pages.showInfo("Account not switched", "The active account is unchanged. " + (e.getMessage() == null ? "" : e.getMessage()), app::showHome);
                });
            }
        });
    }

    /** Derive the passphrase wallet's identity (fingerprint, account 1) for the user to recognise. Keeps no key. */
    private void previewPassphrase(char[] chars, PreviewResult result) {
        app.withSeedKey("Confirm your PIN to open the passphrase wallet", () -> previewWorker(chars, result, false));
    }

    private void previewWorker(char[] chars, PreviewResult result, boolean retried) {
        final int s = app.session();
        if (!host.entryActive() || chars == null || chars.length == 0 || SeedVault.passphraseProblem(CharBuffer.wrap(chars)) != null) return;
        final String pass = new String(chars); // short-lived; web3j derives from a String
        pages.showLoading("Opening passphrase wallet", "Deriving its fingerprint and first address…");
        cryptoExecutor.execute(() -> {
            try {
                if (s != app.session() || !app.unlocked()) return;
                SeedVault.Derived d = app.vault().deriveAccount(0, pass);
                final String fingerprint = d.fingerprint, account0 = d.account0Address;
                app.activity().runOnUiThread(() -> { if (s == app.session() && app.unlocked() && host.entryActive()) result.preview(fingerprint, account0); });
            } catch (Exception e) {
                app.activity().runOnUiThread(() -> {
                    if (s != app.session() || !app.unlocked()) return;
                    if (KeystoreFailures.authLapsed(e) && !retried) {
                        app.forgetConfirmation();
                        app.confirmDevicePin("Confirm your PIN to open the passphrase wallet", () -> previewWorker(chars, result, true), app::showHome);
                        return;
                    }
                    Log.w(TAG, "passphrase preview failed: " + KeystoreFailures.chain(e));
                    pages.showInfo("Passphrase wallet not opened", "Your current wallet is unchanged. Lock and retry.", app::showHome);
                });
            }
        });
    }

    /** "Use this wallet": takes ownership of {@code chars}. */
    private void usePassphrase(char[] chars) {
        synchronized (stateLock) {
            if (pendingPassphrase != null) Arrays.fill(pendingPassphrase, '\0');
            pendingPassphrase = chars;
        }
        app.withSeedKey("Confirm your PIN to open the passphrase wallet", () -> openPassphraseWallet(false));
    }

    private void openPassphraseWallet(boolean retried) {
        final int s = app.session();
        final String pass;
        synchronized (stateLock) {
            if (pendingPassphrase == null || !app.unlocked()) return;
            pass = new String(pendingPassphrase); // short-lived; web3j derives from a String
        }
        pages.showLoading("Opening passphrase wallet", "Deriving Account 1…");
        cryptoExecutor.execute(() -> {
            try {
                if (s != app.session() || !app.unlocked()) return;
                SeedVault.Derived d = app.vault().deriveAccount(0, pass);
                String address = d.credentials.getAddress();
                Bitmap qr = app.qrFor(address);
                synchronized (stateLock) {
                    if (s != app.session() || !app.unlocked() || !app.operational() || pendingPassphrase == null) return;
                    if (app.requestPending() || app.approvalDecision() != null) throw new IllegalStateException("a request arrived; try again after it");
                    if (passphrase != null) Arrays.fill(passphrase, '\0');
                    passphrase = pendingPassphrase;
                    pendingPassphrase = null;
                    passphraseFingerprint = d.fingerprint;
                    passphraseBook = AccountBook.fresh(d.account0Address);
                    app.publishAccount(d.credentials, new SigningAccount(0, passphraseBook.active().name(), true, d.fingerprint, address), address, qr);
                }
                app.activity().runOnUiThread(() -> {
                    if (s != app.session() || !app.unlocked()) return;
                    endPassphraseEntry();
                    app.setStatus("Passphrase wallet open · fingerprint " + d.fingerprint + " · closes when the phone locks");
                    app.showHome();
                    app.drainPendingUsb();
                });
            } catch (Exception e) {
                app.activity().runOnUiThread(() -> {
                    if (s != app.session() || !app.unlocked()) return;
                    if (KeystoreFailures.authLapsed(e) && !retried) {
                        app.forgetConfirmation();
                        app.confirmDevicePin("Confirm your PIN to open the passphrase wallet", () -> openPassphraseWallet(true),
                                () -> { synchronized (stateLock) { if (pendingPassphrase != null) Arrays.fill(pendingPassphrase, '\0'); pendingPassphrase = null; } endPassphraseEntry(); app.showHome(); });
                        return;
                    }
                    synchronized (stateLock) { if (pendingPassphrase != null) Arrays.fill(pendingPassphrase, '\0'); pendingPassphrase = null; }
                    endPassphraseEntry();
                    Log.w(TAG, "passphrase wallet open failed: " + KeystoreFailures.chain(e));
                    pages.showInfo("Passphrase wallet not opened", "Your current wallet is unchanged. " + (e.getMessage() == null ? "" : e.getMessage()), app::showHome);
                });
            }
        });
    }

    /** Back to the standard wallet's active account; the passphrase is zeroed. */
    private void closePassphraseWallet() {
        if (!host.accountScreensReady()) return;
        app.withSeedKey("Confirm your PIN to return to the standard wallet", () -> closePassphraseWorker(false));
    }

    private void closePassphraseWorker(boolean retried) {
        final int s = app.session();
        final AccountBook book = standardBook;
        if (book == null || passphraseBook == null) { app.showHome(); return; }
        pages.showLoading("Closing passphrase wallet", "Returning to the standard wallet…");
        cryptoExecutor.execute(() -> {
            try {
                if (s != app.session() || !app.unlocked()) return;
                SeedVault.Derived d = app.vault().deriveAccount(book.activeIndex(), null);
                String address = d.credentials.getAddress();
                Bitmap qr = app.qrFor(address);
                synchronized (stateLock) {
                    if (s != app.session() || !app.unlocked() || !app.operational()) return;
                    if (!d.account0Address.equals(app.walletId()) || !book.active().address.equalsIgnoreCase(address)) throw new IllegalStateException("the standard wallet did not match its saved account list");
                    if (app.requestPending() || app.approvalDecision() != null) throw new IllegalStateException("a request arrived; try again after it");
                    clearPassphraseWallet();
                    app.publishAccount(d.credentials, new SigningAccount(book.activeIndex(), book.active().name(), false, d.fingerprint, address), address, qr);
                }
                app.activity().runOnUiThread(() -> {
                    if (s != app.session() || !app.unlocked()) return;
                    app.setStatus("Passphrase wallet closed · back to the standard wallet");
                    app.showHome();
                    app.drainPendingUsb();
                });
            } catch (Exception e) {
                app.activity().runOnUiThread(() -> {
                    if (s != app.session() || !app.unlocked()) return;
                    if (KeystoreFailures.authLapsed(e) && !retried) {
                        app.forgetConfirmation();
                        app.confirmDevicePin("Confirm your PIN to return to the standard wallet", () -> closePassphraseWorker(true), app::showHome);
                        return;
                    }
                    pages.showInfo("Still in the passphrase wallet", "Locking the phone always closes it. " + (e.getMessage() == null ? "" : e.getMessage()), app::showHome);
                });
            }
        });
    }
}
