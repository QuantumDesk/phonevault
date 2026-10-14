package dev.phonevault.signer;

import android.app.Activity;
import android.graphics.Bitmap;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;

/**
 * The first-run wizard (create or restore, never silently), optional dice entropy, and on-device
 * restore from 24 words: on first run, and over an existing wallet ("Restore a different wallet",
 * owned by a fresh-PIN sensitive flow and the replacement state machine exactly like Replace, USB
 * excluded throughout). Wallet storage and the publish of the new key run on the host's crypto
 * thread under its state lock with the session re-checked, as they did in MainActivity.
 */
final class SetupScreens {
    private final VaultHost host;
    private final Activity activity;
    private final Pages pages;
    private final Object stateLock;
    private final ExecutorService cryptoExecutor;

    SetupScreens(VaultHost host) {
        this.host = host;
        this.activity = host.activity();
        this.pages = host.pages();
        this.stateLock = host.stateLock();
        this.cryptoExecutor = host.cryptoExecutor();
    }

    /** A restore over the existing wallet is in progress (its screens exist only inside the sensitive flow). */
    boolean replacing() { return restoreReplacing; }

    /** Typed recovery words and dice rolls never outlive the unlocked session (lock, cancel, hide). */
    void clear() {
        clearRestoreEntry();
        clearDice();
        restoreReplacing = false;
        restoreOverOp = -1;
    }

    // ------------------------------------------------------------------ first-run wizard

    /** Step 1: a fresh PIN is set and no wallet exists yet. Create or restore — never silently. */
    void showFirstRunChoice() {
        clearRestoreEntry();
        LinearLayout root = pages.page("SET UP · STEP 1 OF 4", "Set up your wallet",
                "Create a brand-new wallet on this phone, or restore one from a 24-word recovery phrase you already have. Nothing leaves this device either way.");
        pages.card(root, "Create new", "Generates a fresh recovery phrase here, offline. You'll write it down and we'll spot-check a few words.");
        pages.action(root, "Create new wallet", true, () -> host.withSeedKey("Confirm your PIN to seal your new wallet", this::createFirstWallet));
        pages.card(root, "Restore existing", "Type your 24 words on this screen. We'll show the address they produce so you can confirm it's the right wallet before anything is saved.");
        pages.action(root, "Restore from recovery phrase", false, this::showRestoreEntry);
        pages.action(root, "Advanced · add your own dice rolls", false, this::showDiceEntry);
        pages.action(root, "Lock now", false, host::lock);
        pages.present(root, "first-run");
    }

    // ------------------------------------------------------------------ optional user entropy
    // Physical dice rolls, mixed with the two device sources.

    /** Rolls as bytes '1'..'6'; never shown back on screen, zeroed after use and on lock. */
    private final StringBuilder diceRolls = new StringBuilder();
    /** 99 rolls of a fair d6 ≈ 256 bits, the full width of the seed. */
    private static final int DICE_FULL = 99;

    private void clearDice() {
        for (int i = 0; i < diceRolls.length(); i++) diceRolls.setCharAt(i, '0');
        diceRolls.setLength(0);
    }

    private void showDiceEntry() {
        int rolls = diceRolls.length();
        int bits = (int) Math.floor(rolls * 2.585);
        LinearLayout root = pages.page("SET UP · ADVANCED", "Add your own randomness",
                "Roll a real die and tap each result. Your rolls are hashed together with the phone's two hardware entropy sources, so the wallet never depends on the phone's randomness alone. The rolls are not displayed and are discarded after the wallet is created.");
        pages.card(root, "Rolls so far", rolls + " of " + DICE_FULL + " · about " + Math.min(bits, 256) + " of 256 bits"
                + (rolls >= DICE_FULL ? " · full strength" : ""));
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        for (int face = 1; face <= 6; face++) {
            final char c = (char) ('0' + face);
            TextView b = VaultTheme.pixelButton(activity, String.valueOf(face), true);
            VaultTheme.size(b, 20);
            b.setPadding(0, 0, 0, 0);
            b.setGravity(Gravity.CENTER);
            Pages.hardenTouch(b);
            b.setOnClickListener(v -> {
                if (!host.unlocked() || !host.operational()) return;
                if (diceRolls.length() < 512) diceRolls.append(c);
                showDiceEntry();
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, pages.dp(60), 1f);
            lp.setMargins(pages.dp(3), pages.dp(6), pages.dp(3), pages.dp(6));
            row.addView(b, lp);
        }
        root.addView(row);
        if (rolls > 0) {
            pages.action(root, "Create wallet with these rolls", true, () -> host.withSeedKey("Confirm your PIN to seal your new wallet", this::createFirstWallet));
            pages.action(root, "Undo last roll", false, () -> {
                diceRolls.setCharAt(rolls - 1, '0');
                diceRolls.setLength(rolls - 1);
                showDiceEntry();
            });
        }
        pages.action(root, "Back · without dice", false, () -> { clearDice(); showFirstRunChoice(); });
        pages.present(root, "first-run-dice");
    }

    private void createFirstWallet() {
        final int s = host.session();
        final byte[] userEntropy = diceRolls.toString().getBytes(StandardCharsets.US_ASCII);
        clearDice();
        pages.showLoading("Creating your wallet", userEntropy.length == 0
                ? "Generating a new recovery phrase from device entropy…"
                : "Mixing " + userEntropy.length + " dice rolls with device entropy…");
        cryptoExecutor.execute(() -> {
            try {
                synchronized (stateLock) {
                    if (s != host.session() || !host.unlocked() || !host.operational() || host.walletLoaded()) return;
                }
                Credentials fresh;
                try { fresh = host.vault().generateAndStore(userEntropy); host.recordEntropyReport(userEntropy.length > 0); }
                finally { Arrays.fill(userEntropy, (byte) 0); }
                String address = fresh.getAddress();
                Bitmap qr = host.qrFor(address);
                synchronized (stateLock) {
                    if (s != host.session() || !host.unlocked() || !host.operational()) return;
                    host.publishNewWallet(fresh, qr, false);
                }
                activity.runOnUiThread(() -> {
                    if (s != host.session() || !host.unlocked()) return;
                    LinearLayout root = pages.page("SET UP · STEP 2 OF 4", "Write down your recovery phrase",
                            "Your new wallet is ready. Next, copy its 24 words onto paper, in order. Never photograph them or type them into another device.");
                    pages.card(root, "Then", "Step 3 spot-checks a few of the words. Step 4 shows your receiving address.");
                    pages.action(root, "Continue", true, host::confirmRevealBackup);
                    pages.action(root, "Lock now", false, host::lock);
                    pages.present(root, "first-run-created");
                });
            } catch (Exception e) {
                activity.runOnUiThread(() -> {
                    if (s != host.session() || !host.unlocked()) return;
                    pages.showInfo("Could not create a wallet", "Nothing was saved. " + e.getMessage(), this::showFirstRunChoice);
                });
            }
        });
    }

    // ------------------------------------------------------------------ restore over an existing wallet
    // Same entry screens, but owned by a fresh-PIN sensitive flow and the replacement state
    // machine, exactly like Replace (USB excluded throughout).

    private boolean restoreReplacing;
    private int restoreOverOp = -1;

    void confirmRestoreOver() {
        if (!host.walletLoaded() || !host.hasCredentials()) return;
        LinearLayout root = pages.page("SECURITY / RESTORE", "Restore a different wallet?",
                "You will type a 24-word recovery phrase on this phone. The wallet it produces REPLACES the current one on this device. Nothing changes until you confirm the address it shows.");
        String walletId = host.walletId();
        pages.card(root, "Current Account 1", Keys.toChecksumAddress(walletId != null ? walletId : host.walletAddress()));
        pages.card(root, "Keep its backup", "If the current wallet controls any assets, keep its written phrase. This phone will no longer hold that key.");
        pages.action(root, "Continue · verify PIN", true, () -> host.beginSensitive("restore a different wallet", () -> {
            int op;
            synchronized (stateLock) { op = host.replacement().begin(); }
            if (op < 0) { host.hideBackup(); return; }
            restoreOverOp = op;
            restoreReplacing = true;
            clearRestoreEntry();
            showRestoreEntry();
        }));
        pages.action(root, "Back to Security", false, host::showSecurity);
        pages.present(root, "security-restore");
    }

    /** Commit a restore over the existing wallet: the PREPARED → COMMITTING transition, then storage. */
    private void commitRestoreOver(final String mnemonic) {
        final int token = host.activeSensitive(), s = host.session(), op = restoreOverOp;
        if (!restoreReplacing || !host.sensitiveValid(token, s) || !host.replacement().beginCommit(op)) return;
        host.clearReceivingIdentity();
        pages.showLoading("Restoring your wallet", "Saving and checking the restored identity. This step can no longer be cancelled.");
        cryptoExecutor.execute(() -> {
            try {
                String address;
                synchronized (stateLock) {
                    if (!host.sensitiveValid(token, s) || !host.replacement().owns(op) || host.transport() != null || host.requestPending()) return;
                    host.clearCredentials();
                    Credentials restored = host.vault().restore(mnemonic);
                    address = restored.getAddress();
                    host.backupCheck().record(address);
                    host.publishNewWallet(restored, null, true);
                    host.replacement().end(op);
                }
                Bitmap qr = host.qrFor(address);
                activity.runOnUiThread(() -> {
                    if (!host.sensitiveValid(token, s)) return;
                    host.setWalletQr(qr);
                    host.setStatus("Wallet restored · backup verified by entry");
                    host.hideBackup();
                });
            } catch (Exception e) {
                synchronized (stateLock) { host.clearCredentials(); host.clearReceivingIdentity(); host.replacement().end(op); }
                activity.runOnUiThread(() -> {
                    if (s != host.session()) return;
                    host.setGateNotice("Storage could not confirm the restored wallet. Re-enter your PIN to reconcile it. No receiving address is available until loading succeeds.");
                    host.lock();
                });
            }
        });
    }

    // ------------------------------------------------------------------ restore
    // On-device word entry (no system keyboard), validate, confirm address, commit.

    private final String[] restoreWords = new String[SeedRestore.WORD_COUNT];
    private int restoreIndex;
    private final StringBuilder restoreBuffer = new StringBuilder();

    private void clearRestoreEntry() {
        Arrays.fill(restoreWords, null);
        restoreIndex = 0;
        restoreBuffer.setLength(0);
    }

    private int restoreFilled() {
        int n = 0;
        for (String w : restoreWords) if (w != null) n++;
        return n;
    }

    private void showRestoreEntry() {
        if (restoreIndex < 0) restoreIndex = 0;
        if (restoreIndex >= SeedRestore.WORD_COUNT) restoreIndex = SeedRestore.WORD_COUNT - 1;
        String typed = restoreBuffer.toString();
        int filled = restoreFilled();
        LinearLayout root = pages.page((restoreReplacing ? "REPLACE BY RESTORE · WORD " : "RESTORE · WORD ") + (restoreIndex + 1) + " OF " + SeedRestore.WORD_COUNT,
                typed.isEmpty() ? (restoreWords[restoreIndex] == null ? "Type word " + (restoreIndex + 1) : restoreWords[restoreIndex])
                                : typed + "…",
                "Type the first letters, then tap the matching word. " + filled + " of " + SeedRestore.WORD_COUNT + " entered.");

        // On-device letter keyboard: the appliance must not depend on a system IME. It stays at a
        // fixed position (directly under the title) so keys never jump while typing.
        restoreKeyRow(root, "a b c d e f g h i".split(" "));
        restoreKeyRow(root, "j k l m n o p q r".split(" "));
        restoreKeyRow(root, "s t u v w x y z ⌫".split(" "));

        // Suggestions from the BIP39 list for what's been typed, in a slot of constant height.
        List<String> suggestions = SeedRestore.suggestions(typed, 6);
        LinearLayout slot = new LinearLayout(activity);
        slot.setOrientation(LinearLayout.VERTICAL);
        slot.setMinimumHeight(pages.dp(2 * 60 + 8));
        for (int rowStart = 0; rowStart < suggestions.size(); rowStart += 3) {
            LinearLayout srow = new LinearLayout(activity);
            srow.setOrientation(LinearLayout.HORIZONTAL);
            for (int i = rowStart; i < Math.min(rowStart + 3, suggestions.size()); i++) {
                final String word = suggestions.get(i);
                TextView b = VaultTheme.pixelButton(activity, word, i == 0);
                VaultTheme.size(b, 15);
                // Fixed 52 dp slot: no vertical padding, so the word never clips at large text.
                b.setPadding(pages.dp(4), 0, pages.dp(4), 0);
                Pages.hardenTouch(b);
                b.setOnClickListener(v -> { if (host.unlocked() && host.operational()) pickRestoreWord(word); });
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, pages.dp(52), 1f);
                lp.setMargins(pages.dp(3), pages.dp(4), pages.dp(3), pages.dp(4));
                srow.addView(b, lp);
            }
            slot.addView(srow);
        }
        if (suggestions.isEmpty() && !typed.isEmpty()) {
            TextView none = VaultTheme.bodyText(activity, "No recovery word starts with \"" + typed + "\". Use ⌫.", VaultTheme.BODY_SIZE, VaultTheme.DANGER_INK);
            none.setPadding(0, pages.dp(12), 0, pages.dp(6));
            slot.addView(none);
        }
        root.addView(slot);

        // Progress strip: the words so far (this IS the recovery phrase — the screen is sensitive).
        StringBuilder strip = new StringBuilder();
        for (int i = 0; i < SeedRestore.WORD_COUNT; i++) {
            if (restoreWords[i] == null) continue;
            if (strip.length() > 0) strip.append("  ");
            strip.append(i + 1).append(' ').append(restoreWords[i]);
        }
        if (strip.length() > 0) {
            TextView entered = VaultTheme.monoText(activity, strip.toString(), 13, VaultTheme.DIM);
            entered.setPadding(0, pages.dp(8), 0, pages.dp(8));
            root.addView(entered);
        }

        if (filled == SeedRestore.WORD_COUNT) pages.action(root, "Restore this wallet", true, this::validateRestore);
        if (restoreIndex > 0 || restoreWords[restoreIndex] != null) pages.action(root, "← Previous word", false, () -> {
            if (restoreBuffer.length() > 0) restoreBuffer.setLength(0);
            else if (restoreIndex > 0) restoreIndex--;
            showRestoreEntry();
        });
        if (restoreReplacing) pages.action(root, "Cancel · keep current wallet", false, host::hideBackup);
        else pages.action(root, "Cancel · start over", false, () -> { clearRestoreEntry(); showFirstRunChoice(); });
        pages.present(root, "restore-entry");
    }

    private void restoreKeyRow(LinearLayout parent, String[] keys) {
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        for (String key : keys) {
            TextView b = VaultTheme.pixelButton(activity, key, false);
            VaultTheme.size(b, 18);
            b.setPadding(0, 0, 0, 0); // a ninth of the width: any horizontal padding hides the letter
            b.setGravity(Gravity.CENTER);
            Pages.hardenTouch(b);
            b.setOnClickListener(v -> {
                if (!host.unlocked() || !host.operational()) return;
                if ("⌫".equals(key)) {
                    if (restoreBuffer.length() > 0) restoreBuffer.setLength(restoreBuffer.length() - 1);
                    else if (restoreWords[restoreIndex] != null) restoreWords[restoreIndex] = null;
                    else if (restoreIndex > 0) { restoreIndex--; restoreWords[restoreIndex] = null; }
                } else if (restoreBuffer.length() < 8) {
                    restoreBuffer.append(key);
                }
                showRestoreEntry();
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, pages.dp(48), 1f);
            lp.setMargins(pages.dp(2), pages.dp(3), pages.dp(2), pages.dp(3));
            row.addView(b, lp);
        }
        parent.addView(row);
    }

    private void pickRestoreWord(String word) {
        if (!SeedRestore.isWord(word)) return;
        restoreWords[restoreIndex] = word;
        restoreBuffer.setLength(0);
        // Advance to the next empty slot (or stay on the last one).
        int next = restoreIndex + 1;
        while (next < SeedRestore.WORD_COUNT && restoreWords[next] != null) next++;
        restoreIndex = Math.min(next, SeedRestore.WORD_COUNT - 1);
        if (restoreFilled() == SeedRestore.WORD_COUNT) validateRestore();
        else showRestoreEntry();
    }

    /** All 24 entered: validate (count, wordlist, checksum) and show the address for confirmation. */
    private void validateRestore() {
        final int s = host.session();
        final String raw = String.join(" ", Arrays.asList(restoreWords).stream()
                .map(w -> w == null ? "" : w).toArray(String[]::new));
        final String mnemonic;
        try {
            mnemonic = SeedRestore.validate(raw);
        } catch (SeedRestore.RestoreException bad) {
            pages.showInfo("Phrase not valid yet", bad.getMessage() + ". Go back and fix the word.", this::showRestoreEntry);
            return;
        }
        pages.showLoading("Checking your phrase", "Deriving the wallet address these 24 words produce…");
        cryptoExecutor.execute(() -> {
            try {
                final String address = SeedRestore.deriveAddress(mnemonic, 0);
                activity.runOnUiThread(() -> {
                    if (s != host.session() || !host.unlocked()) return;
                    boolean replacing = restoreReplacing;
                    if (replacing && !host.replacement().markPrepared(restoreOverOp)) { host.hideBackup(); return; }
                    LinearLayout root = pages.page(replacing ? "REPLACE BY RESTORE · CONFIRM" : "RESTORE · CONFIRM",
                            replacing ? "Replace with this wallet?" : "Is this your wallet?",
                            replacing ? "This is the address your phrase produces. Confirming REPLACES the current wallet on this phone. If the address is not the one you expect, a word or its order is wrong — nothing has been saved yet."
                                      : "This is the address your phrase produces. Compare it with the wallet you're restoring. If it doesn't match, a word or its order is wrong — nothing has been saved yet.");
                    pages.card(root, replacing ? "New Account 1" : "Account 1", Keys.toChecksumAddress(address));
                    String current = host.walletAddress();
                    if (replacing && current != null) pages.card(root, "Replaces current", Keys.toChecksumAddress(current));
                    pages.card(root, "Derivation", "m/44'/60'/0'/0/0 · no passphrase");
                    pages.action(root, replacing ? "Yes, replace with this wallet" : "Yes, restore this wallet", true,
                            () -> host.withSeedKey("Confirm your PIN to save the restored wallet",
                                    () -> { if (restoreReplacing) commitRestoreOver(mnemonic); else commitRestore(mnemonic, s); }));
                    pages.action(root, "Back · fix words", false, this::showRestoreEntry);
                    if (replacing) pages.action(root, "Cancel · keep current wallet", false, host::hideBackup);
                    else pages.action(root, "Cancel · start over", false, () -> { clearRestoreEntry(); showFirstRunChoice(); });
                    pages.present(root, "restore-confirm");
                });
            } catch (Exception e) {
                activity.runOnUiThread(() -> { if (s == host.session()) pages.showInfo("Could not derive an address", e.getMessage(), this::showRestoreEntry); });
            }
        });
    }

    /** Persist the restored phrase; the user typed it, so the backup is considered verified. */
    private void commitRestore(final String mnemonic, final int s) {
        pages.showLoading("Restoring your wallet", "Saving and verifying the restored identity on this device…");
        cryptoExecutor.execute(() -> {
            try {
                Credentials restored;
                String address;
                Bitmap qr;
                synchronized (stateLock) {
                    if (s != host.session() || !host.unlocked() || !host.operational() || host.walletLoaded()) return;
                    restored = host.vault().restore(mnemonic);
                    address = restored.getAddress();
                    host.backupCheck().record(address);
                    host.publishNewWallet(restored, null, true);
                }
                qr = host.qrFor(address);
                synchronized (stateLock) { if (s == host.session()) host.setWalletQr(qr); }
                clearRestoreEntry();
                activity.runOnUiThread(() -> {
                    if (s != host.session() || !host.unlocked()) return;
                    host.setStatus("Wallet restored · backup verified by entry");
                    host.showHome();
                    host.drainPendingUsb();
                });
            } catch (Exception e) {
                synchronized (stateLock) { host.clearCredentials(); host.markWalletUnloaded(); }
                clearRestoreEntry();
                activity.runOnUiThread(() -> {
                    if (s != host.session()) return;
                    host.setGateNotice("Storage could not confirm the restored wallet. Re-enter your PIN and try again; nothing is active until it saves.");
                    host.lock();
                });
            }
        });
    }
}
