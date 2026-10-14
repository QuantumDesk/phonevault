package dev.phonevault.signer;

import android.app.Activity;
import android.graphics.Bitmap;
import android.os.Handler;
import android.os.SystemClock;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.MnemonicUtils;

import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;

/**
 * The recovery phrase: reveal (words or SeedQR), the spot check, the backup reminder, and
 * replacing the wallet with a new one. Every screen here lives inside a PIN-verified sensitive
 * flow owned by MainActivity (no USB session, FLAG_SECURE window) and is cleared by
 * {@link #clear} on hide, timeout and lock; the seed timer hides the phrase after two minutes
 * without a touch and after eight minutes in any case. (Logic: SeedQr, SeedQrView, BackupCheck,
 * BackupReminder; these are only the screens.)
 */
final class BackupScreens {
    private static final String TAG = "Vault";
    /** Idle time before the phrase hides. Copying 24 words onto paper means not touching the phone;
     *  every touch or page turn restarts it. */
    static final long SEED_TIMEOUT_MS = 120 * 1000L;
    /** Absolute cap on one reveal session, regardless of touches. */
    private static final long SEED_SESSION_MS = 8 * 60 * 1000L;

    private final VaultHost host;
    private final Activity activity;
    private final Pages pages;
    private final Object stateLock;
    private final ExecutorService cryptoExecutor;
    private final Handler ui;
    private final SecureRandom random;
    private final Runnable hideSeed = this::tickSeedTimer;

    private String[] backupWords;
    private String backupIdentity;
    private BackupCheck.Challenge backupChallenge;
    private SeedVault.Generation replacementCandidate;
    private int backupPage, replacementOperation;
    /** Page to reopen at after an idle hide, so the user does not start over at word 1. */
    private int resumeBackupPage;
    private long seedIdleDeadline, seedHardDeadline;
    private TextView seedTimer;
    /** True when the PIN-gated reveal should open on the SeedQR instead of the words. */
    private boolean seedQrRequested;
    private SeedQr.Format seedQrFormat = SeedQr.Format.COMPACT;
    private SeedQrView seedQrView;

    BackupScreens(VaultHost host) {
        this.host = host;
        this.activity = host.activity();
        this.pages = host.pages();
        this.stateLock = host.stateLock();
        this.cryptoExecutor = host.cryptoExecutor();
        this.ui = host.ui();
        this.random = host.random();
    }

    /** The phrase (or its check) is open: the seed timer owns the timeout. */
    boolean showingWords() { return backupWords != null; }

    /** A touch while the phrase is open restarts its idle timer. */
    void touched() { seedIdleDeadline = SystemClock.elapsedRealtime() + SEED_TIMEOUT_MS; }

    void stopSeedTimer() { ui.removeCallbacks(hideSeed); }

    /** Forget the phrase, its check, the replacement candidate and the SeedQR (hide, timeout, lock). */
    void clear() {
        if (backupWords != null) Arrays.fill(backupWords, null);
        backupWords = null;
        if (backupChallenge != null) backupChallenge.destroy();
        backupChallenge = null;
        backupIdentity = null;
        replacementCandidate = null;
        seedTimer = null;
        wipeSeedQr();
        seedQrRequested = false;
    }

    void confirmRevealBackup() { seedQrRequested = false; startBackupAccess(false); }

    void startBackupAccess(boolean checkOnly) {
        host.beginSensitive(checkOnly ? "check your backup" : "view your recovery phrase",
                () -> openBackup(host.activeSensitive(), host.session(), checkOnly, false));
    }

    /**
     * Decrypt the phrase for the sensitive flow {@code token} already owns. If the chip refuses
     * because the PIN window closed before the decrypt reached it (SeedKeyWindow), ask for the PIN
     * once more and retry inside the SAME flow: re-entering beginSensitive would be
     * refused (the flow is still active) and leave the loading screen up for good.
     */
    private void openBackup(int token, int s, boolean checkOnly, boolean retried) {
        pages.showLoading("Opening secure backup", "Keep cameras and other people away from your screen.");
        cryptoExecutor.execute(() -> {
            try {
                if (!host.sensitiveValid(token, s)) return;
                String mnemonic = host.vault().revealMnemonic(() -> host.sensitiveValid(token, s));
                String[] words = mnemonic.split(" ");
                activity.runOnUiThread(() -> {
                    if (!host.sensitiveValid(token, s)) { Arrays.fill(words, null); return; }
                    backupWords = words;
                    backupIdentity = host.walletId(); // the backup covers the wallet: its account-0 identity
                    backupPage = checkOnly ? 0 : Math.min(resumeBackupPage, 5); resumeBackupPage = 0;
                    startSeedTimer();
                    if (checkOnly) startWordCheck();
                    else if (seedQrRequested) showSeedQr();
                    else showPhrasePage();
                });
            } catch (Exception e) {
                activity.runOnUiThread(() -> {
                    if (!host.sensitiveValid(token, s)) return;
                    if (!retried && KeystoreFailures.authLapsed(e)) {
                        host.forgetConfirmation();
                        host.confirmDevicePin("Confirm your PIN to open your backup",
                                () -> { if (host.sensitiveValid(token, s)) openBackup(token, s, checkOnly, true); },
                                host::hideBackup);
                        return;
                    }
                    Log.w(TAG, "backup open failed: " + KeystoreFailures.chain(e));
                    pages.showInfo("Backup unavailable", "The stored phrase could not be opened. Lock and retry; do not replace this wallet to fix a storage problem.", host::hideBackup);
                });
            }
        });
    }

    // ------------------------------------------------------------------ SeedQR + backup reminder

    void confirmRevealSeedQr() { seedQrRequested = true; startBackupAccess(false); }

    /**
     * The recovery phrase as a SeedQR, for copying onto the backup card's grid. Same protections as
     * the phrase pages: inside the sensitive flow (PIN, no USB session), FLAG_SECURE window, the seed
     * timer, and Hide / Back / lock clear it.
     */
    private void showSeedQr() {
        if (!host.sensitiveActive() || backupWords == null || replacementCandidate != null) return;
        wipeSeedQr();
        SeedQr.Modules modules;
        try {
            modules = SeedQr.encode(backupWords, seedQrFormat);
        } catch (RuntimeException e) {
            Log.w(TAG, "SeedQR unavailable: " + e.getClass().getSimpleName());
            pages.showInfo("SeedQR unavailable", "This recovery phrase could not be shown as a SeedQR. Your written words are the backup; nothing changed.", host::hideBackup);
            return;
        }
        boolean compact = seedQrFormat == SeedQr.Format.COMPACT;
        LinearLayout root = pages.page("RECOVERY PHRASE · SEEDQR",
                compact ? "CompactSeedQR · 25 × 25" : "Standard SeedQR · 29 × 29",
                "Copy each black square onto the matching grid of your backup card: row and column numbers match. Never photograph or scan this screen.");
        seedQrView = new SeedQrView(activity, modules);
        root.addView(seedQrView, Pages.matchWrap(pages.dp(4)));
        pages.card(root, "Same secret as your 24 words", compact
                ? "SeedSigner CompactSeedQR (binary). Use the card with the 25 × 25 grid. Wallets that support SeedQR restore it; ordinary camera apps cannot read it."
                : "SeedSigner Standard SeedQR (digits). Use the card with the 29 × 29 grid. More squares to copy, and any QR reader can decode it.");
        pages.action(root, "Hide", true, host::hideBackup);
        pages.action(root, compact ? "Use Standard SeedQR (29 × 29)" : "Use CompactSeedQR (25 × 25)", false, () -> {
            seedQrFormat = compact ? SeedQr.Format.STANDARD : SeedQr.Format.COMPACT;
            showSeedQr();
        });
        pages.action(root, "Show as words", false, () -> { wipeSeedQr(); backupPage = 0; showPhrasePage(); });
        addSeedTimer(root);
        pages.present(root, "backup-seedqr");
    }

    private void wipeSeedQr() {
        if (seedQrView != null) seedQrView.wipe();
        seedQrView = null;
    }

    /** Home, verified wallet, no request in progress: a gentle periodic "check your backup". */
    void addBackupReminderCard(LinearLayout root) {
        if (!host.backupVerified() || host.transport() != null || host.approvalDecision() != null || host.requestPending()) return;
        long now = System.currentTimeMillis();
        if (!host.backupReminder().due(now)) return;
        LinearLayout box = VaultTheme.box(activity);
        box.addView(VaultTheme.bodyText(activity, "BACKUP CHECK", 13, VaultTheme.FAINT));
        TextView headline = VaultTheme.bodyText(activity, host.backupReminder().headline(now), VaultTheme.BODY_SIZE, VaultTheme.INK);
        headline.setPadding(0, pages.dp(6), 0, 0);
        box.addView(headline);
        TextView body = VaultTheme.bodyText(activity, "Pick 3 words from your written backup. Your phrase is not shown.", VaultTheme.BODY_SIZE - 2, VaultTheme.DIM);
        body.setPadding(0, pages.dp(6), 0, 0);
        box.addView(body);
        pages.action(box, "Check my backup now", false, () -> startBackupAccess(true));
        pages.action(box, "Remind me in 2 weeks", false, () -> {
            if (!host.backupReminder().snooze(System.currentTimeMillis())) host.setStatus("Reminder snooze not saved");
            host.showHome();
        });
        root.addView(box, Pages.matchWrap(pages.dp(12)));
    }

    void showBackupReminderSettings() {
        LinearLayout root = pages.page("SECURITY / BACKUP REMINDER", "Check your backup",
                "Now and then Home suggests a two-minute check: pick 3 words from your written backup. Your phrase is not shown, and the reminder never interrupts a request.");
        int last = host.backupReminder().lastCheckDay();
        pages.card(root, "Last checked", last < 0 ? "Not recorded on this phone yet"
                : LocalDate.ofEpochDay(last) + " (by this phone's clock)");
        int current = host.backupReminder().intervalDays();
        for (int days : BackupReminder.CHOICES) {
            pages.action(root, BackupReminder.label(days), days == current, () -> {
                if (host.backupReminder().setIntervalDays(days)) showBackupReminderSettings();
                else pages.showInfo("Setting not saved", "Your previous reminder setting is still active.", this::showBackupReminderSettings);
            });
        }
        pages.action(root, "Back to Security", false, host::showSecurity);
        pages.present(root, "reminder-settings");
    }

    // ------------------------------------------------------------------ seed timer

    private void startSeedTimer() {
        long now = SystemClock.elapsedRealtime();
        seedHardDeadline = now + SEED_SESSION_MS;
        seedIdleDeadline = now + SEED_TIMEOUT_MS;
        // The phrase/SeedQR has its own hide timer; don't let a short screen timeout switch the
        // screen off (and lock) while someone is copying words. Cleared in clearSensitiveUi.
        host.keepScreenOn(true);
        ui.removeCallbacks(hideSeed);
        ui.post(hideSeed);
    }

    private void tickSeedTimer() {
        if (!host.sensitiveActive() || backupWords == null || host.replacement().state() == ReplacementState.COMMITTING) return;
        long remaining = Math.min(seedHardDeadline, seedIdleDeadline) - SystemClock.elapsedRealtime();
        if (remaining <= 0) {
            boolean discarded = replacementCandidate != null;
            if (!discarded) resumeBackupPage = backupPage;
            host.hideBackup();
            String message = discarded ? "Backup timed out. Candidate discarded; keep your current wallet and discard the partial NEW backup."
                    : "Backup hidden after 2 minutes without a touch. Verify your PIN to continue from page " + (resumeBackupPage + 1) + " of 6.";
            host.setStatus(message);
            pages.showInfo("Backup hidden", message, host::showHome);
            return;
        }
        if (seedTimer != null) seedTimer.setText("Hides in " + ((remaining + 999) / 1000) + "s · any touch restarts the timer · 8 minute session limit");
        ui.postDelayed(hideSeed, 1000);
    }

    private void addSeedTimer(LinearLayout root) {
        seedTimer = VaultTheme.bodyText(activity, "", 14, VaultTheme.FAINT);
        seedTimer.setPadding(0, pages.dp(18), 0, 0);
        root.addView(seedTimer);
        ui.removeCallbacks(hideSeed);
        tickSeedTimer();
    }

    // ------------------------------------------------------------------ phrase pages + spot check

    private void showPhrasePage() {
        if (!host.sensitiveActive() || backupWords == null) return;
        LinearLayout root = pages.page(replacementCandidate == null ? "RECOVERY PHRASE" : "NEW WALLET · NOT ACTIVE",
                "Write words " + (backupPage * 4 + 1) + "–" + (backupPage * 4 + 4),
                "Page " + (backupPage + 1) + " of 6. Write each word beside its number. Never photograph or share your phrase.");
        for (int i = backupPage * 4; i < backupPage * 4 + 4; i++) {
            LinearLayout row = VaultTheme.box(activity);
            row.setOrientation(LinearLayout.HORIZONTAL);
            TextView number = VaultTheme.monoText(activity, String.format(Locale.ROOT, "%02d", i + 1), 18, VaultTheme.FAINT);
            number.setWidth(pages.dp(44));
            row.addView(number);
            row.addView(VaultTheme.monoText(activity, backupWords[i], 23, VaultTheme.INK),
                    new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
            root.addView(row, Pages.matchWrap(pages.dp(12)));
        }
        if (backupPage < 5) pages.action(root, "Next four words", true, () -> { backupPage++; showPhrasePage(); });
        else pages.action(root, "I've written them down · spot-check", true, this::startWordCheck);
        if (backupPage > 0) pages.action(root, "Previous words", false, () -> { backupPage--; showPhrasePage(); });
        if (replacementCandidate == null) pages.action(root, "Show as SeedQR", false, this::showSeedQr);
        pages.action(root, replacementCandidate == null ? "Hide phrase" : "Cancel · keep current wallet", false, host::hideBackup);
        addSeedTimer(root);
        pages.present(root, "phrase");
    }

    private void startWordCheck() {
        if (backupWords == null || !host.sensitiveActive()) return;
        if (backupChallenge != null) backupChallenge.destroy();
        backupChallenge = new BackupCheck.Challenge(backupWords, random);
        showWordCheck();
    }

    private void showWordCheck() {
        if (backupChallenge == null || !host.sensitiveActive()) return;
        int position = backupChallenge.position();
        LinearLayout root = pages.page("BACKUP CHECK · " + (backupChallenge.progress() + 1) + " OF " + backupChallenge.total(),
                "Find word " + (position + 1), "Use your written backup. Select the word beside this number.");
        List<String> choices = new ArrayList<>();
        choices.add(backupWords[position]);
        List<String> dictionary = MnemonicUtils.getWords();
        while (choices.size() < 6) {
            String next = dictionary.get(random.nextInt(dictionary.size()));
            if (!choices.contains(next)) choices.add(next);
        }
        Collections.shuffle(choices, random);
        final BackupCheck.Challenge challenge = backupChallenge;
        final int token = host.activeSensitive(), s = host.session();
        for (String choice : choices) pages.action(root, choice, false, () -> {
            if (!host.sensitiveValid(token, s) || backupChallenge != challenge) return;
            if (!challenge.answer(choice)) {
                challenge.destroy();
                LinearLayout failed = pages.page("BACKUP NEEDS ATTENTION", "That word did not match", "Check the number and spelling on your paper. Receiving stays paused until the full check is complete.");
                pages.action(failed, "Review recovery words", true, () -> { backupPage = 0; showPhrasePage(); });
                pages.action(failed, "Restart the 24-word check", false, this::startWordCheck);
                pages.action(failed, "Cancel", false, host::hideBackup);
                addSeedTimer(failed);
                pages.present(failed, "backup-error");
            } else if (challenge.complete()) showBackupChecked();
            else showWordCheck();
        });
        pages.action(root, "Cancel check", false, host::hideBackup);
        addSeedTimer(root);
        pages.present(root, "backup-check");
    }

    private void showBackupChecked() {
        if (backupChallenge == null || !backupChallenge.complete()) return;
        ui.removeCallbacks(hideSeed);
        if (backupWords != null) Arrays.fill(backupWords, null);
        backupWords = null;
        backupChallenge.destroy();
        int checked = backupChallenge == null ? BackupCheck.SPOT_CHECK : backupChallenge.total();
        backupChallenge = null;
        String address = replacementCandidate == null ? backupIdentity : replacementCandidate.address;
        LinearLayout root = pages.page(checked + " OF " + checked + " WORDS CHECKED",
                replacementCandidate == null ? "Your backup matches" : "Ready to replace?",
                replacementCandidate == null ? "Confirm the account below. This check does not replace an independent restore drill."
                        : "Your current wallet will be replaced. Keep its backup if it controls any assets. The new wallet is not active until you confirm.");
        pages.card(root, replacementCandidate == null ? "Account 1" : "New Account 1",
                Keys.toChecksumAddress(address));
        pages.card(root, "Derivation", "m/44'/60'/0'/0/0 · no passphrase");
        pages.action(root, replacementCandidate == null ? "Confirm account & finish" : "Activate new wallet", true,
                replacementCandidate == null ? this::saveBackupCheck
                        : () -> host.withSeedKey("Confirm your PIN to activate the new wallet", this::activateReplacement));
        pages.action(root, "Cancel", false, host::hideBackup);
        pages.present(root, "backup-confirm");
    }

    private void saveBackupCheck() {
        final int token = host.activeSensitive(), s = host.session();
        final String address = backupIdentity;
        pages.showLoading("Saving backup check", "Confirming this account's recovery status…");
        cryptoExecutor.execute(() -> {
            try {
                synchronized (stateLock) {
                    if (!host.sensitiveValid(token, s) || !host.hasCredentials() || address == null || !address.equalsIgnoreCase(host.walletId())) return;
                    host.backupCheck().record(address);
                    host.markBackupVerified();
                }
                activity.runOnUiThread(() -> {
                    if (!host.sensitiveValid(token, s)) return;
                    host.setStatus("Backup checked · ready to receive");
                    host.hideBackup();
                });
            } catch (Exception e) {
                activity.runOnUiThread(() -> {
                    if (host.sensitiveValid(token, s))
                        pages.showInfo("Backup status not saved", "Your wallet is unchanged. Please repeat the check before receiving or signing.", host::hideBackup);
                });
            }
        });
    }

    // ------------------------------------------------------------------ replace with a new wallet

    void confirmReplace() {
        if (!host.backupVerified()) {
            pages.showInfo("Check your existing backup first", "Replacing a wallet requires a verified backup of the current account.", host::showHome);
            return;
        }
        host.beginSensitive("replace your wallet", () -> {
            final int token = host.activeSensitive(), s = host.session();
            LinearLayout root = pages.page("SECURITY / REPLACE WALLET", "Keep your current backup", "Replacement creates a different account. Assets on the old account remain controlled by its original phrase.");
            pages.card(root, "Nothing changes yet", "You will write down all 24 new words and pass a spot-check before a separate Activate step. Cancellation keeps your current wallet.");
            pages.action(root, "Prepare a new wallet", true, () -> {
                if (!host.sensitiveValid(token, s)) return;
                int op = host.replacement().begin();
                if (op < 0) return;
                replacementOperation = op;
                pages.showLoading("Preparing a new wallet", "Your current wallet remains active until the final confirmation.");
                cryptoExecutor.execute(() -> {
                    try {
                        if (!host.sensitiveValid(token, s)) return;
                        SeedVault.Generation candidate = host.vault().prepareReplacement(new byte[0]);
                        host.recordEntropyReport(false);
                        activity.runOnUiThread(() -> {
                            if (!host.sensitiveValid(token, s) || !host.replacement().markPrepared(op)) return;
                            replacementCandidate = candidate;
                            backupWords = candidate.mnemonic.split(" ");
                            backupPage = 0;
                            startSeedTimer();
                            showPhrasePage();
                        });
                    } catch (Exception e) {
                        host.replacement().end(op);
                        activity.runOnUiThread(() -> {
                            if (host.sensitiveValid(token, s))
                                pages.showInfo("Could not prepare a wallet", "Your current wallet is unchanged. Lock and retry.", host::hideBackup);
                        });
                    }
                });
            });
            pages.action(root, "Cancel · keep current wallet", false, host::hideBackup);
            pages.present(root, "replace-confirm");
        });
    }

    private void activateReplacement() {
        final int token = host.activeSensitive(), s = host.session(), op = replacementOperation;
        final SeedVault.Generation candidate = replacementCandidate;
        if (candidate == null || !host.sensitiveValid(token, s) || !host.replacement().beginCommit(op)) return;
        ui.removeCallbacks(hideSeed);
        host.clearReceivingIdentity();
        pages.showLoading("Activating your new wallet", "Saving and checking the new identity. This step can no longer be cancelled.");
        cryptoExecutor.execute(() -> {
            try {
                synchronized (stateLock) {
                    if (!host.sensitiveValid(token, s) || !host.replacement().owns(op) || host.transport() != null || host.requestPending()) return;
                    host.clearCredentials();
                    Credentials fresh = host.vault().commitReplacement(candidate.mnemonic);
                    host.backupCheck().record(fresh.getAddress());
                    host.publishNewWallet(fresh, null, true);
                    host.replacement().end(op);
                }
                Bitmap qr = host.qrFor(candidate.address);
                activity.runOnUiThread(() -> {
                    if (!host.sensitiveValid(token, s)) return;
                    host.setWalletQr(qr);
                    host.setStatus("New wallet active · backup checked");
                    host.hideBackup();
                });
            } catch (Exception e) {
                synchronized (stateLock) { host.clearCredentials(); host.clearReceivingIdentity(); host.replacement().end(op); }
                activity.runOnUiThread(() -> {
                    if (s != host.session()) return;
                    host.setGateNotice("Storage could not confirm the wallet. Re-enter your PIN to reconcile it. No receiving address is available until loading succeeds.");
                    host.lock();
                });
            }
        });
    }
}
