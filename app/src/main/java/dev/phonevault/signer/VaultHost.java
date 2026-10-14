package dev.phonevault.signer;

import android.app.Activity;
import android.graphics.Bitmap;

import org.web3j.crypto.Credentials;

import java.util.concurrent.ExecutorService;

/**
 * What the flow screens (SetupScreens, BackupScreens, BtcScreens, ApprovalScreens,
 * SettingsScreens) borrow from MainActivity, which implements it once. The screens keep
 * MainActivity's rules: a background task captures {@link #session()} when it starts and
 * re-checks it, under {@link #stateLock()}, right before it publishes anything; every wallet
 * publish below is made by the caller while holding {@link #stateLock()}, at the same point as
 * before the split. Getters read MainActivity's volatile fields; call them from any thread.
 */
interface VaultHost {
    Activity activity();
    Pages pages();
    /** MainActivity's state lock: session check + publish (and signing + send) as one step. */
    Object stateLock();
    /** The single crypto thread (signing, key loads, wallet storage). */
    ExecutorService cryptoExecutor();
    /** The unlock session token; lock() increments it. */
    int session();
    boolean unlocked();
    boolean operational();
    VaultKeyStore vault();

    // ---------------------------------------------------------------- PIN window (UI thread)
    void withSeedKey(String why, Runnable op);
    void withSeedKey(String why, Runnable op, Runnable onCancel);
    void confirmDevicePin(String why, Runnable onOk, Runnable onCancel);
    /** The keystore reported the PIN window lapsed: our own confirmation no longer counts. */
    void forgetConfirmation();

    // ---------------------------------------------------------------- navigation (UI thread)
    void showHome();
    void showSecurity();
    void lock();
    /** Leave any phrase / sensitive screen (the single terminal path) and go home. */
    void hideBackup();
    /** PIN, then the recovery phrase pages (BackupScreens). */
    void confirmRevealBackup();
    /** Replay a USB attach that waited behind setup or a sensitive flow. */
    void drainPendingUsb();
    /** The status line on Home (shown the next time Home is drawn). */
    void setStatus(String message);
    /** As {@link #setStatus}, and updates the status line on screen now. */
    void showStatus(String message);
    /** A notice the next PIN gate shows. */
    void setGateNotice(String notice);
    /** Window flags: always posted to the UI thread. Any thread. */
    void keepScreenOn(boolean on);

    // ---------------------------------------------------------------- sensitive flows (UI thread)
    /** Verify the PIN (fresh), then run {@code afterPin} inside a new sensitive flow. */
    void beginSensitive(String purpose, Runnable afterPin);
    /** The sensitive flow {@code token} of session {@code s} still owns the screen. */
    boolean sensitiveValid(int token, int s);
    /** The token of the sensitive flow begun last (-1 when none). */
    int activeSensitive();
    boolean sensitiveActive();
    ReplacementState replacement();

    // ---------------------------------------------------------------- wallet state
    boolean walletLoaded();
    boolean backupVerified();
    /** Account-0 address (lowercase) of the standard wallet, or null. */
    String walletId();
    /** Address of the active account, or null. */
    String walletAddress();
    /** A signing key is in memory. */
    boolean hasCredentials();
    AccessoryTransport transport();
    boolean requestPending();
    ApprovalDecision approvalDecision();
    BackupCheck backupCheck();
    BackupReminder backupReminder();
    /** The receive-address QR for {@code address}. */
    Bitmap qrFor(String address);
    /** Which entropy sources fed the seed just generated (Device information). */
    void recordEntropyReport(boolean dice);

    // ---------------------------------------------------------------- wallet publish (caller holds stateLock)
    /**
     * A wallet was created, restored or replaced: {@code key} (its account 1) becomes the signing
     * key, the account list starts over, and the wallet is loaded with the given backup status.
     * {@code qr} may be null (set later with {@link #setWalletQr}).
     */
    void publishNewWallet(Credentials key, Bitmap qr, boolean backupVerified);
    /** Drop the signing key from memory. */
    void clearCredentials();
    /** Forget the receiving identity (address, QR, account, Bitcoin accounts, loaded/verified). */
    void clearReceivingIdentity();
    /** The wallet is not loaded (a restore failed to save). */
    void markWalletUnloaded();
    void setWalletQr(Bitmap qr);
    /** The backup of the loaded wallet passed the spot check. */
    void markBackupVerified();
}
