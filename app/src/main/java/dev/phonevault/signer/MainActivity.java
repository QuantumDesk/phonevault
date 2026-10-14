package dev.phonevault.signer;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.ColorStateList;
import android.database.ContentObserver;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.hardware.usb.UsbAccessory;
import android.hardware.usb.UsbManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.security.KeyStoreException;
import android.security.keystore.UserNotAuthenticatedException;
import android.text.Layout;
import android.util.Log;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONObject;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.MnemonicUtils;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

public final class MainActivity extends Activity implements AccessoryTransport.Listener {
    private static final String TAG = "Vault";
    private final ExecutorService cryptoExecutor = Executors.newSingleThreadExecutor();
    private final AtomicBoolean requestPending = new AtomicBoolean(false);
    /**
     * Device attestation (USB "attest", AttestationKey) runs on its own thread so a StrongBox key
     * generation (seconds on the Titan M) never delays signing work on cryptoExecutor; one at a time.
     */
    private final ExecutorService attestExecutor = Executors.newSingleThreadExecutor();
    private final AtomicBoolean attesting = new AtomicBoolean(false);
    private final AttestationProtocol.ChallengeLog attestChallenges = new AttestationProtocol.ChallengeLog();
    /**
     * Guards the session-token check + credential publish (and the wallet commit, and signing +
     * send) as one step, so {@link #lock()} on the UI thread can never interleave with a
     * background task between "is my session still current?" and "publish".
     */
    private final Object stateLock = new Object();
    /** Wallet-replacement state machine (see {@link ReplacementState}); transitions under stateLock. */
    private final ReplacementState replacement = new ReplacementState(stateLock);
    private VaultKeyStore vault;
    private volatile Credentials credentials;
    private volatile AccessoryTransport transport;
    private volatile boolean operational;
    private TextView addressView;
    private ImageView qrView;
    private TextView statusView;
    private final SensitiveFlow sensitive = new SensitiveFlow(stateLock);
    /** The live state behind every "does this request still own its slot" re-check (RequestOwnership). */
    private final RequestOwnership.Live live = new RequestOwnership.Live() {
        @Override public AccessoryTransport transport() { return transport; }
        @Override public int session() { return session.get(); }
        @Override public boolean unlocked() { return unlocked; }
        @Override public ApprovalDecision approvalDecision() { return approvalDecision; }
        @Override public boolean sensitiveFlowActive() { return sensitive.active(); }
        @Override public boolean walletLoaded() { return walletLoaded; }
        @Override public boolean backupVerified() { return backupVerified; }
        @Override public boolean operational() { return operational; }
        @Override public boolean debuggingRefused() { return adbRefused(); } // release: never while debugging is on
    };
    private TokenList tokenList;
    /** Address book + recipient history for the reviews (AddressSafety); opened on first use. */
    private AddressSafety addressSafety;
    private SafetyScreens safetyScreens;
    /** Counterparties of the transaction just signed, offered as "Save as contact" on its receipt. */
    private List<TransactionReview.Party> receiptParties;
    private volatile ApprovalDecision approvalDecision;
    // ------------------------------------------------------------------ Bitcoin state
    // See BtcRequest, BtcWallet, BtcPsbtReview, BtcPsbtSigner.
    /**
     * Per network (BtcNetwork ordinal): the STANDARD wallet's Bitcoin account public keys, derived
     * from the seed inside the seed-key window on first use and kept for this unlocked session only
     * (cleared on lock and on any wallet change; never written to disk). Guarded by stateLock.
     */
    private final BtcWallet[] btcWallets = new BtcWallet[BtcNetwork.values().length];
    /** walletId the cached Bitcoin accounts were derived for. */
    private String btcWalletOwner;
    /** Amounts already signed per coin (SegWit fee-attack guard); memory only. */
    private final BtcAmountMemory btcAmounts = new BtcAmountMemory();
    private static final String BTC_PREFS = "bitcoin", BTC_SHARING_KEY = "shared_v1";
    // ------------------------------------------------------------------ accounts + passphrase wallet state
    // See AccountBook, AccountScreens. Published together with credentials.
    /** Non-secret description of the key in {@link #credentials}; set and cleared with it under stateLock. */
    private volatile SigningAccount activeAccount;
    /** Lowercase account-0 address of the STANDARD wallet: identity of the backup check and the saved account list. */
    private volatile String walletId;
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
    /** A passphrase is being typed or confirmed: USB requests wait and the ☰ menu hides. */
    private volatile boolean passphraseEntry;
    private AccountScreens accountScreens;
    private static final String ACCOUNT_PREFS = "accounts", ACCOUNT_BOOK_KEY = "account_book_v1";
    private volatile boolean walletLoaded, backupVerified;
    private volatile String walletAddress;
    private volatile Bitmap walletQr;
    private BackupCheck backupCheck;
    private BackupReminder backupReminder;
    private boolean largeText;
    private long idleTimeoutMs = IDLE_LOCK_MS;
    /** Display & auto-lock preferences (text scale, screen timeout, idle lock, haptics). */
    private DisplaySettings display;
    /** Last battery reading and the header indicator of the page on screen (see onBattery). */
    private BatteryStatus battery = BatteryStatus.UNKNOWN;
    private View batteryIndicator;
    private boolean batteryRegistered;
    private final BroadcastReceiver batteryReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) { onBattery(readBattery(intent)); }
    };
    private String screenName = "loading";
    private String statusMessage = "USB disconnected · connect a host when ready";
    private int activeSensitive = -1, backupPage, replacementOperation;
    private Runnable afterReauth;
    private String[] backupWords;
    private String backupIdentity;
    private BackupCheck.Challenge backupChallenge;
    private SeedVault.Generation replacementCandidate;
    private final SecureRandom random = new SecureRandom();
    private long seedIdleDeadline, seedHardDeadline;
    private TextView seedTimer;
    private char[][] pinSetupEntries;

    // ------------------------------------------------------------------ device security & lifecycle
    /** Idle time (no touch) before the vault locks and drops the key from memory. */
    private static final long IDLE_LOCK_MS = 2 * 60 * 1000L;
    /** Idle time before the phrase hides. Copying 24 words onto paper means not touching the phone;
     *  every touch or page turn restarts it. */
    private static final long SEED_TIMEOUT_MS = 120 * 1000L;
    /** Absolute cap on one reveal session, regardless of touches. */
    private static final long SEED_SESSION_MS = 8 * 60 * 1000L;
    /** Page to reopen at after an idle hide, so the user does not start over at word 1. */
    private int resumeBackupPage;
    /** True from the moment a PIN is SET in this unlocked session until it is used once or the
     *  vault locks: the first-run wizard does not ask for the PIN again seconds after setting it. */
    private boolean firstRunPinFresh;
    /** elapsedRealtime of the last successful device-PIN check (credential mode). */
    private long lastCredentialConfirm;
    /** True while a system PIN prompt is on screen, so a re-created gate does not stack another. */
    private boolean credentialPromptOpen;
    /**
     * Right after a boot the user has just entered the PIN on Android's lock screen (to unlock
     * encrypted storage), which also opens the seed key's window. The FIRST credential gate after
     * a boot therefore tries the key before prompting — once per BOOT, persisted against the boot
     * id (BootUnlockGuard), so re-creating the activity cannot re-arm it, and never once the vault
     * has locked since that boot. Any later gate always prompts.
     */
    private BootUnlockGuard bootUnlock;
    /** Session whose boot-time silent unlock attempt is still pending (-1: none). */
    private int bootAttemptSession = -1;
    private boolean silentUnlockAttempt;
    /** OLED burn-in: nudge the whole UI by a pixel or two on this cadence. */
    private static final long PIXEL_SHIFT_MS = 45 * 1000L;
    /** System screen-off timeout applied as device owner (burn-in + walk-away safety). */
    private static final int SCREEN_OFF_TIMEOUT_MS = 60 * 1000;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final Runnable idleLock = this::lock;
    private final Runnable hideSeed = this::tickSeedTimer;
    /** Set when a lock closed a live USB session: the host must unplug and reconnect to resume. */
    private boolean usbReplugHint;
    private final Runnable pixelShift = this::shiftPixels;
    private VaultPin pin;
    private PinScreen pinScreen;
    private volatile boolean unlocked;
    /**
     * Unlock session token. Incremented by {@link #lock()}; every background crypto task captures
     * it at start and refuses to publish credentials/UI if it changed — a lock can never be undone
     * by a load or regeneration that finishes late.
     */
    private final AtomicInteger session =
            new AtomicInteger();
    /** True between onStart and onStop. Nothing unlocks or publishes while the activity is hidden. */
    private volatile boolean foreground;
    private Intent pendingUsb;
    /**
     * A request that arrived while the vault was LOCKED. The gate reads and decodes it for display
     * only — the phone answers nothing until the PIN is entered — and hands it to the normal request
     * path right after unlock. Cleared by lock().
     */
    private JSONObject heldRequest;
    private String heldSummary;
    /** The connection {@link #heldRequest} arrived on; it is dispatched only to that same, live one. */
    private AccessoryTransport heldSource;
    private String gateNotice;
    private int shiftPhase;
    /** Release builds: watches Settings.Global.ADB_ENABLED and adb_wifi_enabled (see adbRefused). */
    private ContentObserver adbObserver;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        secure(getWindow());
        getWindow().setStatusBarColor(Color.rgb(17, 19, 24));
        getWindow().setBackgroundDrawable(new ColorDrawable(VaultTheme.BG));
        buildUi();
        activateIfPolicyReady();
        ui.postDelayed(pixelShift, PIXEL_SHIFT_MS);
        // Release: USB debugging switched on while the vault is open stops it at once (adbRefused).
        if (!devBuild()) {
            adbObserver = new ContentObserver(ui) {
                @Override public void onChange(boolean selfChange) { activateIfPolicyReady(); }
            };
            getContentResolver().registerContentObserver(Settings.Global.getUriFor(Settings.Global.ADB_ENABLED), false, adbObserver);
            getContentResolver().registerContentObserver(Settings.Global.getUriFor(ADB_WIFI_ENABLED), false, adbObserver);
        }
    }

    @Override protected void onStart() {
        super.onStart();
        foreground = true;
    }

    @Override protected void onResume() {
        super.onResume();
        activateIfPolicyReady();
        // Any PIN entry that was in flight when we were stopped belongs to a dead session: show a
        // fresh gate (its callbacks carry the old token and are ignored).
        if (operational && !unlocked) showPinGate(null);
        // Battery header: the sticky ACTION_BATTERY_CHANGED (protected, system-only; no
        // permission) is delivered at once, then every change while we are in front.
        if (!batteryRegistered) {
            batteryRegistered = true;
            Intent sticky = registerReceiver(batteryReceiver, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
            if (sticky != null) onBattery(readBattery(sticky));
        }
        devDumpUi();
    }

    @Override protected void onPause() {
        if (batteryRegistered) {
            batteryRegistered = false;
            try { unregisterReceiver(batteryReceiver); } catch (IllegalArgumentException ignored) { }
        }
        super.onPause();
    }

    private static BatteryStatus readBattery(Intent intent) {
        if (intent == null) return BatteryStatus.UNKNOWN;
        return BatteryStatus.of(intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1),
                intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1),
                intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1),
                intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0));
    }

    /** UI thread (receiver). Updates the header in place; Home re-renders only when "low" flips. */
    private void onBattery(BatteryStatus next) {
        boolean lowChanged = next.low() != battery.low();
        battery = next;
        if (batteryIndicator != null) VaultTheme.showBattery(batteryIndicator, next);
        if (pinScreen != null) pinScreen.setBattery(next);
        if (lowChanged && unlocked && "wallet".equals(screenName)) showHome();
    }

    /**
     * Screen off / activity hidden ⇒ lock. Walk-away safety and the USB session ends with it. The
     * session is invalidated even while locked, so a PIN save/verify that completes while we are
     * stopped cannot unlock a hidden activity.
     */
    @Override protected void onStop() {
        foreground = false;
        lock();
        super.onStop();
    }

    @Override public void onUserInteraction() {
        super.onUserInteraction();
        if (unlocked) armIdleLock();
        if (sensitive.active() && backupWords != null)
            seedIdleDeadline = SystemClock.elapsedRealtime() + SEED_TIMEOUT_MS;
        devDumpUi(); // dev-only: every touch refreshes the UI dump (no-op in release)
    }

    /**
     * Dev builds only: {@link DevTools} in src/debug (shared by the appliance build type) renders
     * the screen to files/vault_dump.png for UI review. The release source set compiles a no-op,
     * so a release APK contains no screenshot code at all.
     */
    boolean isSensitiveScreen() { return sensitive.active() || (passphraseEntry && accountScreens != null && accountScreens.revealing()); }

    private void devDumpUi() { DevTools.dumpUi(this); }

    @Override public void onBackPressed() {
        if (!unlocked) { lock(); return; }
        if (approvalDecision != null) return; // use the explicit Reject action
        if (sensitive.active()) { hideBackup(); return; }
        if (passphraseEntry) { endPassphraseEntry(); showHome(); return; }
        if ("wallet".equals(screenName)) lock();
        else showHome();
    }

    private void activateIfPolicyReady() {
        DevicePolicyManager policy = (DevicePolicyManager) getSystemService(
                Context.DEVICE_POLICY_SERVICE);
        boolean managed = policy.isDeviceOwnerApp(getPackageName());
        if (isPhoneVaultApplianceBuild() && !managed) {
            deactivate("FATAL POLICY ERROR: Phone Vault is not device owner");
            return;
        }
        if (managed && !enterVaultMode(policy)) {
            deactivate("FATAL POLICY ERROR: lock-task policy could not be enforced");
            return;
        }
        if (adbRefused()) {
            if (operational || !"adb-refused".equals(screenName)) refuseWhileAdbOn();
            return;
        }
        if (!operational) {
            vault = new VaultKeyStore(this);
            pin = new VaultPin(this);
            bootUnlock = new BootUnlockGuard(getSharedPreferences("vault", MODE_PRIVATE));
            // Credential mode keeps only a marker, never the app PIN hash. Also migrates phones
            // that entered credential mode before the marker existed (hash still stored).
            pin.reconcile(SystemCredential.isSet(this));
            backupCheck = new BackupCheck(getSharedPreferences("vault", MODE_PRIVATE));
            backupReminder = new BackupReminder(getSharedPreferences("vault", MODE_PRIVATE));
            operational = true;
            if (managed) applyIdlePolicy(policy);
            // The key is only loaded (and USB only answered) once the PIN gate has been passed.
            showPinGate(getIntent());
        }
    }

    // ------------------------------------------------------------------ PIN gate

    /** Show the PIN screen: SET (first run / after wipe) or UNLOCK. Any USB attach waits behind it. */
    private void showPinGate(Intent maybeUsb) {
        if (maybeUsb != null && UsbManager.ACTION_USB_ACCESSORY_ATTACHED.equals(maybeUsb.getAction())) {
            pendingUsb = maybeUsb;
        }
        final boolean creating = !pin.isSet();
        final boolean sealed = pin.eraseOutstanding();
        clearPinEntry();
        if (!creating && !sealed && credentialMode()) {
            if (gateNotice != null) { statusMessage = gateNotice; gateNotice = null; }
            showCredentialGate(session.get());
            return;
        }
        final char[][] firstEntry = {null};
        pinSetupEntries = firstEntry;
        String title = creating ? "SET PIN" : sealed ? "SEALED" : "LOCKED";
        String subtitle;
        if (creating) {
            subtitle = SystemCredential.willBind(this)
                    ? "Choose a " + VaultPin.PIN_LENGTH + "-digit PIN. The phone's security chip checks it. "
                            + SystemCredential.MAX_FAILED_FOR_WIPE + " wrong tries reset the whole phone."
                    : "Choose a " + VaultPin.PIN_LENGTH + "-digit PIN. It unlocks this vault. "
                            + VaultPin.MAX_ATTEMPTS + " wrong attempts erase the wallet.";
        } else if (sealed) {
            subtitle = "Attempt limit reached but the wallet could not be verifiably erased. "
                    + "The vault stays sealed. Enter any PIN to retry the erase.";
        } else {
            subtitle = "Enter your six-digit PIN." + (pendingUsb != null ? " USB host is waiting." : "");
        }
        if (gateNotice != null) { subtitle = gateNotice + "\n\n" + subtitle; gateNotice = null; }
        final int s = session.get(); // PIN operations are bound to this gate's session
        pinScreen = new PinScreen(this, title, subtitle, entered -> {
            if (creating) onCreatePinEntry(entered, firstEntry, s);
            else onUnlockEntry(entered, s);
        });
        // A request that arrived while locked (or a connected host) is shown on the gate too.
        synchronized (stateLock) { if (heldSummary != null) pinScreen.setPending("INCOMING REQUEST", heldSummary); }
        if (transport != null && !creating && !sealed) pinScreen.setSubtitle("Enter your six-digit PIN. A USB host is connected; its request will appear here.");
        updatePinPolicy(pinScreen);
        screenName = "pin";
        setContentView(pinScreen.view());
        devDumpUi();
    }

    // ------------------------------------------------------------------ device-PIN (credential) mode

    /**
     * The vault PIN is the Android lock credential; the seed key needs a fresh system check. Decided
     * by VaultPin's persisted credential-mode marker (set once SystemCredential.install succeeded).
     */
    private boolean credentialMode() { return pin != null && pin.credentialHeld(); }

    /** Settings.Global.BOOT_COUNT: identifies this boot for BootUnlockGuard (-1 when unknown). */
    private int bootId() {
        return Settings.Global.getInt(getContentResolver(), Settings.Global.BOOT_COUNT, -1);
    }

    /**
     * Run {@code op} with the seed key usable: in credential mode ask the system to verify the PIN
     * unless that happened moments ago (inside the key's window, with margin). Old mode: run now.
     */
    private void withSeedKey(String why, Runnable op) { withSeedKey(why, op, null); }

    /** As {@link #withSeedKey(String, Runnable)}; {@code onCancel} (may be null) runs if the PIN prompt is dismissed. */
    private void withSeedKey(String why, Runnable op, Runnable onCancel) {
        if (!credentialMode()) { op.run(); return; }
        SeedKeyWindow.Decision decision = SeedKeyWindow.decide(lastCredentialConfirm, SystemClock.elapsedRealtime());
        if (decision == SeedKeyWindow.Decision.RUN) { op.run(); return; }
        // Our own confirmation is near or past the window's end: probing now could pass keystore2
        // and still fail on the chip a moment later (SeedKeyWindow), so ask.
        if (decision == SeedKeyWindow.Decision.ASK) { confirmDevicePin(why, op, onCancel); return; }
        // Ask the chip before asking the person: right after a PIN was set or entered on Android's
        // own screen the key may already be usable, and a second prompt would be pure friction.
        final int s = session.get();
        cryptoExecutor.execute(() -> {
            boolean ready = vault.seedKeyUsableNow();
            runOnUiThread(() -> {
                if (s != session.get()) return;
                if (ready) { op.run(); return; }
                confirmDevicePin(why, op, onCancel);
            });
        });
    }

    private void confirmDevicePin(String why, Runnable onOk, Runnable onCancel) {
        if (credentialPromptOpen) return;
        credentialPromptOpen = true;
        final int s = session.get();
        SystemCredential.confirm(this, "Phone Vault", why, (ok, message) -> {
            credentialPromptOpen = false;
            if (s != session.get() && unlocked) return;
            if (ok) {
                lastCredentialConfirm = SystemClock.elapsedRealtime();
                onOk.run();
            } else if (onCancel != null) {
                onCancel.run();
            }
        });
    }

    /** Keystore refused because the PIN window lapsed (the op took longer than the window). */
    private static boolean authLapsed(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof UserNotAuthenticatedException) return true;
            // Keystore2 may report the same refusal as a KeyStoreException instead.
            if (c instanceof KeyStoreException
                    && ((KeyStoreException) c).getNumericErrorCode()
                            == KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED) return true;
            String m = c.getMessage();
            if (m != null && (m.contains("not authenticated") || m.contains("KEY_USER_NOT_AUTHENTICATED"))) return true;
        }
        return false;
    }

    /** Class names and messages of an exception chain for the log (no key material is ever in them). */
    private static String chain(Throwable t) {
        StringBuilder b = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) b.append(c.getClass().getName()).append(": ").append(c.getMessage()).append(" <- ");
        return b.toString();
    }

    /** Locked gate in credential mode: our screen, the system verifies the PIN. */
    private void showCredentialGate(int s) {
        // The boot attempt below is still waiting for this session: onCreate and onResume both
        // show the gate on a cold start, and a second call would replace the attempt's loading
        // screen with the locked page AND queue the system prompt while the boot lock screen is
        // still animating away (the PIN would be asked a second time). The
        // attempt shows the gate itself if the keystore refuses; a new session (lock) passes.
        if (bootAttemptSession == s) return;
        boolean freshBoot = SystemClock.elapsedRealtime() < 10 * 60 * 1000L;
        if (freshBoot && bootUnlock.tryConsume(bootId())) {
            // The boot lock screen may still be animating away: give it up to 4 s to report the
            // device unlocked, then try the key; if the keystore refuses we come back and prompt.
            // tryConsume committed "used for this boot" before we got here.
            bootAttemptSession = s;
            KeyguardManager keyguard = getSystemService(KeyguardManager.class);
            final long deadline = SystemClock.elapsedRealtime() + 4000;
            Runnable attempt = new Runnable() {
                @Override public void run() {
                    if (s != session.get() || unlocked) { bootAttemptSession = -1; return; }
                    if (keyguard != null && keyguard.isDeviceLocked() && SystemClock.elapsedRealtime() < deadline) {
                        ui.postDelayed(this, 250);
                        return;
                    }
                    bootAttemptSession = -1;
                    silentUnlockAttempt = true;
                    unlock(s);
                    if (!unlocked) { silentUnlockAttempt = false; showCredentialGate(session.get()); }
                }
            };
            showLoading("Opening your wallet", "Using the PIN you just entered…");
            ui.post(attempt);
            return;
        }
        LinearLayout root = page("LOCKED", "Phone Vault is locked",
                "Your PIN is checked by the phone's security chip. Tap Unlock and enter it on the next screen.");
        synchronized (stateLock) { if (heldSummary != null) card(root, "Incoming request", heldSummary); }
        if (transport != null) card(root, "USB", "A host is connected. Its request stays unanswered until you unlock and review it.");
        TextView unlockButton = VaultTheme.pixelButton(this, "Unlock", true);
        hardenTouch(unlockButton);
        unlockButton.setOnClickListener(v -> promptUnlock(s));
        root.addView(unlockButton, matchWrap(dp(22)));
        TextView policy = VaultTheme.bodyText(this, SystemCredential.MAX_FAILED_FOR_WIPE
                + " wrong PINs in a row erase this phone completely.", 14, VaultTheme.FAINT);
        policy.setPadding(0, dp(18), 0, 0);
        root.addView(policy);
        screenName = "pin";
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(VaultTheme.BG);
        scroll.addView(root);
        setContentView(scroll);
        devDumpUi();
        ui.post(() -> { if (!unlocked && s == session.get() && foreground) promptUnlock(s); });
    }

    private void promptUnlock(int s) {
        confirmDevicePin("Enter your PIN to unlock", () -> {
            if (s == session.get() && !unlocked) unlock(s);
        }, null);
    }

    private void clearPinEntry() {
        if (pinScreen != null) pinScreen.dispose();
        pinScreen = null;
        if (pinSetupEntries != null && pinSetupEntries[0] != null) Arrays.fill(pinSetupEntries[0], '0');
        pinSetupEntries = null;
    }

    private void onCreatePinEntry(char[] entered, char[][] firstEntry, int s) {
        if (s != session.get()) { Arrays.fill(entered, '0'); return; }
        if (firstEntry[0] == null) {
            firstEntry[0] = entered.clone();
            Arrays.fill(entered, '0');
            pinScreen.setTitle("CONFIRM PIN");
            pinScreen.setSubtitle("Enter the same PIN again.");
            pinScreen.reset();
            return;
        }
        boolean match = Arrays.equals(firstEntry[0], entered);
        Arrays.fill(entered, '0');
        if (!match) {
            Arrays.fill(firstEntry[0], '0');
            firstEntry[0] = null;
            pinScreen.setTitle("SET PIN");
            pinScreen.setSubtitle("Choose a " + VaultPin.PIN_LENGTH + "-digit PIN.");
            pinScreen.showError("PINs did not match · start over");
            return;
        }
        final char[] chosen = firstEntry[0];
        firstEntry[0] = null;
        final char[] forSystem = chosen.clone();
        pinScreen.setSubtitle("Saving…");
        cryptoExecutor.execute(() -> {
            try {
                // Chip first: once it holds the PIN the app stores only the credential-mode
                // marker, never a PBKDF2 hash an offline guesser could search. The app hash is
                // the no-chip fallback only. (A crash after install but before the marker is
                // repaired at startup: VaultPin.reconcile sees the device credential.)
                boolean bound = SystemCredential.install(this, forSystem); // zeroes forSystem
                if (bound) {
                    Arrays.fill(chosen, '0');
                    pin.markCredentialHeld();
                } else {
                    pin.set(chosen); // zeroes the array
                }
                runOnUiThread(() -> {
                    if (!bound) { firstRunPinFresh = true; unlock(s); return; }
                    // The chip now holds the PIN; the next step (creating the wallet) needs it once.
                    unlock(s);
                });
            } catch (Exception e) {
                Arrays.fill(forSystem, '0');
                runOnUiThread(() -> {
                    if (s != session.get() || pinScreen == null) return;
                    pinScreen.setTitle("SET PIN");
                    pinScreen.showError("could not save pin: " + e.getMessage());
                });
            }
        });
    }

    private void onUnlockEntry(char[] entered, int s) {
        if (s != session.get()) { Arrays.fill(entered, '0'); return; }
        pinScreen.setSubtitle("Checking…");
        final char[] forSystem = SystemCredential.supported() ? entered.clone() : new char[0];
        cryptoExecutor.execute(() -> {
            try {
                VaultPin.Result result = pin.verify(entered, this::wipeWalletForFailedPin);
                if (result.outcome == VaultPin.Outcome.OK && forSystem.length > 0 && !credentialMode()) {
                    // One-time upgrade: the verified PIN becomes the device credential.
                    boolean bound = SystemCredential.install(this, forSystem);
                    if (bound) {
                        pin.markCredentialHeld(); // the app hash goes: the chip is the verifier now
                        runOnUiThread(() -> {
                            if (s != session.get() || pinScreen == null) return;
                            pinScreen.setSubtitle("Your PIN is now held by the security chip. Confirm it once more on the next screen.");
                            confirmDevicePin("Confirm your PIN to finish securing the vault", () -> {
                                if (s == session.get() && !unlocked) unlock(s);
                            }, () -> { if (s == session.get()) showPinGate(null); });
                        });
                        return;
                    }
                }
                Arrays.fill(forSystem, '0');
                runOnUiThread(() -> {
                    if (s != session.get() || pinScreen == null) {
                        // Stopped/locked while checking: the gate was re-created with a new token.
                        Log.i(TAG, "pin result discarded: stale session");
                        return;
                    }
                    switch (result.outcome) {
                        case OK:
                            unlock(s);
                            break;
                        case WRONG:
                            pinScreen.setSubtitle("Enter your six-digit PIN.");
                            pinScreen.showError("wrong pin · " + result.attemptsRemaining
                                    + (result.attemptsRemaining == 1 ? " attempt left" : " attempts left"));
                            updatePinPolicy(pinScreen);
                            break;
                        case WIPED:
                            gateNotice = "VAULT ERASED: too many wrong attempts. The wallet and PIN were destroyed. Set a new PIN to create a new wallet.";
                            showPinGate(null);
                            break;
                        case ERASE_FAILED:
                        default:
                            // Fail closed: PIN kept, no key load possible, only the erase retries.
                            showPinGate(null);
                            pinScreen.showError("erase failed · vault sealed");
                            break;
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (s != session.get() || pinScreen == null) return;
                    pinScreen.showError("pin error: " + e.getMessage());
                });
            }
        });
    }

    /**
     * Attempt-limit reached: destroy seed + StrongBox alias. Runs on the crypto executor. Throws
     * if the erase cannot be verified, which VaultPin turns into ERASE_FAILED (PIN kept).
     */
    private void wipeWalletForFailedPin() throws Exception {
        credentials = null;
        activeAccount = null;
        getSharedPreferences(ACCOUNT_PREFS, MODE_PRIVATE).edit().remove(ACCOUNT_BOOK_KEY).commit();
        vault.secureErase();
        backupCheck.clear();
        Log.w(TAG, "wallet erased after " + VaultPin.MAX_ATTEMPTS + " failed PIN attempts");
    }

    /** Only the gate that verified the PIN (token {@code s}) may unlock, and only while visible. */
    private void unlock(int s) {
        if (!operational || !foreground || s != session.get()) {
            Log.i(TAG, "unlock refused: stale session or activity not visible");
            return;
        }
        clearPinEntry();
        unlocked = true;
        loadKey();
        armIdleLock();
    }

    /**
     * Invalidate the session (ALWAYS — even if already locked, so an in-flight PIN op dies), drop
     * the key from memory, end any USB session, and return to the PIN gate.
     */
    private void lock() {
        AccessoryTransport staleTransport;
        synchronized (stateLock) {
            session.incrementAndGet(); // invalidates any in-flight PIN op / load / regeneration
            unlocked = false;
            credentials = null;
            clearPassphraseWallet(); // the passphrase never outlives the unlocked session
            // An un-activated candidate is discarded; a commit or a signing in progress holds
            // stateLock, so by now it has either finished (key dropped above) or never ran.
            replacement.reset();
            sensitive.reset();
            cancelApproval();
            clearReceivingIdentity();
            // USB data-lock (app layer): the session is closed INSIDE the lock so a signing task
            // can never send after this point (send + close are linearized with signing).
            staleTransport = transport;
            transport = null;
            clearHeldRequest();
            if (staleTransport != null) { staleTransport.close(); usbReplugHint = true; }
            keepScreenOn(false);
        }
        clearSensitiveUi();
        clearPinEntry();
        if (!operational) return;
        bootUnlock.noteLock(bootId()); // no silent boot unlock after any lock this boot
        requestPending.set(false);
        ui.removeCallbacks(idleLock);
        ui.removeCallbacks(hideSeed);
        showPinGate(null);
    }

    private void armIdleLock() {
        ui.removeCallbacks(idleLock);
        // While the recovery phrase (or its check) is on screen, the seed timer owns the timeout.
        long delay = backupWords != null ? Math.max(idleTimeoutMs, SEED_TIMEOUT_MS + 10_000L) : idleTimeoutMs;
        ui.postDelayed(idleLock, delay);
    }

    /** Recovery phrase: back to home (button or timeout). */
    /**
     * Leave any phrase screen (reveal or NEW phrase) and return home. For a replacement this is
     * the single terminal path for cancel / timeout / success: the state goes IDLE (unless a
     * commit is in progress, which owns its own outcome) and a parked USB host is replayed.
     */
    private void clearSensitiveUi() {
        ui.removeCallbacks(hideSeed);
        if (approvalDecision == null) keepScreenOn(false);
        sensitive.reset();
        activeSensitive = -1;
        afterReauth = null;
        if (backupWords != null) Arrays.fill(backupWords, null);
        backupWords = null;
        if (backupChallenge != null) backupChallenge.destroy();
        backupChallenge = null;
        backupIdentity = null;
        replacementCandidate = null;
        seedTimer = null;
        wipeSeedQr();
        seedQrRequested = false;
        clearRestoreEntry(); // typed recovery words never outlive the unlocked session
        clearDice();
        endPassphraseEntry(); // nor a typed passphrase
        firstRunPinFresh = false;
        restoreReplacing = false;
        restoreOverOp = -1;
    }

    private void hideBackup() {
        if (replacement.state() == ReplacementState.COMMITTING) return;
        replacement.cancelCurrent();
        clearPinEntry();
        clearSensitiveUi();
        if (unlocked) showHome();
        drainPendingUsb();
    }

    /**
     * After unlock: the request that waited behind the gate goes through the ordinary path — only
     * on the connection it arrived on, and only while that connection is still the live one.
     */
    private void dispatchHeldRequest() {
        final JSONObject held; final AccessoryTransport source;
        synchronized (stateLock) {
            held = heldRequest;
            source = heldSource;
            boolean live = source != null && source == transport && !source.isClosed();
            clearHeldRequest();
            if (held == null || !live) return;
        }
        cryptoExecutor.execute(() -> onRequest(source, held));
    }

    /** Under stateLock (or before any transport runs): forget the held request and its source. */
    private void clearHeldRequest() {
        heldRequest = null;
        heldSummary = null;
        heldSource = null;
    }

    private void drainPendingUsb() {
        if (!unlocked || !operational || !walletLoaded || !backupVerified || sensitive.active()) return;
        Intent usb = pendingUsb;
        pendingUsb = null;
        if (usb != null) handleIntent(usb);
    }

    private boolean replacementActive() { return replacement.active(); }
    private int beginReplacement() { return replacement.begin(); }
    private boolean markPrepared(int op) { return replacement.markPrepared(op); }
    private boolean beginCommit(int op) { return replacement.beginCommit(op); }
    private void endReplacement(int op) { replacement.end(op); }

    /** OLED burn-in mitigation: cycle the content through a 2 px square every PIXEL_SHIFT_MS. */
    private void shiftPixels() {
        View content = findViewById(android.R.id.content);
        if (content != null) {
            int step = VaultTheme.dp(this, 1);
            int[][] offsets = {{0, 0}, {step, 0}, {step, step}, {0, step}};
            shiftPhase = (shiftPhase + 1) % offsets.length;
            content.setTranslationX(offsets[shiftPhase][0]);
            content.setTranslationY(offsets[shiftPhase][1]);
        }
        ui.postDelayed(pixelShift, PIXEL_SHIFT_MS);
    }

    /** Device owner: idle screen-off (burn-in + walk-away). Best effort; never fatal. */
    private void applyIdlePolicy(DevicePolicyManager policy) {
        try {
            ComponentName admin = null;
            List<ComponentName> admins = policy.getActiveAdmins();
            if (admins != null) {
                for (ComponentName c : admins) {
                    if (getPackageName().equals(c.getPackageName())) admin = c;
                }
            }
            if (admin == null) return;
            policy.setSystemSetting(admin, Settings.System.SCREEN_OFF_TIMEOUT,
                    String.valueOf(display != null ? display.screenTimeoutMs() : SCREEN_OFF_TIMEOUT_MS));
        } catch (Exception e) {
            Log.w(TAG, "idle policy not applied", e);
        }
    }

    private static boolean isPhoneVaultApplianceBuild() {
        return "PhoneVault".equals(Build.BRAND);
    }

    private boolean enterVaultMode(DevicePolicyManager policy) {
        try {
            // Self-provisioning (HOME preference, keyguard off, lock-task packages, setup
            // wizards hidden). Also runs from the admin receiver on first boot; idempotent.
            if (!ApplianceProvisioning.apply(this, policy)) return false;
            if (isPhoneVaultApplianceBuild()) {
                enforceApplianceRestrictions(policy);
            }
            if (!policy.isLockTaskPermitted(getPackageName())) return false;
            getWindow().getDecorView().setSystemUiVisibility(
                    View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                            | View.SYSTEM_UI_FLAG_FULLSCREEN
                            | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                            | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                            | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                            | View.SYSTEM_UI_FLAG_LAYOUT_STABLE);
            ActivityManager activityManager = (ActivityManager) getSystemService(
                    Context.ACTIVITY_SERVICE);
            if (activityManager.getLockTaskModeState()
                    == ActivityManager.LOCK_TASK_MODE_NONE) {
                startLockTask();
            }
            return activityManager.getLockTaskModeState()
                    != ActivityManager.LOCK_TASK_MODE_NONE;
        } catch (RuntimeException exception) {
            statusView.setText("Vault policy error: " + exception.getMessage());
            return false;
        }
    }

    /**
     * A development build (debug / dev-appliance). Both markers must agree: the release source set's
     * DevTools has SCREENSHOTS=false, so a release APK is never treated as dev even if a BuildConfig
     * field were mis-set.
     */
    static boolean devBuild() {
        return BuildConfig.VAULT_DEV_BUILD && DevTools.SCREENSHOTS;
    }

    /** Settings.Global.ADB_WIFI_ENABLED (hidden constant): wireless debugging. */
    static final String ADB_WIFI_ENABLED = "adb_wifi_enabled";

    /** Non-zero when USB (Settings.Global.ADB_ENABLED) OR wireless (adb_wifi_enabled) debugging is on. */
    private int adbEnabled() {
        int usb = Settings.Global.getInt(getContentResolver(), Settings.Global.ADB_ENABLED, 0);
        int wifi = Settings.Global.getInt(getContentResolver(), ADB_WIFI_ENABLED, 0);
        return usb != 0 ? usb : wifi;
    }

    /** Release build with USB or wireless debugging on: nothing is shown or approved (ApplianceLockdown). */
    private boolean adbRefused() {
        return ApplianceLockdown.refuseForAdb(devBuild(), adbEnabled());
    }

    private void enforceApplianceRestrictions(DevicePolicyManager policy) {
        ComponentName admin = VaultDeviceAdminReceiver.component(this);
        boolean dev = devBuild();
        // ApplianceLockdown: the base set, the frozen app set (release), and in a release build
        // also debugging features, date/time, physical media and system error dialogs.
        for (String restriction : ApplianceLockdown.userRestrictions(dev, BuildConfig.VAULT_ALLOW_APP_UPDATES)) {
            policy.addUserRestriction(admin, restriction);
        }
        if (ApplianceLockdown.restrictsCameraAndInput(dev)) {
            policy.setCameraDisabled(admin, true);
            // System services/keyboards are always permitted by Android; these lists refuse the rest.
            if (!policy.setPermittedAccessibilityServices(admin, Collections.emptyList())) {
                throw new IllegalStateException("Accessibility services could not be restricted");
            }
            String ime = Settings.Secure.getString(getContentResolver(), Settings.Secure.DEFAULT_INPUT_METHOD);
            if (!policy.setPermittedInputMethods(admin, new ArrayList<>(ApplianceLockdown.permittedInputMethods(ime)))) {
                throw new IllegalStateException("Input methods could not be restricted");
            }
        }
        // Only the power menu (long-press Power: power off / restart) works inside the kiosk.
        // Without it the sole way off is a forced hardware restart. The OS image trims the menu
        // to power + restart (config_globalActionsList); nothing else of lock task is opened up.
        policy.setLockTaskFeatures(VaultDeviceAdminReceiver.component(this),
                DevicePolicyManager.LOCK_TASK_FEATURE_GLOBAL_ACTIONS);
        policy.setScreenCaptureDisabled(VaultDeviceAdminReceiver.component(this),
                !DevTools.SCREENSHOTS);
        if (!policy.setStatusBarDisabled(VaultDeviceAdminReceiver.component(this), true)) {
            throw new IllegalStateException("Status bar could not be disabled");
        }
    }

    private void deactivate(String reason) {
        deactivate("DEVICE NOT READY", "Policy check failed", reason, "Signing is disabled",
                "Have the image provisioning checked. No wallet identity is displayed.", "policy-error");
    }

    /**
     * Release build, USB debugging on: the vault stops (locked, USB session closed, any approval
     * cancelled) and shows only this. Turning debugging off brings back the PIN gate.
     */
    private void refuseWhileAdbOn() {
        deactivate("DEVICE NOT SAFE", ApplianceLockdown.ADB_REFUSAL_TITLE, ApplianceLockdown.ADB_REFUSAL,
                "Nothing will be shown or signed",
                "A computer connected over USB could read or control this phone. Turn USB debugging off "
                        + "(it should never be on in a release vault) and have the phone checked. No wallet identity is displayed.",
                "adb-refused");
    }

    private void deactivate(String eyebrow, String title, String reason, String cardLabel, String cardText, String screen) {
        synchronized (stateLock) {
            session.incrementAndGet();
            operational = false;
            unlocked = false;
            credentials = null;
            clearPassphraseWallet();
            replacement.reset();
            sensitive.reset();
            cancelApproval();
            clearReceivingIdentity();
            AccessoryTransport previous = transport;
            transport = null;
            if (previous != null) previous.close();
        }
        ui.removeCallbacks(idleLock);
        clearSensitiveUi();
        clearPinEntry();
        vault = null;
        LinearLayout root = page(eyebrow, title, reason);
        card(root, cardLabel, cardText);
        present(root, screen);
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (operational) handleIntent(intent);
    }


    // ------------------------------------------------------------------ pages
    // Native, scrollable pages. Sensitive operations never use floating dialogs.

    private LinearLayout page(String eyebrow, String title, String description) {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(24), dp(48), dp(24), dp(30));
        root.setBackgroundColor(VaultTheme.BG);
        TextView brand = VaultTheme.pixelText(this, "PHONE VAULT", 10, VaultTheme.ACCENT);
        // Header row: brand on the left, battery, then ☰ (when available). One menu everywhere.
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setMinimumHeight(dp(42));
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        header.addView(brand, blp);
        batteryIndicator = VaultTheme.batteryIndicator(this);
        VaultTheme.showBattery(batteryIndicator, battery);
        header.addView(batteryIndicator);
        root.addView(header);
        if (menuAvailable()) {
            TextView menu = VaultTheme.pixelButton(this, "☰", false);
            VaultTheme.size(menu, 22);
            menu.setPadding(0, 0, 0, 0);
            menu.setContentDescription("Menu");
            hardenTouch(menu);
            menu.setOnClickListener(v -> { if (menuAvailable()) showMenu(); });
            LinearLayout.LayoutParams mlp = new LinearLayout.LayoutParams(dp(56), dp(48));
            mlp.setMargins(dp(12), -dp(6), 0, 0);
            header.addView(menu, mlp);
        }
        TextView label = VaultTheme.bodyText(this, eyebrow.toUpperCase(Locale.ROOT), 12, VaultTheme.FAINT);
        label.setPadding(0, dp(30), 0, dp(8));
        root.addView(label);
        TextView heading = VaultTheme.bodyText(this, title, 28, VaultTheme.INK);
        heading.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        root.addView(heading);
        if (description != null && !description.isEmpty()) {
            String shown = ReviewStyle.groupEvmIn(description); // e.g. a refusal naming the requested account
            TextView caption = VaultTheme.bodyText(this, shown, VaultTheme.BODY_SIZE, VaultTheme.DIM);
            if (!shown.equals(description)) keepGroupsWhole(caption);
            caption.setPadding(0, dp(12), 0, dp(12));
            root.addView(caption);
        }
        return root;
    }

    private void present(LinearLayout root, String screen) {
        if ((screen.startsWith("backup") || "phrase".equals(screen) || "replace-confirm".equals(screen))
                && !sensitive.active()) return;
        if (screen.startsWith("restore") && restoreReplacing && !sensitive.active()) return;
        screenName = screen;
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(VaultTheme.BG);
        scroll.addView(root);
        setContentView(scroll);
        watchScrollEnd(scroll, root);
        devDumpUi();
    }

    private void action(LinearLayout parent, String label, boolean primary, Runnable run) {
        TextView button = VaultTheme.pixelButton(this, label, primary);
        hardenTouch(button);
        button.setOnClickListener(v -> {
            if (unlocked && operational) run.run();
        });
        parent.addView(button, matchWrap(dp(12)));
    }

    private void card(LinearLayout parent, String label, String value) {
        LinearLayout box = VaultTheme.box(this);
        box.addView(VaultTheme.bodyText(this, label, 13, VaultTheme.FAINT));
        // Whole EVM addresses in groups of four; a card that IS an address is monospace.
        String shown = ReviewStyle.groupEvmIn(value);
        TextView text = Addresses.isEvm(value) ? VaultTheme.monoText(this, shown, VaultTheme.BODY_SIZE, VaultTheme.INK)
                : VaultTheme.bodyText(this, shown, VaultTheme.BODY_SIZE, VaultTheme.INK);
        if (!shown.equals(value)) keepGroupsWhole(text);
        text.setPadding(0, dp(6), 0, 0);
        box.addView(text);
        parent.addView(box, matchWrap(dp(12)));
    }

    /** The menu is available on the ordinary unlocked screens: never over a PIN gate, a sensitive
     *  flow, an approval, or before a wallet exists. */
    private boolean menuAvailable() {
        return accountScreensReady() && !passphraseEntry;
    }

    /** The account / passphrase screens work (the menu itself hides while a passphrase is typed). */
    private boolean accountScreensReady() {
        return unlocked && operational && walletLoaded && !sensitive.active() && approvalDecision == null
                && !replacementActive() && !restoreReplacing;
    }

    private void showMenu() {
        LinearLayout root = page("MENU", "Where to?", null);
        String current = screenName;
        action(root, "Wallet", "wallet".equals(current), () -> { if (menuAvailable()) showHome(); });
        action(root, "Accounts", current.startsWith("account"), () -> { if (menuAvailable()) showAccounts(); });
        action(root, passphraseBook != null ? "Passphrase wallet · open" : "Passphrase wallet", current.startsWith("passphrase"),
                () -> { if (menuAvailable()) showPassphraseWallet(); });
        action(root, "Security", "security".equals(current), () -> { if (menuAvailable()) showSecurity(); });
        action(root, "Display & auto-lock", "preferences".equals(current), () -> { if (menuAvailable()) showPreferences(); });
        action(root, "Address book", current.startsWith("address-book"), () -> { if (menuAvailable()) safetyScreens().showList(); });
        action(root, "Bitcoin sharing", "btc-sharing".equals(current), () -> { if (menuAvailable()) showBtcSharing(); });
        action(root, "Device information", "integrity".equals(current), () -> { if (menuAvailable()) showIntegrity(); });
        action(root, "Coming next", "features".equals(current), () -> { if (menuAvailable()) showFeatures(); });
        action(root, "Lock now", false, this::lock);
        present(root, "menu");
    }

    private void buildUi() {
        // A host attach while the display is off starts this activity: light the screen so the
        // incoming request is visible at once (kiosk: there is no keyguard to bypass).
        setShowWhenLocked(true);
        setTurnScreenOn(true);
        getWindow().setStatusBarColor(VaultTheme.BG);
        getWindow().setNavigationBarColor(VaultTheme.BG);
        display = new DisplaySettings(getPreferences(MODE_PRIVATE));
        applyDisplaySettings();
        battery = readBattery(registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED)));
        statusView = VaultTheme.bodyText(this, "", VaultTheme.BODY_SIZE, VaultTheme.DIM);
        showLoading("Opening Phone Vault", "Checking appliance policy…");
    }

    /** Text scale, haptics and idle lock from the saved Display & auto-lock choices. */
    private void applyDisplaySettings() {
        largeText = display.largeText();
        VaultTheme.setTextScale(DisplaySettings.textScale(largeText));
        Haptics.setEnabled(display.haptics());
        idleTimeoutMs = display.idleLockMs();
    }

    private void showLoading(String title, String caption) {
        LinearLayout root = page("PLEASE WAIT", title, caption);
        card(root, "Privacy", "Your receiving address stays hidden until the wallet is ready.");
        action(root, "Lock now", false, this::lock);
        present(root, "loading");
    }

    private void showHome() {
        if (!walletLoaded) {
            showLoading("Opening your wallet", "Verifying the wallet saved on this device…");
            return;
        }
        endPassphraseEntry();
        SigningAccount account = activeAccount;
        String accountName = account != null ? account.name : AccountBook.defaultName(0);
        boolean passphraseWallet = account != null && account.passphrase;
        LinearLayout root = page(passphraseWallet ? "PASSPHRASE WALLET · " + accountName : accountName,
                !backupVerified ? "Back up your wallet" : passphraseWallet ? "Passphrase wallet" : "Your offline wallet",
                backupVerified ? "Review every request here. Your keys stay on this phone."
                        : "Before receiving or signing, write down all 24 recovery words. We'll then spot-check a few.");
        if (backupVerified && passphraseWallet) {
            card(root, "Passphrase wallet · fingerprint " + account.fingerprint,
                    "Opened with your passphrase. It is not saved: locking the phone closes it. Check the fingerprint is the one you expect.");
        }
        if (battery.low()) card(root, "Battery " + battery.label() + " · charge before signing",
                "Plug in before reviewing a request. If the phone shuts down mid-review, the request is simply lost; nothing is signed.");
        if (backupVerified && walletAddress != null && walletQr != null) {
            LinearLayout box = VaultTheme.box(this);
            box.setGravity(Gravity.CENTER_HORIZONTAL);
            qrView = new ImageView(this);
            qrView.setContentDescription("Receiving address QR. Full address follows.");
            qrView.setImageBitmap(walletQr);
            // Shown at the bitmap's own pixel size: integer-scaled modules stay perfectly square.
            LinearLayout.LayoutParams qlp = new LinearLayout.LayoutParams(walletQr.getWidth(), walletQr.getHeight());
            qlp.gravity = Gravity.CENTER_HORIZONTAL;
            qlp.setMargins(0, dp(4), 0, dp(18));
            box.addView(qrView, qlp);
            box.addView(VaultTheme.bodyText(this, accountName.toUpperCase(Locale.ROOT)
                    + (passphraseWallet ? " · PASSPHRASE" : "") + " · RECEIVE", 13, VaultTheme.FAINT));
            addressView = VaultTheme.monoText(this, formatAddress(
                    Keys.toChecksumAddress(walletAddress)), 16, VaultTheme.INK);
            keepGroupsWhole(addressView);
            addressView.setPadding(0, dp(12), 0, dp(8));
            box.addView(addressView);
            root.addView(box, matchWrap(dp(22)));
            action(root, "Switch account", false, this::showAccounts);
            card(root, "Check the network", "This is an EVM address. Confirm the destination chain in your sending wallet. A matching address does not mean every network is supported.");
            addBackupReminderCard(root);
        } else {
            card(root, "Backup not checked yet", "Receiving and signing are paused until you write the phrase down and pass the spot check. If you already wrote it down, check it now.");
            action(root, "Write down recovery phrase", true, this::confirmRevealBackup);
            action(root, "I have my backup · check words", false, () -> startBackupAccess(true));
        }
        if (usbReplugHint && transport == null) statusMessage = "USB session ended when the vault locked · unplug and reconnect the cable to resume";
        statusView = VaultTheme.bodyText(this, statusMessage, VaultTheme.BODY_SIZE, VaultTheme.DIM);
        statusView.setPadding(dp(2), dp(20), 0, dp(4));
        root.addView(statusView);
        action(root, "Lock now", false, this::lock);
        card(root, DevTools.SCREENSHOTS ? "Development appliance" : "Prototype",
                "Test assets only. Hardware release verification is still pending.");
        present(root, "wallet");
    }

    private void showSecurity() {
        LinearLayout root = page("DEVICE & WALLET", "Security", "Controls that protect access, recovery, and your ability to verify this device.");
        card(root, "Backup", backupVerified
                ? "Spot-checked for Account 1. Keep the written 24 words somewhere safe and private."
                : "Not checked yet. Receiving and signing stay paused until it is.");
        action(root, "Check my backup", !backupVerified, () -> startBackupAccess(true));
        action(root, "Show recovery phrase", false, this::confirmRevealBackup);
        card(root, "Passphrase (optional)", "Your 24 words back up every account of the standard wallet. A passphrase wallet ALSO needs its passphrase, which is not part of this backup and is never saved on the phone: keep it written down separately.");
        action(root, "Passphrase wallet", false, this::showPassphraseWallet);
        action(root, "Show as SeedQR", false, this::confirmRevealSeedQr);
        action(root, "Backup reminder · " + BackupReminder.label(backupReminder.intervalDays()), false, this::showBackupReminderSettings);
        action(root, "Bitcoin sharing", false, this::showBtcSharing);
        card(root, "This wallet", "Replacing or restoring changes the key on this phone. Keep the current backup if the wallet controls anything.");
        action(root, "Replace with a new wallet", false, this::confirmReplace);
        action(root, "Restore a different wallet", false, this::confirmRestoreOver);
        action(root, "Lock now", false, this::lock);
        present(root, "security");
    }

    // ------------------------------------------------------------------ first-run wizard

    /** Step 1: a fresh PIN is set and no wallet exists yet. Create or restore — never silently. */
    private void showFirstRunChoice() {
        clearRestoreEntry();
        LinearLayout root = page("SET UP · STEP 1 OF 4", "Set up your wallet",
                "Create a brand-new wallet on this phone, or restore one from a 24-word recovery phrase you already have. Nothing leaves this device either way.");
        card(root, "Create new", "Generates a fresh recovery phrase here, offline. You'll write it down and we'll spot-check a few words.");
        action(root, "Create new wallet", true, () -> withSeedKey("Confirm your PIN to seal your new wallet", this::createFirstWallet));
        card(root, "Restore existing", "Type your 24 words on this screen. We'll show the address they produce so you can confirm it's the right wallet before anything is saved.");
        action(root, "Restore from recovery phrase", false, this::showRestoreEntry);
        action(root, "Advanced · add your own dice rolls", false, this::showDiceEntry);
        action(root, "Lock now", false, this::lock);
        present(root, "first-run");
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
        LinearLayout root = page("SET UP · ADVANCED", "Add your own randomness",
                "Roll a real die and tap each result. Your rolls are hashed together with the phone's two hardware entropy sources, so the wallet never depends on the phone's randomness alone. The rolls are not displayed and are discarded after the wallet is created.");
        card(root, "Rolls so far", rolls + " of " + DICE_FULL + " · about " + Math.min(bits, 256) + " of 256 bits"
                + (rolls >= DICE_FULL ? " · full strength" : ""));
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        for (int face = 1; face <= 6; face++) {
            final char c = (char) ('0' + face);
            TextView b = VaultTheme.pixelButton(this, String.valueOf(face), true);
            VaultTheme.size(b, 20);
            b.setPadding(0, 0, 0, 0);
            b.setGravity(Gravity.CENTER);
            hardenTouch(b);
            b.setOnClickListener(v -> {
                if (!unlocked || !operational) return;
                if (diceRolls.length() < 512) diceRolls.append(c);
                showDiceEntry();
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(60), 1f);
            lp.setMargins(dp(3), dp(6), dp(3), dp(6));
            row.addView(b, lp);
        }
        root.addView(row);
        if (rolls > 0) {
            action(root, "Create wallet with these rolls", true, () -> withSeedKey("Confirm your PIN to seal your new wallet", this::createFirstWallet));
            action(root, "Undo last roll", false, () -> {
                diceRolls.setCharAt(rolls - 1, '0');
                diceRolls.setLength(rolls - 1);
                showDiceEntry();
            });
        }
        action(root, "Back · without dice", false, () -> { clearDice(); showFirstRunChoice(); });
        present(root, "first-run-dice");
    }

    private void createFirstWallet() {
        final int s = session.get();
        final byte[] userEntropy = diceRolls.toString().getBytes(StandardCharsets.US_ASCII);
        clearDice();
        showLoading("Creating your wallet", userEntropy.length == 0
                ? "Generating a new recovery phrase from device entropy…"
                : "Mixing " + userEntropy.length + " dice rolls with device entropy…");
        cryptoExecutor.execute(() -> {
            try {
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked || !operational || walletLoaded) return;
                }
                Credentials fresh;
                try { fresh = vault.generateAndStore(userEntropy); recordEntropyReport(userEntropy.length > 0); }
                finally { Arrays.fill(userEntropy, (byte) 0); }
                String address = fresh.getAddress();
                Bitmap qr = qrFor(address);
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked || !operational) return;
                    credentials = fresh;
                    adoptNewWallet(fresh.getAddress());
                    walletAddress = address;
                    walletQr = qr;
                    backupVerified = false;
                    walletLoaded = true;
                }
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    LinearLayout root = page("SET UP · STEP 2 OF 4", "Write down your recovery phrase",
                            "Your new wallet is ready. Next, copy its 24 words onto paper, in order. Never photograph them or type them into another device.");
                    card(root, "Then", "Step 3 spot-checks a few of the words. Step 4 shows your receiving address.");
                    action(root, "Continue", true, this::confirmRevealBackup);
                    action(root, "Lock now", false, this::lock);
                    present(root, "first-run-created");
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    showInfo("Could not create a wallet", "Nothing was saved. " + e.getMessage(), this::showFirstRunChoice);
                });
            }
        });
    }

    // ------------------------------------------------------------------ restore over an existing wallet
    // Same entry screens, but owned by a fresh-PIN sensitive flow and the replacement state
    // machine, exactly like Replace (USB excluded throughout).

    private boolean restoreReplacing;
    private int restoreOverOp = -1;

    private void confirmRestoreOver() {
        if (!walletLoaded || credentials == null) return;
        LinearLayout root = page("SECURITY / RESTORE", "Restore a different wallet?",
                "You will type a 24-word recovery phrase on this phone. The wallet it produces REPLACES the current one on this device. Nothing changes until you confirm the address it shows.");
        card(root, "Current Account 1", Keys.toChecksumAddress(walletId != null ? walletId : walletAddress));
        card(root, "Keep its backup", "If the current wallet controls any assets, keep its written phrase. This phone will no longer hold that key.");
        action(root, "Continue · verify PIN", true, () -> beginSensitive("restore a different wallet", () -> {
            int op;
            synchronized (stateLock) { op = beginReplacement(); }
            if (op < 0) { hideBackup(); return; }
            restoreOverOp = op;
            restoreReplacing = true;
            clearRestoreEntry();
            showRestoreEntry();
        }));
        action(root, "Back to Security", false, this::showSecurity);
        present(root, "security-restore");
    }

    /** Commit a restore over the existing wallet: the PREPARED → COMMITTING transition, then storage. */
    private void commitRestoreOver(final String mnemonic) {
        final int token = activeSensitive, s = session.get(), op = restoreOverOp;
        if (!restoreReplacing || !sensitiveValid(token, s) || !beginCommit(op)) return;
        clearReceivingIdentity();
        showLoading("Restoring your wallet", "Saving and checking the restored identity. This step can no longer be cancelled.");
        cryptoExecutor.execute(() -> {
            try {
                String address;
                synchronized (stateLock) {
                    if (!sensitiveValid(token, s) || !replacement.owns(op) || transport != null || requestPending.get()) return;
                    credentials = null;
                    Credentials restored = vault.restore(mnemonic);
                    address = restored.getAddress();
                    backupCheck.record(address);
                    credentials = restored;
                    adoptNewWallet(address);
                    walletAddress = address;
                    backupVerified = true;
                    walletLoaded = true;
                    endReplacement(op);
                }
                Bitmap qr = qrFor(address);
                runOnUiThread(() -> {
                    if (!sensitiveValid(token, s)) return;
                    walletQr = qr;
                    statusMessage = "Wallet restored · backup verified by entry";
                    hideBackup();
                });
            } catch (Exception e) {
                synchronized (stateLock) { credentials = null; clearReceivingIdentity(); endReplacement(op); }
                runOnUiThread(() -> {
                    if (s != session.get()) return;
                    gateNotice = "Storage could not confirm the restored wallet. Re-enter your PIN to reconcile it. No receiving address is available until loading succeeds.";
                    lock();
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
        LinearLayout root = page((restoreReplacing ? "REPLACE BY RESTORE · WORD " : "RESTORE · WORD ") + (restoreIndex + 1) + " OF " + SeedRestore.WORD_COUNT,
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
        LinearLayout slot = new LinearLayout(this);
        slot.setOrientation(LinearLayout.VERTICAL);
        slot.setMinimumHeight(dp(2 * 60 + 8));
        for (int rowStart = 0; rowStart < suggestions.size(); rowStart += 3) {
            LinearLayout srow = new LinearLayout(this);
            srow.setOrientation(LinearLayout.HORIZONTAL);
            for (int i = rowStart; i < Math.min(rowStart + 3, suggestions.size()); i++) {
                final String word = suggestions.get(i);
                TextView b = VaultTheme.pixelButton(this, word, i == 0);
                VaultTheme.size(b, 15);
                // Fixed 52 dp slot: no vertical padding, so the word never clips at large text.
                b.setPadding(dp(4), 0, dp(4), 0);
                hardenTouch(b);
                b.setOnClickListener(v -> { if (unlocked && operational) pickRestoreWord(word); });
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(52), 1f);
                lp.setMargins(dp(3), dp(4), dp(3), dp(4));
                srow.addView(b, lp);
            }
            slot.addView(srow);
        }
        if (suggestions.isEmpty() && !typed.isEmpty()) {
            TextView none = VaultTheme.bodyText(this, "No recovery word starts with \"" + typed + "\". Use ⌫.", VaultTheme.BODY_SIZE, VaultTheme.DANGER_INK);
            none.setPadding(0, dp(12), 0, dp(6));
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
            TextView entered = VaultTheme.monoText(this, strip.toString(), 13, VaultTheme.DIM);
            entered.setPadding(0, dp(8), 0, dp(8));
            root.addView(entered);
        }

        if (filled == SeedRestore.WORD_COUNT) action(root, "Restore this wallet", true, this::validateRestore);
        if (restoreIndex > 0 || restoreWords[restoreIndex] != null) action(root, "← Previous word", false, () -> {
            if (restoreBuffer.length() > 0) restoreBuffer.setLength(0);
            else if (restoreIndex > 0) restoreIndex--;
            showRestoreEntry();
        });
        if (restoreReplacing) action(root, "Cancel · keep current wallet", false, this::hideBackup);
        else action(root, "Cancel · start over", false, () -> { clearRestoreEntry(); showFirstRunChoice(); });
        present(root, "restore-entry");
    }

    private void restoreKeyRow(LinearLayout parent, String[] keys) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        for (String key : keys) {
            TextView b = VaultTheme.pixelButton(this, key, false);
            VaultTheme.size(b, 18);
            b.setPadding(0, 0, 0, 0); // a ninth of the width: any horizontal padding hides the letter
            b.setGravity(Gravity.CENTER);
            hardenTouch(b);
            b.setOnClickListener(v -> {
                if (!unlocked || !operational) return;
                if ("⌫".equals(key)) {
                    if (restoreBuffer.length() > 0) restoreBuffer.setLength(restoreBuffer.length() - 1);
                    else if (restoreWords[restoreIndex] != null) restoreWords[restoreIndex] = null;
                    else if (restoreIndex > 0) { restoreIndex--; restoreWords[restoreIndex] = null; }
                } else if (restoreBuffer.length() < 8) {
                    restoreBuffer.append(key);
                }
                showRestoreEntry();
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(48), 1f);
            lp.setMargins(dp(2), dp(3), dp(2), dp(3));
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
        final int s = session.get();
        final String raw = String.join(" ", Arrays.asList(restoreWords).stream()
                .map(w -> w == null ? "" : w).toArray(String[]::new));
        final String mnemonic;
        try {
            mnemonic = SeedRestore.validate(raw);
        } catch (SeedRestore.RestoreException bad) {
            showInfo("Phrase not valid yet", bad.getMessage() + ". Go back and fix the word.", this::showRestoreEntry);
            return;
        }
        showLoading("Checking your phrase", "Deriving the wallet address these 24 words produce…");
        cryptoExecutor.execute(() -> {
            try {
                final String address = SeedRestore.deriveAddress(mnemonic, 0);
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    boolean replacing = restoreReplacing;
                    if (replacing && !markPrepared(restoreOverOp)) { hideBackup(); return; }
                    LinearLayout root = page(replacing ? "REPLACE BY RESTORE · CONFIRM" : "RESTORE · CONFIRM",
                            replacing ? "Replace with this wallet?" : "Is this your wallet?",
                            replacing ? "This is the address your phrase produces. Confirming REPLACES the current wallet on this phone. If the address is not the one you expect, a word or its order is wrong — nothing has been saved yet."
                                      : "This is the address your phrase produces. Compare it with the wallet you're restoring. If it doesn't match, a word or its order is wrong — nothing has been saved yet.");
                    card(root, replacing ? "New Account 1" : "Account 1", Keys.toChecksumAddress(address));
                    if (replacing && walletAddress != null) card(root, "Replaces current", Keys.toChecksumAddress(walletAddress));
                    card(root, "Derivation", "m/44'/60'/0'/0/0 · no passphrase");
                    action(root, replacing ? "Yes, replace with this wallet" : "Yes, restore this wallet", true,
                            () -> withSeedKey("Confirm your PIN to save the restored wallet",
                                    () -> { if (restoreReplacing) commitRestoreOver(mnemonic); else commitRestore(mnemonic, s); }));
                    action(root, "Back · fix words", false, this::showRestoreEntry);
                    if (replacing) action(root, "Cancel · keep current wallet", false, this::hideBackup);
                    else action(root, "Cancel · start over", false, () -> { clearRestoreEntry(); showFirstRunChoice(); });
                    present(root, "restore-confirm");
                });
            } catch (Exception e) {
                runOnUiThread(() -> { if (s == session.get()) showInfo("Could not derive an address", e.getMessage(), this::showRestoreEntry); });
            }
        });
    }

    /** Persist the restored phrase; the user typed it, so the backup is considered verified. */
    private void commitRestore(final String mnemonic, final int s) {
        showLoading("Restoring your wallet", "Saving and verifying the restored identity on this device…");
        cryptoExecutor.execute(() -> {
            try {
                Credentials restored;
                String address;
                Bitmap qr;
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked || !operational || walletLoaded) return;
                    restored = vault.restore(mnemonic);
                    address = restored.getAddress();
                    backupCheck.record(address);
                    credentials = restored;
                    adoptNewWallet(address);
                    walletAddress = address;
                    backupVerified = true;
                    walletLoaded = true;
                }
                qr = qrFor(address);
                synchronized (stateLock) { if (s == session.get()) walletQr = qr; }
                clearRestoreEntry();
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    statusMessage = "Wallet restored · backup verified by entry";
                    showHome();
                    drainPendingUsb();
                });
            } catch (Exception e) {
                synchronized (stateLock) { credentials = null; walletLoaded = false; }
                clearRestoreEntry();
                runOnUiThread(() -> {
                    if (s != session.get()) return;
                    gateNotice = "Storage could not confirm the restored wallet. Re-enter your PIN and try again; nothing is active until it saves.";
                    lock();
                });
            }
        });
    }

    private void showPreferences() {
        LinearLayout root = page("SECURITY / PREFERENCES", "Display & auto-lock",
                "Text size, screen timeout, locking and touch feedback. Changes apply at once.");
        card(root, "Text size", largeText ? "Large · easier reading" : "Standard · comfortable reading");
        action(root, largeText ? "Use standard text" : "Use larger text", true, () -> {
            if (display.setLargeText(!largeText)) {
                applyDisplaySettings();
                showPreferences();
            } else showInfo("Setting not saved", "Try again. Your previous text size is still active.", this::showPreferences);
        });

        int screen = display.screenTimeoutSeconds();
        card(root, "Screen timeout", "The screen turns off after " + DisplaySettings.durationLabel(screen)
                + " without a touch. Screen off always locks the vault.");
        for (int seconds : DisplaySettings.SCREEN_TIMEOUT_CHOICES) {
            action(root, "Screen off after " + DisplaySettings.durationLabel(seconds), seconds == screen, () -> {
                if (display.setScreenTimeoutSeconds(seconds)) {
                    applyDisplaySettings();
                    DevicePolicyManager policy = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
                    if (policy.isDeviceOwnerApp(getPackageName())) applyIdlePolicy(policy);
                    armIdleLock();
                    showPreferences();
                } else showInfo("Setting not saved", "Your previous screen timeout is still active.", this::showPreferences);
            });
        }

        int idle = display.idleSeconds();
        int effective = DisplaySettings.effectiveIdleSeconds(idle, screen);
        card(root, "Idle lock", "Locks after " + DisplaySettings.durationLabel(effective)
                + " without a touch, even while a review keeps the screen on."
                + (effective < idle ? " (Capped by the screen timeout.)" : ""));
        for (int seconds : DisplaySettings.IDLE_CHOICES) {
            action(root, "Lock after " + DisplaySettings.durationLabel(seconds), idle == seconds, () -> {
                if (display.setIdleSeconds(seconds)) {
                    applyDisplaySettings();
                    armIdleLock();
                    showPreferences();
                } else showInfo("Setting not saved", "Your previous idle timeout is still active.", this::showPreferences);
            });
        }

        boolean haptics = display.haptics();
        card(root, "Haptics", haptics ? "On · a tap for PIN keys, a pulse when you sign, a double pulse on reject"
                : "Off · no vibration feedback");
        action(root, haptics ? "Turn haptics off" : "Turn haptics on", false, () -> {
            if (display.setHaptics(!haptics)) {
                applyDisplaySettings();
                showPreferences();
            } else showInfo("Setting not saved", "Your previous haptics setting is still active.", this::showPreferences);
        });

        card(root, "Turning off", "To turn off: hold the power button, then choose Power off or Restart.");
        action(root, "Back to Security", false, this::showSecurity);
        present(root, "preferences");
    }

    private void showIntegrity() {
        LinearLayout root = page("SECURITY / DEVICE", "Know what is verified", "These are local observations, not independent attestation.");
        card(root, "App build", BuildConfig.VERSION_NAME + " · " + (DevTools.SCREENSHOTS ? "development capture enabled" : "release capture disabled"));
        card(root, "Platform", Build.MANUFACTURER + " " + Build.MODEL + "\nAndroid " + Build.VERSION.RELEASE + "\nReported patch: " + Build.VERSION.SECURITY_PATCH);
        card(root, "Device policy", isPhoneVaultApplianceBuild() && operational ? "Appliance policy active" : "Development environment · appliance policy not established");
        card(root, "Key boundary", BuildConfig.VAULT_REQUIRE_SECURE_HARDWARE
                ? "StrongBox wrapping is required when loading. EVM signing runs in Android memory."
                : "Development build permits software wrapping. EVM signing runs in Android memory.");
        card(root, "Verified boot", "Not independently verified by this screen. Complete the release, relock, and external verification procedure.");
        SigningAccount shownAccount = activeAccount;
        card(root, "Account path", shownAccount == null ? "m/44'/60'/0'/0/0 · no passphrase"
                : shownAccount.path() + (shownAccount.passphrase ? " · passphrase wallet " + shownAccount.fingerprint : " · no passphrase"));
        card(root, "PIN protection", credentialMode()
                ? "Checked by the security chip (Titan M), which slows repeated guesses · "
                        + SystemCredential.MAX_FAILED_FOR_WIPE + " wrong PINs reset the phone · the seed key works only for "
                        + SystemCredential.AUTH_WINDOW_SECONDS + " s after a correct PIN"
                : "App PIN gate · 10 failed attempts erase the wallet. PIN-derived encryption is planned.");
        String entropy = getPreferences(MODE_PRIVATE).getString("entropy_report", null);
        card(root, "Entropy at wallet creation", entropy != null ? entropy
                : "Not recorded (this wallet was created or restored before source reporting existed, or restored from words).");
        Intent battery = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (battery != null) {
            int level = battery.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
            int scale = battery.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
            card(root, "Battery charge", level >= 0 && scale > 0 ? (level * 100 / scale) + "% · charge is not a battery-health assessment" : "Unavailable");
        }
        card(root, "Power", "To turn off: hold the power button, then choose Power off or Restart.");
        action(root, "Back to Security", false, this::showSecurity);
        present(root, "integrity");
    }

    /** Persist WHICH sources fed the last generated seed and whether each passed its health tests
     *  (names and pass/fail only; no entropy bytes). Shown on Device information (R7). */
    private void recordEntropyReport(boolean dice) {
        List<SeedVault.SourceReport> reports = vault.lastGenerationReports();
        if (reports == null) return;
        StringBuilder b = new StringBuilder();
        for (SeedVault.SourceReport r : reports) {
            if (b.length() > 0) b.append('\n');
            b.append(r.healthy ? "✓ " : "✗ ").append(r.name).append(r.healthy ? " · passed health tests" : " · not used: " + r.detail);
        }
        if (dice) b.append("\n✓ your dice rolls");
        getPreferences(MODE_PRIVATE).edit().putString("entropy_report", b.toString()).apply();
    }

    private void showFeatures() {
        LinearLayout root = page("PRODUCT ROADMAP", "Coming next", "What is planned. Nothing here can be enabled in this build.");
        String[][] items = {
            {"Change PIN", "A fresh PIN challenge and atomic PIN-derived rewrapping must land together. The current six-digit PIN remains in effect until then."},
            {"Account discovery", "Finding used accounts automatically and watch-only export. Accounts and passphrase wallets themselves are in ☰ → Accounts and ☰ → Passphrase wallet."},
            {"Desktop companion", "Pairing and independently verified signing on macOS, Windows, and Linux. The current host tool is the Python USB client."},
            {"Browser wallets", "MetaMask and other integrations need a supported adapter. This build does not impersonate Ledger or Trezor."},
            {"Typed-data signing", "Permission-aware EIP-712 review for permits, orders, and authentication. Unsupported signing requests remain refused."},
            {"Verified token details", "Authenticated token identity and decimals. Current token calls show unverified raw arguments."},
            {"Signed updates", "A verified release chain, rollback protection, and recovery from interrupted updates."},
            {"Advanced recovery", "Multisig, optional stateless use, and additional backup formats after core recovery is proven."},
            {"Passkeys", "A future hardware-backed authenticator with its own transport and recovery review."}
        };
        for (String[] item : items) action(root, item[0] + " · planned", false,
                () -> showPlanned(item[0], item[1]));
        present(root, "features");
    }

    private void showPlanned(String title, String description) {
        LinearLayout root = page("PLANNED · NOT AVAILABLE", title, description);
        card(root, "Availability", "No wallet setting was changed. This screen describes upcoming work.");
        action(root, "Back to Coming next", true, this::showFeatures);
        action(root, "Wallet", false, this::showHome);
        present(root, "planned");
    }

    private void showInfo(String title, String description, Runnable back) {
        LinearLayout root = page("NOTICE", title, description);
        action(root, "Continue", true, back);
        present(root, "information");
    }

    private void setStatusActive(boolean active) {
        statusMessage = active ? "USB connected · waiting for a request" : "USB disconnected";
        if (statusView != null) statusView.setText(statusMessage);
    }


    private boolean sensitiveValid(int token, int s) {
        return operational && unlocked && foreground && s == session.get() && sensitive.owns(token);
    }

    private void beginSensitive(String purpose, Runnable afterPin) {
        if (!walletLoaded || credentials == null || !unlocked) return;
        if (transport != null || requestPending.get()) {
            showInfo("Disconnect USB first", "Finish or reject the current request and unplug the host before opening wallet security.", this::showSecurity);
            return;
        }
        int token;
        synchronized (stateLock) {
            token = sensitive.begin();
            if (token < 0) return;
            activeSensitive = token;
        }
        final int s = session.get();
        if (credentialMode()) {
            withSeedKey("Enter your PIN to " + purpose, () -> { if (sensitiveValid(token, s)) afterPin.run(); });
            return;
        }
        if (firstRunPinFresh) {
            // The PIN was set moments ago in this same unlocked session (no lock since): asking for
            // it again reads as a bug. One use only; any lock resets it.
            firstRunPinFresh = false;
            afterPin.run();
            return;
        }
        afterReauth = afterPin;
        pinScreen = new PinScreen(this, "VERIFY PIN", "Enter your PIN to " + purpose + ".", entered -> {
            if (!sensitiveValid(token, s)) { Arrays.fill(entered, '0'); return; }
            final PinScreen gate = pinScreen;
            gate.setSubtitle("Checking PIN…");
            cryptoExecutor.execute(() -> {
                try {
                    if (!sensitiveValid(token, s)) return;
                    VaultPin.Result result = pin.verify(entered, this::wipeWalletForFailedPin);
                    runOnUiThread(() -> {
                        if (!sensitiveValid(token, s) || pinScreen != gate) return;
                        if (result.outcome == VaultPin.Outcome.OK) {
                            Runnable next = afterReauth;
                            afterReauth = null;
                            gate.dispose();
                            pinScreen = null;
                            if (next != null) next.run();
                        } else if (result.outcome == VaultPin.Outcome.WRONG) {
                            gate.setSubtitle("Enter your PIN to " + purpose + ".");
                            gate.showError("Wrong PIN · " + result.attemptsRemaining + " attempts left");
                            updatePinPolicy(gate);
                        } else {
                            gateNotice = result.outcome == VaultPin.Outcome.WIPED
                                    ? "Wallet erased after the attempt limit."
                                    : "Erase could not be verified. The vault is sealed.";
                            lock();
                            showPinGate(null);
                        }
                    });
                } catch (Exception e) {
                    runOnUiThread(() -> {
                        if (sensitiveValid(token, s) && pinScreen == gate) {
                            gate.showError("PIN check failed. Try again.");
                            updatePinPolicy(gate);
                        }
                    });
                } finally { Arrays.fill(entered, '0'); }
            });
        });
        updatePinPolicy(pinScreen);
        pinScreen.addCancel(this::hideBackup);
        screenName = "reauth";
        setContentView(pinScreen.view());
        devDumpUi();
    }

    private void updatePinPolicy(PinScreen gate) {
        gate.setBattery(battery);
        int remaining = pin.attemptsRemaining();
        gate.setPolicy((DevTools.SCREENSHOTS ? "DEVELOPMENT · TEST ASSETS ONLY\n" : "PROTOTYPE · TEST ASSETS ONLY\n")
                + (SystemCredential.willBind(this) && !pin.isSet()
                        ? "Your PIN will be held by the security chip."
                        : remaining + " attempts remaining. " + VaultPin.MAX_ATTEMPTS + " failed attempts erase the wallet."));
        gate.setSubmitRequired(remaining == 1 && !pin.eraseOutstanding());
    }

    private void confirmRevealBackup() { seedQrRequested = false; startBackupAccess(false); }

    private void startBackupAccess(boolean checkOnly) {
        beginSensitive(checkOnly ? "check your backup" : "view your recovery phrase",
                () -> openBackup(activeSensitive, session.get(), checkOnly, false));
    }

    /**
     * Decrypt the phrase for the sensitive flow {@code token} already owns. If the chip refuses
     * because the PIN window closed before the decrypt reached it (SeedKeyWindow), ask for the PIN
     * once more and retry inside the SAME flow: re-entering {@link #beginSensitive} would be
     * refused (the flow is still active) and leave the loading screen up for good.
     */
    private void openBackup(int token, int s, boolean checkOnly, boolean retried) {
        showLoading("Opening secure backup", "Keep cameras and other people away from your screen.");
        cryptoExecutor.execute(() -> {
            try {
                if (!sensitiveValid(token, s)) return;
                String mnemonic = vault.revealMnemonic(() -> sensitiveValid(token, s));
                String[] words = mnemonic.split(" ");
                runOnUiThread(() -> {
                    if (!sensitiveValid(token, s)) { Arrays.fill(words, null); return; }
                    backupWords = words;
                    backupIdentity = walletId; // the backup covers the wallet: its account-0 identity
                    backupPage = checkOnly ? 0 : Math.min(resumeBackupPage, 5); resumeBackupPage = 0;
                    startSeedTimer();
                    if (checkOnly) startWordCheck();
                    else if (seedQrRequested) showSeedQr();
                    else showPhrasePage();
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (!sensitiveValid(token, s)) return;
                    if (!retried && authLapsed(e)) {
                        lastCredentialConfirm = 0;
                        confirmDevicePin("Confirm your PIN to open your backup",
                                () -> { if (sensitiveValid(token, s)) openBackup(token, s, checkOnly, true); },
                                this::hideBackup);
                        return;
                    }
                    Log.w(TAG, "backup open failed: " + chain(e));
                    showInfo("Backup unavailable", "The stored phrase could not be opened. Lock and retry; do not replace this wallet to fix a storage problem.", this::hideBackup);
                });
            }
        });
    }

    // ------------------------------------------------------------------ SeedQR + backup reminder
    // (logic lives in SeedQr / SeedQrView / BackupReminder; these are only the screens)

    /** True when the PIN-gated reveal should open on the SeedQR instead of the words. */
    private boolean seedQrRequested;
    private SeedQr.Format seedQrFormat = SeedQr.Format.COMPACT;
    private SeedQrView seedQrView;

    private void confirmRevealSeedQr() { seedQrRequested = true; startBackupAccess(false); }

    /**
     * The recovery phrase as a SeedQR, for copying onto the backup card's grid. Same protections as
     * the phrase pages: inside the sensitive flow (PIN, no USB session), FLAG_SECURE window, the seed
     * timer, and Hide / Back / lock clear it.
     */
    private void showSeedQr() {
        if (!sensitive.active() || backupWords == null || replacementCandidate != null) return;
        wipeSeedQr();
        SeedQr.Modules modules;
        try {
            modules = SeedQr.encode(backupWords, seedQrFormat);
        } catch (RuntimeException e) {
            Log.w(TAG, "SeedQR unavailable: " + e.getClass().getSimpleName());
            showInfo("SeedQR unavailable", "This recovery phrase could not be shown as a SeedQR. Your written words are the backup; nothing changed.", this::hideBackup);
            return;
        }
        boolean compact = seedQrFormat == SeedQr.Format.COMPACT;
        LinearLayout root = page("RECOVERY PHRASE · SEEDQR",
                compact ? "CompactSeedQR · 25 × 25" : "Standard SeedQR · 29 × 29",
                "Copy each black square onto the matching grid of your backup card: row and column numbers match. Never photograph or scan this screen.");
        seedQrView = new SeedQrView(this, modules);
        root.addView(seedQrView, matchWrap(dp(4)));
        card(root, "Same secret as your 24 words", compact
                ? "SeedSigner CompactSeedQR (binary). Use the card with the 25 × 25 grid. Wallets that support SeedQR restore it; ordinary camera apps cannot read it."
                : "SeedSigner Standard SeedQR (digits). Use the card with the 29 × 29 grid. More squares to copy, and any QR reader can decode it.");
        action(root, "Hide", true, this::hideBackup);
        action(root, compact ? "Use Standard SeedQR (29 × 29)" : "Use CompactSeedQR (25 × 25)", false, () -> {
            seedQrFormat = compact ? SeedQr.Format.STANDARD : SeedQr.Format.COMPACT;
            showSeedQr();
        });
        action(root, "Show as words", false, () -> { wipeSeedQr(); backupPage = 0; showPhrasePage(); });
        addSeedTimer(root);
        present(root, "backup-seedqr");
    }

    private void wipeSeedQr() {
        if (seedQrView != null) seedQrView.wipe();
        seedQrView = null;
    }

    /** Home, verified wallet, no request in progress: a gentle periodic "check your backup". */
    private void addBackupReminderCard(LinearLayout root) {
        if (!backupVerified || transport != null || approvalDecision != null || requestPending.get()) return;
        long now = System.currentTimeMillis();
        if (!backupReminder.due(now)) return;
        LinearLayout box = VaultTheme.box(this);
        box.addView(VaultTheme.bodyText(this, "BACKUP CHECK", 13, VaultTheme.FAINT));
        TextView headline = VaultTheme.bodyText(this, backupReminder.headline(now), VaultTheme.BODY_SIZE, VaultTheme.INK);
        headline.setPadding(0, dp(6), 0, 0);
        box.addView(headline);
        TextView body = VaultTheme.bodyText(this, "Pick 3 words from your written backup. Your phrase is not shown.", VaultTheme.BODY_SIZE - 2, VaultTheme.DIM);
        body.setPadding(0, dp(6), 0, 0);
        box.addView(body);
        action(box, "Check my backup now", false, () -> startBackupAccess(true));
        action(box, "Remind me in 2 weeks", false, () -> {
            if (!backupReminder.snooze(System.currentTimeMillis())) statusMessage = "Reminder snooze not saved";
            showHome();
        });
        root.addView(box, matchWrap(dp(12)));
    }

    private void showBackupReminderSettings() {
        LinearLayout root = page("SECURITY / BACKUP REMINDER", "Check your backup",
                "Now and then Home suggests a two-minute check: pick 3 words from your written backup. Your phrase is not shown, and the reminder never interrupts a request.");
        int last = backupReminder.lastCheckDay();
        card(root, "Last checked", last < 0 ? "Not recorded on this phone yet"
                : LocalDate.ofEpochDay(last) + " (by this phone's clock)");
        int current = backupReminder.intervalDays();
        for (int days : BackupReminder.CHOICES) {
            action(root, BackupReminder.label(days), days == current, () -> {
                if (backupReminder.setIntervalDays(days)) showBackupReminderSettings();
                else showInfo("Setting not saved", "Your previous reminder setting is still active.", this::showBackupReminderSettings);
            });
        }
        action(root, "Back to Security", false, this::showSecurity);
        present(root, "reminder-settings");
    }

    private void startSeedTimer() {
        long now = SystemClock.elapsedRealtime();
        seedHardDeadline = now + SEED_SESSION_MS;
        seedIdleDeadline = now + SEED_TIMEOUT_MS;
        // The phrase/SeedQR has its own hide timer; don't let a short screen timeout switch the
        // screen off (and lock) while someone is copying words. Cleared in clearSensitiveUi.
        keepScreenOn(true);
        ui.removeCallbacks(hideSeed);
        ui.post(hideSeed);
    }

    private void tickSeedTimer() {
        if (!sensitive.active() || backupWords == null || replacement.state() == ReplacementState.COMMITTING) return;
        long remaining = Math.min(seedHardDeadline, seedIdleDeadline) - SystemClock.elapsedRealtime();
        if (remaining <= 0) {
            boolean discarded = replacementCandidate != null;
            if (!discarded) resumeBackupPage = backupPage;
            hideBackup();
            statusMessage = discarded ? "Backup timed out. Candidate discarded; keep your current wallet and discard the partial NEW backup."
                    : "Backup hidden after 2 minutes without a touch. Verify your PIN to continue from page " + (resumeBackupPage + 1) + " of 6.";
            showInfo("Backup hidden", statusMessage, this::showHome);
            return;
        }
        if (seedTimer != null) seedTimer.setText("Hides in " + ((remaining + 999) / 1000) + "s · any touch restarts the timer · 8 minute session limit");
        ui.postDelayed(hideSeed, 1000);
    }

    private void addSeedTimer(LinearLayout root) {
        seedTimer = VaultTheme.bodyText(this, "", 14, VaultTheme.FAINT);
        seedTimer.setPadding(0, dp(18), 0, 0);
        root.addView(seedTimer);
        ui.removeCallbacks(hideSeed);
        tickSeedTimer();
    }

    private void showPhrasePage() {
        if (!sensitive.active() || backupWords == null) return;
        LinearLayout root = page(replacementCandidate == null ? "RECOVERY PHRASE" : "NEW WALLET · NOT ACTIVE",
                "Write words " + (backupPage * 4 + 1) + "–" + (backupPage * 4 + 4),
                "Page " + (backupPage + 1) + " of 6. Write each word beside its number. Never photograph or share your phrase.");
        for (int i = backupPage * 4; i < backupPage * 4 + 4; i++) {
            LinearLayout row = VaultTheme.box(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            TextView number = VaultTheme.monoText(this, String.format(Locale.ROOT, "%02d", i + 1), 18, VaultTheme.FAINT);
            number.setWidth(dp(44));
            row.addView(number);
            row.addView(VaultTheme.monoText(this, backupWords[i], 23, VaultTheme.INK),
                    new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
            root.addView(row, matchWrap(dp(12)));
        }
        if (backupPage < 5) action(root, "Next four words", true, () -> { backupPage++; showPhrasePage(); });
        else action(root, "I've written them down · spot-check", true, this::startWordCheck);
        if (backupPage > 0) action(root, "Previous words", false, () -> { backupPage--; showPhrasePage(); });
        if (replacementCandidate == null) action(root, "Show as SeedQR", false, this::showSeedQr);
        action(root, replacementCandidate == null ? "Hide phrase" : "Cancel · keep current wallet", false, this::hideBackup);
        addSeedTimer(root);
        present(root, "phrase");
    }

    private void startWordCheck() {
        if (backupWords == null || !sensitive.active()) return;
        if (backupChallenge != null) backupChallenge.destroy();
        backupChallenge = new BackupCheck.Challenge(backupWords, random);
        showWordCheck();
    }

    private void showWordCheck() {
        if (backupChallenge == null || !sensitive.active()) return;
        int position = backupChallenge.position();
        LinearLayout root = page("BACKUP CHECK · " + (backupChallenge.progress() + 1) + " OF " + backupChallenge.total(),
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
        final int token = activeSensitive, s = session.get();
        for (String choice : choices) action(root, choice, false, () -> {
            if (!sensitiveValid(token, s) || backupChallenge != challenge) return;
            if (!challenge.answer(choice)) {
                challenge.destroy();
                LinearLayout failed = page("BACKUP NEEDS ATTENTION", "That word did not match", "Check the number and spelling on your paper. Receiving stays paused until the full check is complete.");
                action(failed, "Review recovery words", true, () -> { backupPage = 0; showPhrasePage(); });
                action(failed, "Restart the 24-word check", false, this::startWordCheck);
                action(failed, "Cancel", false, this::hideBackup);
                addSeedTimer(failed);
                present(failed, "backup-error");
            } else if (challenge.complete()) showBackupChecked();
            else showWordCheck();
        });
        action(root, "Cancel check", false, this::hideBackup);
        addSeedTimer(root);
        present(root, "backup-check");
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
        LinearLayout root = page(checked + " OF " + checked + " WORDS CHECKED",
                replacementCandidate == null ? "Your backup matches" : "Ready to replace?",
                replacementCandidate == null ? "Confirm the account below. This check does not replace an independent restore drill."
                        : "Your current wallet will be replaced. Keep its backup if it controls any assets. The new wallet is not active until you confirm.");
        card(root, replacementCandidate == null ? "Account 1" : "New Account 1",
                Keys.toChecksumAddress(address));
        card(root, "Derivation", "m/44'/60'/0'/0/0 · no passphrase");
        action(root, replacementCandidate == null ? "Confirm account & finish" : "Activate new wallet", true,
                replacementCandidate == null ? this::saveBackupCheck
                        : () -> withSeedKey("Confirm your PIN to activate the new wallet", this::activateReplacement));
        action(root, "Cancel", false, this::hideBackup);
        present(root, "backup-confirm");
    }

    private void saveBackupCheck() {
        final int token = activeSensitive, s = session.get();
        final String address = backupIdentity;
        showLoading("Saving backup check", "Confirming this account's recovery status…");
        cryptoExecutor.execute(() -> {
            try {
                synchronized (stateLock) {
                    if (!sensitiveValid(token, s) || credentials == null || address == null || !address.equalsIgnoreCase(walletId)) return;
                    backupCheck.record(address);
                    backupVerified = true;
                }
                runOnUiThread(() -> {
                    if (!sensitiveValid(token, s)) return;
                    statusMessage = "Backup checked · ready to receive";
                    hideBackup();
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (sensitiveValid(token, s))
                        showInfo("Backup status not saved", "Your wallet is unchanged. Please repeat the check before receiving or signing.", this::hideBackup);
                });
            }
        });
    }

    private void confirmReplace() {
        if (!backupVerified) {
            showInfo("Check your existing backup first", "Replacing a wallet requires a verified backup of the current account.", this::showHome);
            return;
        }
        beginSensitive("replace your wallet", () -> {
            final int token = activeSensitive, s = session.get();
            LinearLayout root = page("SECURITY / REPLACE WALLET", "Keep your current backup", "Replacement creates a different account. Assets on the old account remain controlled by its original phrase.");
            card(root, "Nothing changes yet", "You will write down all 24 new words and pass a spot-check before a separate Activate step. Cancellation keeps your current wallet.");
            action(root, "Prepare a new wallet", true, () -> {
                if (!sensitiveValid(token, s)) return;
                int op = beginReplacement();
                if (op < 0) return;
                replacementOperation = op;
                showLoading("Preparing a new wallet", "Your current wallet remains active until the final confirmation.");
                cryptoExecutor.execute(() -> {
                    try {
                        if (!sensitiveValid(token, s)) return;
                        SeedVault.Generation candidate = vault.prepareReplacement(new byte[0]);
                        recordEntropyReport(false);
                        runOnUiThread(() -> {
                            if (!sensitiveValid(token, s) || !markPrepared(op)) return;
                            replacementCandidate = candidate;
                            backupWords = candidate.mnemonic.split(" ");
                            backupPage = 0;
                            startSeedTimer();
                            showPhrasePage();
                        });
                    } catch (Exception e) {
                        endReplacement(op);
                        runOnUiThread(() -> {
                            if (sensitiveValid(token, s))
                                showInfo("Could not prepare a wallet", "Your current wallet is unchanged. Lock and retry.", this::hideBackup);
                        });
                    }
                });
            });
            action(root, "Cancel · keep current wallet", false, this::hideBackup);
            present(root, "replace-confirm");
        });
    }

    private void activateReplacement() {
        final int token = activeSensitive, s = session.get(), op = replacementOperation;
        final SeedVault.Generation candidate = replacementCandidate;
        if (candidate == null || !sensitiveValid(token, s) || !beginCommit(op)) return;
        ui.removeCallbacks(hideSeed);
        clearReceivingIdentity();
        showLoading("Activating your new wallet", "Saving and checking the new identity. This step can no longer be cancelled.");
        cryptoExecutor.execute(() -> {
            try {
                synchronized (stateLock) {
                    if (!sensitiveValid(token, s) || !replacement.owns(op) || transport != null || requestPending.get()) return;
                    credentials = null;
                    Credentials fresh = vault.commitReplacement(candidate.mnemonic);
                    backupCheck.record(fresh.getAddress());
                    credentials = fresh;
                    adoptNewWallet(fresh.getAddress());
                    walletAddress = fresh.getAddress();
                    backupVerified = true;
                    walletLoaded = true;
                    endReplacement(op);
                }
                Bitmap qr = qrFor(candidate.address);
                runOnUiThread(() -> {
                    if (!sensitiveValid(token, s)) return;
                    walletQr = qr;
                    statusMessage = "New wallet active · backup checked";
                    hideBackup();
                });
            } catch (Exception e) {
                synchronized (stateLock) { credentials = null; clearReceivingIdentity(); endReplacement(op); }
                runOnUiThread(() -> {
                    if (s != session.get()) return;
                    gateNotice = "Storage could not confirm the wallet. Re-enter your PIN to reconcile it. No receiving address is available until loading succeeds.";
                    lock();
                });
            }
        });
    }

    private static void secure(Window window) {
        if (!DevTools.SCREENSHOTS) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }

    private void clearReceivingIdentity() {
        clearBtcWallets();
        walletLoaded = false;
        backupVerified = false;
        walletAddress = null;
        walletQr = null;
        activeAccount = null;
        walletId = null;
    }

    private void loadKey() {
        final int s = session.get();
        final VaultKeyStore store = vault;
        clearReceivingIdentity();
        showLoading("Opening your wallet", "Checking the saved identity before displaying an address…");
        cryptoExecutor.execute(() -> {
            try {
                if (s != session.get() || !unlocked || pin.eraseOutstanding()) return;
                if (!store.hasWallet()) {
                    // First run: never silently mint a wallet — the user chooses Create or Restore.
                    // (hasWallet() throws when storage is sealed/corrupt → the catch below.)
                    runOnUiThread(() -> { if (s == session.get() && unlocked) showFirstRunChoice(); });
                    return;
                }
                if (credentialMode() && !store.credentialBound()) store.migrateToCredentialKey();
                // The standard wallet's active account (saved list); one decrypt, like before.
                // Unlock always opens the standard wallet: a passphrase wallet must be re-entered.
                String savedBook = getSharedPreferences(ACCOUNT_PREFS, MODE_PRIVATE).getString(ACCOUNT_BOOK_KEY, null);
                SeedVault.Derived derived = store.deriveAccount(AccountBook.storedActiveIndex(savedBook), null);
                AccountBook book = AccountBook.load(savedBook, derived.account0Address);
                if (book.activeIndex() != derived.index) derived = store.deriveAccount(book.activeIndex(), null);
                String address = derived.credentials.getAddress();
                if (!book.active().address.equalsIgnoreCase(address)) {
                    // Saved metadata disagrees with the seed: start the list over at account 1.
                    book = AccountBook.fresh(derived.account0Address);
                    if (derived.index != 0) derived = store.deriveAccount(0, null);
                    address = derived.credentials.getAddress();
                }
                final Credentials loaded = derived.credentials;
                final AccountBook loadedBook = book;
                Bitmap qr = qrFor(address);
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked || !operational) return;
                    credentials = loaded;
                    clearPassphraseWallet();
                    walletId = derived.account0Address;
                    standardBook = loadedBook;
                    activeAccount = new SigningAccount(loadedBook.activeIndex(), loadedBook.active().name(), false, derived.fingerprint, address);
                    walletAddress = address;
                    walletQr = qr;
                    backupVerified = backupCheck.verified(walletId);
                    walletLoaded = true;
                }
                saveStandardBook(loadedBook);
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    silentUnlockAttempt = false;
                    showHome();
                    drainPendingUsb();
                    if (transport != null) setStatusActive(true); // a session opened behind the gate
                    dispatchHeldRequest();
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    credentials = null;
                    clearReceivingIdentity();
                    Log.w(TAG, "wallet load failed: " + chain(e));
                    if (authLapsed(e)) {
                        if (!silentUnlockAttempt) gateNotice = "Your PIN confirmation expired before the wallet opened. Unlock again.";
                        silentUnlockAttempt = false;
                        lock();
                        return;
                    }
                    LinearLayout root = page("WALLET UNAVAILABLE", "Your address is hidden", "The stored identity could not be verified. Do not replace or reset the wallet to fix this error.");
                    card(root, "Next step", "Lock and retry. If the problem continues, preserve this device and use your written backup with a compatible recovery tool.");
                    action(root, "Lock & retry", true, this::lock);
                    present(root, "wallet-error");
                });
            }
        });
    }

    private Bitmap qrFor(String address) {
        Bitmap qr = VaultTheme.qrBitmap(address, dp(232), dp(12));
        if (qr == null) throw new IllegalStateException("QR could not be generated");
        return qr;
    }

    private void handleIntent(Intent intent) {
        if (!operational || intent == null) return;
        if (!UsbManager.ACTION_USB_ACCESSORY_ATTACHED.equals(intent.getAction())) return;
        if (!unlocked) {
            // USB data-lock (app layer): while locked the phone READS the host's request so the
            // gate can show what is waiting, but it never answers — no bytes leave until the PIN
            // is entered and the request has gone through the ordinary review path.
            UsbAccessory gated = intent.getParcelableExtra(UsbManager.EXTRA_ACCESSORY);
            if (gated == null) return;
            synchronized (stateLock) { clearHeldRequest(); } // a new connection never inherits a held request
            if (pinScreen != null) pinScreen.setPending(null, null);
            if (transport != null) { AccessoryTransport previous = transport; transport = null; previous.close(); }
            try {
                AccessoryTransport opened = AccessoryTransport.open((UsbManager) getSystemService(USB_SERVICE), gated, this);
                transport = opened;
                opened.start();
                pendingUsb = null;
                keepScreenOn(true);
                if (pinScreen != null) pinScreen.setSubtitle("Enter your six-digit PIN. A USB host is connected; its request will appear here.");
            } catch (Exception exception) {
                transport = null;
                pendingUsb = intent; // fall back to replaying the attach after unlock
                if (pinScreen != null) pinScreen.setSubtitle("Enter PIN to unlock.  USB host is waiting.");
            }
            return;
        }
        if (replacementActive() || sensitive.active() || !walletLoaded || !backupVerified) {
            // Sensitive screens, incomplete backup, and USB are mutually exclusive. Park the host
            // until the replacement completes or is cancelled (then replayed from there).
            pendingUsb = intent;
            statusMessage = "USB host waiting · finish wallet setup or security action";
            if (statusView != null) statusView.setText(statusMessage);
            return;
        }
        UsbAccessory accessory = intent.getParcelableExtra(UsbManager.EXTRA_ACCESSORY);
        if (accessory == null) return;
        synchronized (stateLock) { clearHeldRequest(); }
        if (transport != null) {
            AccessoryTransport previous = transport;
            transport = null;
            previous.close();
        }
        boolean replacedRequest = approvalDecision != null;
        cancelApproval();
        if (replacedRequest) showReceipt("USB session changed", "The previous request ended. If you tapped Sign, check the host for a possible signature before retrying.", null);
        try {
            AccessoryTransport opened = AccessoryTransport.open(
                    (UsbManager) getSystemService(USB_SERVICE), accessory, this);
            transport = opened;  // publish first …
            opened.start();      // … then let callbacks fire; none can be mis-attributed now
            statusMessage = "USB connected · waiting for a request";
            if (statusView != null) statusView.setText(statusMessage);
        } catch (Exception exception) {
            transport = null;
            statusMessage = "USB connection failed · reconnect the host";
            if (statusView != null) statusView.setText(statusMessage);
        }
    }

    @Override public void onConnected(AccessoryTransport source) {
        if (source != transport) return;
        runOnUiThread(() -> {
            if (source != transport || !unlocked) return;
            usbReplugHint = false;
            setStatusActive(true);
        });
    }


    @Override public void onRequest(AccessoryTransport source, JSONObject json) {
        if (source != transport) return;
        if (!unlocked) {
            // Gate mode: decode for the lock screen, hold, answer nothing.
            final String label, body;
            String l = "INCOMING REQUEST", b;
            try {
                if ("getAddress".equals(json.optString("method"))) {
                    Eip1559Request.requireExactFields(json, "id", "method");
                    b = "The connected host asks for your receiving address. Unlock to continue.";
                } else if (AttestationProtocol.handles(json.optString("method"))) {
                    // Held like getAddress: the answer names the wallet address, and nothing
                    // leaves a locked phone (device-attestation.md, "Locked phone").
                    AttestationProtocol.parseChallenge(json);
                    b = "The connected host asks this phone to prove it is genuine Phone Vault hardware and firmware. Unlock to continue.";
                } else if (MessageRequest.handles(json.optString("method"))) {
                    b = MessageReview.lockedSummary(MessageRequest.parse(json));
                } else if (BtcRequest.handles(json.optString("method"))) {
                    b = BtcRequest.lockedSummary(json);
                } else {
                    b = TransactionReview.build(Eip1559Request.parse(json), null, tokens()).lockedSummary;
                }
                synchronized (stateLock) { if (!unlocked && source == transport) { heldRequest = json; heldSummary = b; heldSource = source; } }
            } catch (Exception e) {
                b = e instanceof RequestRefusal ? e.getMessage() + " It will be refused after you unlock."
                        : "The connected host sent a request this phone cannot decode. It will be refused after you unlock.";
                synchronized (stateLock) { if (!unlocked && source == transport) { heldRequest = json; heldSummary = b; heldSource = source; } }
            }
            label = l; body = b;
            runOnUiThread(() -> { if (!unlocked && pinScreen != null && source == transport) pinScreen.setPending(label, body); });
            return;
        }
        String id = json.optString("id", "unknown");
        final int s = session.get();
        synchronized (stateLock) {
            if (!operational || !unlocked || !walletLoaded || !backupVerified
                    || sensitive.active() || replacementActive()) {
                sendError(source, id, "Wallet is not ready: unlock and complete the backup check first");
                return;
            }
            if (passphraseEntry || activeAccount == null) {
                sendError(source, id, "Wallet is not ready: finish choosing the account on the phone, then try again");
                return;
            }
        }
        if (BtcRequest.handles(json.optString("method"))) {
            handleBitcoin(source, json, id, s);
            return;
        }
        if ("getAddress".equals(json.optString("method"))) {
            try {
                Eip1559Request.requireExactFields(json, "id", "method");
                id = Eip1559Request.validatedId(json.getString("id"));
                synchronized (stateLock) {
                    if (s != session.get() || source != transport || !unlocked || !backupVerified || sensitive.active()) return;
                    SigningAccount account = activeAccount;
                    if (credentials == null || account == null || !account.address.equalsIgnoreCase(credentials.getAddress())) {
                        throw new IllegalStateException("Wallet is not ready: finish choosing the account on the phone");
                    }
                    // The ACTIVE account, plus which one it is (1-based number, standard/passphrase)
                    // so the companion can label its pairing. No label, no fingerprint, no passphrase.
                    source.send(json("id", id, "status", "ok", "address", credentials.getAddress(),
                            "account", account.accountNumber(), "wallet", account.walletKind()));
                }
            } catch (Exception e) { sendError(source, id, e.getMessage()); }
            return;
        }
        if (AttestationProtocol.handles(json.optString("method"))) {
            answerAttestation(source, json, id, s);
            return;
        }
        final ApprovalDecision decision;
        synchronized (stateLock) {
            if (!requestPending.compareAndSet(false, true)) {
                sendError(source, id, "Another approval is pending");
                return;
            }
            decision = new ApprovalDecision(stateLock);
            approvalDecision = decision;
        }
        try {
            // The ACTIVE account signs: key and its description are read together.
            final Credentials signer;
            final SigningAccount account;
            synchronized (stateLock) { signer = credentials; account = activeAccount; }
            if (signer == null || account == null || !account.address.equalsIgnoreCase(signer.getAddress())) {
                throw new IllegalStateException("Wallet is not ready: finish choosing the account on the phone");
            }
            if (MessageRequest.handles(json.optString("method"))) {
                // Parsed once: the review and the digest both come from this object.
                MessageRequest message = MessageRequest.parse(json);
                RequestRefusal.requireFrom(message.from, account.headline(), account.address);
                MessageApprovalSession approval = new MessageApprovalSession(message, signer, account);
                runOnUiThread(() -> showMessageApproval(source, approval, decision, s));
                return;
            }
            Eip1559Request request = Eip1559Request.parse(json);
            RequestRefusal.requireFrom(request.from, account.headline(), account.address);
            AddressSafety safety = safety();
            safety.setOwnAccounts(ownAccountNames());
            ApprovalSession approval = new ApprovalSession(request, signer, tokens(), safety, account);
            runOnUiThread(() -> showApproval(source, approval, decision, s));
        } catch (Exception e) {
            finishApproval(decision);
            sendError(source, id, e.getMessage());
            if (e instanceof RequestRefusal) {
                RequestRefusal refusal = (RequestRefusal) e;
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked || source != transport || sensitive.active() || approvalDecision != null) return;
                    showInfo(refusal.title, refusal.getMessage(), this::showHome);
                    Haptics.reject(getWindow().getDecorView());
                });
            }
        }
    }

    /**
     * USB "attest": a fresh StrongBox key attests the host's challenge and signs the binding of
     * that challenge to this wallet's address (AttestationProtocol). No review screen: it signs
     * nothing with the wallet key and reveals nothing beyond the address getAddress already gives
     * an unlocked phone. Runs off the signing thread; one at a time; a challenge is answered once.
     */
    private void answerAttestation(AccessoryTransport source, JSONObject json, String fallbackId, int s) {
        final String id;
        final byte[] challenge;
        try {
            challenge = AttestationProtocol.parseChallenge(json);
            id = json.getString("id");
        } catch (Exception e) { sendError(source, fallbackId, e.getMessage()); return; }
        if (!attestChallenges.firstUse(challenge)) { sendError(source, id, "This challenge was already answered"); return; }
        if (!attesting.compareAndSet(false, true)) { sendError(source, id, "Another attestation is in progress"); return; }
        final String address;
        synchronized (stateLock) {
            if (s != session.get() || source != transport || !unlocked || !walletLoaded || credentials == null) {
                attesting.set(false);
                sendError(source, id, "Wallet is not ready: unlock and complete the backup check first");
                return;
            }
            address = credentials.getAddress();
        }
        try {
            attestExecutor.execute(() -> {
                try {
                    AttestationKey.Result r = AttestationKey.attest(challenge, address);
                    JSONObject reply = AttestationProtocol.response(id, address, r.securityLevel, r.chain, r.signature);
                    synchronized (stateLock) {
                        if (s != session.get() || source != transport || !unlocked) return;
                        source.send(reply);
                    }
                } catch (Exception e) {
                    sendError(source, id, "Attestation failed: " + e.getClass().getSimpleName());
                } finally {
                    attesting.set(false);
                }
            });
        } catch (RejectedExecutionException closing) {
            attesting.set(false);
        }
    }

    /**
     * Window flags belong to the UI thread. A change from any other thread (the USB reader, the
     * crypto executor) makes ViewRootImpl throw CalledFromWrongThreadException half-way through
     * a relayout: the decor view is left "layout requested" with no traversal scheduled, so the
     * window never draws again, and the exception ends the USB session before the host gets its
     * answer. Every keep-screen-on change goes through here (MainActivityThreadingTest).
     */
    private void keepScreenOn(boolean on) {
        runOnUiThread(() -> {
            if (on) getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        });
    }

    /** Releases the approval slot; callable from any thread (the refusal path runs on the USB reader). */
    private void finishApproval(ApprovalDecision owner) {
        keepScreenOn(false);
        synchronized (stateLock) {
            if (approvalDecision != owner) return;
            approvalDecision = null;
            requestPending.set(false);
        }
    }

    private void cancelApproval() {
        synchronized (stateLock) {
            if (approvalDecision != null) approvalDecision.cancel();
            approvalDecision = null;
            requestPending.set(false);
        }
    }

    /** Under stateLock or on the UI thread: the request still owns its slot, with the checks {@code need} names. */
    private boolean owns(AccessoryTransport source, int s, ApprovalDecision decision, Set<RequestOwnership.Require> need) {
        return RequestOwnership.holds(live, source, s, decision, need);
    }

    /** Before drawing a request's screen: false if it still owns its slot; else cancels, releases the slot, true. */
    private boolean abandonUnlessOwned(AccessoryTransport source, int s, ApprovalDecision decision,
                                       Set<RequestOwnership.Require> need) {
        if (owns(source, s, decision, need)) return false;
        decision.cancel();
        finishApproval(decision);
        return true;
    }

    private void showApproval(AccessoryTransport source, ApprovalSession approval,
                              ApprovalDecision decision, int s) {
        if (abandonUnlessOwned(source, s, decision, RequestOwnership.SHOW_REVIEW)) return;
        // Rendered from the review built with this exact request in ApprovalSession (same object that is signed).
        TransactionReview review = approval.review;
        keepScreenOn(true);
        LinearLayout root = page(DevTools.SCREENSHOTS ? "DEVELOPMENT · TEST ASSETS ONLY" : review.kicker,
                review.title, review.subtitle);
        List<MessageReview.Row> dangers = ReviewStyle.dangers(review.summary, review.details,
                approval.hostSimulation != null ? approval.hostSimulation.rows : null);
        addDangerSummary(root, dangers);
        if (approval.signingAs != null) root.addView(detail("Signing with", approval.signingAs.signingWith()));
        for (MessageReview.Row row : review.summary) root.addView(detail(row));
        addDetailsToggle(root, review.details, "technical details");
        if (approval.hostSimulation != null) {
            // The Mac's claim, in its own box BELOW the phone's own review; display only, never signed.
            SimulationCheck.Result sim = approval.hostSimulation;
            LinearLayout box = VaultTheme.box(this);
            box.addView(VaultTheme.bodyText(this, sim.title, 13, sim.contradicts ? VaultTheme.DANGER_INK : VaultTheme.FAINT));
            box.addView(VaultTheme.rule(this, dp(8), dp(10)));
            for (MessageReview.Row row : sim.rows) box.addView(detail(row));
            root.addView(box, matchWrap(dp(16)));
        }
        addDecisionControls(root, source, decision, s, approval.request.id, review.reviewPrompt, review.signLabel, dangers,
                approval::signIfIdentityUnchanged,
                "The response was queued for USB. Check your host for receipt and broadcast status. Unplugging cannot revoke a signature already received.",
                "Transaction hash", "transactionHash", true, () -> {
                    // A signature exists: count its counterparties in this phone's history and offer to name them.
                    safety().record(approval.reviewedAddress(), review.parties, System.currentTimeMillis());
                    receiptParties = review.parties;
                });
        present(root, "approval");
    }

    /**
     * The token list built into the APK, checked against its pinned SHA-256 on first use. A list
     * that fails the check is not used: every contract is then reviewed as unknown, and the review
     * says the list was refused.
     */
    private synchronized TokenList tokens() {
        if (tokenList != null) return tokenList;
        try (InputStream in = getResources().openRawResource(R.raw.tokens)) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            for (int n; (n = in.read(buffer)) > 0; ) {
                bytes.write(buffer, 0, n);
                if (bytes.size() > 64 * 1024) break; // loadPinned refuses oversize input
            }
            tokenList = TokenList.loadPinned(bytes.toByteArray());
        } catch (Exception e) {
            tokenList = TokenList.unavailable(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
        return tokenList;
    }

    /** Produces the response for one reviewed request; runs on the crypto thread under stateLock. */
    private interface ReviewedSigner { JSONObject sign(Credentials current) throws Exception; }

    /**
     * Produces the response from the BIP-39 seed (Bitcoin): runs on the crypto thread inside the
     * seed-key window, OUTSIDE stateLock (the decrypt and key derivation take a moment); the
     * response is sent under stateLock only if the session is still the reviewed one.
     */
    private interface SeedSigner { JSONObject sign(byte[] seed) throws Exception; }

    /**
     * The acknowledgement checkbox, Sign and Reject for one request, shared by the transaction and
     * message reviews: one decision, check → sign → send as one step under stateLock.
     */
    private void addDecisionControls(LinearLayout root, AccessoryTransport source, ApprovalDecision decision, int s,
                                     String requestId, String prompt, String signText, List<MessageReview.Row> dangers,
                                     ReviewedSigner signer,
                                     String doneMessage, String receiptLabel, String receiptField, boolean transaction,
                                     Runnable afterSigned) {
        addDecisionControls(root, source, decision, s, requestId, prompt, signText, dangers, signer, null, null,
                doneMessage, receiptLabel, response -> response.optString(receiptField), transaction, afterSigned);
    }

    /** The review's secondary rows behind a Show/Hide button; open from the start if one is a DANGER. */
    private void addDetailsToggle(LinearLayout root, List<MessageReview.Row> rows, String what) {
        LinearLayout raw = new LinearLayout(this);
        raw.setOrientation(LinearLayout.VERTICAL);
        for (MessageReview.Row row : rows) raw.addView(detail(row));
        boolean open = !ReviewStyle.dangers(rows).isEmpty(); // a DANGER is never folded away
        raw.setVisibility(open ? View.VISIBLE : View.GONE);
        TextView details = VaultTheme.pixelButton(this, (open ? "Hide " : "Show ") + what, false);
        hardenTouch(details);
        details.setOnClickListener(v -> {
            boolean visible = raw.getVisibility() == View.VISIBLE;
            raw.setVisibility(visible ? View.GONE : View.VISIBLE);
            details.setText((visible ? "Show " : "Hide ") + what);
        });
        root.addView(details, matchWrap(dp(8)));
        root.addView(raw);
    }

    /** Set on a page's root before {@link #present}: called once the end of the page has been on screen. */
    private interface ScrollEndWatcher { void reachedEnd(); }

    /** Wires a {@link ScrollEndWatcher} tag on the page root to its ScrollView (scrolls and layouts). */
    private void watchScrollEnd(ScrollView scroll, LinearLayout root) {
        if (!(root.getTag() instanceof ScrollEndWatcher)) return;
        ScrollEndWatcher watcher = (ScrollEndWatcher) root.getTag();
        Runnable check = () -> {
            if (scroll.getHeight() == 0) return;
            if (ApprovalGate.atEnd(root.getHeight(), scroll.getScrollY(), scroll.getHeight(), dp(24))) watcher.reachedEnd();
        };
        scroll.setOnScrollChangeListener((v, x, y, ox, oy) -> check.run());
        root.addOnLayoutChangeListener((v, l, t, r, b, ol, ot, or, ob) -> check.run());
        scroll.post(check);
    }

    /**
     * @param seedSigner when non-null (Bitcoin), Sign first opens the seed-key window ({@code seedWhy}
     *                   is the PIN prompt's reason) and the signature is made from the seed; a
     *                   dismissed PIN prompt answers "rejected" and signs nothing
     */
    private void addDecisionControls(LinearLayout root, AccessoryTransport source, ApprovalDecision decision, int s,
                                     String requestId, String prompt, String signText, List<MessageReview.Row> dangers,
                                     ReviewedSigner signer,
                                     SeedSigner seedSigner, String seedWhy,
                                     String doneMessage, String receiptLabel,
                                     Function<JSONObject, String> receiptValue, boolean transaction,
                                     Runnable afterSigned) {
        // Approve needs: the end of the review on screen once, "I verified…", and for a review with
        // a DANGER row a second box that states that danger in words (ApprovalGate).
        ApprovalGate gate = new ApprovalGate(dangers != null && !dangers.isEmpty());
        CheckBox dangerAck = null;
        if (gate.dangerRequired) {
            dangerAck = new CheckBox(this);
            dangerAck.setText(ReviewStyle.dangerAcknowledgement(dangers));
            VaultTheme.size(dangerAck, VaultTheme.BODY_SIZE);
            dangerAck.setTextColor(VaultTheme.DANGER_INK);
            dangerAck.setButtonTintList(ColorStateList.valueOf(VaultTheme.DANGER_INK));
            dangerAck.setMinHeight(dp(56));
            dangerAck.setPadding(dp(4), dp(18), dp(4), dp(18));
            hardenTouch(dangerAck);
            root.addView(dangerAck, matchWrap(dp(12)));
        }
        CheckBox reviewed = new CheckBox(this);
        reviewed.setText(prompt);
        VaultTheme.size(reviewed, VaultTheme.BODY_SIZE);
        reviewed.setTextColor(VaultTheme.INK);
        reviewed.setMinHeight(dp(56));
        reviewed.setPadding(dp(4), dp(18), dp(4), dp(18));
        hardenTouch(reviewed);
        root.addView(reviewed, matchWrap(dp(gate.dangerRequired ? 4 : 12)));
        TextView readToEnd = VaultTheme.bodyText(this, "Approve unlocks once you have scrolled to the end of this review.", 13, VaultTheme.FAINT);
        root.addView(readToEnd, matchWrap(dp(4)));
        TextView sign = VaultTheme.pixelButton(this, signText, true);
        TextView reject = VaultTheme.pixelButton(this, "Reject request", false);
        hardenTouch(sign);
        hardenTouch(reject);
        sign.setEnabled(false);
        Runnable refresh = () -> sign.setEnabled(gate.mayApprove() && decision.state() == ApprovalDecision.State.REVIEW);
        reviewed.setOnCheckedChangeListener((v, checked) -> { gate.setReviewed(checked); refresh.run(); });
        if (dangerAck != null) dangerAck.setOnCheckedChangeListener((v, checked) -> { gate.setDangerAcknowledged(checked); refresh.run(); });
        root.setTag((ScrollEndWatcher) () -> {
            if (gate.hasReachedEnd()) return;
            gate.reachedEnd();
            readToEnd.setVisibility(View.GONE);
            refresh.run();
        });
        final CheckBox dangerBox = dangerAck;
        reject.setOnClickListener(v -> {
            if (!decision.reject()) return;
            Haptics.reject(v);
            source.send(json("id", requestId, "status", "rejected"));
            finishApproval(decision);
            statusMessage = "Request rejected · no signature created";
            showReceipt("Request rejected", "No signature was created for this request.", null, null, transaction);
        });
        sign.setOnClickListener(v -> {
            synchronized (stateLock) {
                if (!owns(source, s, decision, RequestOwnership.SIGN_PRESSED) || !reviewed.isChecked() || !gate.mayApprove()
                        || (dangerBox != null && !dangerBox.isChecked()) || !decision.beginSigning()) return;
            }
            // The decision is now irreversible through Reject. Lock still invalidates queued work.
            Haptics.confirm(v);
            sign.setEnabled(false);
            reject.setEnabled(false);
            reviewed.setEnabled(false);
            if (dangerBox != null) dangerBox.setEnabled(false);
            sign.setText("Signing…");
            statusMessage = "Signing approved request";
            Runnable work = () -> cryptoExecutor.execute(() -> {
                boolean mayHaveLeft = seedSigner == null; // the seed path sends only after signing completes
                try {
                    JSONObject response;
                    if (seedSigner != null) {
                        synchronized (stateLock) {
                            if (!owns(source, s, decision, RequestOwnership.SIGNING)) throw new IllegalStateException("Session ended before signing");
                        }
                        JSONObject prepared = vault.withStandardSeed(seedSigner::sign);
                        synchronized (stateLock) {
                            if (!owns(source, s, decision, RequestOwnership.SIGNING)) throw new IllegalStateException("Session ended before signing");
                            mayHaveLeft = true;
                            if (!source.send(prepared)) throw new IllegalStateException("Signature delivery is uncertain");
                            decision.finish();
                        }
                        response = prepared;
                    } else {
                        synchronized (stateLock) {
                            if (!owns(source, s, decision, RequestOwnership.SIGNING))
                                throw new IllegalStateException("Session ended before signing");
                            response = signer.sign(credentials);
                            if (!source.send(response)) throw new IllegalStateException("Signature delivery is uncertain");
                            decision.finish();
                        }
                    }
                    final JSONObject sent = response;
                    runOnUiThread(() -> {
                        if (s != session.get() || !unlocked || approvalDecision != decision) return;
                        finishApproval(decision);
                        statusMessage = "Signature created · delivery not confirmed";
                        if (afterSigned != null) afterSigned.run();
                        showReceipt("Signature created", doneMessage, receiptLabel, receiptValue.apply(sent), transaction);
                    });
                } catch (Exception e) {
                    final boolean uncertain = mayHaveLeft;
                    final boolean lapsed = authLapsed(e);
                    sendError(source, requestId, uncertain ? e.getMessage()
                            : (lapsed ? "PIN confirmation expired before signing; nothing was signed" : "Not signed: " + e.getMessage()));
                    if (!uncertain) Log.w(TAG, "seed signing failed: " + chain(e));
                    runOnUiThread(() -> {
                        if (s != session.get() || !unlocked || approvalDecision != decision) return;
                        finishApproval(decision);
                        if (!uncertain) {
                            statusMessage = "Not signed";
                            showReceipt("Not signed", lapsed
                                    ? "Your PIN confirmation expired before signing finished. No signature left the phone; send the request again."
                                    : "Signing did not complete. No signature left the phone.", null, null, transaction);
                            return;
                        }
                        showReceipt("Check the host", transaction
                                ? "Signing or delivery did not complete normally. A signature may have reached the host. Check before creating another transaction."
                                : "Signing or delivery did not complete normally. A signature may have reached the host. Check before signing again.",
                                null, null, transaction);
                    });
                }
            });
            if (seedSigner == null) {
                work.run();
                return;
            }
            withSeedKey(seedWhy, work, () -> {
                synchronized (stateLock) { if (approvalDecision != decision) return; }
                decision.cancel();
                source.send(json("id", requestId, "status", "rejected"));
                finishApproval(decision);
                statusMessage = "Not signed · PIN not confirmed";
                showReceipt("Not signed", "The PIN was not confirmed, so nothing was signed.", null, null, transaction);
            });
        });
        root.addView(sign, matchWrap(dp(8)));
        root.addView(reject, matchWrap(dp(10)));
    }

    /** Review for personal_sign / eth_signTypedData_v4, rendered from the parsed request only. */
    private void showMessageApproval(AccessoryTransport source, MessageApprovalSession approval,
                                     ApprovalDecision decision, int s) {
        if (abandonUnlessOwned(source, s, decision, RequestOwnership.SHOW_REVIEW)) return;
        MessageReview review = approval.review;
        keepScreenOn(true);
        LinearLayout root = page(DevTools.SCREENSHOTS ? "DEVELOPMENT · TEST ASSETS ONLY" : review.kicker,
                review.title, review.subtitle);
        List<MessageReview.Row> dangers = ReviewStyle.dangers(review.summary, review.details);
        addDangerSummary(root, dangers);
        if (approval.signingAs != null) root.addView(detail("Signing with", approval.signingAs.signingWith()));
        for (MessageReview.Row row : review.summary) root.addView(detail(row));
        addDetailsToggle(root, review.details, "details");
        addDecisionControls(root, source, decision, s, approval.request.id, review.reviewPrompt, review.signLabel, dangers,
                approval::signIfIdentityUnchanged,
                "The signature was queued for USB. Anyone who receives it can use it as shown on the review; unplugging cannot revoke it.",
                "Signed digest", "digest", false, null);
        present(root, "message-approval");
    }

    private void showReceipt(String title, String message, String hash) {
        showReceipt(title, message, "Transaction hash", hash, true);
    }

    private void showReceipt(String title, String message, String label, String value, boolean transaction) {
        LinearLayout root = page("REQUEST OUTCOME", title, message);
        if (value != null && !value.isEmpty()) card(root, label, value);
        if (transaction) card(root, "Network status", "This offline phone cannot confirm broadcast, inclusion, or settlement.");
        else card(root, "Where it goes", "This offline phone cannot see how the host or website uses the signature.");
        List<TransactionReview.Party> save = receiptParties;
        receiptParties = null;
        if (save != null && !save.isEmpty()) safetyScreens().addSaveActions(root, save);
        action(root, "Back to Wallet", true, this::showHome);
        action(root, "Lock now", false, this::lock);
        present(root, "receipt");
    }

    private View detail(String label, String value) {
        return detail(new MessageReview.Row(label, value));
    }

    /**
     * One review row. DANGER: red, stop glyph, "DANGER · TOPIC", on a red-outlined panel. WARNING:
     * amber, "!" glyph, "CHECK · TOPIC". Whole EVM addresses in the text are shown in groups of
     * four ("0x51dd 9Afd …"), so a line only wraps between groups.
     */
    private View detail(MessageReview.Row r) {
        String label = r.label, value = r.value;
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        ReviewStyle.Level level = ReviewStyle.level(r);
        boolean amber = BtcPsbtReview.TEST_NETWORK.equals(label);
        int ink = level == ReviewStyle.Level.DANGER ? VaultTheme.DANGER_INK
                : level == ReviewStyle.Level.CHECK ? VaultTheme.WARNING_INK : amber ? VaultTheme.AMBER : 0;
        TextView labelView = VaultTheme.bodyText(this, ReviewStyle.heading(r), 13, ink != 0 ? ink : VaultTheme.FAINT);
        String shown = ReviewStyle.displayValue(label, value);
        TextView valueView = VaultTheme.monoText(this, shown, amber ? VaultTheme.BODY_SIZE + 2 : VaultTheme.BODY_SIZE, ink != 0 ? ink : VaultTheme.INK);
        if (!shown.equals(value)) keepGroupsWhole(valueView);
        valueView.setTextIsSelectable(false);
        valueView.setPadding(0, dp(6), 0, dp(15));
        if (level != ReviewStyle.Level.NONE) {
            labelView.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
            LinearLayout heading = new LinearLayout(this);
            heading.setOrientation(LinearLayout.HORIZONTAL);
            heading.setGravity(Gravity.CENTER_VERTICAL);
            LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            glp.rightMargin = dp(8);
            heading.addView(VaultTheme.levelGlyph(this, level), glp);
            heading.addView(labelView, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
            row.addView(heading);
        } else {
            row.addView(labelView);
        }
        row.addView(valueView);
        SafetyScreens.style(this, row, label, valueView, value);
        return row;
    }

    /** Grouped addresses: break lines only at the spaces between groups (no hyphenation inside one). */
    private static void keepGroupsWhole(TextView t) {
        t.setHyphenationFrequency(Layout.HYPHENATION_FREQUENCY_NONE);
        t.setBreakStrategy(Layout.BREAK_STRATEGY_SIMPLE);
    }

    /**
     * Top of a review with DANGER rows: "N dangers below — read before signing" and each one's
     * topic, on the same red-outlined panel the rows use.
     */
    private void addDangerSummary(LinearLayout root, List<MessageReview.Row> dangers) {
        if (dangers.isEmpty()) return;
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0x33FF5A5A);
        bg.setStroke(dp(2), VaultTheme.DANGER_INK);
        bg.setCornerRadius(dp(6));
        panel.setBackground(bg);
        panel.setPadding(dp(12), dp(12), dp(12), dp(12));
        LinearLayout heading = new LinearLayout(this);
        heading.setOrientation(LinearLayout.HORIZONTAL);
        heading.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        glp.rightMargin = dp(10);
        heading.addView(VaultTheme.levelGlyph(this, ReviewStyle.Level.DANGER), glp);
        TextView title = VaultTheme.bodyText(this, ReviewStyle.dangerSummary(dangers.size()), VaultTheme.BODY_SIZE, VaultTheme.DANGER_INK);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        heading.addView(title, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        panel.addView(heading);
        StringBuilder topics = new StringBuilder();
        for (MessageReview.Row d : dangers) {
            String t = ReviewStyle.topic(d);
            if (topics.length() > 0) topics.append('\n');
            topics.append("• ").append(t != null ? t : ReviewStyle.shortenEvm(ReviewStyle.firstSentence(d.value)));
        }
        TextView list = VaultTheme.bodyText(this, topics.toString(), 13, VaultTheme.DANGER_INK);
        list.setPadding(0, dp(8), 0, 0);
        panel.addView(list);
        root.addView(panel, matchWrap(dp(4)));
    }

    // ------------------------------------------------------------------ Bitcoin
    //
    // Same BIP-39 seed and the same PIN window as the EVM accounts. The account public keys of one
    // network are derived on first use in an unlocked session (withSeedKey → VaultKeyStore.
    // withStandardSeed → BtcWallet.derive) and cached in memory until lock; signing derives the
    // input keys from the seed again, inside the window, after the user taps Sign (BtcPsbtSigner),
    // and destroys them. Bitcoin always uses the STANDARD wallet: while a passphrase wallet is open
    // the requests are refused (threat-model.md, "Bitcoin").

    private void clearBtcWallets() {
        synchronized (stateLock) {
            Arrays.fill(btcWallets, null);
            btcWalletOwner = null;
        }
    }

    /** The saved "shared with the Mac" choices of the standard wallet. Call under stateLock. */
    private BtcSharing btcSharing() {
        return BtcSharing.load(getSharedPreferences(BTC_PREFS, MODE_PRIVATE).getString(BTC_SHARING_KEY, null), walletId);
    }

    private void saveBtcSharing(BtcSharing sharing) {
        if (!getSharedPreferences(BTC_PREFS, MODE_PRIVATE).edit().putString(BTC_SHARING_KEY, sharing.encode()).commit()) {
            Log.w(TAG, "Bitcoin sharing choice not saved (the phone will ask again)");
        }
    }

    private interface BtcWalletUse { void use(BtcWallet wallet) throws Exception; }

    /** btcGetAccount / btcShowAddress / btcSignPsbt: one request owns the approval slot until answered. */
    private void handleBitcoin(AccessoryTransport source, JSONObject json, String fallbackId, int s) {
        final ApprovalDecision decision;
        synchronized (stateLock) {
            if (!requestPending.compareAndSet(false, true)) {
                sendError(source, fallbackId, "Another approval is pending");
                return;
            }
            decision = new ApprovalDecision(stateLock);
            approvalDecision = decision;
        }
        String id = fallbackId;
        try {
            final BtcRequest r = BtcRequest.parse(json);
            id = r.id;
            synchronized (stateLock) {
                if (passphraseBook != null) {
                    throw new RequestRefusal("Close the passphrase wallet first", "Bitcoin uses the standard wallet (your 24 words "
                            + "without a passphrase). Close the passphrase wallet on the phone (☰ → Passphrase wallet), then send "
                            + "the request again. Nothing was shared or signed.");
                }
                if (walletId == null) throw new IllegalStateException("Wallet is not ready: unlock and complete the backup check first");
            }
            withBtcWallet(r.network, source, r.id, decision, s, wallet -> {
                switch (r.kind) {
                    case GET_ACCOUNT:
                        answerBtcAccount(source, r, wallet, decision, s);
                        break;
                    case SHOW_ADDRESS: {
                        String address = wallet.address(r.type, r.account, r.change, r.index);
                        runOnUiThread(() -> showBtcAddress(source, r, wallet, address, decision, s));
                        break;
                    }
                    default: {
                        // Built once: the review and the signer both use this object.
                        BtcPsbtReview review = BtcPsbtReview.build(r.psbt, r.network, wallet, safety(), btcAmounts);
                        runOnUiThread(() -> showBtcApproval(source, r, review, decision, s));
                    }
                }
            });
        } catch (Exception e) {
            failBitcoin(source, id, decision, s, e);
        }
    }

    /** Answer an error, release the slot, and show a refusal's reason on the phone. Any thread. */
    private void failBitcoin(AccessoryTransport source, String id, ApprovalDecision decision, int s, Exception e) {
        finishApproval(decision);
        sendError(source, id, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        runOnUiThread(() -> {
            if (s != session.get() || !unlocked || source != transport || sensitive.active() || approvalDecision != null) return;
            if (e instanceof RequestRefusal) {
                showInfo(((RequestRefusal) e).title, e.getMessage(), this::showHome);
                Haptics.reject(getWindow().getDecorView());
            } else if ("loading".equals(screenName)) {
                showHome();
            }
        });
    }

    /**
     * Run {@code use} with the standard wallet's Bitcoin accounts for {@code network}: from the
     * session cache, or derived now from the seed (PIN window; a dismissed prompt answers "rejected").
     */
    private void withBtcWallet(BtcNetwork network, AccessoryTransport source, String id, ApprovalDecision decision, int s,
                               BtcWalletUse use) throws Exception {
        BtcWallet cached;
        synchronized (stateLock) {
            cached = walletId != null && walletId.equals(btcWalletOwner) ? btcWallets[network.ordinal()] : null;
        }
        if (cached != null) {
            use.use(cached);
            return;
        }
        runOnUiThread(() -> {
            if (!owns(source, s, decision, RequestOwnership.BTC_UNDECIDED)) { finishApproval(decision); return; }
            showLoading("Opening your Bitcoin accounts", "Deriving your " + network.label + " accounts from your recovery phrase…");
            withSeedKey("Confirm your PIN to open your Bitcoin accounts", () -> {
                try {
                    cryptoExecutor.execute(() -> {
                        try {
                            final String owner;
                            synchronized (stateLock) {
                                if (!owns(source, s, decision, RequestOwnership.BTC_UNDECIDED)) throw new IllegalStateException("Session ended before the Bitcoin accounts opened");
                                owner = walletId;
                            }
                            BtcWallet derived = vault.withStandardSeed(seed -> BtcWallet.derive(seed, network));
                            synchronized (stateLock) {
                                if (s != session.get() || owner == null || !owner.equals(walletId)) {
                                    throw new IllegalStateException("The wallet changed; send the request again");
                                }
                                if (!owner.equals(btcWalletOwner)) {
                                    Arrays.fill(btcWallets, null);
                                    btcWalletOwner = owner;
                                }
                                btcWallets[network.ordinal()] = derived;
                            }
                            use.use(derived);
                        } catch (Exception e) {
                            if (authLapsed(e)) {
                                runOnUiThread(() -> lastCredentialConfirm = 0);
                                failBitcoin(source, id, decision, s, new RequestRefusal("PIN confirmation expired",
                                        "The PIN confirmation expired before your Bitcoin accounts opened. Send the request again. Nothing was shared or signed."));
                            } else {
                                failBitcoin(source, id, decision, s, e);
                            }
                        }
                    });
                } catch (RejectedExecutionException closing) {
                    finishApproval(decision);
                }
            }, () -> {
                synchronized (stateLock) { if (approvalDecision != decision) return; }
                decision.cancel();
                source.send(json("id", id, "status", "rejected"));
                finishApproval(decision);
                statusMessage = "Bitcoin request declined · PIN not confirmed";
                showHome();
            });
        });
    }

    /** btcGetAccount: answer at once if the user shared this account before; otherwise ask on screen. */
    private void answerBtcAccount(AccessoryTransport source, BtcRequest r, BtcWallet wallet, ApprovalDecision decision, int s) throws Exception {
        boolean shared;
        synchronized (stateLock) { shared = walletId != null && btcSharing().isShared(r.network, r.type, r.account); }
        if (!shared) {
            runOnUiThread(() -> showBtcShare(source, r, wallet, decision, s));
            return;
        }
        JSONObject reply = BtcRequest.accountResponse(r.id, wallet, r.type, r.account);
        synchronized (stateLock) {
            if (owns(source, s, decision, RequestOwnership.BTC_UNDECIDED) && decision.beginSigning()) {
                source.send(reply);
                decision.finish();
            }
        }
        finishApproval(decision);
        runOnUiThread(() -> {
            if (s != session.get() || !unlocked) return;
            statusMessage = r.network.label + " " + BtcWallet.accountLabel(r.type, r.account) + " sent to the host (watch-only, shared before)";
            if ("loading".equals(screenName) && approvalDecision == null) showHome();
            else if (statusView != null) statusView.setText(statusMessage);
        });
    }

    private void showBtcShare(AccessoryTransport source, BtcRequest r, BtcWallet wallet, ApprovalDecision decision, int s) {
        if (abandonUnlessOwned(source, s, decision, RequestOwnership.BTC_SHOW)) return;
        keepScreenOn(true);
        LinearLayout root = page(r.network.test() ? r.network.label.toUpperCase(Locale.ROOT) + " · SHARE ACCOUNT" : "BITCOIN · SHARE ACCOUNT",
                "Share Bitcoin account with the Mac?",
                "The connected computer asks for this account's watch-only key, to show your balance and prepare transactions.");
        root.addView(detail(r.network.test() ? BtcPsbtReview.TEST_NETWORK : "Network", r.network.label));
        root.addView(detail("Account", BtcWallet.accountLabel(r.type, r.account) + "\n" + wallet.accountPathString(r.type, r.account)));
        root.addView(detail("Wallet fingerprint", wallet.fingerprintHex()));
        root.addView(detail("What the Mac will see", "Every address, balance and payment of this account, past and future, "
                + "becomes visible to the Mac and to any software on it. It cannot spend: every payment still needs your approval on this phone."));
        root.addView(detail("Asked once", "If you share, the phone remembers it for this account and network and answers "
                + "this request without asking again."));
        TextView share = VaultTheme.pixelButton(this, "Share with the Mac", true);
        TextView decline = VaultTheme.pixelButton(this, "Don't share", false);
        hardenTouch(share);
        hardenTouch(decline);
        share.setOnClickListener(v -> {
            JSONObject reply;
            try {
                reply = BtcRequest.accountResponse(r.id, wallet, r.type, r.account);
            } catch (Exception e) {
                failBitcoin(source, r.id, decision, s, e);
                return;
            }
            synchronized (stateLock) {
                if (!owns(source, s, decision, RequestOwnership.BTC_UNDECIDED) || !decision.beginSigning()) return;
                BtcSharing sharing = btcSharing();
                sharing.share(r.network, r.type, r.account);
                saveBtcSharing(sharing);
                source.send(reply);
                decision.finish();
            }
            Haptics.confirm(v);
            finishApproval(decision);
            statusMessage = "Bitcoin account shared (watch-only)";
            showInfo("Account shared", BtcWallet.accountLabel(r.type, r.account) + " on " + r.network.label
                    + " is now visible to the Mac (watch-only). It cannot spend without this phone.", this::showHome);
        });
        decline.setOnClickListener(v -> {
            if (!decision.reject()) return;
            Haptics.reject(v);
            source.send(json("id", r.id, "status", "rejected"));
            finishApproval(decision);
            statusMessage = "Bitcoin account not shared";
            showHome();
        });
        root.addView(share, matchWrap(dp(16)));
        root.addView(decline, matchWrap(dp(10)));
        present(root, "btc-share");
    }

    /**
     * ☰ → Bitcoin sharing: the accounts btcGetAccount answers without asking, each revocable. A
     * privacy control only: revoking makes the phone ask again; it cannot recall what the Mac
     * already received, and it never changes what is signed.
     */
    private void showBtcSharing() {
        List<String> keys;
        synchronized (stateLock) { keys = walletId != null ? btcSharing().keys() : Collections.emptyList(); }
        LinearLayout root = page("SECURITY / PRIVACY", "Bitcoin sharing",
                "Bitcoin accounts whose watch-only key the Mac receives without asking. Stop sharing to make the phone ask again.");
        if (keys.isEmpty()) {
            card(root, "Nothing shared", "No Bitcoin account is shared. The phone asks before the Mac can see any account.");
        } else {
            card(root, "Already received", "Stopping does not erase what the Mac already received: it can still watch those addresses. "
                    + "It only stops new requests from being answered silently.");
            for (String key : keys) {
                action(root, "Stop sharing · " + BtcSharing.label(key), false, () -> {
                    synchronized (stateLock) {
                        if (walletId == null) return;
                        BtcSharing sharing = btcSharing();
                        sharing.revoke(key);
                        saveBtcSharing(sharing);
                    }
                    statusMessage = "Bitcoin account no longer shared · the phone will ask again";
                    showBtcSharing();
                });
            }
            if (keys.size() > 1) action(root, "Stop sharing all", false, () -> {
                synchronized (stateLock) {
                    if (walletId == null) return;
                    BtcSharing sharing = btcSharing();
                    sharing.revokeAll();
                    saveBtcSharing(sharing);
                }
                statusMessage = "No Bitcoin account is shared · the phone will ask again";
                showBtcSharing();
            });
        }
        action(root, "Back to Security", false, this::showSecurity);
        present(root, "btc-sharing");
    }

    /** btcShowAddress: the address big, for comparison with the Mac; answered only after Done. */
    private void showBtcAddress(AccessoryTransport source, BtcRequest r, BtcWallet wallet, String address,
                                ApprovalDecision decision, int s) {
        if (abandonUnlessOwned(source, s, decision, RequestOwnership.BTC_SHOW)) return;
        keepScreenOn(true);
        LinearLayout root = page(r.network.test() ? r.network.label.toUpperCase(Locale.ROOT) + " · ADDRESS" : "BITCOIN · RECEIVE ADDRESS",
                "Compare with your Mac", "Check that your Mac shows exactly this address, every group. Only this phone's screen is trusted.");
        root.addView(detail(r.network.test() ? BtcPsbtReview.TEST_NETWORK : "Network", r.network.label));
        LinearLayout box = VaultTheme.box(this);
        TextView big = VaultTheme.monoText(this, BtcScript.grouped(address, 4), 24, VaultTheme.INK);
        big.setTextIsSelectable(false);
        box.addView(big);
        root.addView(box, matchWrap(dp(12)));
        root.addView(detail("Account", BtcWallet.accountLabel(r.type, r.account)));
        root.addView(detail("Path", wallet.addressPathString(r.type, r.account, r.change, r.index)
                + (r.change == 0 ? " (receiving address " : " (change address ") + r.index + ")"));
        root.addView(detail("If anything differs", "Tap Cancel and do not use the address shown on the Mac."));
        TextView done = VaultTheme.pixelButton(this, "Done: it matches", true);
        TextView cancel = VaultTheme.pixelButton(this, "Cancel", false);
        hardenTouch(done);
        hardenTouch(cancel);
        done.setOnClickListener(v -> {
            JSONObject reply;
            try {
                reply = BtcRequest.addressResponse(r.id, address);
            } catch (Exception e) {
                failBitcoin(source, r.id, decision, s, e);
                return;
            }
            synchronized (stateLock) {
                if (!owns(source, s, decision, RequestOwnership.BTC_UNDECIDED) || !decision.beginSigning()) return;
                source.send(reply);
                decision.finish();
            }
            Haptics.confirm(v);
            finishApproval(decision);
            statusMessage = "Bitcoin address confirmed on the phone";
            showHome();
        });
        cancel.setOnClickListener(v -> {
            if (!decision.reject()) return;
            Haptics.reject(v);
            source.send(json("id", r.id, "status", "rejected"));
            finishApproval(decision);
            statusMessage = "Bitcoin address not confirmed";
            showHome();
        });
        root.addView(done, matchWrap(dp(16)));
        root.addView(cancel, matchWrap(dp(10)));
        present(root, "btc-address");
    }

    /** btcSignPsbt review, rendered from the BtcPsbtReview built once in handleBitcoin. */
    private void showBtcApproval(AccessoryTransport source, BtcRequest r, BtcPsbtReview review, ApprovalDecision decision, int s) {
        if (abandonUnlessOwned(source, s, decision, RequestOwnership.BTC_SHOW)) return;
        keepScreenOn(true);
        LinearLayout root = page(DevTools.SCREENSHOTS ? "DEVELOPMENT · TEST ASSETS ONLY" : review.kicker, review.title, review.subtitle);
        List<MessageReview.Row> dangers = ReviewStyle.dangers(review.summary, review.details);
        addDangerSummary(root, dangers);
        for (MessageReview.Row row : review.summary) root.addView(detail(row));
        addDetailsToggle(root, review.details, "technical details");
        final String txid = BtcCrypto.hex(BtcCrypto.reversed(review.psbt.tx.txid()));
        addDecisionControls(root, source, decision, s, r.id, review.reviewPrompt, review.signLabel, dangers, null,
                seed -> {
                    byte[] signed = BtcPsbtSigner.sign(review, seed, random);
                    // Remember what each coin was signed as (SegWit fee-attack guard), before it can leave;
                    // only amounts proven by the previous transaction (a lied Taproot amount must not stick).
                    for (BtcPsbtReview.SignInput in : review.inputs) {
                        if (in.amountProven) btcAmounts.record(review.psbt.tx.inputs.get(in.index).outpoint(), in.amount, in.script);
                    }
                    return BtcRequest.signedResponse(r.id, signed);
                },
                "Confirm your PIN to sign this Bitcoin transaction",
                "The signed PSBT was queued for USB. Your Mac finalizes and broadcasts it; unplugging cannot revoke a signature already received.",
                "Transaction ID (once broadcast)", response -> txid, true, () -> {
                    safety().record(review.walletKey, review.parties, System.currentTimeMillis());
                    receiptParties = review.parties;
                });
        present(root, "btc-approval");
    }

    // ------------------------------------------------------------------ accounts + passphrase wallet
    //
    // One private key in memory: the ACTIVE account's (credentials). Switching derives
    // the new account from the seed inside the PIN window (withSeedKey → VaultKeyStore.deriveAccount,
    // one decrypt) and replaces credentials under stateLock, like unlock does. The passphrase lives
    // only in `passphrase` (char[]) while its wallet is open, and is zeroed on lock / close.

    /** A typed passphrase handed over by "Use this wallet", until its wallet is open. Zeroed on lock. */
    private char[] pendingPassphrase;

    private AccountBook currentBook() { return passphraseBook != null ? passphraseBook : standardBook; }

    /** Zero and forget the passphrase wallet. Call under stateLock (or where nothing else runs). */
    private void clearPassphraseWallet() {
        if (passphrase != null) Arrays.fill(passphrase, '\0');
        if (pendingPassphrase != null) Arrays.fill(pendingPassphrase, '\0');
        passphrase = null;
        pendingPassphrase = null;
        passphraseBook = null;
        passphraseFingerprint = null;
    }

    /** Leave passphrase typing: the screen buffer is overwritten, USB requests are answered again. */
    private void endPassphraseEntry() {
        passphraseEntry = false;
        if (accountScreens != null) accountScreens.clear();
    }

    private void saveStandardBook(AccountBook book) {
        if (book == null) return;
        if (!getSharedPreferences(ACCOUNT_PREFS, MODE_PRIVATE).edit().putString(ACCOUNT_BOOK_KEY, book.encode()).commit()) {
            Log.w(TAG, "account list not saved (it is rebuilt from the seed on demand)");
        }
    }

    /** A wallet was created, restored or replaced: its account 1 is active and the list starts over. Under stateLock. */
    private void adoptNewWallet(String account0Address) {
        clearPassphraseWallet();
        clearBtcWallets();
        walletId = account0Address.toLowerCase(Locale.ROOT);
        standardBook = AccountBook.fresh(walletId);
        activeAccount = new SigningAccount(0, standardBook.active().name(), false, null, walletId);
        saveStandardBook(standardBook);
    }

    private void showAccounts() {
        if (!accountScreensReady()) return;
        if (!backupVerified) { showInfo("Check your backup first", "Accounts open after the backup spot-check, like receiving and signing.", this::showHome); return; }
        accountScreens().showAccounts();
    }

    private void showPassphraseWallet() {
        if (!accountScreensReady()) return;
        if (!backupVerified) { showInfo("Check your backup first", "A passphrase wallet opens after the backup spot-check of your 24 words.", this::showHome); return; }
        accountScreens().showPassphraseIntro();
    }

    /** Derive {@code index} of the open wallet (adding it to the list when {@code add}) and make it the signing account. */
    private void activateAccount(int index, boolean add) {
        if (!accountScreensReady() || !backupVerified) return;
        if (requestPending.get()) { showInfo("Finish the request first", "Approve or reject the request on screen before switching accounts.", this::showHome); return; }
        withSeedKey("Confirm your PIN to switch account", () -> deriveAndActivate(index, add, false));
    }

    private void deriveAndActivate(int index, boolean add, boolean retried) {
        final int s = session.get();
        final AccountBook book;
        final String fingerprint;
        synchronized (stateLock) { book = currentBook(); fingerprint = passphraseFingerprint; }
        if (book == null || !unlocked) return;
        final String name = book.get(index) != null ? book.get(index).name() : AccountBook.defaultName(index);
        showLoading(add ? "Adding " + name : "Switching to " + name, "Deriving its address from your recovery phrase…");
        cryptoExecutor.execute(() -> {
            try {
                String pass;
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked) return;
                    if (currentBook() != book) throw new IllegalStateException("the wallet changed while switching");
                    // web3j derives from a String passphrase: this copy is short-lived and unreferenced after derivation.
                    pass = passphrase == null ? null : new String(passphrase);
                }
                if ((pass == null) != (fingerprint == null)) throw new IllegalStateException("the wallet changed while switching");
                SeedVault.Derived d = vault.deriveAccount(index, pass);
                pass = null;
                String address = d.credentials.getAddress();
                Bitmap qr = qrFor(address);
                boolean switched = false;
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked || !operational) return;
                    boolean sameWallet = currentBook() == book && (fingerprint != null
                            ? fingerprint.equals(d.fingerprint) && fingerprint.equals(passphraseFingerprint)
                            : d.account0Address.equals(walletId));
                    if (!sameWallet) throw new IllegalStateException("the wallet changed while switching");
                    if (!requestPending.get() && approvalDecision == null) {
                        if (add && book.get(index) == null) book.add(index, address);
                        book.select(index, address);
                        credentials = d.credentials;
                        activeAccount = new SigningAccount(index, book.active().name(), fingerprint != null, d.fingerprint, address);
                        walletAddress = address;
                        walletQr = qr;
                        switched = true;
                    }
                }
                if (switched && fingerprint == null) saveStandardBook(book);
                final boolean done = switched;
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    if (approvalDecision != null) return; // the request's own screen is showing
                    statusMessage = done ? "Now using " + name + (fingerprint != null ? " (passphrase wallet)" : "")
                            : "Account not switched: a request arrived. Try again after it.";
                    showHome();
                    drainPendingUsb();
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    if (authLapsed(e) && !retried) {
                        lastCredentialConfirm = 0;
                        confirmDevicePin("Confirm your PIN to switch account", () -> deriveAndActivate(index, add, true), this::showHome);
                        return;
                    }
                    Log.w(TAG, "account switch failed: " + chain(e));
                    showInfo("Account not switched", "The active account is unchanged. " + (e.getMessage() == null ? "" : e.getMessage()), this::showHome);
                });
            }
        });
    }

    /** Derive the passphrase wallet's identity (fingerprint, account 1) for the user to recognise. Keeps no key. */
    private void previewPassphrase(char[] chars, AccountScreens.PreviewResult result) {
        withSeedKey("Confirm your PIN to open the passphrase wallet", () -> previewWorker(chars, result, false));
    }

    private void previewWorker(char[] chars, AccountScreens.PreviewResult result, boolean retried) {
        final int s = session.get();
        if (!passphraseEntry || chars == null || chars.length == 0 || SeedVault.passphraseProblem(CharBuffer.wrap(chars)) != null) return;
        final String pass = new String(chars); // short-lived; web3j derives from a String
        showLoading("Opening passphrase wallet", "Deriving its fingerprint and first address…");
        cryptoExecutor.execute(() -> {
            try {
                if (s != session.get() || !unlocked) return;
                SeedVault.Derived d = vault.deriveAccount(0, pass);
                final String fingerprint = d.fingerprint, account0 = d.account0Address;
                runOnUiThread(() -> { if (s == session.get() && unlocked && passphraseEntry) result.preview(fingerprint, account0); });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    if (authLapsed(e) && !retried) {
                        lastCredentialConfirm = 0;
                        confirmDevicePin("Confirm your PIN to open the passphrase wallet", () -> previewWorker(chars, result, true), this::showHome);
                        return;
                    }
                    Log.w(TAG, "passphrase preview failed: " + chain(e));
                    showInfo("Passphrase wallet not opened", "Your current wallet is unchanged. Lock and retry.", this::showHome);
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
        withSeedKey("Confirm your PIN to open the passphrase wallet", () -> openPassphraseWallet(false));
    }

    private void openPassphraseWallet(boolean retried) {
        final int s = session.get();
        final String pass;
        synchronized (stateLock) {
            if (pendingPassphrase == null || !unlocked) return;
            pass = new String(pendingPassphrase); // short-lived; web3j derives from a String
        }
        showLoading("Opening passphrase wallet", "Deriving Account 1…");
        cryptoExecutor.execute(() -> {
            try {
                if (s != session.get() || !unlocked) return;
                SeedVault.Derived d = vault.deriveAccount(0, pass);
                String address = d.credentials.getAddress();
                Bitmap qr = qrFor(address);
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked || !operational || pendingPassphrase == null) return;
                    if (requestPending.get() || approvalDecision != null) throw new IllegalStateException("a request arrived; try again after it");
                    if (passphrase != null) Arrays.fill(passphrase, '\0');
                    passphrase = pendingPassphrase;
                    pendingPassphrase = null;
                    passphraseFingerprint = d.fingerprint;
                    passphraseBook = AccountBook.fresh(d.account0Address);
                    credentials = d.credentials;
                    activeAccount = new SigningAccount(0, passphraseBook.active().name(), true, d.fingerprint, address);
                    walletAddress = address;
                    walletQr = qr;
                }
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    endPassphraseEntry();
                    statusMessage = "Passphrase wallet open · fingerprint " + d.fingerprint + " · closes when the phone locks";
                    showHome();
                    drainPendingUsb();
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    if (authLapsed(e) && !retried) {
                        lastCredentialConfirm = 0;
                        confirmDevicePin("Confirm your PIN to open the passphrase wallet", () -> openPassphraseWallet(true),
                                () -> { synchronized (stateLock) { if (pendingPassphrase != null) Arrays.fill(pendingPassphrase, '\0'); pendingPassphrase = null; } endPassphraseEntry(); showHome(); });
                        return;
                    }
                    synchronized (stateLock) { if (pendingPassphrase != null) Arrays.fill(pendingPassphrase, '\0'); pendingPassphrase = null; }
                    endPassphraseEntry();
                    Log.w(TAG, "passphrase wallet open failed: " + chain(e));
                    showInfo("Passphrase wallet not opened", "Your current wallet is unchanged. " + (e.getMessage() == null ? "" : e.getMessage()), this::showHome);
                });
            }
        });
    }

    /** Back to the standard wallet's active account; the passphrase is zeroed. */
    private void closePassphraseWallet() {
        if (!accountScreensReady()) return;
        withSeedKey("Confirm your PIN to return to the standard wallet", () -> closePassphraseWorker(false));
    }

    private void closePassphraseWorker(boolean retried) {
        final int s = session.get();
        final AccountBook book = standardBook;
        if (book == null || passphraseBook == null) { showHome(); return; }
        showLoading("Closing passphrase wallet", "Returning to the standard wallet…");
        cryptoExecutor.execute(() -> {
            try {
                if (s != session.get() || !unlocked) return;
                SeedVault.Derived d = vault.deriveAccount(book.activeIndex(), null);
                String address = d.credentials.getAddress();
                Bitmap qr = qrFor(address);
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked || !operational) return;
                    if (!d.account0Address.equals(walletId) || !book.active().address.equalsIgnoreCase(address)) throw new IllegalStateException("the standard wallet did not match its saved account list");
                    if (requestPending.get() || approvalDecision != null) throw new IllegalStateException("a request arrived; try again after it");
                    clearPassphraseWallet();
                    credentials = d.credentials;
                    activeAccount = new SigningAccount(book.activeIndex(), book.active().name(), false, d.fingerprint, address);
                    walletAddress = address;
                    walletQr = qr;
                }
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    statusMessage = "Passphrase wallet closed · back to the standard wallet";
                    showHome();
                    drainPendingUsb();
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    if (authLapsed(e) && !retried) {
                        lastCredentialConfirm = 0;
                        confirmDevicePin("Confirm your PIN to return to the standard wallet", () -> closePassphraseWorker(true), this::showHome);
                        return;
                    }
                    showInfo("Still in the passphrase wallet", "Locking the phone always closes it. " + (e.getMessage() == null ? "" : e.getMessage()), this::showHome);
                });
            }
        });
    }

    private AccountScreens accountScreens() {
        if (accountScreens == null) {
            final MainActivity activity = this;
            accountScreens = new AccountScreens(new AccountScreens.Host() {
                @Override public Context context() { return activity; }
                @Override public LinearLayout page(String eyebrow, String title, String description) { return activity.page(eyebrow, title, description); }
                @Override public void present(LinearLayout root, String screen) { activity.present(root, screen); }
                @Override public void action(LinearLayout parent, String label, boolean primary, Runnable run) { activity.action(parent, label, primary, run); }
                @Override public void card(LinearLayout parent, String label, String value) { activity.card(parent, label, value); }
                @Override public boolean ready() { return accountScreensReady() && backupVerified; }
                @Override public void showHome() { endPassphraseEntry(); activity.showHome(); }
                @Override public void harden(View view) { hardenTouch(view); }
                @Override public int dp(int value) { return activity.dp(value); }
                @Override public AccountBook book() { return currentBook(); }
                @Override public String passphraseFingerprint() { return passphraseFingerprint; }
                @Override public SigningAccount active() { return activeAccount; }
                @Override public void activate(int index, boolean add) { activateAccount(index, add); }
                @Override public void bookChanged() {
                    // Labels change the name shown everywhere; the passphrase wallet's list stays in memory.
                    synchronized (stateLock) {
                        AccountBook book = currentBook();
                        SigningAccount a = activeAccount;
                        if (book != null && a != null && book.get(a.index) != null) {
                            activeAccount = new SigningAccount(a.index, book.get(a.index).name(), a.passphrase, a.fingerprint, a.address);
                        }
                    }
                    if (passphraseBook == null) saveStandardBook(standardBook);
                }
                @Override public void previewPassphrase(char[] chars, AccountScreens.PreviewResult result) { activity.previewPassphrase(chars, result); }
                @Override public void usePassphrase(char[] chars) { activity.usePassphrase(chars); }
                @Override public void closePassphrase() { closePassphraseWallet(); }
                @Override public void entryActive(boolean active) { passphraseEntry = active; }
            });
        }
        return accountScreens;
    }

    /**
     * Every account of the open wallet(s) (address → name, hidden ones too), so the review names a
     * send to your own other account and catches look-alikes of it. Display only; a list being
     * edited on screen at that instant just yields no names this time.
     */
    private Map<String, String> ownAccountNames() {
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

    /** The phone's address book and recipient history (app-private files); see AddressSafety. */
    private synchronized AddressSafety safety() {
        if (addressSafety == null) {
            FileSafetyStore store = new FileSafetyStore(this);
            addressSafety = new AddressSafety(new AddressBook(store), new RecipientHistory(store));
        }
        return addressSafety;
    }

    private SafetyScreens safetyScreens() {
        if (safetyScreens == null) {
            final MainActivity activity = this;
            safetyScreens = new SafetyScreens(new SafetyScreens.Host() {
                @Override public Context context() { return activity; }
                @Override public LinearLayout page(String eyebrow, String title, String description) { return activity.page(eyebrow, title, description); }
                @Override public void present(LinearLayout root, String screen) { activity.present(root, screen); }
                @Override public void action(LinearLayout parent, String label, boolean primary, Runnable run) { activity.action(parent, label, primary, run); }
                @Override public void card(LinearLayout parent, String label, String value) { activity.card(parent, label, value); }
                @Override public boolean ready() { return menuAvailable(); }
                @Override public void showMenu() { activity.showMenu(); }
                @Override public void showHome() { activity.showHome(); }
                @Override public void harden(View view) { hardenTouch(view); }
                @Override public int dp(int value) { return activity.dp(value); }
            }, safety().book);
        }
        return safetyScreens;
    }

    private void sendError(AccessoryTransport source, String id, String message) {
        if (source != null) source.send(json("id", id, "status", "error", "error", message));
        final int s = session.get();
        runOnUiThread(() -> {
            if (s == session.get() && unlocked && source == transport) {
                statusMessage = "Request error: " + message;
                if (statusView != null) statusView.setText(statusMessage);
            }
        });
    }

    @Override public void onDisconnected(AccessoryTransport source, String reason) {
        boolean droppedHeld;
        synchronized (stateLock) {
            droppedHeld = heldSource == source;
            if (droppedHeld) clearHeldRequest(); // its host is gone
        }
        runOnUiThread(() -> {
            if (droppedHeld && !unlocked && pinScreen != null) pinScreen.setPending(null, null);
            if (source != transport) return;
            boolean hadApproval = approvalDecision != null;
            transport = null;
            cancelApproval();
            setStatusActive(false);
            if (unlocked && hadApproval)
                showReceipt("USB disconnected", "The request session ended. If you tapped Sign, delivery may be uncertain. Check the host before trying another transaction.", null);
        });
    }

    @Override protected void onDestroy() {
        ui.removeCallbacksAndMessages(null);
        if (adbObserver != null) getContentResolver().unregisterContentObserver(adbObserver);
        synchronized (stateLock) {
            session.incrementAndGet();
            unlocked = false;
            operational = false;
            credentials = null;
            clearPassphraseWallet();
            clearBtcWallets();
            cancelApproval();
            sensitive.reset();
            if (transport != null) transport.close();
            transport = null;
        }
        clearSensitiveUi();
        clearPinEntry();
        cryptoExecutor.shutdownNow();
        attestExecutor.shutdownNow();
        super.onDestroy();
    }

    private TextView text(String value, float size, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        VaultTheme.size(view, size);
        view.setTextColor(color);
        view.setLineSpacing(0, 1.12f);
        return view;
    }

    private static void hardenTouch(View view) {
        view.setFilterTouchesWhenObscured(true);
        view.setOnTouchListener((ignored, event) -> (event.getFlags()
                & (MotionEvent.FLAG_WINDOW_IS_OBSCURED
                | MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)) != 0);
    }

    private LinearLayout.LayoutParams matchWrap(int topMargin) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.topMargin = topMargin;
        return params;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    /** Home receive address: "0x51dd 9Afd 5f32 …" in two lines of five groups (the QR stays ungrouped). */
    private String formatAddress(String address) {
        return ReviewStyle.groupEvmTwoLines(address);
    }

    private JSONObject json(Object... pairs) {
        JSONObject object = new JSONObject();
        try {
            for (int index = 0; index < pairs.length; index += 2) {
                object.put((String) pairs[index], pairs[index + 1]);
            }
            return object;
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
