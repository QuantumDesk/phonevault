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
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final SecureRandom random = new SecureRandom();
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
    /** Last battery reading (see onBattery). */
    private BatteryStatus battery = BatteryStatus.UNKNOWN;
    /** Page frame, cards, actions, review rows; owns the name of the screen on display. */
    private final Pages pages = new Pages(this, new Pages.Host() {
        @Override public BatteryStatus battery() { return battery; }
        @Override public boolean menuAvailable() { return MainActivity.this.menuAvailable(); }
        @Override public void showMenu() { MainActivity.this.showMenu(); }
        @Override public boolean mayPresent(String screen) {
            // Phrase and restore-over screens exist only inside their sensitive flow.
            if ((screen.startsWith("backup") || "phrase".equals(screen) || "replace-confirm".equals(screen))
                    && !sensitive.active()) return false;
            return !(screen.startsWith("restore") && setup.replacing() && !sensitive.active());
        }
        @Override public boolean actionsEnabled() { return unlocked && operational; }
        @Override public void keepScreenOn(boolean on) { MainActivity.this.keepScreenOn(on); }
        @Override public void lock() { MainActivity.this.lock(); }
    });
    /** This activity as the flow screens see it (VaultHost). */
    private final ScreenHost host = new ScreenHost();
    /** First-run wizard, dice entropy, restore (first run and over an existing wallet). */
    private final SetupScreens setup = new SetupScreens(host);
    /** Recovery phrase reveal / SeedQR / spot check / reminder, and Replace. */
    private final BackupScreens backup = new BackupScreens(host);
    /** EVM transaction and message reviews, the shared Sign / Reject controls, the receipt. */
    private final ApprovalScreens approvals = new ApprovalScreens(host);
    private boolean batteryRegistered;
    private final BroadcastReceiver batteryReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) { onBattery(readBattery(intent)); }
    };
    private String statusMessage = "USB disconnected · connect a host when ready";
    private int activeSensitive = -1;
    private Runnable afterReauth;
    private char[][] pinSetupEntries;

    // ------------------------------------------------------------------ device security & lifecycle
    /** Idle time (no touch) before the vault locks and drops the key from memory. */
    private static final long IDLE_LOCK_MS = 2 * 60 * 1000L;
    /** True from the moment a PIN is SET in this unlocked session until it is used once or the
     *  vault locks: the first-run wizard does not ask for the PIN again seconds after setting it. */
    private boolean firstRunPinFresh;
    /**
     * Once-per-boot record of the credential gate's silent unlock (see CredentialGate#show): persisted
     * against the boot id, so re-creating the activity cannot re-arm it.
     */
    private BootUnlockGuard bootUnlock;
    /** Device-PIN prompt, boot unlock and seed-key window decisions (credential mode). */
    private final CredentialGate credentialGate = new CredentialGate(new CredentialGate.Env() {
        @Override public int session() { return session.get(); }
        @Override public boolean unlocked() { return unlocked; }
        @Override public boolean foreground() { return foreground; }
        @Override public boolean credentialMode() { return MainActivity.this.credentialMode(); }
        @Override public long elapsedRealtime() { return SystemClock.elapsedRealtime(); }
        @Override public int bootId() { return MainActivity.this.bootId(); }
        @Override public BootUnlockGuard bootUnlock() { return bootUnlock; }
        @Override public boolean deviceLocked() {
            KeyguardManager keyguard = getSystemService(KeyguardManager.class);
            return keyguard != null && keyguard.isDeviceLocked();
        }
        @Override public void post(Runnable r) { ui.post(r); }
        @Override public void postDelayed(Runnable r, long delayMs) { ui.postDelayed(r, delayMs); }
        @Override public void showLoading(String title, String caption) { pages.showLoading(title, caption); }
        @Override public void showLockedPage(int s) { MainActivity.this.showLockedPage(s); }
        @Override public void unlock(int s) { MainActivity.this.unlock(s); }
        @Override public void systemConfirm(String why, CredentialGate.Confirmed result) {
            SystemCredential.confirm(MainActivity.this, "Phone Vault", why, (ok, message) -> result.done(ok));
        }
        @Override public void probeSeedKey(CredentialGate.Probed result) {
            cryptoExecutor.execute(() -> {
                boolean ready = vault.seedKeyUsableNow();
                runOnUiThread(() -> result.done(ready));
            });
        }
    });
    /** OLED burn-in: nudge the whole UI by a pixel or two on this cadence. */
    private static final long PIXEL_SHIFT_MS = 45 * 1000L;
    /** System screen-off timeout applied as device owner (burn-in + walk-away safety). */
    private static final int SCREEN_OFF_TIMEOUT_MS = 60 * 1000;
    private final Runnable idleLock = this::lock;
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
    /** A request that arrived while LOCKED, bound to its connection (HeldRequest). Under stateLock; cleared by lock(). */
    private final HeldRequest heldRequest = new HeldRequest();
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
            getContentResolver().registerContentObserver(Settings.Global.getUriFor(ApplianceLockdown.ADB_WIFI_ENABLED), false, adbObserver);
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
        pages.showBattery(next);
        if (pinScreen != null) pinScreen.setBattery(next);
        if (lowChanged && unlocked && "wallet".equals(pages.screen())) showHome();
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
        if (sensitive.active() && backup.showingWords()) backup.touched();
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
        if ("wallet".equals(pages.screen())) lock();
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
            if (operational || !"adb-refused".equals(pages.screen())) refuseWhileAdbOn();
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
        synchronized (stateLock) { if (heldRequest.summary() != null) pinScreen.setPending("INCOMING REQUEST", heldRequest.summary()); }
        if (transport != null && !creating && !sealed) pinScreen.setSubtitle("Enter your six-digit PIN. A USB host is connected; its request will appear here.");
        updatePinPolicy(pinScreen);
        pages.setScreen("pin");
        setContentView(pinScreen.view());
        devDumpUi();
    }

    // ------------------------------------------------------------------ device-PIN (credential) mode

    /**
     * The vault PIN is the Android lock credential; the seed key needs a fresh system check. Decided
     * by VaultPin's persisted credential-mode marker (set once SystemCredential.install succeeded).
     */
    private boolean credentialMode() { return CredentialGate.credentialMode(pin); }

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
    private void withSeedKey(String why, Runnable op, Runnable onCancel) { credentialGate.withSeedKey(why, op, onCancel); }

    private void confirmDevicePin(String why, Runnable onOk, Runnable onCancel) { credentialGate.confirmDevicePin(why, onOk, onCancel); }

    /** Locked gate in credential mode: our screen, the system verifies the PIN (CredentialGate#show). */
    private void showCredentialGate(int s) { credentialGate.show(s); }

    /** The locked page of session {@code s}; CredentialGate then offers the system prompt. */
    private void showLockedPage(int s) {
        LinearLayout root = pages.page("LOCKED", "Phone Vault is locked",
                "Your PIN is checked by the phone's security chip. Tap Unlock and enter it on the next screen.");
        synchronized (stateLock) { if (heldRequest.summary() != null) pages.card(root, "Incoming request", heldRequest.summary()); }
        if (transport != null) pages.card(root, "USB", "A host is connected. Its request stays unanswered until you unlock and review it.");
        TextView unlockButton = VaultTheme.pixelButton(this, "Unlock", true);
        Pages.hardenTouch(unlockButton);
        unlockButton.setOnClickListener(v -> credentialGate.promptUnlock(s));
        root.addView(unlockButton, Pages.matchWrap(pages.dp(22)));
        TextView policy = VaultTheme.bodyText(this, SystemCredential.MAX_FAILED_FOR_WIPE
                + " wrong PINs in a row erase this phone completely.", 14, VaultTheme.FAINT);
        policy.setPadding(0, pages.dp(18), 0, 0);
        root.addView(policy);
        pages.setScreen("pin");
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(VaultTheme.BG);
        scroll.addView(root);
        setContentView(scroll);
        devDumpUi();
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
                // marker, never a PBKDF2 hash (CredentialGate.storeNewPin; the hash is the
                // no-chip fallback only).
                boolean bound = CredentialGate.storeNewPin(chosen, forSystem, p -> SystemCredential.install(this, p), pin);
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
            heldRequest.clear();
            if (staleTransport != null) { staleTransport.close(); usbReplugHint = true; }
            keepScreenOn(false);
        }
        clearSensitiveUi();
        clearPinEntry();
        if (!operational) return;
        bootUnlock.noteLock(bootId()); // no silent boot unlock after any lock this boot
        requestPending.set(false);
        ui.removeCallbacks(idleLock);
        backup.stopSeedTimer();
        showPinGate(null);
    }

    private void armIdleLock() {
        ui.removeCallbacks(idleLock);
        // While the recovery phrase (or its check) is on screen, the seed timer owns the timeout.
        long delay = backup.showingWords() ? Math.max(idleTimeoutMs, BackupScreens.SEED_TIMEOUT_MS + 10_000L) : idleTimeoutMs;
        ui.postDelayed(idleLock, delay);
    }

    /** Recovery phrase: back to home (button or timeout). */
    /**
     * Leave any phrase screen (reveal or NEW phrase) and return home. For a replacement this is
     * the single terminal path for cancel / timeout / success: the state goes IDLE (unless a
     * commit is in progress, which owns its own outcome) and a parked USB host is replayed.
     */
    private void clearSensitiveUi() {
        backup.stopSeedTimer();
        if (approvalDecision == null) keepScreenOn(false);
        sensitive.reset();
        activeSensitive = -1;
        afterReauth = null;
        backup.clear(); // the phrase, its check, a replacement candidate, the SeedQR
        setup.clear(); // typed recovery words and dice rolls never outlive the unlocked session
        endPassphraseEntry(); // nor a typed passphrase
        firstRunPinFresh = false;
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
        final HeldRequest.Taken held;
        synchronized (stateLock) {
            held = heldRequest.take(transport);
            if (held == null) return;
        }
        cryptoExecutor.execute(() -> onRequest(held.source, held.request));
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

    /** Non-zero when USB (Settings.Global.ADB_ENABLED) OR wireless (adb_wifi_enabled) debugging is on. */
    private int adbEnabled() {
        int usb = Settings.Global.getInt(getContentResolver(), Settings.Global.ADB_ENABLED, 0);
        int wifi = Settings.Global.getInt(getContentResolver(), ApplianceLockdown.ADB_WIFI_ENABLED, 0);
        return ApplianceLockdown.debuggingSetting(usb, wifi);
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
        LinearLayout root = pages.page(eyebrow, title, reason);
        pages.card(root, cardLabel, cardText);
        pages.present(root, screen);
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (operational) handleIntent(intent);
    }


    // ------------------------------------------------------------------ pages
    // Native, scrollable pages. Sensitive operations never use floating dialogs.

    /** The menu is available on the ordinary unlocked screens: never over a PIN gate, a sensitive
     *  flow, an approval, or before a wallet exists. */
    private boolean menuAvailable() {
        return accountScreensReady() && !passphraseEntry;
    }

    /** The account / passphrase screens work (the menu itself hides while a passphrase is typed). */
    private boolean accountScreensReady() {
        return unlocked && operational && walletLoaded && !sensitive.active() && approvalDecision == null
                && !replacementActive() && !setup.replacing();
    }

    private void showMenu() {
        LinearLayout root = pages.page("MENU", "Where to?", null);
        String current = pages.screen();
        pages.action(root, "Wallet", "wallet".equals(current), () -> { if (menuAvailable()) showHome(); });
        pages.action(root, "Accounts", current.startsWith("account"), () -> { if (menuAvailable()) showAccounts(); });
        pages.action(root, passphraseBook != null ? "Passphrase wallet · open" : "Passphrase wallet", current.startsWith("passphrase"),
                () -> { if (menuAvailable()) showPassphraseWallet(); });
        pages.action(root, "Security", "security".equals(current), () -> { if (menuAvailable()) showSecurity(); });
        pages.action(root, "Display & auto-lock", "preferences".equals(current), () -> { if (menuAvailable()) showPreferences(); });
        pages.action(root, "Address book", current.startsWith("address-book"), () -> { if (menuAvailable()) safetyScreens().showList(); });
        pages.action(root, "Bitcoin sharing", "btc-sharing".equals(current), () -> { if (menuAvailable()) showBtcSharing(); });
        pages.action(root, "Device information", "integrity".equals(current), () -> { if (menuAvailable()) showIntegrity(); });
        pages.action(root, "Coming next", "features".equals(current), () -> { if (menuAvailable()) showFeatures(); });
        pages.action(root, "Lock now", false, this::lock);
        pages.present(root, "menu");
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
        pages.showLoading("Opening Phone Vault", "Checking appliance policy…");
    }

    /** Text scale, haptics and idle lock from the saved Display & auto-lock choices. */
    private void applyDisplaySettings() {
        largeText = display.largeText();
        VaultTheme.setTextScale(DisplaySettings.textScale(largeText));
        Haptics.setEnabled(display.haptics());
        idleTimeoutMs = display.idleLockMs();
    }

    private void showHome() {
        if (!walletLoaded) {
            pages.showLoading("Opening your wallet", "Verifying the wallet saved on this device…");
            return;
        }
        endPassphraseEntry();
        SigningAccount account = activeAccount;
        String accountName = account != null ? account.name : AccountBook.defaultName(0);
        boolean passphraseWallet = account != null && account.passphrase;
        LinearLayout root = pages.page(passphraseWallet ? "PASSPHRASE WALLET · " + accountName : accountName,
                !backupVerified ? "Back up your wallet" : passphraseWallet ? "Passphrase wallet" : "Your offline wallet",
                backupVerified ? "Review every request here. Your keys stay on this phone."
                        : "Before receiving or signing, write down all 24 recovery words. We'll then spot-check a few.");
        if (backupVerified && passphraseWallet) {
            pages.card(root, "Passphrase wallet · fingerprint " + account.fingerprint,
                    "Opened with your passphrase. It is not saved: locking the phone closes it. Check the fingerprint is the one you expect.");
        }
        if (battery.low()) pages.card(root, "Battery " + battery.label() + " · charge before signing",
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
            qlp.setMargins(0, pages.dp(4), 0, pages.dp(18));
            box.addView(qrView, qlp);
            box.addView(VaultTheme.bodyText(this, accountName.toUpperCase(Locale.ROOT)
                    + (passphraseWallet ? " · PASSPHRASE" : "") + " · RECEIVE", 13, VaultTheme.FAINT));
            addressView = VaultTheme.monoText(this, ReviewStyle.groupEvmTwoLines(
                    Keys.toChecksumAddress(walletAddress)), 16, VaultTheme.INK);
            Pages.keepGroupsWhole(addressView);
            addressView.setPadding(0, pages.dp(12), 0, pages.dp(8));
            box.addView(addressView);
            root.addView(box, Pages.matchWrap(pages.dp(22)));
            pages.action(root, "Switch account", false, this::showAccounts);
            pages.card(root, "Check the network", "This is an EVM address. Confirm the destination chain in your sending wallet. A matching address does not mean every network is supported.");
            backup.addBackupReminderCard(root);
        } else {
            pages.card(root, "Backup not checked yet", "Receiving and signing are paused until you write the phrase down and pass the spot check. If you already wrote it down, check it now.");
            pages.action(root, "Write down recovery phrase", true, backup::confirmRevealBackup);
            pages.action(root, "I have my backup · check words", false, () -> backup.startBackupAccess(true));
        }
        if (usbReplugHint && transport == null) statusMessage = "USB session ended when the vault locked · unplug and reconnect the cable to resume";
        statusView = VaultTheme.bodyText(this, statusMessage, VaultTheme.BODY_SIZE, VaultTheme.DIM);
        statusView.setPadding(pages.dp(2), pages.dp(20), 0, pages.dp(4));
        root.addView(statusView);
        pages.action(root, "Lock now", false, this::lock);
        pages.card(root, DevTools.SCREENSHOTS ? "Development appliance" : "Prototype",
                "Test assets only. Hardware release verification is still pending.");
        pages.present(root, "wallet");
    }

    private void showSecurity() {
        LinearLayout root = pages.page("DEVICE & WALLET", "Security", "Controls that protect access, recovery, and your ability to verify this device.");
        pages.card(root, "Backup", backupVerified
                ? "Spot-checked for Account 1. Keep the written 24 words somewhere safe and private."
                : "Not checked yet. Receiving and signing stay paused until it is.");
        pages.action(root, "Check my backup", !backupVerified, () -> backup.startBackupAccess(true));
        pages.action(root, "Show recovery phrase", false, backup::confirmRevealBackup);
        pages.card(root, "Passphrase (optional)", "Your 24 words back up every account of the standard wallet. A passphrase wallet ALSO needs its passphrase, which is not part of this backup and is never saved on the phone: keep it written down separately.");
        pages.action(root, "Passphrase wallet", false, this::showPassphraseWallet);
        pages.action(root, "Show as SeedQR", false, backup::confirmRevealSeedQr);
        pages.action(root, "Backup reminder · " + BackupReminder.label(backupReminder.intervalDays()), false, backup::showBackupReminderSettings);
        pages.action(root, "Bitcoin sharing", false, this::showBtcSharing);
        pages.card(root, "This wallet", "Replacing or restoring changes the key on this phone. Keep the current backup if the wallet controls anything.");
        pages.action(root, "Replace with a new wallet", false, backup::confirmReplace);
        pages.action(root, "Restore a different wallet", false, setup::confirmRestoreOver);
        pages.action(root, "Lock now", false, this::lock);
        pages.present(root, "security");
    }

    // ------------------------------------------------------------------ first-run wizard

    // ------------------------------------------------------------------ optional user entropy
    // Physical dice rolls, mixed with the two device sources.

    // ------------------------------------------------------------------ restore over an existing wallet
    // Same entry screens, but owned by a fresh-PIN sensitive flow and the replacement state
    // machine, exactly like Replace (USB excluded throughout).

    // ------------------------------------------------------------------ restore
    // On-device word entry (no system keyboard), validate, confirm address, commit.

    private void showPreferences() {
        LinearLayout root = pages.page("SECURITY / PREFERENCES", "Display & auto-lock",
                "Text size, screen timeout, locking and touch feedback. Changes apply at once.");
        pages.card(root, "Text size", largeText ? "Large · easier reading" : "Standard · comfortable reading");
        pages.action(root, largeText ? "Use standard text" : "Use larger text", true, () -> {
            if (display.setLargeText(!largeText)) {
                applyDisplaySettings();
                showPreferences();
            } else pages.showInfo("Setting not saved", "Try again. Your previous text size is still active.", this::showPreferences);
        });

        int screen = display.screenTimeoutSeconds();
        pages.card(root, "Screen timeout", "The screen turns off after " + DisplaySettings.durationLabel(screen)
                + " without a touch. Screen off always locks the vault.");
        for (int seconds : DisplaySettings.SCREEN_TIMEOUT_CHOICES) {
            pages.action(root, "Screen off after " + DisplaySettings.durationLabel(seconds), seconds == screen, () -> {
                if (display.setScreenTimeoutSeconds(seconds)) {
                    applyDisplaySettings();
                    DevicePolicyManager policy = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
                    if (policy.isDeviceOwnerApp(getPackageName())) applyIdlePolicy(policy);
                    armIdleLock();
                    showPreferences();
                } else pages.showInfo("Setting not saved", "Your previous screen timeout is still active.", this::showPreferences);
            });
        }

        int idle = display.idleSeconds();
        int effective = DisplaySettings.effectiveIdleSeconds(idle, screen);
        pages.card(root, "Idle lock", "Locks after " + DisplaySettings.durationLabel(effective)
                + " without a touch, even while a review keeps the screen on."
                + (effective < idle ? " (Capped by the screen timeout.)" : ""));
        for (int seconds : DisplaySettings.IDLE_CHOICES) {
            pages.action(root, "Lock after " + DisplaySettings.durationLabel(seconds), idle == seconds, () -> {
                if (display.setIdleSeconds(seconds)) {
                    applyDisplaySettings();
                    armIdleLock();
                    showPreferences();
                } else pages.showInfo("Setting not saved", "Your previous idle timeout is still active.", this::showPreferences);
            });
        }

        boolean haptics = display.haptics();
        pages.card(root, "Haptics", haptics ? "On · a tap for PIN keys, a pulse when you sign, a double pulse on reject"
                : "Off · no vibration feedback");
        pages.action(root, haptics ? "Turn haptics off" : "Turn haptics on", false, () -> {
            if (display.setHaptics(!haptics)) {
                applyDisplaySettings();
                showPreferences();
            } else pages.showInfo("Setting not saved", "Your previous haptics setting is still active.", this::showPreferences);
        });

        pages.card(root, "Turning off", "To turn off: hold the power button, then choose Power off or Restart.");
        pages.action(root, "Back to Security", false, this::showSecurity);
        pages.present(root, "preferences");
    }

    private void showIntegrity() {
        LinearLayout root = pages.page("SECURITY / DEVICE", "Know what is verified", "These are local observations, not independent attestation.");
        pages.card(root, "App build", BuildConfig.VERSION_NAME + " · " + (DevTools.SCREENSHOTS ? "development capture enabled" : "release capture disabled"));
        pages.card(root, "Platform", Build.MANUFACTURER + " " + Build.MODEL + "\nAndroid " + Build.VERSION.RELEASE + "\nReported patch: " + Build.VERSION.SECURITY_PATCH);
        pages.card(root, "Device policy", isPhoneVaultApplianceBuild() && operational ? "Appliance policy active" : "Development environment · appliance policy not established");
        pages.card(root, "Key boundary", BuildConfig.VAULT_REQUIRE_SECURE_HARDWARE
                ? "StrongBox wrapping is required when loading. EVM signing runs in Android memory."
                : "Development build permits software wrapping. EVM signing runs in Android memory.");
        pages.card(root, "Verified boot", "Not independently verified by this screen. Complete the release, relock, and external verification procedure.");
        SigningAccount shownAccount = activeAccount;
        pages.card(root, "Account path", shownAccount == null ? "m/44'/60'/0'/0/0 · no passphrase"
                : shownAccount.path() + (shownAccount.passphrase ? " · passphrase wallet " + shownAccount.fingerprint : " · no passphrase"));
        pages.card(root, "PIN protection", credentialMode()
                ? "Checked by the security chip (Titan M), which slows repeated guesses · "
                        + SystemCredential.MAX_FAILED_FOR_WIPE + " wrong PINs reset the phone · the seed key works only for "
                        + SystemCredential.AUTH_WINDOW_SECONDS + " s after a correct PIN"
                : "App PIN gate · 10 failed attempts erase the wallet. PIN-derived encryption is planned.");
        String entropy = getPreferences(MODE_PRIVATE).getString("entropy_report", null);
        pages.card(root, "Entropy at wallet creation", entropy != null ? entropy
                : "Not recorded (this wallet was created or restored before source reporting existed, or restored from words).");
        Intent battery = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (battery != null) {
            int level = battery.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
            int scale = battery.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
            pages.card(root, "Battery charge", level >= 0 && scale > 0 ? (level * 100 / scale) + "% · charge is not a battery-health assessment" : "Unavailable");
        }
        pages.card(root, "Power", "To turn off: hold the power button, then choose Power off or Restart.");
        pages.action(root, "Back to Security", false, this::showSecurity);
        pages.present(root, "integrity");
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
        LinearLayout root = pages.page("PRODUCT ROADMAP", "Coming next", "What is planned. Nothing here can be enabled in this build.");
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
        for (String[] item : items) pages.action(root, item[0] + " · planned", false,
                () -> showPlanned(item[0], item[1]));
        pages.present(root, "features");
    }

    private void showPlanned(String title, String description) {
        LinearLayout root = pages.page("PLANNED · NOT AVAILABLE", title, description);
        pages.card(root, "Availability", "No wallet setting was changed. This screen describes upcoming work.");
        pages.action(root, "Back to Coming next", true, this::showFeatures);
        pages.action(root, "Wallet", false, this::showHome);
        pages.present(root, "planned");
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
            pages.showInfo("Disconnect USB first", "Finish or reject the current request and unplug the host before opening wallet security.", this::showSecurity);
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
        pages.setScreen("reauth");
        setContentView(pinScreen.view());
        devDumpUi();
    }

    private void updatePinPolicy(PinScreen gate) {
        gate.setBattery(battery);
        int remaining = pin.attemptsRemaining();
        gate.setPolicy((DevTools.SCREENSHOTS ? Pages.DEV_KICKER + "\n" : "PROTOTYPE · TEST ASSETS ONLY\n")
                + (SystemCredential.willBind(this) && !pin.isSet()
                        ? "Your PIN will be held by the security chip."
                        : remaining + " attempts remaining. " + VaultPin.MAX_ATTEMPTS + " failed attempts erase the wallet."));
        gate.setSubmitRequired(remaining == 1 && !pin.eraseOutstanding());
    }

    // ------------------------------------------------------------------ SeedQR + backup reminder
    // (logic lives in SeedQr / SeedQrView / BackupReminder; these are only the screens)

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
        pages.showLoading("Opening your wallet", "Checking the saved identity before displaying an address…");
        cryptoExecutor.execute(() -> {
            try {
                if (s != session.get() || !unlocked || pin.eraseOutstanding()) return;
                if (!store.hasWallet()) {
                    // First run: never silently mint a wallet — the user chooses Create or Restore.
                    // (hasWallet() throws when storage is sealed/corrupt → the catch below.)
                    runOnUiThread(() -> { if (s == session.get() && unlocked) setup.showFirstRunChoice(); });
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
                    credentialGate.endSilentUnlockAttempt();
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
                    Log.w(TAG, "wallet load failed: " + KeystoreFailures.chain(e));
                    if (KeystoreFailures.authLapsed(e)) {
                        if (!credentialGate.silentUnlockAttempt()) gateNotice = "Your PIN confirmation expired before the wallet opened. Unlock again.";
                        credentialGate.endSilentUnlockAttempt();
                        lock();
                        return;
                    }
                    LinearLayout root = pages.page("WALLET UNAVAILABLE", "Your address is hidden", "The stored identity could not be verified. Do not replace or reset the wallet to fix this error.");
                    pages.card(root, "Next step", "Lock and retry. If the problem continues, preserve this device and use your written backup with a compatible recovery tool.");
                    pages.action(root, "Lock & retry", true, this::lock);
                    pages.present(root, "wallet-error");
                });
            }
        });
    }

    private Bitmap qrFor(String address) {
        Bitmap qr = VaultTheme.qrBitmap(address, pages.dp(232), pages.dp(12));
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
            synchronized (stateLock) { heldRequest.clear(); } // a new connection never inherits a held request
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
        synchronized (stateLock) { heldRequest.clear(); }
        if (transport != null) {
            AccessoryTransport previous = transport;
            transport = null;
            previous.close();
        }
        boolean replacedRequest = approvalDecision != null;
        cancelApproval();
        if (replacedRequest) approvals.showReceipt("USB session changed", "The previous request ended. If you tapped Sign, check the host for a possible signature before retrying.", null);
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
                synchronized (stateLock) { heldRequest.holdIfLocked(unlocked, transport, source, json, b); }
            } catch (Exception e) {
                b = e instanceof RequestRefusal ? e.getMessage() + " It will be refused after you unlock."
                        : "The connected host sent a request this phone cannot decode. It will be refused after you unlock.";
                synchronized (stateLock) { heldRequest.holdIfLocked(unlocked, transport, source, json, b); }
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
                    source.send(Pages.json("id", id, "status", "ok", "address", credentials.getAddress(),
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
                runOnUiThread(() -> approvals.showMessageApproval(source, approval, decision, s));
                return;
            }
            Eip1559Request request = Eip1559Request.parse(json);
            RequestRefusal.requireFrom(request.from, account.headline(), account.address);
            AddressSafety safety = safety();
            safety.setOwnAccounts(ownAccountNames());
            ApprovalSession approval = new ApprovalSession(request, signer, tokens(), safety, account);
            runOnUiThread(() -> approvals.showApproval(source, approval, decision, s));
        } catch (Exception e) {
            finishApproval(decision);
            sendError(source, id, e.getMessage());
            if (e instanceof RequestRefusal) {
                RequestRefusal refusal = (RequestRefusal) e;
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked || source != transport || sensitive.active() || approvalDecision != null) return;
                    pages.showInfo(refusal.title, refusal.getMessage(), this::showHome);
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
                pages.showInfo(((RequestRefusal) e).title, e.getMessage(), this::showHome);
                Haptics.reject(getWindow().getDecorView());
            } else if ("loading".equals(pages.screen())) {
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
            pages.showLoading("Opening your Bitcoin accounts", "Deriving your " + network.label + " accounts from your recovery phrase…");
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
                            if (KeystoreFailures.authLapsed(e)) {
                                runOnUiThread(credentialGate::forgetConfirmation);
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
                source.send(Pages.json("id", id, "status", "rejected"));
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
            if ("loading".equals(pages.screen()) && approvalDecision == null) showHome();
            else if (statusView != null) statusView.setText(statusMessage);
        });
    }

    private void showBtcShare(AccessoryTransport source, BtcRequest r, BtcWallet wallet, ApprovalDecision decision, int s) {
        if (abandonUnlessOwned(source, s, decision, RequestOwnership.BTC_SHOW)) return;
        keepScreenOn(true);
        LinearLayout root = pages.page(r.network.test() ? r.network.label.toUpperCase(Locale.ROOT) + " · SHARE ACCOUNT" : "BITCOIN · SHARE ACCOUNT",
                "Share Bitcoin account with the Mac?",
                "The connected computer asks for this account's watch-only key, to show your balance and prepare transactions.");
        root.addView(pages.detail(r.network.test() ? BtcPsbtReview.TEST_NETWORK : "Network", r.network.label));
        root.addView(pages.detail("Account", BtcWallet.accountLabel(r.type, r.account) + "\n" + wallet.accountPathString(r.type, r.account)));
        root.addView(pages.detail("Wallet fingerprint", wallet.fingerprintHex()));
        root.addView(pages.detail("What the Mac will see", "Every address, balance and payment of this account, past and future, "
                + "becomes visible to the Mac and to any software on it. It cannot spend: every payment still needs your approval on this phone."));
        root.addView(pages.detail("Asked once", "If you share, the phone remembers it for this account and network and answers "
                + "this request without asking again."));
        TextView share = VaultTheme.pixelButton(this, "Share with the Mac", true);
        TextView decline = VaultTheme.pixelButton(this, "Don't share", false);
        Pages.hardenTouch(share);
        Pages.hardenTouch(decline);
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
            pages.showInfo("Account shared", BtcWallet.accountLabel(r.type, r.account) + " on " + r.network.label
                    + " is now visible to the Mac (watch-only). It cannot spend without this phone.", this::showHome);
        });
        decline.setOnClickListener(v -> {
            if (!decision.reject()) return;
            Haptics.reject(v);
            source.send(Pages.json("id", r.id, "status", "rejected"));
            finishApproval(decision);
            statusMessage = "Bitcoin account not shared";
            showHome();
        });
        root.addView(share, Pages.matchWrap(pages.dp(16)));
        root.addView(decline, Pages.matchWrap(pages.dp(10)));
        pages.present(root, "btc-share");
    }

    /**
     * ☰ → Bitcoin sharing: the accounts btcGetAccount answers without asking, each revocable. A
     * privacy control only: revoking makes the phone ask again; it cannot recall what the Mac
     * already received, and it never changes what is signed.
     */
    private void showBtcSharing() {
        List<String> keys;
        synchronized (stateLock) { keys = walletId != null ? btcSharing().keys() : Collections.emptyList(); }
        LinearLayout root = pages.page("SECURITY / PRIVACY", "Bitcoin sharing",
                "Bitcoin accounts whose watch-only key the Mac receives without asking. Stop sharing to make the phone ask again.");
        if (keys.isEmpty()) {
            pages.card(root, "Nothing shared", "No Bitcoin account is shared. The phone asks before the Mac can see any account.");
        } else {
            pages.card(root, "Already received", "Stopping does not erase what the Mac already received: it can still watch those addresses. "
                    + "It only stops new requests from being answered silently.");
            for (String key : keys) {
                pages.action(root, "Stop sharing · " + BtcSharing.label(key), false, () -> {
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
            if (keys.size() > 1) pages.action(root, "Stop sharing all", false, () -> {
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
        pages.action(root, "Back to Security", false, this::showSecurity);
        pages.present(root, "btc-sharing");
    }

    /** btcShowAddress: the address big, for comparison with the Mac; answered only after Done. */
    private void showBtcAddress(AccessoryTransport source, BtcRequest r, BtcWallet wallet, String address,
                                ApprovalDecision decision, int s) {
        if (abandonUnlessOwned(source, s, decision, RequestOwnership.BTC_SHOW)) return;
        keepScreenOn(true);
        LinearLayout root = pages.page(r.network.test() ? r.network.label.toUpperCase(Locale.ROOT) + " · ADDRESS" : "BITCOIN · RECEIVE ADDRESS",
                "Compare with your Mac", "Check that your Mac shows exactly this address, every group. Only this phone's screen is trusted.");
        root.addView(pages.detail(r.network.test() ? BtcPsbtReview.TEST_NETWORK : "Network", r.network.label));
        LinearLayout box = VaultTheme.box(this);
        TextView big = VaultTheme.monoText(this, BtcScript.grouped(address, 4), 24, VaultTheme.INK);
        big.setTextIsSelectable(false);
        box.addView(big);
        root.addView(box, Pages.matchWrap(pages.dp(12)));
        root.addView(pages.detail("Account", BtcWallet.accountLabel(r.type, r.account)));
        root.addView(pages.detail("Path", wallet.addressPathString(r.type, r.account, r.change, r.index)
                + (r.change == 0 ? " (receiving address " : " (change address ") + r.index + ")"));
        root.addView(pages.detail("If anything differs", "Tap Cancel and do not use the address shown on the Mac."));
        TextView done = VaultTheme.pixelButton(this, "Done: it matches", true);
        TextView cancel = VaultTheme.pixelButton(this, "Cancel", false);
        Pages.hardenTouch(done);
        Pages.hardenTouch(cancel);
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
            source.send(Pages.json("id", r.id, "status", "rejected"));
            finishApproval(decision);
            statusMessage = "Bitcoin address not confirmed";
            showHome();
        });
        root.addView(done, Pages.matchWrap(pages.dp(16)));
        root.addView(cancel, Pages.matchWrap(pages.dp(10)));
        pages.present(root, "btc-address");
    }

    /** btcSignPsbt review, rendered from the BtcPsbtReview built once in handleBitcoin. */
    private void showBtcApproval(AccessoryTransport source, BtcRequest r, BtcPsbtReview review, ApprovalDecision decision, int s) {
        if (abandonUnlessOwned(source, s, decision, RequestOwnership.BTC_SHOW)) return;
        List<MessageReview.Row> dangers = ReviewStyle.dangers(review.summary, review.details);
        LinearLayout root = pages.renderReview(review.kicker, review.title, review.subtitle, dangers, null,
                review.summary, review.details, "technical details");
        final String txid = BtcCrypto.hex(BtcCrypto.reversed(review.psbt.tx.txid()));
        approvals.addDecisionControls(root, source, decision, s, ApprovalScreens.SignSpec.withSeed(r.id, review.reviewPrompt, review.signLabel, dangers,
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
                    approvals.offerToSave(review.parties);
                }));
        pages.present(root, "btc-approval");
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
        if (!backupVerified) { pages.showInfo("Check your backup first", "Accounts open after the backup spot-check, like receiving and signing.", this::showHome); return; }
        accountScreens().showAccounts();
    }

    private void showPassphraseWallet() {
        if (!accountScreensReady()) return;
        if (!backupVerified) { pages.showInfo("Check your backup first", "A passphrase wallet opens after the backup spot-check of your 24 words.", this::showHome); return; }
        accountScreens().showPassphraseIntro();
    }

    /** Derive {@code index} of the open wallet (adding it to the list when {@code add}) and make it the signing account. */
    private void activateAccount(int index, boolean add) {
        if (!accountScreensReady() || !backupVerified) return;
        if (requestPending.get()) { pages.showInfo("Finish the request first", "Approve or reject the request on screen before switching accounts.", this::showHome); return; }
        withSeedKey("Confirm your PIN to switch account", () -> deriveAndActivate(index, add, false));
    }

    private void deriveAndActivate(int index, boolean add, boolean retried) {
        final int s = session.get();
        final AccountBook book;
        final String fingerprint;
        synchronized (stateLock) { book = currentBook(); fingerprint = passphraseFingerprint; }
        if (book == null || !unlocked) return;
        final String name = book.get(index) != null ? book.get(index).name() : AccountBook.defaultName(index);
        pages.showLoading(add ? "Adding " + name : "Switching to " + name, "Deriving its address from your recovery phrase…");
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
                    if (KeystoreFailures.authLapsed(e) && !retried) {
                        credentialGate.forgetConfirmation();
                        confirmDevicePin("Confirm your PIN to switch account", () -> deriveAndActivate(index, add, true), this::showHome);
                        return;
                    }
                    Log.w(TAG, "account switch failed: " + KeystoreFailures.chain(e));
                    pages.showInfo("Account not switched", "The active account is unchanged. " + (e.getMessage() == null ? "" : e.getMessage()), this::showHome);
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
        pages.showLoading("Opening passphrase wallet", "Deriving its fingerprint and first address…");
        cryptoExecutor.execute(() -> {
            try {
                if (s != session.get() || !unlocked) return;
                SeedVault.Derived d = vault.deriveAccount(0, pass);
                final String fingerprint = d.fingerprint, account0 = d.account0Address;
                runOnUiThread(() -> { if (s == session.get() && unlocked && passphraseEntry) result.preview(fingerprint, account0); });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    if (KeystoreFailures.authLapsed(e) && !retried) {
                        credentialGate.forgetConfirmation();
                        confirmDevicePin("Confirm your PIN to open the passphrase wallet", () -> previewWorker(chars, result, true), this::showHome);
                        return;
                    }
                    Log.w(TAG, "passphrase preview failed: " + KeystoreFailures.chain(e));
                    pages.showInfo("Passphrase wallet not opened", "Your current wallet is unchanged. Lock and retry.", this::showHome);
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
        pages.showLoading("Opening passphrase wallet", "Deriving Account 1…");
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
                    if (KeystoreFailures.authLapsed(e) && !retried) {
                        credentialGate.forgetConfirmation();
                        confirmDevicePin("Confirm your PIN to open the passphrase wallet", () -> openPassphraseWallet(true),
                                () -> { synchronized (stateLock) { if (pendingPassphrase != null) Arrays.fill(pendingPassphrase, '\0'); pendingPassphrase = null; } endPassphraseEntry(); showHome(); });
                        return;
                    }
                    synchronized (stateLock) { if (pendingPassphrase != null) Arrays.fill(pendingPassphrase, '\0'); pendingPassphrase = null; }
                    endPassphraseEntry();
                    Log.w(TAG, "passphrase wallet open failed: " + KeystoreFailures.chain(e));
                    pages.showInfo("Passphrase wallet not opened", "Your current wallet is unchanged. " + (e.getMessage() == null ? "" : e.getMessage()), this::showHome);
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
        pages.showLoading("Closing passphrase wallet", "Returning to the standard wallet…");
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
                    if (KeystoreFailures.authLapsed(e) && !retried) {
                        credentialGate.forgetConfirmation();
                        confirmDevicePin("Confirm your PIN to return to the standard wallet", () -> closePassphraseWorker(true), this::showHome);
                        return;
                    }
                    pages.showInfo("Still in the passphrase wallet", "Locking the phone always closes it. " + (e.getMessage() == null ? "" : e.getMessage()), this::showHome);
                });
            }
        });
    }

    private AccountScreens accountScreens() {
        if (accountScreens == null) {
            final MainActivity activity = this;
            accountScreens = new AccountScreens(new AccountScreens.Host() {
                @Override public Context context() { return activity; }
                @Override public LinearLayout page(String eyebrow, String title, String description) { return pages.page(eyebrow, title, description); }
                @Override public void present(LinearLayout root, String screen) { pages.present(root, screen); }
                @Override public void action(LinearLayout parent, String label, boolean primary, Runnable run) { pages.action(parent, label, primary, run); }
                @Override public void card(LinearLayout parent, String label, String value) { pages.card(parent, label, value); }
                @Override public boolean ready() { return accountScreensReady() && backupVerified; }
                @Override public void showHome() { endPassphraseEntry(); activity.showHome(); }
                @Override public void harden(View view) { Pages.hardenTouch(view); }
                @Override public int dp(int value) { return pages.dp(value); }
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
                @Override public LinearLayout page(String eyebrow, String title, String description) { return pages.page(eyebrow, title, description); }
                @Override public void present(LinearLayout root, String screen) { pages.present(root, screen); }
                @Override public void action(LinearLayout parent, String label, boolean primary, Runnable run) { pages.action(parent, label, primary, run); }
                @Override public void card(LinearLayout parent, String label, String value) { pages.card(parent, label, value); }
                @Override public boolean ready() { return menuAvailable(); }
                @Override public void showMenu() { activity.showMenu(); }
                @Override public void showHome() { activity.showHome(); }
                @Override public void harden(View view) { Pages.hardenTouch(view); }
                @Override public int dp(int value) { return pages.dp(value); }
            }, safety().book);
        }
        return safetyScreens;
    }

    private void sendError(AccessoryTransport source, String id, String message) {
        if (source != null) source.send(Pages.json("id", id, "status", "error", "error", message));
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
            droppedHeld = heldRequest.dropIfFrom(source); // its host is gone
        }
        runOnUiThread(() -> {
            if (droppedHeld && !unlocked && pinScreen != null) pinScreen.setPending(null, null);
            if (source != transport) return;
            boolean hadApproval = approvalDecision != null;
            transport = null;
            cancelApproval();
            setStatusActive(false);
            if (unlocked && hadApproval)
                approvals.showReceipt("USB disconnected", "The request session ended. If you tapped Sign, delivery may be uncertain. Check the host before trying another transaction.", null);
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

    /** MainActivity as the flow screens see it: its fields, locks and navigation (VaultHost). */
    private final class ScreenHost implements VaultHost {
        @Override public Activity activity() { return MainActivity.this; }
        @Override public Pages pages() { return pages; }
        @Override public Handler ui() { return ui; }
        @Override public SecureRandom random() { return random; }
        @Override public Object stateLock() { return stateLock; }
        @Override public ExecutorService cryptoExecutor() { return cryptoExecutor; }
        @Override public int session() { return session.get(); }
        @Override public boolean unlocked() { return unlocked; }
        @Override public boolean operational() { return operational; }
        @Override public VaultKeyStore vault() { return vault; }
        @Override public void withSeedKey(String why, Runnable op) { MainActivity.this.withSeedKey(why, op); }
        @Override public void withSeedKey(String why, Runnable op, Runnable onCancel) { MainActivity.this.withSeedKey(why, op, onCancel); }
        @Override public void confirmDevicePin(String why, Runnable onOk, Runnable onCancel) { MainActivity.this.confirmDevicePin(why, onOk, onCancel); }
        @Override public void forgetConfirmation() { credentialGate.forgetConfirmation(); }
        @Override public void showHome() { MainActivity.this.showHome(); }
        @Override public void showSecurity() { MainActivity.this.showSecurity(); }
        @Override public void lock() { MainActivity.this.lock(); }
        @Override public void hideBackup() { MainActivity.this.hideBackup(); }
        @Override public void confirmRevealBackup() { backup.confirmRevealBackup(); }
        @Override public void drainPendingUsb() { MainActivity.this.drainPendingUsb(); }
        @Override public void setStatus(String message) { statusMessage = message; }
        @Override public void showStatus(String message) {
            statusMessage = message;
            if (statusView != null) statusView.setText(statusMessage);
        }
        @Override public void setGateNotice(String notice) { gateNotice = notice; }
        @Override public void keepScreenOn(boolean on) { MainActivity.this.keepScreenOn(on); }
        @Override public void beginSensitive(String purpose, Runnable afterPin) { MainActivity.this.beginSensitive(purpose, afterPin); }
        @Override public boolean sensitiveValid(int token, int s) { return MainActivity.this.sensitiveValid(token, s); }
        @Override public int activeSensitive() { return activeSensitive; }
        @Override public boolean sensitiveActive() { return sensitive.active(); }
        @Override public ReplacementState replacement() { return replacement; }
        @Override public boolean walletLoaded() { return walletLoaded; }
        @Override public boolean backupVerified() { return backupVerified; }
        @Override public String walletId() { return walletId; }
        @Override public String walletAddress() { return walletAddress; }
        @Override public boolean hasCredentials() { return credentials != null; }
        @Override public AccessoryTransport transport() { return transport; }
        @Override public boolean requestPending() { return requestPending.get(); }
        @Override public ApprovalDecision approvalDecision() { return approvalDecision; }
        @Override public BackupCheck backupCheck() { return backupCheck; }
        @Override public BackupReminder backupReminder() { return backupReminder; }
        @Override public Bitmap qrFor(String address) { return MainActivity.this.qrFor(address); }
        @Override public void recordEntropyReport(boolean dice) { MainActivity.this.recordEntropyReport(dice); }
        @Override public void publishNewWallet(Credentials key, Bitmap qr, boolean verified) {
            credentials = key;
            adoptNewWallet(key.getAddress());
            walletAddress = key.getAddress();
            if (qr != null) walletQr = qr;
            backupVerified = verified;
            walletLoaded = true;
        }
        @Override public void clearCredentials() { credentials = null; }
        @Override public void clearReceivingIdentity() { MainActivity.this.clearReceivingIdentity(); }
        @Override public void markWalletUnloaded() { walletLoaded = false; }
        @Override public void setWalletQr(Bitmap qr) { walletQr = qr; }
        @Override public void markBackupVerified() { backupVerified = true; }
        @Override public boolean owns(AccessoryTransport source, int s, ApprovalDecision decision, Set<RequestOwnership.Require> need) {
            return MainActivity.this.owns(source, s, decision, need);
        }
        @Override public boolean abandonUnlessOwned(AccessoryTransport source, int s, ApprovalDecision decision, Set<RequestOwnership.Require> need) {
            return MainActivity.this.abandonUnlessOwned(source, s, decision, need);
        }
        @Override public void finishApproval(ApprovalDecision owner) { MainActivity.this.finishApproval(owner); }
        @Override public void sendError(AccessoryTransport source, String id, String message) { MainActivity.this.sendError(source, id, message); }
        @Override public Credentials signingKey() { return credentials; }
        @Override public AddressSafety safety() { return MainActivity.this.safety(); }
        @Override public void addSaveActions(LinearLayout root, List<TransactionReview.Party> parties) { safetyScreens().addSaveActions(root, parties); }
    }
}
