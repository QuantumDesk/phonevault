package dev.phonevault.signer;

import android.app.Activity;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.ContentObserver;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.hardware.usb.UsbAccessory;
import android.hardware.usb.UsbManager;
import android.os.BatteryManager;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.os.SystemClock;
import android.provider.Settings;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONObject;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public final class MainActivity extends Activity implements AccessoryTransport.Listener {
    private static final String TAG = "Vault";
    private final ExecutorService cryptoExecutor = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final SecureRandom random = new SecureRandom();
    private final AtomicBoolean requestPending = new AtomicBoolean(false);
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
    /** Address book + recipient history for the reviews (AddressSafety); opened on first use. */
    private AddressSafety addressSafety;
    private SafetyScreens safetyScreens;
    private volatile ApprovalDecision approvalDecision;
    // ------------------------------------------------------------------ accounts + passphrase wallet state
    // See AccountBook, AccountScreens (which holds the account lists and the passphrase). Published together with credentials.
    /** Non-secret description of the key in {@link #credentials}; set and cleared with it under stateLock. */
    private volatile SigningAccount activeAccount;
    /** Lowercase account-0 address of the STANDARD wallet: identity of the backup check and the saved account list. */
    private volatile String walletId;
    /** A passphrase is being typed or confirmed: USB requests wait and the ☰ menu hides. */
    private volatile boolean passphraseEntry;
    private volatile boolean walletLoaded, backupVerified;
    private volatile String walletAddress;
    private volatile Bitmap walletQr;
    private BackupCheck backupCheck;
    private BackupReminder backupReminder;
    private boolean largeText;
    /** Display & auto-lock preferences (text scale, brightness, screen timeout, idle lock, lock after screen off, haptics). */
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
    /** Bitcoin: share account, show address, PSBT review; the session's account-key cache. */
    private final BtcScreens btc = new BtcScreens(host, approvals);
    /** ☰ → Security, Display & auto-lock, Device information, Coming next. */
    private final SettingsScreens settings = new SettingsScreens(host, backup, setup, btc);
    /** USB listAddresses: "Share N addresses with your Mac?" (migration: which account numbering holds funds). */
    private final AddressShareScreens addressShare = new AddressShareScreens(host);
    /** USB requests: held behind the lock, readiness, getAddress, attestation, dispatch to a review. */
    private final RequestRouter router = new RequestRouter(host, approvals, btc, addressShare);
    /** ☰ → Accounts and ☰ → Passphrase wallet: screens, account lists, the passphrase, switching. */
    private final AccountScreens accounts = new AccountScreens(new AccountScreens.Host() {
        @Override public Context context() { return MainActivity.this; }
        @Override public LinearLayout page(String eyebrow, String title, String description) { return pages.page(eyebrow, title, description); }
        @Override public void present(LinearLayout root, String screen) { pages.present(root, screen); }
        @Override public void action(LinearLayout parent, String label, boolean primary, Runnable run) { pages.action(parent, label, primary, run); }
        @Override public void card(LinearLayout parent, String label, String value) { pages.card(parent, label, value); }
        @Override public boolean ready() { return accountScreensReady() && backupVerified; }
        @Override public boolean accountScreensReady() { return MainActivity.this.accountScreensReady(); }
        @Override public void showHome() { endPassphraseEntry(); MainActivity.this.showHome(); }
        @Override public void harden(View view) { Pages.hardenTouch(view); }
        @Override public int dp(int value) { return pages.dp(value); }
        @Override public SigningAccount active() { return activeAccount; }
        @Override public void entryActive(boolean active) { passphraseEntry = active; }
        @Override public boolean entryActive() { return passphraseEntry; }
    }, host);
    private boolean batteryRegistered;
    private final BroadcastReceiver batteryReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) { onBattery(readBattery(intent)); }
    };
    private String statusMessage = "USB disconnected · connect your Mac when ready";
    private int activeSensitive = -1;
    private Runnable afterReauth;
    private char[][] pinSetupEntries;

    // ------------------------------------------------------------------ device security & lifecycle
    /** True from the moment a PIN is SET in this unlocked session until it is used once or the
     *  vault locks: the first-run wizard does not ask for the PIN again seconds after setting it. */
    private boolean firstRunPinFresh;
    /**
     * Once-per-boot record of the credential gate's silent unlock (see CredentialGate#show): persisted
     * against the boot id, so re-creating the activity cannot re-arm it.
     */
    private BootUnlockGuard bootUnlock;
    /** Cancels the system PIN prompt that is open (null: none); see CredentialGate#heldRequestChanged. */
    private CancellationSignal promptCancel;
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
        @Override public void systemConfirm(CredentialGate.PromptText text, CredentialGate.Confirmed result) {
            CancellationSignal cancel = new CancellationSignal();
            promptCancel = cancel;
            SystemCredential.confirm(MainActivity.this, text.title, text.subtitle, text.description, cancel, (ok, message) -> {
                if (promptCancel == cancel) promptCancel = null;
                result.done(ok);
            });
        }
        @Override public void cancelSystemConfirm() {
            CancellationSignal cancel = promptCancel;
            if (cancel != null) cancel.cancel();
        }
        @Override public HeldRequest.LockPrompt heldPrompt() {
            synchronized (stateLock) { return heldRequest.lockPrompt(); }
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
    private static final int SCREEN_OFF_TIMEOUT_MS = DisplaySettings.DEFAULT_SCREEN_TIMEOUT_SECONDS * 1000;
    private final Runnable idleLock = this::lock;
    /** uptimeMillis of the last touch (or unlock, or wake inside the grace): the idle lock counts from it. */
    private long lastActivityUptime;
    /** A screen holds the display on (the keep-screen-on window flag, set only through keepScreenOn). UI thread. */
    private boolean screenHeldOn;
    /** Lock after screen off: the grace window and its rules (ScreenOffLock). UI thread. */
    private final ScreenOffLock screenOffLock = new ScreenOffLock();
    private final Runnable graceLock = this::graceTimerFired;
    /** Power-off or reboot from the power menu: lock first, so the key leaves memory before the process dies. */
    private final BroadcastReceiver shutdownReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            if (Intent.ACTION_SHUTDOWN.equals(intent.getAction())) lock();
        }
    };
    /**
     * USB_STATE (sticky): when the bus comes back configured under an open session, ask its
     * descriptor whether it can still send (AccessoryTransport.WriteProbe). A bus reset or a
     * re-enumeration leaves f_accessory's descriptor unable to write (ENODEV) while reads may go
     * on: without this the next request was read and its answer silently lost (the Mac waited
     * for its timeout). Only a check: a stale session ends and is reopened (onDisconnected).
     */
    private final BroadcastReceiver usbStateReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            if (!AccessoryTransport.ACTION_USB_STATE.equals(intent.getAction())) return;
            AccessoryTransport live = transport;
            if (live == null || live.isClosed()) return;
            if (!intent.getBooleanExtra("connected", false) || !intent.getBooleanExtra("configured", false)) return;
            if (!live.writable()) live.failStale("USB bus was reset under the session");
        }
    };
    /** What a host that gave up left behind (gate card "REQUEST ENDED"); cleared by the next held request or unlock. */
    private String gateUsbNote;
    static final String MAC_STOPPED_WAITING = "Your Mac stopped waiting for its request. Nothing was signed. Ask again from your Mac.";
    /** A request read on a session that could no longer answer it: dispatched on the session reopened next (resumed only). */
    private JSONObject carriedRequest;
    private long carriedUntil;
    static final long CARRY_WINDOW_MS = 5000;
    /** Reopens after sessions that ended by themselves without reading a request: bounded, so a failing gadget cannot loop. */
    private volatile int usbSelfReopens;
    static final int MAX_SELF_REOPENS = 3;
    /** Set when a lock closed a live USB session; shown on Home only if it could not be reopened. */
    private boolean usbReplugHint;
    /** Reopen attempts for an accessory that is still attached (see resumeAttachedAccessory). */
    private static final int USB_RESUME_ATTEMPTS = 4;
    private static final long USB_RESUME_RETRY_MS = 400;
    /** Unplug: end the session at once (a reader can be left waiting on an accessory that is gone). */
    private final BroadcastReceiver usbDetachReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            if (!UsbManager.ACTION_USB_ACCESSORY_DETACHED.equals(intent.getAction())) return;
            AccessoryTransport live = transport;
            if (live == null) return;
            live.detached();
            onDisconnected(live, "USB cable disconnected");
        }
    };
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
     * A request that arrived while LOCKED, bound to its connection (HeldRequest). Under stateLock.
     * A relock while still locked keeps it (with its gate session); a lock from unlocked refuses it.
     */
    private final HeldRequest heldRequest = new HeldRequest();
    /** Session whose credential-mode locked page is on screen (-1: none yet); see refreshGateRequest. */
    private int lockedPageSession = -1;
    private String gateNotice;
    /** {@link AccountBook#listNotice} from this unlock, shown on the home screen until the phone locks. */
    private String accountNotice;
    private int shiftPhase;
    /** Release builds: watches Settings.Global.ADB_ENABLED and adb_wifi_enabled (see adbRefused). */
    private ContentObserver adbObserver;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        secure(getWindow());
        getWindow().setStatusBarColor(Color.rgb(17, 19, 24));
        getWindow().setBackgroundDrawable(new ColorDrawable(VaultTheme.BG));
        buildUi();
        IntentFilter detached = new IntentFilter(UsbManager.ACTION_USB_ACCESSORY_DETACHED);
        IntentFilter usbState = new IntentFilter(AccessoryTransport.ACTION_USB_STATE);
        IntentFilter shutdown = new IntentFilter(Intent.ACTION_SHUTDOWN);
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            registerReceiver(usbDetachReceiver, detached, Context.RECEIVER_NOT_EXPORTED);
            registerReceiver(usbStateReceiver, usbState, Context.RECEIVER_NOT_EXPORTED);
            registerReceiver(shutdownReceiver, shutdown, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(usbDetachReceiver, detached);
            registerReceiver(usbStateReceiver, usbState);
            registerReceiver(shutdownReceiver, shutdown);
        }
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
        ui.removeCallbacks(graceLock);
        if (screenOffLock.wakeMustLock(SystemClock.elapsedRealtime())) {
            // The grace ran out while the display was off (the CPU may have slept through the
            // timer): lock before anything is drawn.
            lock();
        } else if (unlocked) {
            // Woken inside the grace: no PIN. The idle lock counts from the wake.
            lastActivityUptime = SystemClock.uptimeMillis();
            armIdleLock();
        }
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
     *
     * <p>Lock after screen off (Display &amp; auto-lock, at most 1 minute): only when the DISPLAY
     * went off, the vault is unlocked, and no screen is up that must never outlive the display
     * ({@link #mustLockWithDisplay}), the lock waits for the grace (ScreenOffLock). The key stays
     * in memory for that long; a held or open USB request still needs Approve on screen; the next
     * sensitive action asks for the PIN again; the idle lock is off while the display is.
     */
    @Override protected void onStop() {
        foreground = false;
        long now = SystemClock.elapsedRealtime();
        if (display != null && screenOffLock.screenOff(display.screenOffGraceSeconds(), !displayInteractive(), unlocked,
                mustLockWithDisplay(), now) == ScreenOffLock.Action.GRACE) {
            ui.removeCallbacks(idleLock);
            credentialGate.forgetConfirmation(); // the chip's window is not reused for a sensitive action
            firstRunPinFresh = false;
            ui.removeCallbacks(graceLock);
            ui.postDelayed(graceLock, Math.max(1, screenOffLock.remainingMs(now)));
            Log.i(TAG, "display off: the vault locks after the grace");
        } else {
            lock();
        }
        super.onStop();
    }

    /** The grace timer (uptime-based, may run late while the CPU sleeps; never early). */
    private void graceTimerFired() {
        long now = SystemClock.elapsedRealtime();
        if (screenOffLock.timerMustLock(now)) lock();
        else if (screenOffLock.running()) ui.postDelayed(graceLock, Math.max(1, screenOffLock.remainingMs(now)));
    }

    private boolean displayInteractive() {
        PowerManager power = getSystemService(PowerManager.class);
        return power == null || power.isInteractive();
    }

    /**
     * Screens that never outlive the display, grace or not: a sensitive flow (recovery phrase,
     * backup check, replace, restore), PIN entry of any kind, passphrase typing, first-run setup
     * or a wallet still loading, and a replacement in progress.
     */
    private boolean mustLockWithDisplay() {
        return sensitive.active() || backup.showingWords() || passphraseEntry || replacementActive() || setup.replacing()
                || !walletLoaded || !operational || pinScreen != null || credentialGate.promptOpen();
    }

    @Override public void onUserInteraction() {
        super.onUserInteraction();
        lastActivityUptime = SystemClock.uptimeMillis();
        if (unlocked) armIdleLock();
        if (sensitive.active() && backup.showingWords()) backup.touched();
        devDumpUi(); // dev-only: every touch refreshes the UI dump (no-op in release)
    }

    /**
     * Dev builds only: {@link DevTools} in src/debug (shared by the appliance build type) renders
     * the screen to files/vault_dump.png for UI review. The release source set compiles a no-op,
     * so a release APK contains no screenshot code at all.
     */
    boolean isSensitiveScreen() { return sensitive.active() || (passphraseEntry && accounts.revealing()); }

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
        if (ApplianceProvisioning.applianceImage() && !managed) {
            deactivate("Phone Vault is not this phone's device owner, so it cannot lock the phone down.");
            return;
        }
        if (managed && !enterVaultMode(policy)) {
            deactivate("The kiosk (lock-task) policy could not be enforced.");
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
            // Started (or restarted) with the Mac already attached: its session is read behind the gate.
            resumeAttachedAccessory(USB_RESUME_ATTEMPTS);
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
                            + SystemCredential.MAX_FAILED_FOR_WIPE + " wrong PINs erase the phone."
                    : "Choose a " + VaultPin.PIN_LENGTH + "-digit PIN. It unlocks this vault. "
                            + VaultPin.MAX_ATTEMPTS + " wrong attempts erase the wallet.";
        } else if (sealed) {
            subtitle = "Attempt limit reached but the wallet could not be verifiably erased. "
                    + "The vault stays sealed. Enter any PIN to retry the erase.";
        } else {
            subtitle = "Enter your six-digit PIN." + (pendingUsb != null ? " Your Mac is waiting." : "");
        }
        if (gateNotice != null) { subtitle = gateNotice + "\n\n" + subtitle; gateNotice = null; }
        final int s = session.get(); // PIN operations are bound to this gate's session
        pinScreen = new PinScreen(this, title, subtitle, entered -> {
            if (creating) onCreatePinEntry(entered, firstEntry, s);
            else onUnlockEntry(entered, s);
        });
        // A request that arrived while locked (or a connected host) is shown on the gate too.
        synchronized (stateLock) { if (heldRequest.summary() != null) pinScreen.setPending("INCOMING REQUEST", heldRequest.summary()); }
        if (transport != null && !creating && !sealed) pinScreen.setSubtitle("Enter your six-digit PIN. Your Mac is connected; its request will appear here.");
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
        lockedPageSession = s;
        LinearLayout root = pages.page("LOCKED", "Phone Vault is locked",
                "Your PIN is checked by the phone's security chip. Tap Unlock and enter it on the next screen.");
        boolean holding;
        synchronized (stateLock) {
            holding = heldRequest.summary() != null;
            if (holding) pages.card(root, "INCOMING REQUEST", heldRequest.summary());
        }
        if (!holding && gateUsbNote != null) pages.card(root, "REQUEST ENDED", gateUsbNote);
        if (transport != null) pages.card(root, "USB", "Your Mac is connected. Its request stays unanswered until you unlock and review it.");
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

    /**
     * The gate shows what is held right now: the PIN screen's pending line and, in credential mode,
     * the locked page (which draws its "INCOMING REQUEST" and USB cards only when it is built, so
     * it is rebuilt for the current session). A request or a session that arrives while the locked
     * page is up appears at once, not only on the next lock. UI thread.
     */
    private void refreshGateRequest(String label, String body) {
        if (unlocked) return;
        if (pinScreen != null) pinScreen.setPending(label, body);
        if (lockedPageSession == session.get()) showLockedPage(lockedPageSession);
        // The system PIN prompt covers that page: it says the same (re-shown with the new text).
        credentialGate.heldRequestChanged();
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
            // Choosing a PIN (first run, which also precedes a restore): never one a thief tries
            // first (GuessablePins). Unlock never applies this check.
            if (GuessablePins.guessable(entered)) {
                Arrays.fill(entered, '0');
                pinScreen.showError(GuessablePins.MESSAGE);
                return;
            }
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
                            pinScreen.showError("Wrong PIN · " + result.attemptsRemaining
                                    + (result.attemptsRemaining == 1 ? " attempt left" : " attempts left"));
                            updatePinPolicy(pinScreen);
                            break;
                        case WIPED:
                            gateNotice = "Wallet erased: too many wrong PINs. The wallet and PIN were destroyed. Set a new PIN, then create or restore a wallet.";
                            showPinGate(null);
                            break;
                        case ERASE_FAILED:
                        default:
                            // Fail closed: PIN kept, no key load possible, only the erase retries.
                            showPinGate(null);
                            pinScreen.showError("Erase not confirmed · enter any PIN to retry");
                            break;
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (s != session.get() || pinScreen == null) return;
                    Log.w(TAG, "pin check failed: " + e);
                    pinScreen.showError("PIN check failed. Try again.");
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
        getSharedPreferences(AccountScreens.ACCOUNT_PREFS, MODE_PRIVATE).edit().remove(AccountScreens.ACCOUNT_BOOK_KEY).commit();
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
        if (gateUsbNote != null) { statusMessage = gateUsbNote; gateUsbNote = null; }
        loadKey();
        lastActivityUptime = SystemClock.uptimeMillis();
        armIdleLock();
    }

    /**
     * Invalidate the session (ALWAYS — even if already locked, so an in-flight PIN op dies), drop
     * the key from memory, end any USB session, and return to the PIN gate.
     */
    private void lock() {
        AccessoryTransport staleTransport;
        synchronized (stateLock) {
            final boolean wasUnlocked = unlocked;
            session.incrementAndGet(); // invalidates any in-flight PIN op / load / regeneration
            unlocked = false;
            credentials = null;
            accounts.clearPassphraseWallet(); // the passphrase never outlives the unlocked session
            // An un-activated candidate is discarded; a commit or a signing in progress holds
            // stateLock, so by now it has either finished (key dropped above) or never ran.
            replacement.reset();
            sensitive.reset();
            cancelApproval();
            clearReceivingIdentity();
            // USB data-lock (app layer): the session is closed INSIDE the lock so a signing task
            // can never send after this point (send + close are linearized with signing).
            // A relock while already locked (screen off, Back on the gate) keeps the gate's own
            // session: it was opened behind the gate, it only reads and holds, and it has answered
            // nothing. Its held request stays on the gate until the PIN, as before the screen went
            // off (dropping it silently left the host waiting for its timeout).
            boolean keepGateSession = !wasUnlocked && transport != null && !transport.isClosed();
            staleTransport = keepGateSession ? null : transport;
            if (!keepGateSession) {
                transport = null;
                // Locking from unlocked: a request held behind the gate and not dispatched yet (the
                // wallet was still loading) gets a refusal, the one answer a locked phone gives, as
                // the session's last frame. Nothing else can be sent on it after this point.
                HeldRequest.Taken undispatched = heldRequest.take(staleTransport); // always forgets it
                if (staleTransport != null) {
                    if (undispatched != null) staleTransport.closeAfter(HeldRequest.lockedRefusal(undispatched.request));
                    else staleTransport.close();
                    usbReplugHint = true;
                }
            }
            keepScreenOn(false);
        }
        clearSensitiveUi();
        clearPinEntry();
        screenOffLock.locked();
        ui.removeCallbacks(graceLock);
        if (!operational) return;
        bootUnlock.noteLock(bootId()); // no silent boot unlock after any lock this boot
        requestPending.set(false);
        ui.removeCallbacks(idleLock);
        backup.stopSeedTimer();
        showPinGate(null);
        // The lock ended the session, not the attachment: read the host again behind the gate
        // (posted: the closed session's reader first has to leave read() and release the device).
        ui.postDelayed(() -> resumeAttachedAccessory(USB_RESUME_ATTEMPTS), USB_RESUME_RETRY_MS);
    }

    /**
     * The idle lock: no touch for the effective idle time (DisplaySettings#idleLockMs, which also
     * knows whether a screen holds the display on), counted from the last touch, unlock or wake.
     * Off while the display is (the screen-off path owns that time).
     */
    private void armIdleLock() {
        ui.removeCallbacks(idleLock);
        if (!foreground && screenOffLock.running()) return;
        long idle = display.idleLockMs(screenHeldOn);
        // While the recovery phrase (or its check) is on screen, the seed timer owns the timeout.
        long delay = backup.showingWords() ? Math.max(idle, BackupScreens.SEED_TIMEOUT_MS + 10_000L) : idle;
        long now = SystemClock.uptimeMillis();
        if (lastActivityUptime <= 0 || lastActivityUptime > now) lastActivityUptime = now;
        ui.postDelayed(idleLock, Math.max(0, delay - (now - lastActivityUptime)));
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
        if (!held.source.writable()) {
            // The bus dropped after the request was read (its host timed out, was killed, or reset
            // the port): no answer can reach the host that sent it. Nothing is reviewed; the
            // session ends as stale and the still-attached accessory is opened again.
            held.source.failStale("the held request's host went away");
            statusMessage = MAC_STOPPED_WAITING;
            if (statusView != null) statusView.setText(statusMessage);
            return;
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

    /** Self-provisioning, lockdown and lock task (ApplianceProvisioning); a refused step is a policy error. */
    private boolean enterVaultMode(DevicePolicyManager policy) {
        try {
            return ApplianceProvisioning.enterVaultMode(this, policy, devBuild());
        } catch (RuntimeException exception) {
            statusView.setText("Vault policy error: " + exception.getMessage());
            return false;
        }
    }

    /** Device owner: idle screen-off (burn-in + walk-away). Best effort; never fatal. */
    private void applyIdlePolicy(DevicePolicyManager policy) {
        ApplianceProvisioning.applyIdlePolicy(this, policy, () -> display != null ? display.screenTimeoutMs() : SCREEN_OFF_TIMEOUT_MS);
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

    private void deactivate(String reason) {
        deactivate("DEVICE NOT READY", "Policy check failed", reason, "Signing is disabled",
                "Phone Vault could not take control of this phone as an appliance. Restart the phone; if this screen comes back, "
                        + "flash the Phone Vault image again by following the setup guide. No wallet identity is displayed.", "policy-error");
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
            accounts.clearPassphraseWallet();
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
        pages.action(root, accounts.passphraseWalletOpen() ? "Passphrase wallet · open" : "Passphrase wallet", current.startsWith("passphrase"),
                () -> { if (menuAvailable()) showPassphraseWallet(); });
        pages.action(root, "Security", "security".equals(current), () -> { if (menuAvailable()) settings.showSecurity(); });
        pages.action(root, "Display & auto-lock", "preferences".equals(current), () -> { if (menuAvailable()) settings.showPreferences(); });
        pages.action(root, "Address book", current.startsWith("address-book"), () -> { if (menuAvailable()) safetyScreens().showList(); });
        pages.action(root, "Bitcoin sharing", "btc-sharing".equals(current), () -> { if (menuAvailable()) btc.showBtcSharing(); });
        pages.action(root, "Device information", "integrity".equals(current), () -> { if (menuAvailable()) settings.showIntegrity(); });
        pages.action(root, "Power", current.startsWith("power"), () -> { if (menuAvailable()) settings.showPower(); });
        pages.action(root, "Coming next", "features".equals(current), () -> { if (menuAvailable()) settings.showFeatures(); });
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

    /** Text scale, haptics and brightness from the saved Display & auto-lock choices (the idle lock reads them when armed). */
    private void applyDisplaySettings() {
        largeText = display.largeText();
        VaultTheme.setTextScale(DisplaySettings.textScale(largeText));
        Haptics.setEnabled(display.haptics());
        applyBrightness();
    }

    /** The saved brightness, re-applied on every start; nothing until the owner chose one here. */
    private void applyBrightness() {
        if (display == null || !display.brightnessChosen()) return;
        applyBrightness(display.brightnessPercent(), display.brightnessAuto());
    }

    /**
     * Device owner: Settings.System SCREEN_BRIGHTNESS_MODE / SCREEN_BRIGHTNESS through
     * DevicePolicyManager#setSystemSetting (as the screen timeout; no WRITE_SETTINGS). Otherwise,
     * or if the system refuses, this window's own brightness (WindowManager.LayoutParams).
     */
    private void applyBrightness(int percent, boolean auto) {
        DevicePolicyManager policy = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        if (policy != null && policy.isDeviceOwnerApp(getPackageName())
                && ApplianceProvisioning.applyBrightness(this, policy, percent, auto)) {
            setWindowBrightness(WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_NONE);
            return;
        }
        setWindowBrightness(auto ? WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_NONE : DisplaySettings.windowBrightness(percent));
    }

    private void setWindowBrightness(float value) {
        runOnUiThread(() -> {
            WindowManager.LayoutParams attributes = getWindow().getAttributes();
            if (attributes.screenBrightness == value) return;
            attributes.screenBrightness = value;
            getWindow().setAttributes(attributes);
        });
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
                        : "Before receiving or signing, write down all the words of your recovery phrase. We'll then spot-check a few.");
        if (backupVerified && passphraseWallet) {
            pages.card(root, "Passphrase wallet · fingerprint " + account.fingerprint,
                    "Opened with your passphrase. It is not saved: locking the phone closes it. Check the fingerprint is the one you expect.");
        }
        if (accountNotice != null && !passphraseWallet) pages.card(root, "Account list", accountNotice);
        if (battery.low()) pages.card(root, "Battery " + battery.label() + " · charge before signing",
                "Plug in before reviewing a request. If the phone shuts down mid-review, the request is simply lost; nothing is signed.");
        if (backupVerified && walletAddress != null && walletQr != null) {
            LinearLayout box = VaultTheme.box(this);
            box.setGravity(Gravity.CENTER_HORIZONTAL);
            ImageView qrView = new ImageView(this);
            qrView.setContentDescription("Receiving address QR. Full address follows.");
            qrView.setImageBitmap(walletQr);
            // Shown at the bitmap's own pixel size: integer-scaled modules stay perfectly square.
            LinearLayout.LayoutParams qlp = new LinearLayout.LayoutParams(walletQr.getWidth(), walletQr.getHeight());
            qlp.gravity = Gravity.CENTER_HORIZONTAL;
            qlp.setMargins(0, pages.dp(4), 0, pages.dp(18));
            box.addView(qrView, qlp);
            box.addView(VaultTheme.bodyText(this, accountName.toUpperCase(Locale.ROOT)
                    + (passphraseWallet ? " · PASSPHRASE" : "") + " · RECEIVE", 13, VaultTheme.FAINT));
            TextView addressView = VaultTheme.monoText(this, ReviewStyle.groupEvmTwoLines(
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
        if (usbReplugHint && transport == null) statusMessage = "USB session ended when the vault locked · ask again from your Mac; if it cannot connect, unplug and reconnect the cable";
        statusView = VaultTheme.bodyText(this, statusMessage, VaultTheme.BODY_SIZE, VaultTheme.DIM);
        statusView.setPadding(pages.dp(2), pages.dp(20), 0, pages.dp(4));
        root.addView(statusView);
        pages.action(root, "Lock now", false, this::lock);
        pages.card(root, "Development · test assets only",
                "Hardware release verification is still pending.");
        pages.present(root, "wallet");
    }

    private void setStatusActive(boolean active) {
        statusMessage = active ? "USB connected · waiting for a request" : "USB disconnected";
        if (statusView != null) statusView.setText(statusMessage);
    }


    private boolean sensitiveValid(int token, int s) {
        return operational && unlocked && foreground && s == session.get() && sensitive.owns(token);
    }

    /** A sensitive flow whose PIN check was dismissed: free the token (no-op if a lock already reset it). */
    private void releaseSensitive(int token) {
        if (sensitive.end(token) && activeSensitive == token) activeSensitive = -1;
    }

    /**
     * ☰ → Power → Restart (confirmed): lock first (key out of memory, USB closed), then
     * DevicePolicyManager#reboot, device owner only. Never while a request is held or reviewed.
     */
    private void restart() {
        if (!host.restartAvailable() || host.requestUnderReview() || !unlocked) return;
        lock();
        try {
            DevicePolicyManager policy = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
            policy.reboot(VaultDeviceAdminReceiver.component(this));
        } catch (RuntimeException refused) {
            Log.w(TAG, "restart refused: " + refused.getMessage());
            gateNotice = "The phone did not restart. Hold the power button, then choose Restart.";
            showPinGate(null);
        }
    }

    private void beginSensitive(String purpose, Runnable afterPin) {
        if (!walletLoaded || credentials == null || !unlocked) return;
        if (transport != null || requestPending.get()) {
            pages.showInfo("Disconnect USB first", "Finish or reject the current request and unplug your Mac before opening wallet security.", settings::showSecurity);
            return;
        }
        // A system PIN prompt is already open: it would not stack a second one, and the token
        // taken below would then wait for a prompt that never comes.
        if (credentialMode() && credentialGate.promptOpen()) return;
        int token;
        synchronized (stateLock) {
            token = sensitive.begin();
            if (token < 0) return;
            activeSensitive = token;
        }
        final int s = session.get();
        if (credentialMode()) {
            // Back, an error or a timeout on the system prompt ends the flow: without this the token
            // stayed taken and every later sensitive action (Continue · verify PIN, ☰ → Wallet)
            // did nothing until the next lock.
            if (screenOffLock.pinRequiredForSensitive()) {
                // Woken inside "Lock after screen off": a sensitive action always asks for the
                // PIN, even while the chip's window from the last PIN is still open.
                confirmDevicePin("Enter your PIN to " + purpose, () -> {
                    screenOffLock.sensitivePinConfirmed();
                    if (sensitiveValid(token, s)) afterPin.run();
                }, () -> releaseSensitive(token));
                return;
            }
            withSeedKey("Enter your PIN to " + purpose, () -> { if (sensitiveValid(token, s)) afterPin.run(); },
                    () -> releaseSensitive(token));
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
        gate.setPolicy(Pages.DEV_KICKER + "\n"
                + (SystemCredential.willBind(this) && !pin.isSet()
                        ? "Your PIN will be held by the security chip."
                        : remaining + " attempts remaining. " + VaultPin.MAX_ATTEMPTS + " failed attempts erase the wallet."));
        gate.setSubmitRequired(remaining == 1 && !pin.eraseOutstanding());
    }

    private static void secure(Window window) {
        if (!DevTools.SCREENSHOTS) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }

    private void clearReceivingIdentity() {
        btc.clearWallets();
        accountNotice = null;
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
                // The standard wallet's saved account list, checked against the seed in ONE decrypt.
                // Unlock always opens the standard wallet: a passphrase wallet must be re-entered.
                // The saved account numbering (Standard or Ledger Live) decides which path each account is.
                // Every listed account (both numberings) is re-derived; one whose saved address the
                // seed does not give is dropped, so the list never names a foreign address as yours.
                final String savedBook = getSharedPreferences(AccountScreens.ACCOUNT_PREFS, MODE_PRIVATE).getString(AccountScreens.ACCOUNT_BOOK_KEY, null);
                final int[] dropped = new int[1];
                final SeedVault.Derived[] active = new SeedVault.Derived[1];
                AccountBook book = store.withWallet(null, w -> {
                    AccountBook b = AccountBook.load(savedBook, w.account0Address);
                    dropped[0] = b.dropUnverified(w::address);
                    active[0] = w.account(b.activeIndex(), b.scheme);
                    return b;
                });
                SeedVault.Derived derived = active[0];
                String address = derived.credentials.getAddress();
                book.select(book.activeIndex(), address); // dropUnverified checked it; a mismatch here is refused, never published
                final Credentials loaded = derived.credentials;
                final AccountBook loadedBook = book;
                final String notice = AccountBook.listNotice(book.resetNotice(), dropped[0]);
                Bitmap qr = qrFor(address);
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked || !operational) return;
                    credentials = loaded;
                    accounts.clearPassphraseWallet();
                    walletId = derived.account0Address;
                    accounts.setStandardBook(loadedBook);
                    activeAccount = new SigningAccount(loadedBook.activeIndex(), loadedBook.active().name(), false, derived.fingerprint, address, loadedBook.scheme);
                    walletAddress = address;
                    walletQr = qr;
                    backupVerified = backupCheck.verified(walletId);
                    accountNotice = notice;
                    walletLoaded = true;
                }
                accounts.saveStandardBook(loadedBook);
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    credentialGate.endSilentUnlockAttempt();
                    showHome();
                    drainPendingUsb();
                    if (transport == null) resumeAttachedAccessory(USB_RESUME_ATTEMPTS);
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

    private void handleIntent(Intent intent) { handleIntent(intent, false); }

    /**
     * The framework still has our accessory attached, but no session reads it: the vault locked
     * and closed the session, or this activity (re)started after the attach. A host that comes
     * back finds the phone already in accessory mode, and its AOA handshake does not re-enumerate
     * it (UsbDeviceManager skips an unchanged function set), so no new USB_ACCESSORY_ATTACHED
     * arrives: open the attached accessory again, exactly as an attach would (behind the gate
     * while locked: read and held, never answered). The host then finds a reader on the same
     * endpoints, without a replug. Only the accessory our filter admits, only with the permission
     * the attach already granted (never requested here). UI thread. Retried a few times: the
     * closed session's descriptor is released only once its reader has left read(), and the
     * accessory device opens exclusively (EBUSY until then).
     */
    private void resumeAttachedAccessory(int attemptsLeft) {
        if (!operational || transport != null || attemptsLeft <= 0) return;
        // Unlocked but not ready for USB (setup, a sensitive flow, the backup check): an attach
        // would only be parked; the parked one, if any, is replayed when that ends.
        if (unlocked && (replacementActive() || sensitive.active() || !walletLoaded || !backupVerified)) return;
        UsbManager usb = (UsbManager) getSystemService(USB_SERVICE);
        UsbAccessory attached;
        try {
            // Only while the accessory function is really the configured one. getAccessoryList()
            // can name an accessory whose function is gone (a function change other than an
            // accessory exit leaves it set), and an open /dev/usb_accessory is exclusive: the
            // framework could then not read a host's handshake strings (START ignored).
            if (!AccessoryTransport.accessoryConfigured(registerReceiver(null, new IntentFilter(AccessoryTransport.ACTION_USB_STATE)))) return;
            attached = AccessoryTransport.ourHost(usb.getAccessoryList());
            if (attached == null || !usb.hasPermission(attached)) return;
        } catch (RuntimeException e) {
            return;
        }
        handleIntent(new Intent(UsbManager.ACTION_USB_ACCESSORY_ATTACHED).putExtra(UsbManager.EXTRA_ACCESSORY, attached), true);
        if (transport == null && attemptsLeft > 1) {
            ui.postDelayed(() -> resumeAttachedAccessory(attemptsLeft - 1), USB_RESUME_RETRY_MS);
        } else if (transport != null) {
            Log.i(TAG, "USB: reopened the attached accessory");
        }
    }

    /** {@code resumed}: the accessory was already attached (resumeAttachedAccessory), not just plugged in. */
    private void handleIntent(Intent intent, boolean resumed) {
        if (!operational || intent == null) return;
        if (!UsbManager.ACTION_USB_ACCESSORY_ATTACHED.equals(intent.getAction())) return;
        if (!unlocked) {
            // USB data-lock (app layer): while locked the phone READS the host's request so the
            // gate can show what is waiting, but it never answers — no bytes leave until the PIN
            // is entered and the request has gone through the ordinary review path.
            UsbAccessory gated = intent.getParcelableExtra(UsbManager.EXTRA_ACCESSORY);
            if (gated == null) return;
            boolean hadHeld;
            synchronized (stateLock) { hadHeld = heldRequest.summary() != null; }
            synchronized (stateLock) { heldRequest.clear(); } // a new connection never inherits a held request
            // A host attached afresh (START) while a request waited: the host that sent it gave up.
            if (hadHeld && !resumed) gateUsbNote = MAC_STOPPED_WAITING;
            if (!resumed) usbSelfReopens = 0;
            if (transport != null) { AccessoryTransport previous = transport; transport = null; previous.close(); }
            try {
                AccessoryTransport opened = AccessoryTransport.open((UsbManager) getSystemService(USB_SERVICE), gated, this);
                transport = opened;
                opened.start();
                pendingUsb = null;
                if (resumed) dispatchCarried(opened);
                // A fresh attach lights the gate for the waiting Mac; a resumed session (after a
                // lock) must not hold the screen on: the gate lights when a request arrives.
                if (!resumed) keepScreenOn(true);
                if (pinScreen != null) pinScreen.setSubtitle("Enter your six-digit PIN. Your Mac is connected; its request will appear here.");
            } catch (Exception exception) {
                transport = null;
                pendingUsb = intent; // fall back to replaying the attach after unlock
                if (pinScreen != null) pinScreen.setSubtitle("Enter your six-digit PIN. Your Mac is waiting.");
            }
            refreshGateRequest(null, null); // nothing held on the new connection; its USB card shows
            return;
        }
        if (replacementActive() || sensitive.active() || !walletLoaded || !backupVerified) {
            // Sensitive screens, incomplete backup, and USB are mutually exclusive. Park the host
            // until the replacement completes or is cancelled (then replayed from there).
            pendingUsb = intent;
            statusMessage = "Your Mac is waiting · finish wallet setup or the security step first";
            if (statusView != null) statusView.setText(statusMessage);
            return;
        }
        UsbAccessory accessory = intent.getParcelableExtra(UsbManager.EXTRA_ACCESSORY);
        if (accessory == null) return;
        synchronized (stateLock) { heldRequest.clear(); }
        if (!resumed) usbSelfReopens = 0;
        if (transport != null) {
            AccessoryTransport previous = transport;
            transport = null;
            previous.close();
        }
        ApprovalDecision replaced = approvalDecision;
        boolean undecided = replaced != null && replaced.state() == ApprovalDecision.State.REVIEW;
        cancelApproval();
        if (undecided) approvals.showReceipt("Your Mac stopped waiting", "Your Mac connected again, so the request on screen ended before you decided. Nothing was signed. Ask again from your Mac if you still want it.", null);
        else if (replaced != null) approvals.showReceipt("USB session changed", "The previous request ended. If you tapped Approve & sign, check your Mac for a possible signature before retrying.", null);
        try {
            AccessoryTransport opened = AccessoryTransport.open(
                    (UsbManager) getSystemService(USB_SERVICE), accessory, this);
            transport = opened;  // publish first …
            opened.start();      // … then let callbacks fire; none can be mis-attributed now
            if (resumed) dispatchCarried(opened);
            statusMessage = "USB connected · waiting for a request";
            if (statusView != null) statusView.setText(statusMessage);
        } catch (Exception exception) {
            transport = null;
            statusMessage = "USB connection failed · unplug and reconnect your Mac";
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

    /** USB reader thread (or the crypto thread for a held request): RequestRouter decides. */
    @Override public void onRequest(AccessoryTransport source, JSONObject json) { router.onRequest(source, json); }

    /**
     * A request read on a session that could no longer answer it (AccessoryTransport#takeCarried),
     * handed to the session reopened on the same, still-attached accessory within
     * {@link #CARRY_WINDOW_MS}: its sender wrote it after the bus dropped, so it is the host on the
     * bus now. It takes the ordinary path (held behind the lock, or reviewed); never answered by
     * this hand-over itself. UI thread.
     */
    private void dispatchCarried(AccessoryTransport opened) {
        JSONObject carried = carriedRequest;
        carriedRequest = null;
        if (carried == null || SystemClock.elapsedRealtime() > carriedUntil) return;
        cryptoExecutor.execute(() -> onRequest(opened, carried));
    }

    /**
     * A session ended by itself (a failed write, a stale descriptor, a read error) while the
     * accessory may still be attached: open it again, as after a lock, so the next host finds a
     * reader without a replug. Bounded by {@link #MAX_SELF_REOPENS} until a request is read again.
     */
    private void reopenAfterOwnEnd(JSONObject carried) {
        if (!operational) return;
        if (usbSelfReopens >= MAX_SELF_REOPENS) {
            Log.w(TAG, "USB: not reopening again (" + usbSelfReopens + " sessions ended by themselves)");
            usbReplugHint = true;
            return;
        }
        usbSelfReopens++;
        if (carried != null) {
            carriedRequest = carried;
            carriedUntil = SystemClock.elapsedRealtime() + CARRY_WINDOW_MS;
        }
        ui.postDelayed(() -> resumeAttachedAccessory(USB_RESUME_ATTEMPTS), USB_RESUME_RETRY_MS);
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
            boolean changed = screenHeldOn != on;
            screenHeldOn = on;
            if (changed && unlocked && foreground) armIdleLock(); // its bound depends on it (DisplaySettings#idleLockMs)
        });
    }

    /**
     * One request at a time: take the approval slot for a new decision, or answer "Another approval
     * is pending" (inside the lock) and return null.
     */
    private ApprovalDecision claimApproval(AccessoryTransport source, String id) {
        synchronized (stateLock) {
            if (!requestPending.compareAndSet(false, true)) {
                sendError(source, id, "Another approval is pending");
                return null;
            }
            ApprovalDecision decision = new ApprovalDecision(stateLock);
            approvalDecision = decision;
            return decision;
        }
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

    // ------------------------------------------------------------------ accounts + passphrase wallet (AccountScreens)

    /** Leave passphrase typing: the screen buffer is overwritten, USB requests are answered again. */
    private void endPassphraseEntry() {
        passphraseEntry = false;
        accounts.clear();
    }

    /** A wallet was created, restored or replaced: its account 1 is active and the list starts over. Under stateLock. */
    private void adoptNewWallet(String account0Address) {
        accounts.clearPassphraseWallet();
        btc.clearWallets();
        walletId = account0Address.toLowerCase(Locale.ROOT);
        AccountBook book = accounts.startStandardBook(walletId);
        activeAccount = new SigningAccount(0, book.active().name(), false, null, walletId);
        accounts.saveStandardBook(book);
    }

    private void showAccounts() {
        if (!accountScreensReady()) return;
        if (!backupVerified) { pages.showInfo("Check your backup first", "Accounts open after the backup spot-check, like receiving and signing.", this::showHome); return; }
        accounts.showAccounts();
    }

    private void showPassphraseWallet() {
        if (!accountScreensReady()) return;
        if (!backupVerified) { pages.showInfo("Check your backup first", "A passphrase wallet opens after the backup spot-check of your recovery phrase.", this::showHome); return; }
        accounts.showPassphraseIntro();
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

    /**
     * A session ended. Unplugged: as always. Ended by itself (AccessoryTransport#endedByItself: a
     * write the host never took, a descriptor the bus dropped under, a read error) while the
     * accessory may still be attached: what it held for its host is dropped with a clear note
     * ("Your Mac stopped waiting… Nothing was signed"), and the accessory is opened again
     * (reopenAfterOwnEnd), so the next host is answered without a replug.
     */
    @Override public void onDisconnected(AccessoryTransport source, String reason) {
        boolean droppedHeld;
        synchronized (stateLock) {
            droppedHeld = heldRequest.dropIfFrom(source); // its host is gone
        }
        final boolean byItself = source.endedByItself();
        final JSONObject carried = source.takeCarried();
        if (source.requestsRead() > 0) usbSelfReopens = 0; // it worked: reopening after its own end is allowed again
        Log.i(TAG, "USB session ended (" + source.end() + "): " + reason);
        runOnUiThread(() -> {
            if (droppedHeld && byItself) gateUsbNote = MAC_STOPPED_WAITING;
            if (source != transport) {
                if (droppedHeld) refreshGateRequest(gateNoteLabel(), gateUsbNote);
                if (byItself && transport == null) reopenAfterOwnEnd(carried);
                return;
            }
            ApprovalDecision open = approvalDecision;
            boolean undecided = open != null && open.state() == ApprovalDecision.State.REVIEW;
            transport = null;
            cancelApproval();
            setStatusActive(false);
            refreshGateRequest(gateNoteLabel(), gateUsbNote); // locked: the gate drops the held request and the USB card
            if (unlocked && open != null) {
                if (undecided && byItself)
                    approvals.showReceipt("Your Mac stopped waiting", "The connection to your Mac ended before you decided. Nothing was signed. Ask again from your Mac if you still want it.", null);
                else
                    approvals.showReceipt("USB disconnected", "The request session ended. If you tapped Approve & sign, delivery may be uncertain. Check your Mac before trying another transaction.", null);
            } else if (unlocked && source.end() == AccessoryTransport.End.WRITE_FAILED) {
                statusMessage = "Your Mac stopped waiting before the answer arrived · it never left this phone. Ask again from your Mac.";
                if (statusView != null) statusView.setText(statusMessage);
            }
            if (byItself) reopenAfterOwnEnd(carried);
        });
    }

    private String gateNoteLabel() { return gateUsbNote != null ? "REQUEST ENDED" : null; }

    @Override protected void onDestroy() {
        ui.removeCallbacksAndMessages(null);
        if (adbObserver != null) getContentResolver().unregisterContentObserver(adbObserver);
        try { unregisterReceiver(usbDetachReceiver); } catch (IllegalArgumentException ignored) { }
        try { unregisterReceiver(usbStateReceiver); } catch (IllegalArgumentException ignored) { }
        try { unregisterReceiver(shutdownReceiver); } catch (IllegalArgumentException ignored) { }
        synchronized (stateLock) {
            session.incrementAndGet();
            unlocked = false;
            operational = false;
            credentials = null;
            accounts.clearPassphraseWallet();
            btc.clearWallets();
            cancelApproval();
            sensitive.reset();
            if (transport != null) transport.close();
            transport = null;
        }
        clearSensitiveUi();
        clearPinEntry();
        cryptoExecutor.shutdownNow();
        router.shutdown();
        super.onDestroy();
    }

    /** MainActivity as the flow screens see it: its fields, locks and navigation (VaultHost). */
    private final class ScreenHost implements BtcScreens.Host, SettingsScreens.Host, RequestRouter.Host, AddressShareScreens.Host {
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
        @Override public void showSecurity() { settings.showSecurity(); }
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
        @Override public void recordEntropyReport(boolean dice) { settings.recordEntropyReport(dice); }
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
        @Override public ApprovalDecision claimApproval(AccessoryTransport source, String id) { return MainActivity.this.claimApproval(source, id); }
        @Override public boolean passphraseWalletOpen() { return accounts.passphraseWalletOpen(); }
        @Override public void publishAccount(Credentials key, SigningAccount account, String address, Bitmap qr) {
            credentials = key;
            activeAccount = account;
            walletAddress = address;
            walletQr = qr;
        }
        @Override public void relabelActiveAccount(SigningAccount account) { activeAccount = account; }
        @Override public void showPassphraseWallet() { MainActivity.this.showPassphraseWallet(); }
        @Override public DisplaySettings display() { return display; }
        @Override public boolean largeText() { return largeText; }
        @Override public void applyDisplaySettings() { MainActivity.this.applyDisplaySettings(); }
        @Override public void screenTimeoutChanged() {
            DevicePolicyManager policy = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (policy.isDeviceOwnerApp(getPackageName())) applyIdlePolicy(policy);
            MainActivity.this.armIdleLock();
        }
        @Override public void armIdleLock() { MainActivity.this.armIdleLock(); }
        @Override public void applyBrightness() { MainActivity.this.applyBrightness(); }
        @Override public void previewBrightness(int percent) { MainActivity.this.applyBrightness(percent, false); }
        @Override public boolean restartAvailable() {
            DevicePolicyManager policy = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
            return policy != null && policy.isDeviceOwnerApp(getPackageName());
        }
        @Override public boolean requestUnderReview() {
            synchronized (stateLock) {
                return approvalDecision != null || requestPending.get() || heldRequest.summary() != null;
            }
        }
        @Override public void restart() { MainActivity.this.restart(); }
        @Override public boolean appliancePolicyActive() { return ApplianceProvisioning.applianceImage() && operational; }
        @Override public boolean credentialMode() { return MainActivity.this.credentialMode(); }
        @Override public SigningAccount activeAccount() { return activeAccount; }
        @Override public HeldRequest heldRequest() { return heldRequest; }
        @Override public void showHeldOnGate(AccessoryTransport source, String label, String body) {
            if (unlocked || source != transport) return;
            gateUsbNote = null; // a new request: the earlier one's note is old news
            keepScreenOn(true); // a request is waiting (also on a session resumed after a lock): keep the gate lit
            refreshGateRequest(label, body); // the PIN screen and the credential-mode locked page
        }
        @Override public boolean passphraseEntry() { return passphraseEntry; }
        @Override public Map<String, String> ownAccountNames() { return accounts.ownAccountNames(); }
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
