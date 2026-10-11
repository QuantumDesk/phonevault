package dev.phonevault.signer;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.AlertDialog;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.hardware.usb.UsbAccessory;
import android.hardware.usb.UsbManager;
import android.os.Build;
import android.os.Bundle;
import android.os.UserManager;
import android.text.InputType;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONObject;
import org.web3j.crypto.Credentials;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public final class MainActivity extends Activity implements AccessoryTransport.Listener {
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
    private android.widget.ImageView qrView;
    private TextView statusView;
    private final SensitiveFlow sensitive = new SensitiveFlow(stateLock);
    private TokenList tokenList;
    private volatile ApprovalDecision approvalDecision;
    private volatile boolean walletLoaded, backupVerified;
    private volatile String walletAddress;
    private volatile android.graphics.Bitmap walletQr;
    private BackupCheck backupCheck;
    private boolean largeText;
    private long idleTimeoutMs = IDLE_LOCK_MS;
    private String screenName = "loading";
    private String statusMessage = "USB disconnected · connect a host when ready";
    private int activeSensitive = -1, backupPage, replacementOperation;
    private Runnable afterReauth;
    private String[] backupWords;
    private String backupIdentity;
    private BackupCheck.Challenge backupChallenge;
    private SeedVault.Generation replacementCandidate;
    private final java.security.SecureRandom random = new java.security.SecureRandom();
    private long seedIdleDeadline, seedHardDeadline;
    private TextView seedTimer;
    private char[][] pinSetupEntries;

    // --- device security & lifecycle (roadmap chunk 1) ---
    /** Idle time (no touch) before the vault locks and drops the key from memory. */
    private static final long IDLE_LOCK_MS = 2 * 60 * 1000L;
    /** The recovery phrase never stays on screen longer than this. */
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
     * encrypted storage), which also opens the seed key's window. The FIRST gate of this process,
     * shortly after boot, therefore tries the key before prompting. Any later lock always prompts.
     */
    private boolean bootUnlockEligible = true;
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
    private final java.util.concurrent.atomic.AtomicInteger session =
            new java.util.concurrent.atomic.AtomicInteger();
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
    private String gateNotice;
    private int shiftPhase;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        secure(getWindow());
        getWindow().setStatusBarColor(Color.rgb(17, 19, 24));
        getWindow().setBackgroundDrawable(new ColorDrawable(VaultTheme.BG));
        buildUi();
        activateIfPolicyReady();
        ui.postDelayed(pixelShift, PIXEL_SHIFT_MS);
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
        devDumpUi();
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
            seedIdleDeadline = android.os.SystemClock.elapsedRealtime() + SEED_TIMEOUT_MS;
        devDumpUi(); // dev-only: every touch refreshes the UI dump (no-op in release)
    }

    /**
     * Dev builds only: {@link DevTools} in src/debug (shared by the appliance build type) renders
     * the screen to files/vault_dump.png for UI review. The release source set compiles a no-op,
     * so a release APK contains no screenshot code at all.
     */
    boolean isSensitiveScreen() { return sensitive.active(); }

    private void devDumpUi() { DevTools.dumpUi(this); }

    @Override public void onBackPressed() {
        if (!unlocked) { lock(); return; }
        if (approvalDecision != null) return; // use the explicit Reject action
        if (sensitive.active()) { hideBackup(); return; }
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
        if (!operational) {
            vault = new VaultKeyStore(this);
            pin = new VaultPin(this);
            backupCheck = new BackupCheck(getSharedPreferences("vault", MODE_PRIVATE));
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

    /** The vault PIN is the Android lock credential; the seed key needs a fresh system check. */
    private boolean credentialMode() { return SystemCredential.isSet(this); }

    /**
     * Run {@code op} with the seed key usable: in credential mode ask the system to verify the PIN
     * unless that happened moments ago (inside the key's window, with margin). Old mode: run now.
     */
    private void withSeedKey(String why, Runnable op) {
        if (!credentialMode()) { op.run(); return; }
        long age = android.os.SystemClock.elapsedRealtime() - lastCredentialConfirm;
        if (lastCredentialConfirm > 0 && age < (SystemCredential.AUTH_WINDOW_SECONDS - 8) * 1000L) { op.run(); return; }
        // Ask the chip before asking the person: right after a PIN was set or entered on Android's
        // own screen the key may already be usable, and a second prompt would be pure friction.
        final int s = session.get();
        cryptoExecutor.execute(() -> {
            boolean ready = vault.seedKeyUsableNow();
            runOnUiThread(() -> {
                if (s != session.get()) return;
                if (ready) { op.run(); return; }
                confirmDevicePin(why, op, null);
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
                lastCredentialConfirm = android.os.SystemClock.elapsedRealtime();
                onOk.run();
            } else if (onCancel != null) {
                onCancel.run();
            }
        });
    }

    /** Keystore refused because the PIN window lapsed (the op took longer than the window). */
    private static boolean authLapsed(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof android.security.keystore.UserNotAuthenticatedException) return true;
            // Keystore2 may report the same refusal as a KeyStoreException instead.
            if (c instanceof android.security.KeyStoreException
                    && ((android.security.KeyStoreException) c).getNumericErrorCode()
                            == android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED) return true;
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
        boolean freshBoot = android.os.SystemClock.elapsedRealtime() < 10 * 60 * 1000L;
        if (bootUnlockEligible && freshBoot) {
            // The boot lock screen may still be animating away: give it up to 4 s to report the
            // device unlocked, then try the key; if the keystore refuses we come back and prompt.
            bootUnlockEligible = false;
            android.app.KeyguardManager keyguard = getSystemService(android.app.KeyguardManager.class);
            final long deadline = android.os.SystemClock.elapsedRealtime() + 4000;
            Runnable attempt = new Runnable() {
                @Override public void run() {
                    if (s != session.get() || unlocked) return;
                    if (keyguard != null && keyguard.isDeviceLocked() && android.os.SystemClock.elapsedRealtime() < deadline) {
                        ui.postDelayed(this, 250);
                        return;
                    }
                    silentUnlockAttempt = true;
                    unlock(s);
                    if (!unlocked) { silentUnlockAttempt = false; showCredentialGate(session.get()); }
                }
            };
            showLoading("Opening your wallet", "Using the PIN you just entered…");
            ui.post(attempt);
            return;
        }
        bootUnlockEligible = false;
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
        if (pinSetupEntries != null && pinSetupEntries[0] != null) java.util.Arrays.fill(pinSetupEntries[0], '0');
        pinSetupEntries = null;
    }

    private void onCreatePinEntry(char[] entered, char[][] firstEntry, int s) {
        if (s != session.get()) { java.util.Arrays.fill(entered, '0'); return; }
        if (firstEntry[0] == null) {
            firstEntry[0] = entered.clone();
            java.util.Arrays.fill(entered, '0');
            pinScreen.setTitle("CONFIRM PIN");
            pinScreen.setSubtitle("Enter the same PIN again.");
            pinScreen.reset();
            return;
        }
        boolean match = java.util.Arrays.equals(firstEntry[0], entered);
        java.util.Arrays.fill(entered, '0');
        if (!match) {
            java.util.Arrays.fill(firstEntry[0], '0');
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
                pin.set(chosen); // zeroes the array
                boolean bound = SystemCredential.install(this, forSystem); // zeroes forSystem
                runOnUiThread(() -> {
                    if (!bound) { firstRunPinFresh = true; unlock(s); return; }
                    // The chip now holds the PIN; the next step (creating the wallet) needs it once.
                    unlock(s);
                });
            } catch (Exception e) {
                java.util.Arrays.fill(forSystem, '0');
                runOnUiThread(() -> {
                    if (s != session.get() || pinScreen == null) return;
                    pinScreen.setTitle("SET PIN");
                    pinScreen.showError("could not save pin: " + e.getMessage());
                });
            }
        });
    }

    private void onUnlockEntry(char[] entered, int s) {
        if (s != session.get()) { java.util.Arrays.fill(entered, '0'); return; }
        pinScreen.setSubtitle("Checking…");
        final char[] forSystem = SystemCredential.supported() ? entered.clone() : new char[0];
        cryptoExecutor.execute(() -> {
            try {
                VaultPin.Result result = pin.verify(entered, this::wipeWalletForFailedPin);
                if (result.outcome == VaultPin.Outcome.OK && forSystem.length > 0 && !credentialMode()) {
                    // One-time upgrade: the verified PIN becomes the device credential.
                    boolean bound = SystemCredential.install(this, forSystem);
                    if (bound) {
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
                java.util.Arrays.fill(forSystem, '0');
                runOnUiThread(() -> {
                    if (s != session.get() || pinScreen == null) {
                        // Stopped/locked while checking: the gate was re-created with a new token.
                        android.util.Log.i("Vault", "pin result discarded: stale session");
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
        vault.secureErase();
        backupCheck.clear();
        android.util.Log.w("Vault", "wallet erased after " + VaultPin.MAX_ATTEMPTS + " failed PIN attempts");
    }

    /** Only the gate that verified the PIN (token {@code s}) may unlock, and only while visible. */
    private void unlock(int s) {
        if (!operational || !foreground || s != session.get()) {
            android.util.Log.i("Vault", "unlock refused: stale session or activity not visible");
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
            heldRequest = null;
            heldSummary = null;
            if (staleTransport != null) { staleTransport.close(); usbReplugHint = true; }
            keepScreenOn(false);
        }
        clearSensitiveUi();
        clearPinEntry();
        if (!operational) return;
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
        sensitive.reset();
        activeSensitive = -1;
        afterReauth = null;
        if (backupWords != null) java.util.Arrays.fill(backupWords, null);
        backupWords = null;
        if (backupChallenge != null) backupChallenge.destroy();
        backupChallenge = null;
        backupIdentity = null;
        replacementCandidate = null;
        seedTimer = null;
        clearRestoreEntry(); // typed recovery words never outlive the unlocked session
        clearDice();
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

    /** After unlock: the request that waited behind the gate goes through the ordinary path. */
    private void dispatchHeldRequest() {
        final JSONObject held; final AccessoryTransport source;
        synchronized (stateLock) { held = heldRequest; heldRequest = null; heldSummary = null; source = transport; }
        if (held == null || source == null) return;
        cryptoExecutor.execute(() -> onRequest(source, held));
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
                    String.valueOf(SCREEN_OFF_TIMEOUT_MS));
        } catch (Exception e) {
            android.util.Log.w("Vault", "idle policy not applied", e);
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

    private void enforceApplianceRestrictions(DevicePolicyManager policy) {
        List<String> restrictions = new java.util.ArrayList<>(java.util.Arrays.asList(
                UserManager.DISALLOW_ADD_USER,
                UserManager.DISALLOW_MODIFY_ACCOUNTS,
                UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES,
                UserManager.DISALLOW_SAFE_BOOT,
                UserManager.DISALLOW_USB_FILE_TRANSFER,
                UserManager.DISALLOW_CONFIG_WIFI,
                UserManager.DISALLOW_CONFIG_BLUETOOTH,
                UserManager.DISALLOW_BLUETOOTH,
                UserManager.DISALLOW_BLUETOOTH_SHARING,
                UserManager.DISALLOW_CONFIG_MOBILE_NETWORKS,
                UserManager.DISALLOW_CONFIG_TETHERING,
                UserManager.DISALLOW_CONFIG_VPN,
                UserManager.DISALLOW_SHARE_LOCATION));
        if (!BuildConfig.VAULT_ALLOW_APP_UPDATES) {
            // Release: the app set is frozen. Dev builds leave these off so `adb install -r`
            // works; no network + kiosk still prevent sideloading in dev.
            restrictions.add(UserManager.DISALLOW_INSTALL_APPS);
            restrictions.add(UserManager.DISALLOW_UNINSTALL_APPS);
        }
        for (String restriction : restrictions) {
            policy.addUserRestriction(VaultDeviceAdminReceiver.component(this), restriction);
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
        synchronized (stateLock) {
            session.incrementAndGet();
            operational = false;
            unlocked = false;
            credentials = null;
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
        LinearLayout root = page("DEVICE NOT READY", "Policy check failed", reason);
        card(root, "Signing is disabled", "Have the image provisioning checked. No wallet identity is displayed.");
        present(root, "policy-error");
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (operational) handleIntent(intent);
    }


    // ---------- Native, scrollable pages. Sensitive operations never use floating dialogs.

    private float bodySize() { return largeText ? 19 : 16; }

    private LinearLayout page(String eyebrow, String title, String description) {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(24), dp(48), dp(24), dp(30));
        root.setBackgroundColor(VaultTheme.BG);
        TextView brand = VaultTheme.pixelText(this, "PHONE VAULT", 10, VaultTheme.ACCENT);
        if (menuAvailable()) {
            // Header row: brand on the left, ☰ on the right. One menu everywhere instead of tab rows.
            LinearLayout header = new LinearLayout(this);
            header.setOrientation(LinearLayout.HORIZONTAL);
            header.setGravity(Gravity.CENTER_VERTICAL);
            LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
            header.addView(brand, blp);
            TextView menu = VaultTheme.pixelButton(this, "☰", false);
            menu.setTextSize(22);
            menu.setPadding(0, 0, 0, 0);
            menu.setContentDescription("Menu");
            hardenTouch(menu);
            menu.setOnClickListener(v -> { if (menuAvailable()) showMenu(); });
            LinearLayout.LayoutParams mlp = new LinearLayout.LayoutParams(dp(56), dp(48));
            mlp.setMargins(dp(8), -dp(6), 0, 0);
            header.addView(menu, mlp);
            root.addView(header);
        } else {
            root.addView(brand);
        }
        TextView label = VaultTheme.bodyText(this, eyebrow.toUpperCase(java.util.Locale.ROOT), 12, VaultTheme.FAINT);
        label.setPadding(0, dp(30), 0, dp(8));
        root.addView(label);
        TextView heading = VaultTheme.bodyText(this, title, largeText ? 32 : 28, VaultTheme.INK);
        heading.setTypeface(android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.NORMAL));
        root.addView(heading);
        if (description != null && !description.isEmpty()) {
            TextView caption = VaultTheme.bodyText(this, description, bodySize(), VaultTheme.DIM);
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
        TextView text = VaultTheme.bodyText(this, value, bodySize(), VaultTheme.INK);
        text.setPadding(0, dp(6), 0, 0);
        box.addView(text);
        parent.addView(box, matchWrap(dp(12)));
    }

    /** The menu is available on the ordinary unlocked screens: never over a PIN gate, a sensitive
     *  flow, an approval, or before a wallet exists. */
    private boolean menuAvailable() {
        return unlocked && operational && walletLoaded && !sensitive.active() && approvalDecision == null
                && !replacementActive() && !restoreReplacing;
    }

    /** Former tab row. Navigation moved into the ☰ header menu; kept so screens stay one-line simple. */
    private void nav(LinearLayout parent, String selected) { }

    private void showMenu() {
        LinearLayout root = page("MENU", "Where to?", null);
        String current = screenName;
        action(root, "Wallet", "wallet".equals(current), () -> { if (menuAvailable()) showHome(); });
        action(root, "Security", "security".equals(current), () -> { if (menuAvailable()) showSecurity(); });
        action(root, "Display & auto-lock", "preferences".equals(current), () -> { if (menuAvailable()) showPreferences(); });
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
        largeText = getPreferences(MODE_PRIVATE).getBoolean("large_text", false);
        int saved = getPreferences(MODE_PRIVATE).getInt("idle_seconds", 120);
        idleTimeoutMs = (saved == 30 || saved == 60 || saved == 120) ? saved * 1000L : IDLE_LOCK_MS;
        statusView = VaultTheme.bodyText(this, "", bodySize(), VaultTheme.DIM);
        showLoading("Opening Phone Vault", "Checking appliance policy…");
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
        LinearLayout root = page("ACCOUNT 1", backupVerified ? "Your offline wallet" : "Back up your wallet",
                backupVerified ? "Review every request here. Your keys stay on this phone."
                        : "Before receiving or signing, write down all 24 recovery words. We'll then spot-check a few.");
        if (backupVerified && walletAddress != null && walletQr != null) {
            LinearLayout box = VaultTheme.box(this);
            box.setGravity(Gravity.CENTER_HORIZONTAL);
            qrView = new android.widget.ImageView(this);
            qrView.setContentDescription("Receiving address QR. Full address follows.");
            qrView.setImageBitmap(walletQr);
            // Shown at the bitmap's own pixel size: integer-scaled modules stay perfectly square.
            LinearLayout.LayoutParams qlp = new LinearLayout.LayoutParams(walletQr.getWidth(), walletQr.getHeight());
            qlp.gravity = Gravity.CENTER_HORIZONTAL;
            qlp.setMargins(0, dp(4), 0, dp(18));
            box.addView(qrView, qlp);
            box.addView(VaultTheme.bodyText(this, "ACCOUNT 1 · RECEIVE", 13, VaultTheme.FAINT));
            addressView = VaultTheme.monoText(this, formatAddress(
                    org.web3j.crypto.Keys.toChecksumAddress(walletAddress)), largeText ? 18 : 16, VaultTheme.INK);
            addressView.setPadding(0, dp(12), 0, dp(8));
            box.addView(addressView);
            root.addView(box, matchWrap(dp(22)));
            card(root, "Check the network", "This is an EVM address. Confirm the destination chain in your sending wallet. A matching address does not mean every network is supported.");
        } else {
            card(root, "Backup not checked yet", "Receiving and signing are paused until you write the phrase down and pass the spot check. If you already wrote it down, check it now.");
            action(root, "Write down recovery phrase", true, this::confirmRevealBackup);
            action(root, "I have my backup · check words", false, () -> startBackupAccess(true));
        }
        if (usbReplugHint && transport == null) statusMessage = "USB session ended when the vault locked · unplug and reconnect the cable to resume";
        statusView = VaultTheme.bodyText(this, statusMessage, bodySize(), VaultTheme.DIM);
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

    // --- optional user entropy: physical dice rolls, mixed with the two device sources.

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
            b.setTextSize(20);
            b.setPadding(0, 0, 0, 0);
            b.setGravity(android.view.Gravity.CENTER);
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
        final byte[] userEntropy = diceRolls.toString().getBytes(java.nio.charset.StandardCharsets.US_ASCII);
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
                finally { java.util.Arrays.fill(userEntropy, (byte) 0); }
                String address = fresh.getAddress();
                android.graphics.Bitmap qr = qrFor(address);
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked || !operational) return;
                    credentials = fresh;
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

    // --- restore OVER an existing wallet: same entry screens, but owned by a fresh-PIN sensitive
    //     flow and the replacement state machine, exactly like Replace (USB excluded throughout).

    private boolean restoreReplacing;
    private int restoreOverOp = -1;

    private void confirmRestoreOver() {
        if (!walletLoaded || credentials == null) return;
        LinearLayout root = page("SECURITY / RESTORE", "Restore a different wallet?",
                "You will type a 24-word recovery phrase on this phone. The wallet it produces REPLACES the current one on this device. Nothing changes until you confirm the address it shows.");
        card(root, "Current Account 1", org.web3j.crypto.Keys.toChecksumAddress(walletAddress));
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
                    walletAddress = address;
                    backupVerified = true;
                    walletLoaded = true;
                    endReplacement(op);
                }
                android.graphics.Bitmap qr = qrFor(address);
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

    // --- restore: on-device word entry (no system keyboard), validate, confirm address, commit

    private final String[] restoreWords = new String[SeedRestore.WORD_COUNT];
    private int restoreIndex;
    private final StringBuilder restoreBuffer = new StringBuilder();

    private void clearRestoreEntry() {
        java.util.Arrays.fill(restoreWords, null);
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
        java.util.List<String> suggestions = SeedRestore.suggestions(typed, 6);
        LinearLayout slot = new LinearLayout(this);
        slot.setOrientation(LinearLayout.VERTICAL);
        slot.setMinimumHeight(dp(2 * 60 + 8));
        for (int rowStart = 0; rowStart < suggestions.size(); rowStart += 3) {
            LinearLayout srow = new LinearLayout(this);
            srow.setOrientation(LinearLayout.HORIZONTAL);
            for (int i = rowStart; i < Math.min(rowStart + 3, suggestions.size()); i++) {
                final String word = suggestions.get(i);
                TextView b = VaultTheme.pixelButton(this, word, i == 0);
                b.setTextSize(15);
                b.setPadding(dp(4), b.getPaddingTop(), dp(4), b.getPaddingBottom());
                hardenTouch(b);
                b.setOnClickListener(v -> { if (unlocked && operational) pickRestoreWord(word); });
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(52), 1f);
                lp.setMargins(dp(3), dp(4), dp(3), dp(4));
                srow.addView(b, lp);
            }
            slot.addView(srow);
        }
        if (suggestions.isEmpty() && !typed.isEmpty()) {
            TextView none = VaultTheme.bodyText(this, "No recovery word starts with \"" + typed + "\". Use ⌫.", bodySize(), VaultTheme.DANGER_INK);
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
            b.setTextSize(18);
            b.setPadding(0, 0, 0, 0); // a ninth of the width: any horizontal padding hides the letter
            b.setGravity(android.view.Gravity.CENTER);
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
        final String raw = String.join(" ", java.util.Arrays.asList(restoreWords).stream()
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
                    card(root, replacing ? "New Account 1" : "Account 1", org.web3j.crypto.Keys.toChecksumAddress(address));
                    if (replacing && walletAddress != null) card(root, "Replaces current", org.web3j.crypto.Keys.toChecksumAddress(walletAddress));
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
                android.graphics.Bitmap qr;
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked || !operational || walletLoaded) return;
                    restored = vault.restore(mnemonic);
                    address = restored.getAddress();
                    backupCheck.record(address);
                    credentials = restored;
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
        LinearLayout root = page("SECURITY / PREFERENCES", "Make it comfortable", "Larger text and shorter idle locking are available now.");
        card(root, "Text size", largeText ? "Large · easier reading" : "Standard · comfortable reading");
        action(root, largeText ? "Use standard text" : "Use larger text", true, () -> {
            boolean next = !largeText;
            if (getPreferences(MODE_PRIVATE).edit().putBoolean("large_text", next).commit()) {
                largeText = next;
                showPreferences();
            } else showInfo("Setting not saved", "Try again. Your previous text size is still active.", this::showPreferences);
        });
        card(root, "Idle lock", (idleTimeoutMs / 1000) + " seconds without interaction. Screen off always locks immediately; the appliance screen-off policy is 60 seconds.");
        for (int seconds : new int[] {30, 60, 120}) {
            action(root, seconds == 120 ? "Lock after 2 minutes" : "Lock after " + seconds + " seconds",
                    idleTimeoutMs == seconds * 1000L, () -> {
                if (getPreferences(MODE_PRIVATE).edit().putInt("idle_seconds", seconds).commit()) {
                    idleTimeoutMs = seconds * 1000L;
                    armIdleLock();
                    showPreferences();
                } else showInfo("Setting not saved", "Your previous idle timeout is still active.", this::showPreferences);
            });
        }
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
        card(root, "Account path", "m/44'/60'/0'/0/0 · no passphrase");
        card(root, "PIN protection", credentialMode()
                ? "Checked by the security chip (Titan M), which slows repeated guesses · "
                        + SystemCredential.MAX_FAILED_FOR_WIPE + " wrong PINs reset the phone · the seed key works only for "
                        + SystemCredential.AUTH_WINDOW_SECONDS + " s after a correct PIN"
                : "App PIN gate · 10 failed attempts erase the wallet. PIN-derived encryption is planned.");
        String entropy = getPreferences(MODE_PRIVATE).getString("entropy_report", null);
        card(root, "Entropy at wallet creation", entropy != null ? entropy
                : "Not recorded (this wallet was created or restored before source reporting existed, or restored from words).");
        android.content.Intent battery = registerReceiver(null, new android.content.IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (battery != null) {
            int level = battery.getIntExtra(android.os.BatteryManager.EXTRA_LEVEL, -1);
            int scale = battery.getIntExtra(android.os.BatteryManager.EXTRA_SCALE, -1);
            card(root, "Battery charge", level >= 0 && scale > 0 ? (level * 100 / scale) + "% · charge is not a battery-health assessment" : "Unavailable");
        }
        action(root, "Back to Security", false, this::showSecurity);
        present(root, "integrity");
    }

    /** Persist WHICH sources fed the last generated seed and whether each passed its health tests
     *  (names and pass/fail only; no entropy bytes). Shown on Device information (R7). */
    private void recordEntropyReport(boolean dice) {
        java.util.List<SeedVault.SourceReport> reports = vault.lastGenerationReports();
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
            {"Multiple accounts", "Account discovery, explicit derivation paths, and watch-only export."},
            {"Passphrase wallets", "A separate wallet for each exact passphrase. A typo creates a different wallet; recovery must be tested before release."},
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
            if (!sensitiveValid(token, s)) { java.util.Arrays.fill(entered, '0'); return; }
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
                } finally { java.util.Arrays.fill(entered, '0'); }
            });
        });
        updatePinPolicy(pinScreen);
        pinScreen.addCancel(this::hideBackup);
        screenName = "reauth";
        setContentView(pinScreen.view());
        devDumpUi();
    }

    private void updatePinPolicy(PinScreen gate) {
        gate.setLargeText(largeText);
        int remaining = pin.attemptsRemaining();
        gate.setPolicy((DevTools.SCREENSHOTS ? "DEVELOPMENT · TEST ASSETS ONLY\n" : "PROTOTYPE · TEST ASSETS ONLY\n")
                + (SystemCredential.willBind(this) && !pin.isSet()
                        ? "Your PIN will be held by the security chip."
                        : remaining + " attempts remaining. " + VaultPin.MAX_ATTEMPTS + " failed attempts erase the wallet."));
        gate.setSubmitRequired(remaining == 1 && !pin.eraseOutstanding());
    }

    private void confirmRevealBackup() { startBackupAccess(false); }

    private void startBackupAccess(boolean checkOnly) {
        beginSensitive(checkOnly ? "check your backup" : "view your recovery phrase", () -> {
            int token = activeSensitive, s = session.get();
            showLoading("Opening secure backup", "Keep cameras and other people away from your screen.");
            cryptoExecutor.execute(() -> {
                try {
                    if (!sensitiveValid(token, s)) return;
                    String mnemonic = vault.revealMnemonic(() -> sensitiveValid(token, s));
                    String[] words = mnemonic.split(" ");
                    runOnUiThread(() -> {
                        if (!sensitiveValid(token, s)) { java.util.Arrays.fill(words, null); return; }
                        backupWords = words;
                        backupIdentity = walletAddress;
                        backupPage = checkOnly ? 0 : Math.min(resumeBackupPage, 5); resumeBackupPage = 0;
                        startSeedTimer();
                        if (checkOnly) startWordCheck();
                        else showPhrasePage();
                    });
                } catch (Exception e) {
                    runOnUiThread(() -> {
                        if (sensitiveValid(token, s))
                            showInfo("Backup unavailable", "The stored phrase could not be opened. Lock and retry; do not replace this wallet to fix a storage problem.", this::hideBackup);
                    });
                }
            });
        });
    }

    private void startSeedTimer() {
        long now = android.os.SystemClock.elapsedRealtime();
        seedHardDeadline = now + SEED_SESSION_MS;
        seedIdleDeadline = now + SEED_TIMEOUT_MS;
        ui.removeCallbacks(hideSeed);
        ui.post(hideSeed);
    }

    private void tickSeedTimer() {
        if (!sensitive.active() || backupWords == null || replacement.state() == ReplacementState.COMMITTING) return;
        long remaining = Math.min(seedHardDeadline, seedIdleDeadline) - android.os.SystemClock.elapsedRealtime();
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
            TextView number = VaultTheme.monoText(this, String.format(java.util.Locale.ROOT, "%02d", i + 1), 18, VaultTheme.FAINT);
            number.setWidth(dp(44));
            row.addView(number);
            row.addView(VaultTheme.monoText(this, backupWords[i], largeText ? 26 : 23, VaultTheme.INK),
                    new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
            root.addView(row, matchWrap(dp(12)));
        }
        if (backupPage < 5) action(root, "Next four words", true, () -> { backupPage++; showPhrasePage(); });
        else action(root, "I've written them down · spot-check", true, this::startWordCheck);
        if (backupPage > 0) action(root, "Previous words", false, () -> { backupPage--; showPhrasePage(); });
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
        java.util.List<String> choices = new java.util.ArrayList<>();
        choices.add(backupWords[position]);
        java.util.List<String> dictionary = org.web3j.crypto.MnemonicUtils.getWords();
        while (choices.size() < 6) {
            String next = dictionary.get(random.nextInt(dictionary.size()));
            if (!choices.contains(next)) choices.add(next);
        }
        java.util.Collections.shuffle(choices, random);
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
        if (backupWords != null) java.util.Arrays.fill(backupWords, null);
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
                org.web3j.crypto.Keys.toChecksumAddress(address));
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
                    if (!sensitiveValid(token, s) || credentials == null || !credentials.getAddress().equalsIgnoreCase(address)) return;
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
                    walletAddress = fresh.getAddress();
                    backupVerified = true;
                    walletLoaded = true;
                    endReplacement(op);
                }
                android.graphics.Bitmap qr = qrFor(candidate.address);
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

    private static void secure(android.view.Window window) {
        if (!DevTools.SCREENSHOTS) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }

    private void clearReceivingIdentity() {
        walletLoaded = false;
        backupVerified = false;
        walletAddress = null;
        walletQr = null;
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
                Credentials loaded = store.loadOrCreate();
                String address = loaded.getAddress();
                android.graphics.Bitmap qr = qrFor(address);
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked || !operational) return;
                    credentials = loaded;
                    walletAddress = address;
                    walletQr = qr;
                    backupVerified = backupCheck.verified(address);
                    walletLoaded = true;
                }
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
                    android.util.Log.w("Vault", "wallet load failed: " + chain(e));
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

    private android.graphics.Bitmap qrFor(String address) {
        android.graphics.Bitmap qr = VaultTheme.qrBitmap(address, dp(232), dp(12));
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
                pendingUsb = intent; // fall back to the old replay-after-unlock behaviour
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
                } else {
                    b = TransactionReview.build(Eip1559Request.parse(json), null, tokens()).lockedSummary;
                }
                synchronized (stateLock) { if (!unlocked) { heldRequest = json; heldSummary = b; } }
            } catch (Exception e) {
                b = "The connected host sent a request this phone cannot decode. It will be refused after you unlock.";
                synchronized (stateLock) { if (!unlocked) { heldRequest = json; heldSummary = b; } }
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
        }
        if ("getAddress".equals(json.optString("method"))) {
            try {
                Eip1559Request.requireExactFields(json, "id", "method");
                id = Eip1559Request.validatedId(json.getString("id"));
                synchronized (stateLock) {
                    if (s != session.get() || source != transport || !unlocked || !backupVerified || sensitive.active()) return;
                    source.send(json("id", id, "status", "ok", "address", credentials.getAddress()));
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
            if (MessageRequest.handles(json.optString("method"))) {
                // Parsed once: the review and the digest both come from this object.
                MessageApprovalSession approval = new MessageApprovalSession(MessageRequest.parse(json), credentials);
                runOnUiThread(() -> showMessageApproval(source, approval, decision, s));
                return;
            }
            Eip1559Request request = Eip1559Request.parse(json);
            ApprovalSession approval = new ApprovalSession(request, credentials, tokens());
            runOnUiThread(() -> showApproval(source, approval, decision, s));
        } catch (Exception e) {
            finishApproval(decision);
            sendError(source, id, e.getMessage());
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
        } catch (java.util.concurrent.RejectedExecutionException closing) {
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

    private void showApproval(AccessoryTransport source, ApprovalSession approval,
                              ApprovalDecision decision, int s) {
        if (source != transport || s != session.get() || !unlocked || sensitive.active()
                || approvalDecision != decision || !walletLoaded || !backupVerified) {
            decision.cancel();
            finishApproval(decision);
            return;
        }
        // Rendered from the review built with this exact request in ApprovalSession (same object that is signed).
        TransactionReview review = approval.review;
        keepScreenOn(true);
        LinearLayout root = page(DevTools.SCREENSHOTS ? "DEVELOPMENT · TEST ASSETS ONLY" : review.kicker,
                review.title, review.subtitle);
        for (MessageReview.Row row : review.summary) root.addView(detail(row.label, row.value));
        LinearLayout raw = new LinearLayout(this);
        raw.setOrientation(LinearLayout.VERTICAL);
        for (MessageReview.Row row : review.details) raw.addView(detail(row.label, row.value));
        raw.setVisibility(View.GONE);
        TextView details = VaultTheme.pixelButton(this, "Show technical details", false);
        hardenTouch(details);
        details.setOnClickListener(v -> {
            boolean visible = raw.getVisibility() == View.VISIBLE;
            raw.setVisibility(visible ? View.GONE : View.VISIBLE);
            details.setText(visible ? "Show technical details" : "Hide technical details");
        });
        root.addView(details, matchWrap(dp(8)));
        root.addView(raw);
        addDecisionControls(root, source, decision, s, approval.request.id, review.reviewPrompt, review.signLabel,
                approval::signIfIdentityUnchanged,
                "The response was queued for USB. Check your host for receipt and broadcast status. Unplugging cannot revoke a signature already received.",
                "Transaction hash", "transactionHash", true);
        present(root, "approval");
    }

    /**
     * The token list built into the APK, checked against its pinned SHA-256 on first use. A list
     * that fails the check is not used: every contract is then reviewed as unknown, and the review
     * says the list was refused.
     */
    private synchronized TokenList tokens() {
        if (tokenList != null) return tokenList;
        try (java.io.InputStream in = getResources().openRawResource(R.raw.tokens)) {
            java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
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
     * The acknowledgement checkbox, Sign and Reject for one request, shared by the transaction and
     * message reviews: one decision, check → sign → send as one step under stateLock.
     */
    private void addDecisionControls(LinearLayout root, AccessoryTransport source, ApprovalDecision decision, int s,
                                     String requestId, String prompt, String signText, ReviewedSigner signer,
                                     String doneMessage, String receiptLabel, String receiptField, boolean transaction) {
        CheckBox reviewed = new CheckBox(this);
        reviewed.setText(prompt);
        reviewed.setTextSize(bodySize());
        reviewed.setTextColor(VaultTheme.INK);
        reviewed.setMinHeight(dp(56));
        reviewed.setPadding(dp(4), dp(18), dp(4), dp(18));
        hardenTouch(reviewed);
        root.addView(reviewed, matchWrap(dp(12)));
        TextView sign = VaultTheme.pixelButton(this, signText, true);
        TextView reject = VaultTheme.pixelButton(this, "Reject request", false);
        hardenTouch(sign);
        hardenTouch(reject);
        sign.setEnabled(false);
        reviewed.setOnCheckedChangeListener((v, checked) -> sign.setEnabled(checked && decision.state() == ApprovalDecision.State.REVIEW));
        reject.setOnClickListener(v -> {
            if (!decision.reject()) return;
            source.send(json("id", requestId, "status", "rejected"));
            finishApproval(decision);
            statusMessage = "Request rejected · no signature created";
            showReceipt("Request rejected", "No signature was created for this request.", null, null, transaction);
        });
        sign.setOnClickListener(v -> {
            synchronized (stateLock) {
                if (source != transport || s != session.get() || !unlocked
                        || approvalDecision != decision || !reviewed.isChecked() || !decision.beginSigning()) return;
            }
            // The decision is now irreversible through Reject. Lock still invalidates queued work.
            sign.setEnabled(false);
            reject.setEnabled(false);
            reviewed.setEnabled(false);
            sign.setText("Signing…");
            statusMessage = "Signing approved request";
            cryptoExecutor.execute(() -> {
                try {
                    JSONObject response;
                    synchronized (stateLock) {
                        if (!operational || !unlocked || s != session.get() || sensitive.active()
                                || !backupVerified || source != transport || source.isClosed()
                                || approvalDecision != decision || !decision.maySign())
                            throw new IllegalStateException("Session ended before signing");
                        response = signer.sign(credentials);
                        if (!source.send(response)) throw new IllegalStateException("Signature delivery is uncertain");
                        decision.finish();
                    }
                    runOnUiThread(() -> {
                        if (s != session.get() || !unlocked || approvalDecision != decision) return;
                        finishApproval(decision);
                        statusMessage = "Signature created · delivery not confirmed";
                        showReceipt("Signature created", doneMessage, receiptLabel, response.optString(receiptField), transaction);
                    });
                } catch (Exception e) {
                    sendError(source, requestId, e.getMessage());
                    runOnUiThread(() -> {
                        if (s != session.get() || !unlocked || approvalDecision != decision) return;
                        finishApproval(decision);
                        showReceipt("Check the host", transaction
                                ? "Signing or delivery did not complete normally. A signature may have reached the host. Check before creating another transaction."
                                : "Signing or delivery did not complete normally. A signature may have reached the host. Check before signing again.",
                                null, null, transaction);
                    });
                }
            });
        });
        root.addView(sign, matchWrap(dp(8)));
        root.addView(reject, matchWrap(dp(10)));
    }

    /** Review for personal_sign / eth_signTypedData_v4, rendered from the parsed request only. */
    private void showMessageApproval(AccessoryTransport source, MessageApprovalSession approval,
                                     ApprovalDecision decision, int s) {
        if (source != transport || s != session.get() || !unlocked || sensitive.active()
                || approvalDecision != decision || !walletLoaded || !backupVerified) {
            decision.cancel();
            finishApproval(decision);
            return;
        }
        MessageReview review = approval.review;
        keepScreenOn(true);
        LinearLayout root = page(DevTools.SCREENSHOTS ? "DEVELOPMENT · TEST ASSETS ONLY" : review.kicker,
                review.title, review.subtitle);
        for (MessageReview.Row row : review.summary) root.addView(detail(row.label, row.value));
        LinearLayout raw = new LinearLayout(this);
        raw.setOrientation(LinearLayout.VERTICAL);
        for (MessageReview.Row row : review.details) raw.addView(detail(row.label, row.value));
        raw.setVisibility(View.GONE);
        TextView details = VaultTheme.pixelButton(this, "Show details", false);
        hardenTouch(details);
        details.setOnClickListener(v -> {
            boolean visible = raw.getVisibility() == View.VISIBLE;
            raw.setVisibility(visible ? View.GONE : View.VISIBLE);
            details.setText(visible ? "Show details" : "Hide details");
        });
        root.addView(details, matchWrap(dp(8)));
        root.addView(raw);
        addDecisionControls(root, source, decision, s, approval.request.id, review.reviewPrompt, review.signLabel,
                approval::signIfIdentityUnchanged,
                "The signature was queued for USB. Anyone who receives it can use it as shown on the review; unplugging cannot revoke it.",
                "Signed digest", "digest", false);
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
        action(root, "Back to Wallet", true, this::showHome);
        action(root, "Lock now", false, this::lock);
        present(root, "receipt");
    }

    private View detail(String label, String value) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        boolean danger = "DANGER".equalsIgnoreCase(label) || "WARNING".equalsIgnoreCase(label);
        TextView labelView = VaultTheme.bodyText(this, label.toUpperCase(java.util.Locale.ROOT), 13,
                danger ? VaultTheme.DANGER_INK : VaultTheme.FAINT);
        TextView valueView = VaultTheme.monoText(this, value, bodySize(),
                danger ? VaultTheme.DANGER_INK : VaultTheme.INK);
        valueView.setTextIsSelectable(false);
        valueView.setPadding(0, dp(6), 0, dp(15));
        row.addView(labelView);
        row.addView(valueView);
        return row;
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
        runOnUiThread(() -> {
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
        synchronized (stateLock) {
            session.incrementAndGet();
            unlocked = false;
            operational = false;
            credentials = null;
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
        view.setTextSize(size);
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

    private String formatAddress(String address) {
        return address.length() > 22 ? address.substring(0, 22) + "\n" + address.substring(22) : address;
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
