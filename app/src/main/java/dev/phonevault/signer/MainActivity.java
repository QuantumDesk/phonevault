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
    private View statusDot;
    private View homeView;
    private AlertDialog approvalDialog;

    // --- device security & lifecycle (roadmap chunk 1) ---
    /** Idle time (no touch) before the vault locks and drops the key from memory. */
    private static final long IDLE_LOCK_MS = 2 * 60 * 1000L;
    /** The recovery phrase never stays on screen longer than this. */
    private static final long SEED_TIMEOUT_MS = 60 * 1000L;
    /** OLED burn-in: nudge the whole UI by a pixel or two on this cadence. */
    private static final long PIXEL_SHIFT_MS = 45 * 1000L;
    /** System screen-off timeout applied as device owner (burn-in + walk-away safety). */
    private static final int SCREEN_OFF_TIMEOUT_MS = 60 * 1000;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final Runnable idleLock = this::lock;
    private final Runnable hideSeed = this::hideBackup;
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
        devDumpUi(); // dev-only: every touch refreshes the UI dump (no-op in release)
    }

    /**
     * Dev builds only: {@link DevTools} in src/debug (shared by the appliance build type) renders
     * the screen to files/vault_dump.png for UI review. The release source set compiles a no-op,
     * so a release APK contains no screenshot code at all.
     */
    private void devDumpUi() {
        DevTools.dumpUi(this);
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
        final char[][] firstEntry = {null};
        String title = creating ? "SET PIN" : sealed ? "SEALED" : "LOCKED";
        String subtitle;
        if (creating) {
            subtitle = "Choose a " + VaultPin.PIN_LENGTH + "-digit PIN. It unlocks this vault. "
                    + VaultPin.MAX_ATTEMPTS + " wrong attempts erase the wallet.";
        } else if (sealed) {
            subtitle = "Attempt limit reached but the wallet could not be verifiably erased. "
                    + "The vault stays sealed. Enter any PIN to retry the erase.";
        } else {
            subtitle = "Enter PIN to unlock." + (pendingUsb != null ? "  USB host is waiting." : "");
        }
        if (gateNotice != null) { subtitle = gateNotice + "\n\n" + subtitle; gateNotice = null; }
        final int s = session.get(); // PIN operations are bound to this gate's session
        pinScreen = new PinScreen(this, title, subtitle, entered -> {
            if (creating) onCreatePinEntry(entered, firstEntry, s);
            else onUnlockEntry(entered, s);
        });
        setContentView(pinScreen.view());
        devDumpUi();
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
        pinScreen.setSubtitle("Saving…");
        cryptoExecutor.execute(() -> {
            try {
                pin.set(chosen); // zeroes the array
                runOnUiThread(() -> unlock(s));
            } catch (Exception e) {
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
        cryptoExecutor.execute(() -> {
            try {
                VaultPin.Result result = pin.verify(entered, this::wipeWalletForFailedPin);
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
                            pinScreen.setSubtitle("Enter PIN to unlock.");
                            pinScreen.showError("wrong pin · " + result.attemptsRemaining
                                    + (result.attemptsRemaining == 1 ? " attempt left" : " attempts left"));
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
        android.util.Log.w("Vault", "wallet erased after " + VaultPin.MAX_ATTEMPTS + " failed PIN attempts");
    }

    /** Only the gate that verified the PIN (token {@code s}) may unlock, and only while visible. */
    private void unlock(int s) {
        if (!operational || !foreground || s != session.get()) {
            android.util.Log.i("Vault", "unlock refused: stale session or activity not visible");
            return;
        }
        unlocked = true;
        pinScreen = null;
        setContentView(this.homeView);
        loadKey();
        armIdleLock();
        Intent usb = pendingUsb;
        pendingUsb = null;
        if (usb != null) handleIntent(usb);
        devDumpUi();
    }

    /**
     * Invalidate the session (ALWAYS — even if already locked, so an in-flight PIN op dies), drop
     * the key from memory, end any USB session, and return to the PIN gate.
     */
    private void lock() {
        boolean wasUnlocked;
        AccessoryTransport staleTransport;
        synchronized (stateLock) {
            session.incrementAndGet(); // invalidates any in-flight PIN op / load / regeneration
            wasUnlocked = unlocked;
            unlocked = false;
            credentials = null;
            // An un-activated candidate is discarded; a commit or a signing in progress holds
            // stateLock, so by now it has either finished (key dropped above) or never ran.
            replacement.reset();
            // USB data-lock (app layer): the session is closed INSIDE the lock so a signing task
            // can never send after this point (send + close are linearized with signing).
            staleTransport = transport;
            transport = null;
            if (staleTransport != null) staleTransport.close();
        }
        if (!operational || !wasUnlocked) return;
        requestPending.set(false);
        AlertDialog pending = approvalDialog;
        approvalDialog = null;
        if (pending != null) pending.dismiss();
        ui.removeCallbacks(idleLock);
        ui.removeCallbacks(hideSeed);
        showPinGate(null);
    }

    private void armIdleLock() {
        ui.removeCallbacks(idleLock);
        ui.postDelayed(idleLock, IDLE_LOCK_MS);
    }

    /** Recovery phrase: back to home (button or timeout). */
    /**
     * Leave any phrase screen (reveal or NEW phrase) and return home. For a replacement this is
     * the single terminal path for cancel / timeout / success: the state goes IDLE (unless a
     * commit is in progress, which owns its own outcome) and a parked USB host is replayed.
     */
    private void hideBackup() {
        ui.removeCallbacks(hideSeed);
        replacement.cancelCurrent(); // no-op when IDLE or COMMITTING
        if (unlocked && homeView != null) setContentView(this.homeView);
        drainPendingUsb();
    }

    /** Replay a parked accessory attach exactly once; handleIntent re-parks it if still blocked. */
    private void drainPendingUsb() {
        Intent usb = pendingUsb;
        pendingUsb = null;
        if (usb != null && unlocked && operational) handleIntent(usb);
        else if (usb != null && !unlocked) pendingUsb = usb; // locked: keep for the next unlock
    }

    private boolean replacementActive() { return replacement.active(); }
    private int beginReplacement() { return replacement.begin(); }
    private boolean markPrepared(int op) { return replacement.markPrepared(op); }
    private boolean beginCommit(int op) { return replacement.beginCommit(op); }
    private void endReplacement(int op) { replacement.end(op); }
    private boolean cancelReplacement(int op) { return replacement.cancel(op); }

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
            policy.setLockTaskPackages(VaultDeviceAdminReceiver.component(this),
                    new String[]{getPackageName()});
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
        policy.setLockTaskFeatures(VaultDeviceAdminReceiver.component(this),
                DevicePolicyManager.LOCK_TASK_FEATURE_NONE);
        policy.setScreenCaptureDisabled(VaultDeviceAdminReceiver.component(this),
                !DevTools.SCREENSHOTS);
        if (!policy.setStatusBarDisabled(VaultDeviceAdminReceiver.component(this), true)) {
            throw new IllegalStateException("Status bar could not be disabled");
        }
    }

    private void deactivate(String reason) {
        // Same serialized invalidation as lock(): a commit in flight finishes under stateLock
        // first, then its key is dropped here; nothing can publish after this block.
        AccessoryTransport staleTransport;
        synchronized (stateLock) {
            session.incrementAndGet();
            operational = false;
            unlocked = false;
            credentials = null;
            replacement.reset();
            staleTransport = transport;
            transport = null;
            if (staleTransport != null) staleTransport.close();
        }
        ui.removeCallbacks(idleLock);
        ui.removeCallbacks(hideSeed);
        if (homeView != null) setContentView(this.homeView);
        vault = null;
        requestPending.set(false);
        AlertDialog pending = approvalDialog;
        if (pending != null) pending.dismiss();
        statusView.setText(reason);
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (operational) handleIntent(intent);
    }

    private void buildUi() {
        getWindow().setStatusBarColor(VaultTheme.BG);
        getWindow().setNavigationBarColor(VaultTheme.BG);
        int pad = dp(26);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(pad, dp(56), pad, dp(34));
        content.setBackgroundColor(VaultTheme.BG);

        // Brand header: crisp pixel padlock + pixel wordmark
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.addView(VaultTheme.pixelLock(this, dp(3), VaultTheme.INK));
        TextView title = VaultTheme.pixelText(this, "PHONE VAULT", 17, VaultTheme.INK);
        title.setPadding(dp(18), 0, 0, 0);
        header.addView(title);
        content.addView(header);

        TextView tagline = VaultTheme.monoText(this, "OFFLINE EVM SIGNER · phonevault.org", 12, VaultTheme.DIM);
        tagline.setPadding(0, dp(14), 0, 0);
        content.addView(tagline);

        // Flexible spacer above centers the wallet block vertically
        content.addView(new View(this), new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        // QR of the receiving address — scannable, and black/white suits the mono theme
        LinearLayout qrBox = new LinearLayout(this);
        qrBox.setOrientation(LinearLayout.VERTICAL);
        qrBox.setGravity(Gravity.CENTER_HORIZONTAL);
        qrBox.setBackgroundColor(VaultTheme.INK);
        int qp = dp(16);
        qrBox.setPadding(qp, qp, qp, dp(13));
        qrView = new android.widget.ImageView(this);
        int qs = dp(220);
        qrView.setLayoutParams(new LinearLayout.LayoutParams(qs, qs));
        qrBox.addView(qrView);
        TextView qrLabel = VaultTheme.pixelText(this, "SCAN TO RECEIVE", 7, VaultTheme.BG);
        qrLabel.setPadding(0, dp(11), 0, 0);
        qrBox.addView(qrLabel);
        LinearLayout.LayoutParams qlp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        qlp.gravity = Gravity.CENTER_HORIZONTAL;
        content.addView(qrBox, qlp);

        // Signing address (full, wraps to two lines)
        LinearLayout addrBox = VaultTheme.box(this);
        addrBox.addView(VaultTheme.pixelText(this, "SIGNING ADDRESS", 7, VaultTheme.FAINT));
        addressView = VaultTheme.monoText(this, "generating…", 15, VaultTheme.INK);
        addressView.setTextIsSelectable(true);
        addressView.setPadding(0, dp(14), 0, dp(2));
        addrBox.addView(addressView);
        content.addView(addrBox, matchWrap(dp(24)));

        // Status row: pixel indicator (fills when a host connects) + uppercase mono status
        LinearLayout statusRow = new LinearLayout(this);
        statusRow.setOrientation(LinearLayout.HORIZONTAL);
        statusRow.setGravity(Gravity.CENTER_VERTICAL);
        statusRow.setPadding(dp(4), dp(20), 0, 0);
        statusDot = VaultTheme.statusDot(this, false);
        statusRow.addView(statusDot);
        statusView = VaultTheme.monoText(this, "usb: waiting for host", 12, VaultTheme.DIM);
        statusView.setAllCaps(true);
        statusView.setLetterSpacing(0.06f);
        statusView.setPadding(dp(12), 0, 0, 0);
        statusRow.addView(statusView);
        content.addView(statusRow);

        // Flexible spacer below — keeps actions + footer anchored to the bottom
        content.addView(new View(this), new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        // Actions
        TextView backup = VaultTheme.pixelButton(this, "Recovery phrase", false);
        hardenTouch(backup);
        backup.setOnClickListener(v -> confirmRevealBackup());
        content.addView(backup, matchWrap(0));

        TextView replace = VaultTheme.pixelButton(this, "Regenerate wallet", false);
        hardenTouch(replace);
        replace.setOnClickListener(v -> confirmReplace());
        content.addView(replace, matchWrap(dp(14)));

        // Footer anchored at the bottom
        content.addView(VaultTheme.divider(this));
        TextView warning = VaultTheme.monoText(this,
                "TEST ASSETS ONLY — unaudited prototype. Do not store real funds.",
                12, VaultTheme.BG);
        warning.setBackgroundColor(VaultTheme.INK);
        warning.setPadding(dp(14), dp(13), dp(14), dp(13));
        content.addView(warning, matchWrap(dp(4)));

        TextView version = VaultTheme.monoText(this,
                "PHONE VAULT OS 0.1.0 · " + BuildConfig.VERSION_NAME + " · m/44'/60'/0'/0/0",
                10, VaultTheme.FAINT);
        version.setPadding(dp(2), dp(14), 0, 0);
        content.addView(version);

        homeView = content;
        setContentView(content);
    }

    private void setStatusActive(boolean active) {
        if (statusDot == null) return;
        android.graphics.drawable.GradientDrawable d = new android.graphics.drawable.GradientDrawable();
        d.setColor(active ? VaultTheme.INK : VaultTheme.BG);
        d.setStroke(VaultTheme.px(this, 2), VaultTheme.INK);
        d.setCornerRadius(0f);
        statusDot.setBackground(d);
    }

    private void confirmRevealBackup() {
        if (!operational || !unlocked) { statusView.setText("vault disabled: appliance policy is not active"); return; }
        if (transport != null || requestPending.get() || replacementActive()) {
            statusView.setText("disconnect usb and finish any approval first");
            return;
        }
        AlertDialog dialog = darkDialog()
                .setTitle("Show recovery phrase?")
                .setMessage("Your 24 words control all funds. Make sure no camera or person can see the screen. "
                        + "Never type them into a computer or website.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Show", (d, w) -> showBackup())
                .create();
        secure(dialog.getWindow());
        dialog.setOnShowListener(i -> {
            hardenTouch(dialog.getButton(AlertDialog.BUTTON_NEGATIVE));
            hardenTouch(dialog.getButton(AlertDialog.BUTTON_POSITIVE));
        });
        dialog.show();
    }

    private void showBackup() {
        final int s = session.get(); // a reveal never crosses into a later unlock session
        cryptoExecutor.execute(() -> {
            try {
                String mnemonic = vault.revealMnemonic();
                String[] words = mnemonic.split(" ");
                runOnUiThread(() -> {
                    if (s != session.get() || !unlocked) return;
                    setContentView(buildBackupView(words));
                    ui.removeCallbacks(hideSeed);
                    ui.postDelayed(hideSeed, SEED_TIMEOUT_MS);
                    devDumpUi();
                });
            } catch (Exception e) {
                runOnUiThread(() -> statusView.setText("backup error: " + e.getMessage()));
            }
        });
    }

    /** Full-screen recovery-phrase view: 24 words in an aligned two-column grid. */
    /**
     * Phase 2 UI of a wallet replacement: the NEW phrase is shown for backup with an explicit
     * activate step. Only "Activate" commits; Cancel, timeout, or lock keep the current wallet.
     */
    private void showReplacementPhrase(SeedVault.Generation candidate, int s, int op) {
        final TextView activate = VaultTheme.pixelButton(this, "Activate new wallet", true);
        final TextView cancel = VaultTheme.pixelButton(this, "Cancel · keep current wallet", false);
        hardenTouch(activate);
        hardenTouch(cancel);
        activate.setOnClickListener(v -> {
            // PREPARED → COMMITTING is the single serialized transition; after it, Cancel and the
            // timeout are inert and the commit owns the outcome.
            if (s != session.get() || !beginCommit(op)) return;
            activate.setEnabled(false);
            cancel.setEnabled(false);
            ui.removeCallbacks(hideSeed);
            cryptoExecutor.execute(() -> {
                try {
                    final Credentials fresh;
                    // Commit + publish are one step under stateLock: lock()/deactivate() either run
                    // before (session changed → nothing written) or after (new key already dropped).
                    synchronized (stateLock) {
                        boolean owner = replacement.owns(op);
                        boolean usbQuiet = transport == null && !requestPending.get();
                        if (s != session.get() || !unlocked || !operational || !owner || !usbQuiet) {
                            endReplacement(op);
                            runOnUiThread(() -> {
                                statusView.setText(usbQuiet ? "replacement cancelled"
                                        : "replacement cancelled: USB became active");
                                hideBackup(); // terminal path: → home, parked USB replayed
                            });
                            return;
                        }
                        try {
                            fresh = vault.commitReplacement(candidate.mnemonic);
                        } catch (VaultKeyStore.PersistenceException uncertain) {
                            // The durable identity is unknown: drop the OLD runtime key too and
                            // force a reconcile-from-disk on the next unlock (loadOrCreate refuses
                            // to mint a wallet while the write journal is pending).
                            credentials = null;
                            endReplacement(op);
                            runOnUiThread(() -> {
                                statusView.setText("storage error: wallet identity must be reconciled — re-enter PIN");
                                lock();
                            });
                            return;
                        }
                        credentials = fresh;
                        endReplacement(op); // identity swapped; USB may resume
                    }
                    final String address = fresh.getAddress();
                    final android.graphics.Bitmap qr = qrFor(address);
                    runOnUiThread(() -> {
                        if (s != session.get()) return;
                        renderAddress(address, qr); // text + QR together, never one without the other
                        hideBackup();               // terminal path: → home, parked USB replayed
                        statusView.setText("new wallet active");
                        devDumpUi();
                    });
                } catch (Exception exception) {
                    endReplacement(op);
                    runOnUiThread(() -> {
                        statusView.setText("Key error: " + exception.getMessage());
                        hideBackup(); // terminal path
                    });
                }
            });
        });
        cancel.setOnClickListener(v -> {
            if (!cancelReplacement(op)) return; // COMMITTING: too late, ignore
            hideBackup();
            devDumpUi();
        });
        setContentView(buildBackupView(candidate.mnemonic.split(" "), "NEW RECOVERY PHRASE",
                "This wallet is NOT active yet. Write all 24 words down on paper first, then activate. Cancel keeps your current wallet.",
                activate, cancel));
        ui.removeCallbacks(hideSeed);
        ui.postDelayed(hideSeed, SEED_TIMEOUT_MS);
        devDumpUi();
    }

    private View buildBackupView(String[] words) {
        TextView hide = VaultTheme.pixelButton(this, "Hide phrase", true);
        hardenTouch(hide);
        hide.setOnClickListener(v -> { hideBackup(); devDumpUi(); });
        return buildBackupView(words, "RECOVERY PHRASE",
                "Write these 24 words down in order on paper. This is the only backup — never photograph them or type them into any device.",
                hide);
    }

    private View buildBackupView(String[] words, String titleText, String captionText, View... actions) {
        int pad = dp(26);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, dp(56), pad, dp(32));
        root.setBackgroundColor(VaultTheme.BG);

        // Header with brand mark for continuity
        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);
        head.addView(VaultTheme.pixelLock(this, dp(2), VaultTheme.INK));
        TextView title = VaultTheme.pixelText(this, titleText, 13, VaultTheme.INK);
        title.setPadding(dp(14), 0, 0, 0);
        head.addView(title);
        root.addView(head);
        TextView caption = VaultTheme.monoText(this, captionText, 12, VaultTheme.DIM);
        caption.setPadding(0, dp(14), 0, 0);
        root.addView(caption);

        // Two aligned, ruled columns: 1–12 | 13–24 ("ledger paper")
        LinearLayout grid = new LinearLayout(this);
        grid.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout colL = new LinearLayout(this);
        colL.setOrientation(LinearLayout.VERTICAL);
        LinearLayout colR = new LinearLayout(this);
        colR.setOrientation(LinearLayout.VERTICAL);
        colR.setPadding(dp(18), 0, 0, 0);
        int half = words.length / 2;
        for (int i = 0; i < words.length; i++) {
            LinearLayout col = i < half ? colL : colR;
            col.addView(wordCell(i + 1, words[i]));
            if ((i % half) != half - 1) col.addView(VaultTheme.rule(this, 0, 0));
        }
        grid.addView(colL, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        grid.addView(colR, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        // grid gets the flexible weight so rows spread to fill the screen
        LinearLayout.LayoutParams glp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        glp.topMargin = dp(26);
        glp.bottomMargin = dp(22);
        grid.setGravity(Gravity.CENTER_VERTICAL);
        root.addView(grid, glp);

        for (int i = 0; i < actions.length; i++) {
            root.addView(actions[i], matchWrap(i == 0 ? 0 : dp(10)));
        }
        return root;
    }

    /** One numbered word, with the index in a fixed-width mono column so words line up. */
    private View wordCell(int n, String word) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(9), 0, dp(9));
        TextView num = VaultTheme.monoText(this, String.format("%02d", n), 15, VaultTheme.FAINT);
        num.setWidth(dp(34));
        TextView w = VaultTheme.monoText(this, word, 17, VaultTheme.INK);
        row.addView(num);
        row.addView(w);
        return row;
    }

    private AlertDialog.Builder darkDialog() {
        return new AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert);
    }

    /** Adds FLAG_SECURE unless this is a dev build that permits screenshots for UI review. */
    private static void secure(android.view.Window window) {
        if (!DevTools.SCREENSHOTS) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
    }

    private void loadKey() {
        final int s = session.get();
        cryptoExecutor.execute(() -> {
            try {
                if (pin.eraseOutstanding()) {
                    throw new IllegalStateException("vault is sealed: erase outstanding");
                }
                final Credentials loaded = vault.loadOrCreate();
                final String address = loaded.getAddress();
                final android.graphics.Bitmap qr = qrFor(address);
                synchronized (stateLock) {
                    if (s != session.get() || !unlocked || !operational) return; // locked/deactivated: drop it
                    credentials = loaded;
                }
                runOnUiThread(() -> {
                    if (s != session.get()) return;
                    renderAddress(address, qr);
                });
            } catch (Exception exception) {
                runOnUiThread(() -> statusView.setText("Key error: " + exception.getMessage()));
            }
        });
    }

    private android.graphics.Bitmap qrFor(String address) {
        android.graphics.Bitmap raw = VaultTheme.qrBitmap(address, dp(180));
        return raw == null ? null : VaultTheme.framedQr(raw, dp(14), dp(3), dp(6));
    }

    /** Address text and QR always change together — a stale QR is a funds-loss bug. */
    private void renderAddress(String address, android.graphics.Bitmap qr) {
        addressView.setText(formatAddress(address));
        if (qrView != null) qrView.setImageBitmap(qr);
    }

    private void confirmReplace() {
        if (!operational || !unlocked) {
            statusView.setText("Vault disabled: appliance policy is not active");
            return;
        }
        if (transport != null || requestPending.get() || replacementActive()) {
            statusView.setText("Disconnect USB and finish any approval before replacing the key");
            return;
        }
        AlertDialog dialog = darkDialog()
                .setTitle("Regenerate wallet?")
                .setMessage("A brand-new seed will be generated and its recovery phrase shown. Nothing changes until you activate it. Once activated, the current phrase and any funds it controls are UNRECOVERABLE unless you have written the current phrase down.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Continue", (ignoredDialog, which) -> {
                    if (transport != null || requestPending.get()) {
                        statusView.setText(
                                "Disconnect USB and finish any approval before replacing the key");
                        return;
                    }
                    final int op = beginReplacement(); // IDLE → PREPARING; this flow owns the token
                    if (op < 0) {
                        statusView.setText("A wallet replacement is already in progress");
                        return;
                    }
                    final int s = session.get();
                    cryptoExecutor.execute(() -> {
                        try {
                            // Requests arriving after the CAS above observe
                            // replacement.active() and are parked/rejected.
                            if (transport != null || requestPending.get()) {
                                endReplacement(op);
                                runOnUiThread(() -> {
                                    statusView.setText("Key replacement cancelled because USB became active");
                                    drainPendingUsb();
                                });
                                return;
                            }
                            // Phase 1: candidate only — the stored wallet is untouched.
                            final SeedVault.Generation candidate = vault.prepareReplacement(new byte[0]);
                            runOnUiThread(() -> {
                                if (s != session.get() || !unlocked || !markPrepared(op)) {
                                    endReplacement(op);
                                    drainPendingUsb();
                                    return;
                                }
                                showReplacementPhrase(candidate, s, op);
                            });
                        } catch (Exception exception) {
                            endReplacement(op);
                            runOnUiThread(() -> {
                                statusView.setText("Key error: " + exception.getMessage());
                                drainPendingUsb();
                            });
                        }
                    });
                }).create();
        secure(dialog.getWindow());
        dialog.setOnShowListener(ignored -> {
            hardenTouch(dialog.getButton(AlertDialog.BUTTON_NEGATIVE));
            hardenTouch(dialog.getButton(AlertDialog.BUTTON_POSITIVE));
        });
        dialog.show();
    }

    private void handleIntent(Intent intent) {
        if (!operational || intent == null) return;
        if (!UsbManager.ACTION_USB_ACCESSORY_ATTACHED.equals(intent.getAction())) return;
        if (!unlocked) {
            // USB data-lock (app layer): the host gets no responder until the PIN is entered.
            pendingUsb = intent;
            if (pinScreen != null) pinScreen.setSubtitle("Enter PIN to unlock.  USB host is waiting.");
            return;
        }
        if (replacementActive()) {
            // Threat-model invariant: replacement and USB are mutually exclusive. Park the host
            // until the replacement completes or is cancelled (then replayed from there).
            pendingUsb = intent;
            statusView.setText("USB host waiting: finish the wallet replacement first");
            return;
        }
        UsbAccessory accessory = intent.getParcelableExtra(UsbManager.EXTRA_ACCESSORY);
        if (accessory == null) return;
        if (transport != null) {
            AccessoryTransport previous = transport;
            transport = null;
            previous.close();
        }
        requestPending.set(false);
        AlertDialog previousApproval = approvalDialog;
        if (previousApproval != null) previousApproval.dismiss();
        try {
            AccessoryTransport opened = AccessoryTransport.open(
                    (UsbManager) getSystemService(USB_SERVICE), accessory, this);
            transport = opened;  // publish first …
            opened.start();      // … then let callbacks fire; none can be mis-attributed now
            statusView.setText("USB: connected — waiting for request");
        } catch (Exception exception) {
            transport = null;
            statusView.setText("USB error: " + exception.getMessage());
        }
    }

    @Override public void onConnected(AccessoryTransport source) {
        if (source != transport) return;
        runOnUiThread(() -> {
            statusView.setText("USB: connected — waiting for request");
            setStatusActive(true);
        });
    }

    @Override public void onRequest(AccessoryTransport source, JSONObject json) {
        if (!operational) {
            sendError(source, json.optString("id", "unknown"), "Appliance policy is not active");
            return;
        }
        if (source != transport) return;
        String id = json.optString("id", "unknown");
        if (replacementActive()) {
            sendError(source, id, "Signing key replacement is in progress");
            return;
        }
        if ("getAddress".equals(json.optString("method"))) {
            try {
                Eip1559Request.requireExactFields(json, "id", "method");
                id = Eip1559Request.validatedId(json.getString("id"));
                Credentials current = credentials;
                if (current == null) {
                    sendError(source, id, "Key is not ready");
                } else {
                    source.send(json("id", id, "status", "ok", "address", current.getAddress()));
                }
            } catch (Exception exception) {
                sendError(source, id, exception.getMessage());
            }
            return;
        }
        if (!requestPending.compareAndSet(false, true)) {
            sendError(source, id, "Another approval is pending");
            return;
        }
        try {
            Eip1559Request request = Eip1559Request.parse(json);
            Credentials reviewedCredentials = credentials;
            if (reviewedCredentials == null) {
                throw new IllegalStateException("Key is not ready");
            }
            ApprovalSession approval = new ApprovalSession(request, reviewedCredentials);
            runOnUiThread(() -> showApproval(source, approval));
        } catch (Exception exception) {
            requestPending.set(false);
            sendError(source, id, exception.getMessage());
        }
    }

    private void showApproval(AccessoryTransport source, ApprovalSession approval) {
        final int s = session.get(); // the approval is bound to THIS unlock session
        if (source != transport || !unlocked) {
            requestPending.set(false);
            sendError(source, approval.request.id, "Vault is locked");
            return;
        }
        Eip1559Request request = approval.request;
        LinearLayout details = new LinearLayout(this);
        details.setOrientation(LinearLayout.VERTICAL);
        details.setBackgroundColor(VaultTheme.BG);
        int padding = dp(20);
        details.setPadding(padding, dp(8), padding, 0);
        details.addView(detail("Transaction type", request.transactionTypeLabel()));
        details.addView(detail("Signing address", approval.signerAddressLabel()));
        details.addView(detail("Network", request.networkLabel()));
        details.addView(detail(request.displayedAmountTitle(), request.displayedAmountLabel()));
        details.addView(detail(request.displayedPartyTitle(), request.displayedRecipientLabel()));
        if (request.kind != Eip1559Request.Kind.NATIVE_TRANSFER) {
            details.addView(detail("Target contract", request.contractLabel()));
        }
        details.addView(detail(request.contractWarningTitle(), request.contractWarningLabel()));
        details.addView(detail("Maximum network fee", request.maximumFeeEth()));
        details.addView(detail("Gas limit", request.gasLimitLabel()));
        details.addView(detail("Maximum fee per gas", request.maxFeePerGasLabel()));
        details.addView(detail("Priority fee per gas", request.maxPriorityFeePerGasLabel()));
        details.addView(detail("Nonce", request.nonce.toString()));
        details.addView(detail("Contract data", request.contractDataLabel()));
        CheckBox reviewed = new CheckBox(this);
        reviewed.setText(request.reviewPrompt());
        reviewed.setTextColor(VaultTheme.INK);
        reviewed.setTypeface(VaultTheme.mono());
        reviewed.setPadding(dp(8), dp(10), 0, dp(10));
        hardenTouch(reviewed);
        details.addView(reviewed);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(VaultTheme.BG);
        scroll.addView(details);
        AlertDialog dialog = darkDialog()
                .setTitle("Approve transaction?")
                .setView(scroll)
                .setCancelable(false)
                .setNegativeButton("Reject", (d, which) -> {
                    requestPending.set(false);
                    source.send(json("id", request.id, "status", "rejected"));
                    statusView.setText("USB: transaction rejected");
                })
                .setPositiveButton("Sign", null)
                .create();
        secure(dialog.getWindow());
        dialog.setOnShowListener(ignored -> {
            Button signButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            signButton.setEnabled(false);
            reviewed.setOnCheckedChangeListener((button, checked) -> signButton.setEnabled(checked));
            signButton.setOnClickListener(view -> {
                if (source != transport || s != session.get() || !unlocked) {
                    requestPending.set(false);
                    dialog.dismiss();
                    return;
                }
                signButton.setEnabled(false);
                reviewed.setEnabled(false);
                statusView.setText("Signing approved transaction…");
                cryptoExecutor.execute(() -> {
                    try {
                        JSONObject response;
                        // Check-sign-send is one step under stateLock: lock()/deactivate() close the
                        // transport inside the same lock, so the outcome is linearized — either the
                        // signature is sent before the lock, or nothing is computed after it.
                        synchronized (stateLock) {
                            if (!operational || !unlocked || s != session.get()
                                    || source != transport || source.isClosed()) {
                                throw new IllegalStateException("Vault locked or USB session is no longer active");
                            }
                            response = approval.signIfIdentityUnchanged(credentials);
                            source.send(response);
                        }
                        runOnUiThread(() -> {
                            statusView.setText("USB: signature returned");
                            dialog.dismiss();
                        });
                    } catch (Exception exception) {
                        sendError(source, request.id, exception.getMessage());
                        runOnUiThread(dialog::dismiss);
                    } finally {
                        requestPending.set(false);
                    }
                });
            });
        });
        dialog.setOnDismissListener(ignored -> {
            if (approvalDialog == dialog) approvalDialog = null;
        });
        approvalDialog = dialog;
        dialog.show();
        hardenTouch(dialog.getButton(AlertDialog.BUTTON_NEGATIVE));
        hardenTouch(dialog.getButton(AlertDialog.BUTTON_POSITIVE));
    }

    private View detail(String label, String value) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        boolean danger = "DANGER".equalsIgnoreCase(label) || "WARNING".equalsIgnoreCase(label);
        TextView labelView = VaultTheme.pixelText(this, label.toUpperCase(), 7,
                danger ? VaultTheme.DANGER_INK : VaultTheme.FAINT);
        TextView valueView = VaultTheme.monoText(this, value, 14,
                danger ? VaultTheme.DANGER_INK : VaultTheme.INK);
        valueView.setTextIsSelectable(true);
        valueView.setPadding(0, dp(6), 0, dp(15));
        row.addView(labelView);
        row.addView(valueView);
        return row;
    }

    private void sendError(AccessoryTransport source, String id, String message) {
        if (source != null) source.send(json("id", id, "status", "error", "error", message));
        runOnUiThread(() -> statusView.setText("Request error: " + message));
    }

    @Override public void onDisconnected(AccessoryTransport source, String reason) {
        if (source != transport) return;
        transport = null;
        requestPending.set(false);
        runOnUiThread(() -> {
            AlertDialog pending = approvalDialog;
            if (pending != null) pending.dismiss();
            statusView.setText("USB: disconnected" + (reason == null ? "" : " — " + reason));
            setStatusActive(false);
        });
    }

    @Override protected void onDestroy() {
        ui.removeCallbacksAndMessages(null);
        if (transport != null) transport.close();
        cryptoExecutor.shutdownNow();
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
