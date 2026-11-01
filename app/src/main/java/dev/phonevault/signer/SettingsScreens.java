package dev.phonevault.signer;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.widget.LinearLayout;
import android.widget.SeekBar;
import android.widget.TextView;

import java.util.List;

/**
 * ☰ → Security, Display & auto-lock, Device information and Coming next. Screens and the saved
 * display choices only: the recovery-phrase, replace, restore and Bitcoin-sharing actions open
 * their own screen classes, which keep their own PIN and sensitive-flow rules.
 */
final class SettingsScreens {
    /** What these screens borrow from MainActivity beyond {@link VaultHost}. */
    interface Host extends VaultHost {
        void showPassphraseWallet();
        DisplaySettings display();
        /** The text size in effect (as last applied). */
        boolean largeText();
        /** Re-read text scale, haptics and idle lock from {@link #display()}. */
        void applyDisplaySettings();
        /** The screen timeout changed: apply it as device owner (when we are) and re-arm the idle lock. */
        void screenTimeoutChanged();
        /** A display choice changed the idle lock: re-arm it. */
        void armIdleLock();
        /** Apply the saved brightness choice (device owner: the system setting; else this window). */
        void applyBrightness();
        /** Show a slider position while it is dragged, without saving it. */
        void previewBrightness(int percent);
        /** Restart is possible here: this app is the device owner (DevicePolicyManager#reboot). */
        boolean restartAvailable();
        /** A USB request is held, under review or being answered: no restart now. */
        boolean requestUnderReview();
        /** Lock (the key leaves memory), then restart the phone. Refused while a request is under review. */
        void restart();
        /** PhoneVault appliance image, policy established. */
        boolean appliancePolicyActive();
        boolean credentialMode();
        SigningAccount activeAccount();
    }

    private final Host host;
    private final Activity activity;
    private final Pages pages;
    private final BackupScreens backup;
    private final SetupScreens setup;
    private final BtcScreens btc;

    SettingsScreens(Host host, BackupScreens backup, SetupScreens setup, BtcScreens btc) {
        this.host = host;
        this.activity = host.activity();
        this.pages = host.pages();
        this.backup = backup;
        this.setup = setup;
        this.btc = btc;
    }

    void showSecurity() {
        LinearLayout root = pages.page("DEVICE & WALLET", "Security", "Controls that protect access, recovery, and your ability to verify this device.");
        pages.card(root, "Backup", host.backupVerified()
                ? "Spot-checked for Account 1. Keep your written recovery phrase somewhere safe and private."
                : "Not checked yet. Receiving and signing stay paused until it is.");
        pages.action(root, "Check my backup", !host.backupVerified(), () -> backup.startBackupAccess(true));
        pages.action(root, "Show recovery phrase", false, backup::confirmRevealBackup);
        pages.card(root, "Passphrase (optional)", "Your recovery phrase backs up every account of the standard wallet. A passphrase wallet also needs its passphrase, which is not part of this backup and is never saved on the phone: keep it written down separately.");
        pages.action(root, "Passphrase wallet", false, host::showPassphraseWallet);
        pages.action(root, "Show as SeedQR", false, backup::confirmRevealSeedQr);
        pages.action(root, "Backup reminder · " + BackupReminder.label(host.backupReminder().intervalDays()), false, backup::showBackupReminderSettings);
        pages.action(root, "Bitcoin sharing", false, btc::showBtcSharing);
        pages.card(root, "This wallet", "Replacing or restoring changes the key on this phone. Keep the current backup if the wallet controls anything.");
        pages.action(root, "Replace with a new wallet", false, backup::confirmReplace);
        pages.action(root, "Restore a different wallet", false, setup::confirmRestoreOver);
        pages.action(root, "Lock now", false, host::lock);
        pages.present(root, "security");
    }

    void showPreferences() {
        DisplaySettings display = host.display();
        LinearLayout root = pages.page("SECURITY / PREFERENCES", "Display & auto-lock",
                "Text size, brightness, screen timeout, locking and touch feedback. Changes apply at once.");
        pages.card(root, "Text size", host.largeText() ? "Large · easier reading" : "Standard · comfortable reading");
        pages.action(root, host.largeText() ? "Use standard text" : "Use larger text", true, () -> {
            if (display.setLargeText(!host.largeText())) {
                host.applyDisplaySettings();
                showPreferences();
            } else pages.showInfo("Setting not saved", "Try again. Your previous text size is still active.", this::showPreferences);
        });

        addBrightness(root, display);

        int screen = display.screenTimeoutSeconds();
        int grace = display.screenOffGraceSeconds();
        pages.card(root, "Screen timeout", "The screen turns off after " + DisplaySettings.durationLabel(screen)
                + " without a touch. " + (grace == 0 ? "Screen off locks the vault."
                        : "The vault locks " + DisplaySettings.durationLabel(grace) + " after the screen turns off."));
        for (int seconds : DisplaySettings.SCREEN_TIMEOUT_CHOICES) {
            pages.action(root, "Screen off after " + DisplaySettings.durationLabel(seconds), seconds == screen, () -> {
                if (display.setScreenTimeoutSeconds(seconds)) {
                    host.applyDisplaySettings();
                    host.screenTimeoutChanged();
                    showPreferences();
                } else pages.showInfo("Setting not saved", "Your previous screen timeout is still active.", this::showPreferences);
            });
        }

        int idle = display.idleSeconds();
        int effective = DisplaySettings.effectiveIdleSeconds(idle, screen, grace, true);
        pages.card(root, "Idle lock", "Locks after " + DisplaySettings.durationLabel(effective)
                + " without a touch, even while a review keeps the screen on."
                + (effective < idle ? " (Capped by the screen timeout.)" : ""));
        for (int seconds : DisplaySettings.IDLE_CHOICES) {
            pages.action(root, "Lock after " + DisplaySettings.durationLabel(seconds), idle == seconds, () -> {
                if (display.setIdleSeconds(seconds)) {
                    host.applyDisplaySettings();
                    host.armIdleLock();
                    showPreferences();
                } else pages.showInfo("Setting not saved", "Your previous idle timeout is still active.", this::showPreferences);
            });
        }

        pages.card(root, "Lock after screen off", grace == 0 ? "Immediately · waking the phone always asks for the PIN"
                : DisplaySettings.durationLabel(grace) + " · waking the phone within this time does not ask for the PIN. "
                        + "Showing the recovery phrase, restoring or replacing the wallet always does; a restart always locks.");
        if (grace > 0) {
            TextView warning = VaultTheme.bodyText(activity, DisplaySettings.GRACE_WARNING, 14, VaultTheme.WARNING_INK);
            warning.setPadding(0, pages.dp(8), 0, 0);
            root.addView(warning);
        }
        for (int seconds : DisplaySettings.SCREEN_OFF_GRACE_CHOICES) {
            pages.action(root, "Lock after screen off · " + DisplaySettings.graceLabel(seconds), seconds == grace, () -> {
                if (display.setScreenOffGraceSeconds(seconds)) {
                    host.applyDisplaySettings();
                    host.armIdleLock();
                    showPreferences();
                } else pages.showInfo("Setting not saved", "Your previous lock setting is still active.", this::showPreferences);
            });
        }

        boolean haptics = display.haptics();
        pages.card(root, "Haptics", haptics ? "On · a tap for PIN keys, a pulse when you sign, a double pulse on reject"
                : "Off · no vibration feedback");
        pages.action(root, haptics ? "Turn haptics off" : "Turn haptics on", false, () -> {
            if (display.setHaptics(!haptics)) {
                host.applyDisplaySettings();
                showPreferences();
            } else pages.showInfo("Setting not saved", "Your previous haptics setting is still active.", this::showPreferences);
        });

        pages.card(root, "Turning off", "To turn off: hold the power button, then choose Power off or Restart. ☰ → Power can restart the phone too.");
        pages.action(root, "Back to Security", false, this::showSecurity);
        pages.present(root, "preferences");
    }

    /** Brightness: a slider (1..100 %) and Automatic. Saved on release; the slider is live while dragged. */
    private void addBrightness(LinearLayout root, DisplaySettings display) {
        boolean auto = display.brightnessAuto();
        int percent = display.brightnessPercent();
        pages.card(root, "Brightness", !display.brightnessChosen() ? "The phone's own setting · move the slider or choose Automatic"
                : auto ? "Automatic · follows the light around you" : "Manual · " + percent + "%");
        SeekBar slider = new SeekBar(activity);
        slider.setContentDescription("Brightness");
        slider.setMax(DisplaySettings.MAX_BRIGHTNESS_PERCENT - DisplaySettings.MIN_BRIGHTNESS_PERCENT);
        slider.setProgress(percent - DisplaySettings.MIN_BRIGHTNESS_PERCENT);
        slider.setAlpha(auto ? 0.5f : 1f);
        Pages.hardenTouch(slider);
        slider.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override public void onProgressChanged(SeekBar bar, int progress, boolean fromUser) {
                if (fromUser) host.previewBrightness(progress + DisplaySettings.MIN_BRIGHTNESS_PERCENT);
            }
            @Override public void onStartTrackingTouch(SeekBar bar) { }
            @Override public void onStopTrackingTouch(SeekBar bar) {
                // Moving the slider is a manual choice: Automatic turns off.
                if (display.setBrightnessPercent(bar.getProgress() + DisplaySettings.MIN_BRIGHTNESS_PERCENT)) {
                    host.applyBrightness();
                    showPreferences();
                } else {
                    host.applyBrightness();
                    pages.showInfo("Setting not saved", "Your previous brightness is still active.", SettingsScreens.this::showPreferences);
                }
            }
        });
        root.addView(slider, Pages.matchWrap(pages.dp(10)));
        pages.action(root, auto ? "Automatic brightness · on" : "Automatic brightness", auto, () -> {
            if (display.setBrightnessAuto(!auto)) {
                host.applyBrightness();
                showPreferences();
            } else pages.showInfo("Setting not saved", "Your previous brightness is still active.", this::showPreferences);
        });
    }

    /** ☰ → Power: restart (device owner only, confirmed, never while a request is under review); power off stays on the button. */
    void showPower() {
        LinearLayout root = pages.page("DEVICE", "Power", "Restart the phone, or turn it off with the power button.");
        pages.card(root, "Turning off", "To turn off: hold the power button, then choose Power off.");
        if (!host.restartAvailable()) {
            pages.card(root, "Restart", "To restart: hold the power button, then choose Restart. (This phone is not set up as a Phone Vault appliance, so the app cannot restart it.)");
        } else if (host.requestUnderReview()) {
            pages.card(root, "Restart", "Not while a request from your Mac is waiting or under review. Approve or reject it first.");
        } else {
            pages.card(root, "Restart", "Locks the vault and restarts the phone. You will enter your PIN on the start screen.");
            pages.action(root, "Restart", false, this::confirmRestart);
        }
        pages.action(root, "Back to Security", false, this::showSecurity);
        pages.present(root, "power");
    }

    private void confirmRestart() {
        if (!host.restartAvailable() || host.requestUnderReview()) { showPower(); return; }
        LinearLayout root = pages.page("DEVICE / POWER", "Restart the phone?",
                "The vault locks first: your keys leave memory. After the restart, enter your PIN to unlock.");
        pages.action(root, "Restart now", true, () -> {
            if (host.restartAvailable() && !host.requestUnderReview()) host.restart();
            else showPower();
        });
        pages.action(root, "Cancel", false, this::showPower);
        pages.present(root, "power-confirm");
    }

    void showIntegrity() {
        LinearLayout root = pages.page("SECURITY / DEVICE", "Know what is verified",
                "These are this phone's own observations. The genuine check in Phone Vault Companion verifies the phone independently.");
        pages.card(root, "App build", BuildConfig.VERSION_NAME + " · " + (DevTools.SCREENSHOTS ? "development capture enabled" : "release capture disabled"));
        pages.card(root, "Platform", Build.MANUFACTURER + " " + Build.MODEL + "\nAndroid " + Build.VERSION.RELEASE + "\nReported patch: " + Build.VERSION.SECURITY_PATCH);
        pages.card(root, "Device policy", host.appliancePolicyActive() ? "Appliance policy active" : "Development environment · appliance policy not established");
        pages.card(root, "Key boundary", BuildConfig.VAULT_REQUIRE_SECURE_HARDWARE
                ? "Keys are sealed in the security chip; loading refuses anything else. EVM signing runs in Android memory."
                : "Keys are sealed in the security chip when it is available; this development build also allows a software key. "
                        + "EVM signing runs in Android memory.");
        pages.card(root, "Verified boot", "Not independently verified by this screen. Complete the release, relock, and external verification procedure.");
        SigningAccount shownAccount = host.activeAccount();
        pages.card(root, "Account path", shownAccount == null ? "m/44'/60'/0'/0/0 · no passphrase"
                : shownAccount.path() + (shownAccount.passphrase ? " · passphrase wallet " + shownAccount.fingerprint : " · no passphrase"));
        pages.card(root, "Account numbering", (shownAccount == null ? AccountScheme.STANDARD : shownAccount.scheme).label
                + " · " + (shownAccount == null ? AccountScheme.STANDARD : shownAccount.scheme).pathPattern() + " · change it in ☰ → Accounts");
        pages.card(root, "PIN protection", host.credentialMode()
                ? "Held by the security chip, which slows repeated guesses · "
                        + SystemCredential.MAX_FAILED_FOR_WIPE + " wrong PINs erase the phone · the key that unlocks your "
                        + "recovery phrase works only for " + SystemCredential.AUTH_WINDOW_SECONDS + " s after a correct PIN"
                : "Checked by this app, not by the security chip (this phone could not hand the PIN to it) · "
                        + VaultPin.MAX_ATTEMPTS + " wrong PINs erase the wallet.");
        String entropy = EntropySource.plainReport(activity.getPreferences(Context.MODE_PRIVATE).getString("entropy_report", null));
        pages.card(root, "Randomness at wallet creation", entropy != null ? entropy
                : "Not recorded (this wallet was created or restored before source reporting existed, or restored from a recovery phrase).");
        Intent battery = activity.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (battery != null) {
            int level = battery.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
            int scale = battery.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
            pages.card(root, "Battery charge", level >= 0 && scale > 0 ? (level * 100 / scale) + "% · charge is not a battery-health assessment" : "Unavailable");
        }
        pages.card(root, "Power", "To turn off: hold the power button, then choose Power off or Restart. ☰ → Power can restart the phone too.");
        pages.action(root, "Back to Security", false, this::showSecurity);
        pages.present(root, "integrity");
    }

    /** Persist WHICH sources fed the last generated seed and whether each passed its health tests
     *  (names and pass/fail only; no entropy bytes). Shown on Device information (R7). */
    void recordEntropyReport(boolean dice) {
        List<SeedVault.SourceReport> reports = host.vault().lastGenerationReports();
        if (reports == null) return;
        StringBuilder b = new StringBuilder();
        for (SeedVault.SourceReport r : reports) {
            if (b.length() > 0) b.append('\n');
            b.append(r.healthy ? "✓ " : "✗ ").append(r.name).append(r.healthy ? " · passed health tests" : " · not used: " + r.detail);
        }
        if (dice) b.append("\n✓ your dice rolls");
        activity.getPreferences(Context.MODE_PRIVATE).edit().putString("entropy_report", b.toString()).apply();
    }

    void showFeatures() {
        LinearLayout root = pages.page("PRODUCT ROADMAP", "Coming next", "What is planned. Nothing here can be enabled in this build.");
        String[][] items = {
            {"Linux and Windows versions of Phone Vault Companion", "Phone Vault Companion runs on macOS today. Signed Linux and Windows versions follow the signed, notarized macOS release."},
            {"Updatable token list", "A signed token list that can be updated without a new app release, and token names and decimals in permit message reviews. Today the list changes only with an app update."},
            {"Ethereum account discovery", "Finding the accounts you have already used automatically, and sharing a watch-only view with other wallets. Today you add accounts yourself in ☰ → Accounts."},
            {"Change PIN", "Changing the PIN on the phone. Until then the PIN you chose at setup stays in effect."},
            {"Signed updates", "A verified release chain, rollback protection, and recovery from interrupted updates."},
            {"Advanced recovery", "Multisig, optional stateless use, and Shamir (SLIP-39) backups after core recovery is proven."},
            {"Passkeys", "A future authenticator whose keys stay in the security chip, with its own transport and recovery review."}
        };
        for (String[] item : items) pages.action(root, item[0] + " · planned", false,
                () -> showPlanned(item[0], item[1]));
        pages.present(root, "features");
    }

    private void showPlanned(String title, String description) {
        LinearLayout root = pages.page("PLANNED · NOT AVAILABLE", title, description);
        pages.card(root, "Availability", "No wallet setting was changed. This screen describes upcoming work.");
        pages.action(root, "Back to Coming next", true, this::showFeatures);
        pages.action(root, "Wallet", false, host::showHome);
        pages.present(root, "planned");
    }
}
