package dev.phonevault.signer;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.widget.LinearLayout;

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
                ? "Spot-checked for Account 1. Keep the written 24 words somewhere safe and private."
                : "Not checked yet. Receiving and signing stay paused until it is.");
        pages.action(root, "Check my backup", !host.backupVerified(), () -> backup.startBackupAccess(true));
        pages.action(root, "Show recovery phrase", false, backup::confirmRevealBackup);
        pages.card(root, "Passphrase (optional)", "Your 24 words back up every account of the standard wallet. A passphrase wallet ALSO needs its passphrase, which is not part of this backup and is never saved on the phone: keep it written down separately.");
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
                "Text size, screen timeout, locking and touch feedback. Changes apply at once.");
        pages.card(root, "Text size", host.largeText() ? "Large · easier reading" : "Standard · comfortable reading");
        pages.action(root, host.largeText() ? "Use standard text" : "Use larger text", true, () -> {
            if (display.setLargeText(!host.largeText())) {
                host.applyDisplaySettings();
                showPreferences();
            } else pages.showInfo("Setting not saved", "Try again. Your previous text size is still active.", this::showPreferences);
        });

        int screen = display.screenTimeoutSeconds();
        pages.card(root, "Screen timeout", "The screen turns off after " + DisplaySettings.durationLabel(screen)
                + " without a touch. Screen off always locks the vault.");
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
        int effective = DisplaySettings.effectiveIdleSeconds(idle, screen);
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

        boolean haptics = display.haptics();
        pages.card(root, "Haptics", haptics ? "On · a tap for PIN keys, a pulse when you sign, a double pulse on reject"
                : "Off · no vibration feedback");
        pages.action(root, haptics ? "Turn haptics off" : "Turn haptics on", false, () -> {
            if (display.setHaptics(!haptics)) {
                host.applyDisplaySettings();
                showPreferences();
            } else pages.showInfo("Setting not saved", "Your previous haptics setting is still active.", this::showPreferences);
        });

        pages.card(root, "Turning off", "To turn off: hold the power button, then choose Power off or Restart.");
        pages.action(root, "Back to Security", false, this::showSecurity);
        pages.present(root, "preferences");
    }

    void showIntegrity() {
        LinearLayout root = pages.page("SECURITY / DEVICE", "Know what is verified", "These are local observations, not independent attestation.");
        pages.card(root, "App build", BuildConfig.VERSION_NAME + " · " + (DevTools.SCREENSHOTS ? "development capture enabled" : "release capture disabled"));
        pages.card(root, "Platform", Build.MANUFACTURER + " " + Build.MODEL + "\nAndroid " + Build.VERSION.RELEASE + "\nReported patch: " + Build.VERSION.SECURITY_PATCH);
        pages.card(root, "Device policy", host.appliancePolicyActive() ? "Appliance policy active" : "Development environment · appliance policy not established");
        pages.card(root, "Key boundary", BuildConfig.VAULT_REQUIRE_SECURE_HARDWARE
                ? "StrongBox wrapping is required when loading. EVM signing runs in Android memory."
                : "Development build permits software wrapping. EVM signing runs in Android memory.");
        pages.card(root, "Verified boot", "Not independently verified by this screen. Complete the release, relock, and external verification procedure.");
        SigningAccount shownAccount = host.activeAccount();
        pages.card(root, "Account path", shownAccount == null ? "m/44'/60'/0'/0/0 · no passphrase"
                : shownAccount.path() + (shownAccount.passphrase ? " · passphrase wallet " + shownAccount.fingerprint : " · no passphrase"));
        pages.card(root, "PIN protection", host.credentialMode()
                ? "Checked by the security chip (Titan M), which slows repeated guesses · "
                        + SystemCredential.MAX_FAILED_FOR_WIPE + " wrong PINs reset the phone · the seed key works only for "
                        + SystemCredential.AUTH_WINDOW_SECONDS + " s after a correct PIN"
                : "App PIN gate · 10 failed attempts erase the wallet. PIN-derived encryption is planned.");
        String entropy = activity.getPreferences(Context.MODE_PRIVATE).getString("entropy_report", null);
        pages.card(root, "Entropy at wallet creation", entropy != null ? entropy
                : "Not recorded (this wallet was created or restored before source reporting existed, or restored from words).");
        Intent battery = activity.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
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
        pages.action(root, "Wallet", false, host::showHome);
        pages.present(root, "planned");
    }
}
