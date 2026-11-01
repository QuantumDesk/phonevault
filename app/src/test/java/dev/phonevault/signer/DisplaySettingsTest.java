package dev.phonevault.signer;

import static org.junit.Assert.*;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class DisplaySettingsTest {

    // ---------------------------------------------------------------- screen timeout / idle lock

    @Test public void defaults() {
        DisplaySettings d = new DisplaySettings(new VaultPinTest.FakePrefs());
        assertEquals("beta5: two minutes by default", 120, d.screenTimeoutSeconds());
        assertEquals(120_000, d.screenTimeoutMs());
        assertEquals(120, d.idleSeconds());
        assertEquals(120_000L, d.idleLockMs());
        assertEquals("lock after screen off: at once", 0, d.screenOffGraceSeconds());
        assertFalse("the phone's own brightness until one is chosen here", d.brightnessChosen());
        assertFalse(d.largeText());
        assertTrue(d.haptics());
    }

    @Test public void aSavedScreenTimeoutIsNotOverriddenByTheNewDefault() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        prefs.edit().putInt(DisplaySettings.KEY_SCREEN_TIMEOUT_SECONDS, 60).commit(); // saved under beta4
        assertEquals(60, new DisplaySettings(prefs).screenTimeoutSeconds());
        assertEquals(60_000, new DisplaySettings(prefs).screenTimeoutMs());
    }

    @Test public void timeoutChoices() {
        assertArrayEquals(new int[] {30, 60, 120, 300, 600}, DisplaySettings.SCREEN_TIMEOUT_CHOICES);
        assertArrayEquals(new int[] {30, 60, 120, 300, 600}, DisplaySettings.IDLE_CHOICES);
        assertArrayEquals(new int[] {0, 30, 60}, DisplaySettings.SCREEN_OFF_GRACE_CHOICES);
        for (int g : DisplaySettings.SCREEN_OFF_GRACE_CHOICES) assertTrue("never longer than a minute", g <= 60);
    }

    @Test public void screenTimeoutChoicesMapToMilliseconds() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        DisplaySettings d = new DisplaySettings(prefs);
        int[][] expected = {{30, 30_000}, {60, 60_000}, {120, 120_000}, {300, 300_000}, {600, 600_000}};
        for (int[] e : expected) {
            assertTrue(d.setScreenTimeoutSeconds(e[0]));
            assertEquals(e[0], d.screenTimeoutSeconds());
            assertEquals(e[1], d.screenTimeoutMs());
            assertEquals(e[0], prefs.getInt(DisplaySettings.KEY_SCREEN_TIMEOUT_SECONDS, -1));
        }
    }

    @Test public void unsupportedTimeoutsAreRefusedOrFallBack() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        DisplaySettings d = new DisplaySettings(prefs);
        try { d.setScreenTimeoutSeconds(0); fail(); } catch (IllegalArgumentException expected) { }
        try { d.setScreenTimeoutSeconds(3600); fail(); } catch (IllegalArgumentException expected) { }
        try { d.setIdleSeconds(900); fail(); } catch (IllegalArgumentException expected) { }
        try { d.setScreenOffGraceSeconds(120); fail(); } catch (IllegalArgumentException expected) { }
        try { d.setScreenOffGraceSeconds(-1); fail(); } catch (IllegalArgumentException expected) { }
        // A corrupt or old stored value never yields "never lock".
        prefs.edit().putInt(DisplaySettings.KEY_SCREEN_TIMEOUT_SECONDS, Integer.MAX_VALUE).commit();
        prefs.edit().putInt(DisplaySettings.KEY_IDLE_SECONDS, -5).commit();
        prefs.edit().putInt(DisplaySettings.KEY_SCREEN_OFF_GRACE_SECONDS, 3600).commit();
        assertEquals(120, d.screenTimeoutSeconds());
        assertEquals(120, d.idleSeconds());
        assertEquals("a grace that is not a choice locks at once", 0, d.screenOffGraceSeconds());
    }

    @Test public void idleLockNeverOutlastsTheScreenTimeout() {
        assertEquals(30, DisplaySettings.effectiveIdleSeconds(120, 30));
        assertEquals(60, DisplaySettings.effectiveIdleSeconds(60, 300));
        assertEquals(120, DisplaySettings.effectiveIdleSeconds(120, 300));
        assertEquals(30, DisplaySettings.effectiveIdleSeconds(30, 120));
        assertEquals(600, DisplaySettings.effectiveIdleSeconds(600, 600));
        DisplaySettings d = new DisplaySettings(new VaultPinTest.FakePrefs());
        d.setScreenTimeoutSeconds(300);
        d.setIdleSeconds(120);
        assertEquals(120_000L, d.idleLockMs());
        d.setScreenTimeoutSeconds(30);
        assertEquals(30_000L, d.idleLockMs());
    }

    @Test public void idleLockWithAGraceWindow() {
        // Shorter than the screen timeout: always as chosen.
        assertEquals(60, DisplaySettings.effectiveIdleSeconds(60, 120, 60, false));
        assertEquals(60, DisplaySettings.effectiveIdleSeconds(60, 120, 60, true));
        // Otherwise the screen goes off first and its grace bounds the open time: the idle lock is
        // that bound (a backstop) while the display may sleep, and never longer than chosen while
        // a review holds the display on.
        assertEquals(150, DisplaySettings.effectiveIdleSeconds(120, 120, 30, false));
        assertEquals(120, DisplaySettings.effectiveIdleSeconds(120, 120, 30, true));
        assertEquals(90, DisplaySettings.effectiveIdleSeconds(600, 30, 60, true));
        assertEquals(90, DisplaySettings.effectiveIdleSeconds(600, 30, 60, false));
        // No grace: exactly the beta4 rule (the shorter of the two), held on or not.
        for (int idle : DisplaySettings.IDLE_CHOICES) for (int screen : DisplaySettings.SCREEN_TIMEOUT_CHOICES) {
            int old = Math.min(idle, screen);
            assertEquals(old, DisplaySettings.effectiveIdleSeconds(idle, screen, 0, false));
            assertEquals(old, DisplaySettings.effectiveIdleSeconds(idle, screen, 0, true));
            for (int grace : DisplaySettings.SCREEN_OFF_GRACE_CHOICES) for (boolean held : new boolean[] {false, true}) {
                int e = DisplaySettings.effectiveIdleSeconds(idle, screen, grace, held);
                assertTrue("the vault is never open longer than screen timeout + grace", e <= screen + grace);
                assertTrue(e <= Math.max(idle, screen + grace));
                if (held) assertTrue("held on: never past the chosen idle lock", e <= idle);
            }
        }
        DisplaySettings d = new DisplaySettings(new VaultPinTest.FakePrefs());
        d.setScreenOffGraceSeconds(60);
        assertEquals(180_000L, d.idleLockMs(false));
        assertEquals(120_000L, d.idleLockMs(true));
    }

    // ---------------------------------------------------------------- lock after screen off

    @Test public void graceChoicesPersist() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        for (int g : DisplaySettings.SCREEN_OFF_GRACE_CHOICES) {
            assertTrue(new DisplaySettings(prefs).setScreenOffGraceSeconds(g));
            assertEquals(g, new DisplaySettings(prefs).screenOffGraceSeconds());
            assertEquals(g, prefs.getInt(DisplaySettings.KEY_SCREEN_OFF_GRACE_SECONDS, -1));
        }
        assertEquals("Immediately", DisplaySettings.graceLabel(0));
        assertEquals("30 seconds", DisplaySettings.graceLabel(30));
        assertEquals("1 minute", DisplaySettings.graceLabel(60));
        assertEquals("Anyone who picks up the phone in this time can open it without the PIN. Signing still needs your approval on screen.",
                DisplaySettings.GRACE_WARNING);
    }

    // ---------------------------------------------------------------- brightness

    @Test public void brightnessMapsOntoTheSystemRange() {
        assertEquals(3, DisplaySettings.systemBrightness(1));
        assertEquals(128, DisplaySettings.systemBrightness(50));
        assertEquals(255, DisplaySettings.systemBrightness(100));
        assertEquals("clamped, never 0 (a black screen)", 3, DisplaySettings.systemBrightness(0));
        assertEquals(3, DisplaySettings.systemBrightness(-40));
        assertEquals(255, DisplaySettings.systemBrightness(1000));
        int last = 0;
        for (int p = 1; p <= 100; p++) {
            int v = DisplaySettings.systemBrightness(p);
            assertTrue("1..255", v >= 1 && v <= 255);
            assertTrue("monotonic", v >= last);
            last = v;
            assertEquals("the slider shows what it set", p, DisplaySettings.percentForSystem(v));
            assertEquals(v / 255f, DisplaySettings.windowBrightness(p), 1e-6f);
        }
        assertEquals(1, DisplaySettings.percentForSystem(0));
        assertEquals(100, DisplaySettings.percentForSystem(400));
    }

    @Test public void brightnessPersists() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        DisplaySettings d = new DisplaySettings(prefs);
        assertFalse(d.brightnessChosen());
        assertEquals(50, d.brightnessPercent());
        assertTrue(d.setBrightnessPercent(70));
        DisplaySettings again = new DisplaySettings(prefs); // re-applied on start from what was saved
        assertTrue(again.brightnessChosen());
        assertEquals(70, again.brightnessPercent());
        assertFalse(again.brightnessAuto());
        assertEquals(DisplaySettings.BRIGHTNESS_MODE_MANUAL, again.systemBrightnessMode());

        assertTrue(again.setBrightnessAuto(true));
        assertTrue(new DisplaySettings(prefs).brightnessAuto());
        assertEquals("Automatic keeps the slider's position", 70, new DisplaySettings(prefs).brightnessPercent());
        assertEquals(DisplaySettings.BRIGHTNESS_MODE_AUTOMATIC, new DisplaySettings(prefs).systemBrightnessMode());

        assertTrue("moving the slider is a manual choice", new DisplaySettings(prefs).setBrightnessPercent(20));
        assertFalse(new DisplaySettings(prefs).brightnessAuto());
        assertEquals(20, new DisplaySettings(prefs).brightnessPercent());

        assertTrue(new DisplaySettings(prefs).setBrightnessPercent(0));
        assertEquals("stored clamped", 1, prefs.getInt(DisplaySettings.KEY_BRIGHTNESS_PERCENT, -1));
        prefs.edit().putInt(DisplaySettings.KEY_BRIGHTNESS_PERCENT, 999).commit();
        assertEquals(100, new DisplaySettings(prefs).brightnessPercent());
    }

    @Test public void brightnessIsAppliedAsDeviceOwnerAndOnEveryStart() throws Exception {
        String provisioning = SourceGuard.source("ApplianceProvisioning.java");
        assertTrue(provisioning.contains("Settings.System.SCREEN_BRIGHTNESS_MODE"));
        assertTrue(provisioning.contains("Settings.System.SCREEN_BRIGHTNESS,"));
        assertTrue("re-applied on every provisioning pass, once chosen",
                provisioning.contains("if (display.brightnessChosen()) applyBrightness(context, policy, display.brightnessPercent(), display.brightnessAuto());"));
        String apply = SourceGuard.definition("private void applyBrightness(int percent, boolean auto) {");
        assertTrue("falls back to the window's own brightness", apply.contains("setWindowBrightness(auto ? WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_NONE : DisplaySettings.windowBrightness(percent));"));
        assertTrue("applied with the other display settings on start",
                SourceGuard.definition("private void applyDisplaySettings() {").contains("applyBrightness();"));
    }

    @Test public void failedCommitIsReported() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        prefs.failAtCommit = 1;
        assertFalse(new DisplaySettings(prefs).setScreenTimeoutSeconds(120));
    }

    @Test public void durationLabels() {
        assertEquals("30 seconds", DisplaySettings.durationLabel(30));
        assertEquals("1 minute", DisplaySettings.durationLabel(60));
        assertEquals("2 minutes", DisplaySettings.durationLabel(120));
        assertEquals("5 minutes", DisplaySettings.durationLabel(300));
        assertEquals("10 minutes", DisplaySettings.durationLabel(600));
        assertEquals("90 seconds", DisplaySettings.durationLabel(90));
    }

    // ---------------------------------------------------------------- haptics

    @Test public void hapticsDefaultOnAndPersist() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        assertTrue(new DisplaySettings(prefs).haptics());
        assertTrue(new DisplaySettings(prefs).setHaptics(false));
        assertFalse(new DisplaySettings(prefs).haptics()); // a fresh instance reads it back
        assertEquals(Boolean.FALSE, prefs.map.get(DisplaySettings.KEY_HAPTICS));
        assertTrue(new DisplaySettings(prefs).setHaptics(true));
        assertTrue(new DisplaySettings(prefs).haptics());
    }

    // ---------------------------------------------------------------- text scale

    @Test public void oneScaleFactorDrivesEveryTextSize() {
        assertEquals(1f, DisplaySettings.textScale(false), 0f);
        assertEquals(1.2f, DisplaySettings.textScale(true), 0f);
        float large = DisplaySettings.textScale(true);
        // Base sizes used across the screens, and the large-text result (rounded to 0.5 sp).
        float[][] cases = {{8, 9.5f}, {10, 12}, {12, 14.5f}, {13, 15.5f}, {14, 17}, {15, 18},
                {16, 19}, {18, 21.5f}, {20, 24}, {22, 26.5f}, {23, 27.5f}, {28, 33.5f}};
        for (float[] c : cases) assertEquals("base " + c[0], c[1], DisplaySettings.scaledSp(c[0], large), 0f);
        for (float[] c : cases) assertEquals(c[0], DisplaySettings.scaledSp(c[0], 1f), 0f);
        // Ordering is preserved: a heading stays larger than body text, body larger than labels.
        assertTrue(DisplaySettings.scaledSp(28, large) > DisplaySettings.scaledSp(16, large));
        assertTrue(DisplaySettings.scaledSp(16, large) > DisplaySettings.scaledSp(13, large));
        assertEquals(0f, DisplaySettings.scaledSp(0, large), 0f);
    }

    @Test public void largeTextPersists() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        assertTrue(new DisplaySettings(prefs).setLargeText(true));
        assertTrue(new DisplaySettings(prefs).largeText());
        assertEquals(Boolean.TRUE, prefs.map.get("large_text")); // the stored key name is fixed: existing settings keep working
    }

    /**
     * Large text is one factor in VaultTheme: a raw TextView#setTextSize anywhere else would
     * escape it. (SeedQrView sizes a Paint to its grid cells and is exempt by design.)
     */
    @Test public void noScreenSetsATextSizeOutsideTheTheme() throws Exception {
        try (DirectoryStream<Path> files = Files.newDirectoryStream(SourceGuard.dir(), "*.java")) {
            for (Path f : files) {
                String name = f.getFileName().toString();
                if (name.equals("VaultTheme.java") || name.equals("SeedQrView.java")) continue;
                String src = new String(Files.readAllBytes(f), StandardCharsets.UTF_8);
                assertEquals(name + " calls setTextSize directly; use VaultTheme.size", -1, src.indexOf(".setTextSize("));
                assertFalse(name + " branches on largeText for a size; VaultTheme scales it",
                        src.matches("(?s).*largeText \\? \\d+.*"));
            }
        }
    }
}
