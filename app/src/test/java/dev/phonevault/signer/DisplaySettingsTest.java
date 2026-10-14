package dev.phonevault.signer;

import static org.junit.Assert.*;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class DisplaySettingsTest {

    // ---------------------------------------------------------------- screen timeout / idle lock

    @Test public void defaultsKeepTheLongStandingBehaviour() {
        DisplaySettings d = new DisplaySettings(new VaultPinTest.FakePrefs());
        assertEquals(60, d.screenTimeoutSeconds());
        assertEquals(60_000, d.screenTimeoutMs());
        assertEquals(120, d.idleSeconds());
        // Idle lock 2 min, screen 1 min: the vault locks after 1 min either way.
        assertEquals(60_000L, d.idleLockMs());
        assertFalse(d.largeText());
        assertTrue(d.haptics());
    }

    @Test public void screenTimeoutChoicesMapToMilliseconds() {
        VaultPinTest.FakePrefs prefs = new VaultPinTest.FakePrefs();
        DisplaySettings d = new DisplaySettings(prefs);
        int[][] expected = {{30, 30_000}, {60, 60_000}, {120, 120_000}, {300, 300_000}};
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
        try { d.setIdleSeconds(300); fail(); } catch (IllegalArgumentException expected) { }
        // A corrupt or old stored value never yields "never lock".
        prefs.edit().putInt(DisplaySettings.KEY_SCREEN_TIMEOUT_SECONDS, Integer.MAX_VALUE).commit();
        prefs.edit().putInt(DisplaySettings.KEY_IDLE_SECONDS, -5).commit();
        assertEquals(60, d.screenTimeoutSeconds());
        assertEquals(120, d.idleSeconds());
    }

    @Test public void idleLockNeverOutlastsTheScreenTimeout() {
        assertEquals(30, DisplaySettings.effectiveIdleSeconds(120, 30));
        assertEquals(60, DisplaySettings.effectiveIdleSeconds(60, 300));
        assertEquals(120, DisplaySettings.effectiveIdleSeconds(120, 300));
        assertEquals(30, DisplaySettings.effectiveIdleSeconds(30, 120));
        DisplaySettings d = new DisplaySettings(new VaultPinTest.FakePrefs());
        d.setScreenTimeoutSeconds(300);
        d.setIdleSeconds(120);
        assertEquals(120_000L, d.idleLockMs());
        d.setScreenTimeoutSeconds(30);
        assertEquals(30_000L, d.idleLockMs());
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
