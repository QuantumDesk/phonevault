package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Source guard for a phone-only failure the JVM cannot reproduce: a request refused on the USB
 * reader thread (e.g. ERC-20 calldata with a trailing byte) released the approval slot with a
 * direct {@code getWindow().clearFlags(...)}. Off the UI thread that throws
 * CalledFromWrongThreadException mid-relayout, which ended the USB session before the refusal
 * was sent (the host timed out) and left the window permanently undrawn (blank screen, empty
 * uiautomator dump). Window flags may only change inside {@code keepScreenOn}, which posts to the
 * UI thread.
 */
public class MainActivityThreadingTest {

    private static String source() throws Exception {
        for (String path : new String[] {
                "src/main/java/dev/phonevault/signer/MainActivity.java",
                "app/src/main/java/dev/phonevault/signer/MainActivity.java"}) {
            Path p = Paths.get(path);
            if (Files.exists(p)) return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
        }
        fail("MainActivity.java not found from " + Paths.get("").toAbsolutePath());
        return null;
    }

    @Test public void windowFlagsChangeOnlyThroughTheUiThreadHelper() throws Exception {
        String src = source();
        int start = src.indexOf("private void keepScreenOn(boolean on) {");
        assertTrue("keepScreenOn helper is missing", start >= 0);
        int end = src.indexOf("\n    }\n", start);
        assertTrue(end > start);
        String helper = src.substring(start, end);
        assertTrue("keepScreenOn must post to the UI thread", helper.contains("runOnUiThread("));

        String rest = src.substring(0, start) + src.substring(end);
        for (String banned : new String[] {"FLAG_KEEP_SCREEN_ON",
                "getWindow().addFlags(", "getWindow().clearFlags(", "getWindow().setFlags("}) {
            assertEquals(banned + " outside keepScreenOn (window flags are UI-thread only)",
                    -1, rest.indexOf(banned));
        }
    }

    @Test public void refusalPathReleasesTheSlotThroughTheHelper() throws Exception {
        String src = source();
        int start = src.indexOf("private void finishApproval(ApprovalDecision owner) {");
        assertTrue(start >= 0);
        String body = src.substring(start, src.indexOf("\n    }\n", start));
        assertTrue("finishApproval runs on the USB reader for refused requests",
                body.contains("keepScreenOn(false)"));
        assertEquals(-1, body.indexOf("getWindow()"));
    }
}
