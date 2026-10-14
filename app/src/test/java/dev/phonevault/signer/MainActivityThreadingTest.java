package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Source guard for a phone-only failure the JVM cannot reproduce: a request refused on the USB
 * reader thread (e.g. ERC-20 calldata with a trailing byte) releases the approval slot there. A
 * direct {@code getWindow().clearFlags(...)} off the UI thread throws
 * CalledFromWrongThreadException mid-relayout, which ends the USB session before the refusal is
 * sent (the host times out) and leaves the window permanently undrawn (blank screen, empty
 * uiautomator dump). Window flags may only change inside {@code keepScreenOn}, which posts to the
 * UI thread.
 */
public class MainActivityThreadingTest {

    private static String source() throws Exception { return SourceGuard.mainActivity(); }

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
