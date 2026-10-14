package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Map;

/**
 * Source guard for a phone-only failure the JVM cannot reproduce: a request refused on the USB
 * reader thread (e.g. ERC-20 calldata with a trailing byte) releases the approval slot there. A
 * direct {@code getWindow().clearFlags(...)} off the UI thread throws
 * CalledFromWrongThreadException mid-relayout, which ends the USB session before the refusal is
 * sent (the host times out) and leaves the window permanently undrawn (blank screen, empty
 * uiautomator dump). Window flags may only change inside {@code keepScreenOn}, which posts to the
 * UI thread. Scans every class of the package, so moving screen code cannot drop the check.
 */
public class MainActivityThreadingTest {
    private static final String HELPER = "private void keepScreenOn(boolean on) {";

    @Test public void windowFlagsChangeOnlyThroughTheUiThreadHelper() throws Exception {
        String home = SourceGuard.fileWith(HELPER);
        boolean sawHelper = false;
        for (Map.Entry<String, String> f : SourceGuard.all().entrySet()) {
            String src = f.getValue();
            if (f.getKey().equals(home)) {
                int start = src.indexOf(HELPER);
                int end = src.indexOf("\n    }\n", start);
                assertTrue(end > start);
                String helper = src.substring(start, end);
                assertTrue("keepScreenOn must post to the UI thread", helper.contains("runOnUiThread("));
                src = src.substring(0, start) + src.substring(end);
                sawHelper = true;
            }
            for (String banned : new String[] {"FLAG_KEEP_SCREEN_ON",
                    "getWindow().addFlags(", "getWindow().clearFlags(", "getWindow().setFlags("}) {
                assertEquals(banned + " in " + f.getKey() + " outside keepScreenOn (window flags are UI-thread only)",
                        -1, src.indexOf(banned));
            }
        }
        assertTrue(sawHelper);
    }

    @Test public void refusalPathReleasesTheSlotThroughTheHelper() throws Exception {
        String body = SourceGuard.definition("private void finishApproval(ApprovalDecision owner) {");
        assertTrue("finishApproval runs on the USB reader for refused requests",
                body.contains("keepScreenOn(false)"));
        assertEquals(-1, body.indexOf("getWindow()"));
    }
}
