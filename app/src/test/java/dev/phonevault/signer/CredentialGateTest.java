package dev.phonevault.signer;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Source guard for a phone-only race: on a cold start after the boot PIN, onCreate and onResume
 * both show the credential gate. The second call replaced the boot attempt's loading screen with
 * the locked page and queued the system PIN prompt while Android's lock screen was still going
 * away, so the vault asked for the PIN a second time (credentialtest, rung 4b, 2026-10-11).
 */
public class CredentialGateTest {
    private static String gate() throws Exception {
        for (String path : new String[] {
                "src/main/java/dev/phonevault/signer/MainActivity.java",
                "app/src/main/java/dev/phonevault/signer/MainActivity.java"}) {
            Path p = Paths.get(path);
            if (!Files.exists(p)) continue;
            String src = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            int start = src.indexOf("private void showCredentialGate(int s) {");
            assertTrue(start >= 0);
            return src.substring(start, src.indexOf("\n    }\n", start));
        }
        fail("MainActivity.java not found from " + Paths.get("").toAbsolutePath());
        return null;
    }

    @Test public void pendingBootAttemptIsNotReplacedByASecondGate() throws Exception {
        String gate = gate();
        int guard = gate.indexOf("if (bootAttemptSession == s) return;");
        assertTrue("showCredentialGate must return while this session's boot attempt is pending", guard >= 0);
        assertTrue("the guard comes before any screen or prompt", guard < gate.indexOf("showLoading(")
                && guard < gate.indexOf("promptUnlock("));
        assertTrue(gate.contains("bootAttemptSession = s;"));
        // The attempt releases the guard on every exit, before it can fall back to the gate.
        int release = gate.indexOf("bootAttemptSession = -1;\n                    silentUnlockAttempt = true;");
        assertTrue(release >= 0 && release < gate.indexOf("showCredentialGate(session.get())"));
        assertTrue(gate.contains("if (s != session.get() || unlocked) { bootAttemptSession = -1; return; }"));
    }
}
