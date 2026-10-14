package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Architecture guards for MainActivity's split into screen classes (VaultHost): the wallet key and
 * identity are still published only under MainActivity's stateLock, the screens share the
 * activity's lock, threads and handler instead of making their own, and the activity builds the
 * screens only after everything they borrow exists. Package-wide, so new screen classes are covered.
 */
public class ScreenSplitTest {

    /** VaultHost calls that publish or drop key material / wallet identity, or read the key to sign with. */
    private static final Pattern UNDER_LOCK = Pattern.compile(
            "\\b(?:host|app)\\.(publishNewWallet|publishAccount|relabelActiveAccount|clearCredentials|markWalletUnloaded|markBackupVerified|signingKey)\\(");

    @Test public void walletPublishHappensOnlyUnderStateLock() throws Exception {
        int calls = 0;
        for (Map.Entry<String, String> f : SourceGuard.all().entrySet()) {
            String code = SourceGuard.code(f.getValue());
            Matcher m = UNDER_LOCK.matcher(code);
            while (m.find()) {
                calls++;
                assertTrue(f.getKey() + ": " + m.group(1) + " outside synchronized (stateLock) at "
                        + code.substring(Math.max(0, m.start() - 80), m.start()).replace('\n', ' '),
                        insideStateLock(code, m.start()));
            }
        }
        assertTrue("the guard sees the publish sites (" + calls + ")", calls >= 15);
    }

    /** True when {@code at} is inside a {@code synchronized (stateLock) { … }} block (string literals skipped). */
    static boolean insideStateLock(String code, int at) {
        Deque<Boolean> blocks = new ArrayDeque<>();
        boolean nextIsLock = false;
        for (int i = 0; i < at; i++) {
            char c = code.charAt(i);
            if (c == '"' || c == '\'') {
                for (i++; i < at && code.charAt(i) != c; i++) if (code.charAt(i) == '\\') i++;
                continue;
            }
            if (code.startsWith("synchronized (stateLock)", i)) nextIsLock = true;
            if (c == '{') { blocks.push(nextIsLock); nextIsLock = false; }
            else if (c == '}' && !blocks.isEmpty()) blocks.pop();
        }
        return blocks.contains(Boolean.TRUE);
    }

    @Test public void theLockScannerWorks() {
        String code = "void a() { synchronized (stateLock) { x(); if (y) { HERE1 } } HERE2 } \"synchronized (stateLock) {\" HERE3";
        assertTrue(insideStateLock(code, code.indexOf("HERE1")));
        assertTrue(!insideStateLock(code, code.indexOf("HERE2")));
        assertTrue(!insideStateLock(code, code.indexOf("HERE3")));
    }

    /** Only MainActivity holds the signing-key field; the screens and the router reach it through VaultHost. */
    @Test public void onlyMainActivityAssignsTheSigningKey() throws Exception {
        int checked = 0;
        for (Map.Entry<String, String> f : SourceGuard.all().entrySet()) {
            String name = f.getKey();
            if (!name.endsWith("Screens.java") && !name.equals("Pages.java") && !name.equals("RequestRouter.java")) continue;
            checked++;
            String code = SourceGuard.code(f.getValue());
            assertEquals(name + " assigns a credentials field", -1, code.indexOf("credentials = "));
            assertEquals(name + " holds a Credentials field", -1, code.indexOf("private Credentials"));
        }
        assertTrue(checked >= 8);
    }

    /**
     * One lock, one crypto thread, one UI handler: a screen class with its own would no longer be
     * serialized with lock(), and onDestroy would not clear its callbacks.
     */
    @Test public void screensShareTheActivitysLockThreadsAndHandler() throws Exception {
        for (Map.Entry<String, String> f : SourceGuard.all().entrySet()) {
            String name = f.getKey(), code = SourceGuard.code(f.getValue());
            if (!name.endsWith("Screens.java") && !name.equals("Pages.java") && !name.equals("RequestRouter.java")) continue;
            assertEquals(name + " makes its own UI handler", -1, code.indexOf("new Handler("));
            assertEquals(name + " makes its own lock", -1, code.indexOf("stateLock = new"));
            if (!name.equals("RequestRouter.java")) assertEquals(name + " makes its own executor", -1, code.indexOf("Executors.new"));
        }
        // RequestRouter's one executor is the attestation thread, never used for signing.
        String router = SourceGuard.code(SourceGuard.source("RequestRouter.java"));
        assertEquals(1, router.split("Executors\\.new", -1).length - 1);
        assertTrue(router.contains("private final ExecutorService attestExecutor = Executors.newSingleThreadExecutor();"));
    }

    /**
     * The screens copy the activity's lock, executor, handler, random and pages in their
     * constructors: those fields must be initialized before the screens are built.
     */
    @Test public void screensAreBuiltAfterWhatTheyBorrow() throws Exception {
        String src = SourceGuard.mainActivity();
        int host = src.indexOf("private final ScreenHost host = new ScreenHost();");
        assertTrue(host > 0);
        for (String field : new String[] {"private final Object stateLock", "private final ExecutorService cryptoExecutor",
                "private final Handler ui", "private final SecureRandom random", "private final Pages pages"}) {
            int at = src.indexOf(field);
            assertTrue(field + " declared", at > 0);
            assertTrue(field + " must come before the screens", at < host);
        }
        Matcher screens = Pattern.compile("new (\\w+Screens|RequestRouter)\\(").matcher(src);
        int built = 0;
        while (screens.find()) {
            built++;
            if (screens.start() < host) fail(screens.group(1) + " is built before ScreenHost");
        }
        assertTrue(built >= 7);
    }
}
