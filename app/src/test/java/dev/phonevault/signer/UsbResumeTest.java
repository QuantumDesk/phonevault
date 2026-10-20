package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * The stale-accessory fix (phone side): a USB session the vault closed while the framework still
 * has the accessory attached is reopened, so a Mac that comes back finds a reader on the same
 * endpoints without a replug. The phone-only paths are source guards (no UsbManager on the JVM).
 */
public class UsbResumeTest {
    @Test public void onlyTheFilteredHostIdentityIsReopened() {
        assertTrue(AccessoryTransport.isOurHost("PhoneVault", "EVM Signer"));
        assertFalse(AccessoryTransport.isOurHost("PhoneVault", "Other"));
        assertFalse(AccessoryTransport.isOurHost("phonevault", "EVM Signer"));
        assertFalse(AccessoryTransport.isOurHost(null, null));
        assertEquals(null, AccessoryTransport.ourHost(null));
    }

    @Test public void filterAndMatcherAgree() throws Exception {
        String filter = new String(java.nio.file.Files.readAllBytes(SourceGuard.dir()
                .resolve("../../../../res/xml/accessory_filter.xml").normalize()), java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(filter.contains("manufacturer=\"" + AccessoryTransport.HOST_MANUFACTURER + "\""));
        assertTrue(filter.contains("model=\"" + AccessoryTransport.HOST_MODEL + "\""));
    }

    @Test public void lockReopensTheAttachedAccessory() throws Exception {
        String lock = SourceGuard.definition("private void lock() {");
        assertTrue("lock() closes the session inside stateLock", lock.indexOf("staleTransport.close()") > 0);
        assertTrue("…and reopens the still-attached accessory after the gate is up",
                lock.indexOf("resumeAttachedAccessory(") > lock.indexOf("showPinGate(null)"));
    }

    @Test public void resumeNeverAsksForPermissionAndNeverRunsWhileDeactivated() throws Exception {
        String resume = SourceGuard.definition("private void resumeAttachedAccessory(int attemptsLeft) {");
        assertTrue(resume.contains("if (!operational || transport != null"));
        assertTrue(resume.contains("hasPermission("));
        assertEquals("no permission prompt anywhere", -1, SourceGuard.code(SourceGuard.mainActivity()).indexOf("requestPermission("));
        assertTrue("goes through the ordinary attach path (gate while locked)", resume.contains("handleIntent("));
    }

    @Test public void aResumedSessionDoesNotHoldTheScreenOn() throws Exception {
        String handle = SourceGuard.definition("private void handleIntent(Intent intent, boolean resumed) {");
        assertTrue(handle.contains("if (!resumed) keepScreenOn(true);"));
    }
}
