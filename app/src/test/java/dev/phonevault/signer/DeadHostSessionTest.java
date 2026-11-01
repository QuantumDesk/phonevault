package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A host that gave up (timed out, killed, port reset) while the phone held or showed its request
 * (Pixel 6a beta4, release build): f_accessory's open descriptor is left unable to write (ENODEV)
 * while reads may go on. The session must notice (a failed write, or the write probe), end as a
 * session that ended by itself (so MainActivity reopens the still-attached accessory), and hand on
 * a request it read but could not answer.
 */
public class DeadHostSessionTest {

    private static final class Recorder implements AccessoryTransport.Listener {
        final List<JSONObject> requests = Collections.synchronizedList(new ArrayList<>());
        final List<String> reasons = Collections.synchronizedList(new ArrayList<>());
        final CountDownLatch disconnected = new CountDownLatch(1);
        final CountDownLatch requested = new CountDownLatch(1);
        @Override public void onConnected(AccessoryTransport s) { }
        @Override public void onRequest(AccessoryTransport s, JSONObject r) { requests.add(r); requested.countDown(); }
        @Override public void onDisconnected(AccessoryTransport s, String reason) { reasons.add(reason); disconnected.countDown(); }
    }

    private static final class Fd implements Closeable {
        final AtomicInteger closes = new AtomicInteger();
        @Override public void close() { closes.incrementAndGet(); }
    }

    /** An accessory whose writes fail with ENODEV once the bus has dropped (f_accessory's disconnected flag). */
    private static final class DeadAfterDrop extends OutputStream {
        final AtomicBoolean dropped = new AtomicBoolean();
        final ByteArrayOutputStream written = new ByteArrayOutputStream();
        @Override public synchronized void write(int b) throws IOException {
            if (dropped.get()) throw new IOException("write failed: ENODEV (No such device)");
            written.write(b);
        }
        @Override public synchronized void write(byte[] b, int off, int len) throws IOException {
            if (dropped.get()) throw new IOException("write failed: ENODEV (No such device)");
            written.write(b, off, len);
        }
    }

    private static byte[] line(String id) throws Exception {
        return (new JSONObject().put("id", id).put("method", "getAddress").toString() + "\n").getBytes(StandardCharsets.UTF_8);
    }

    @Test public void aWriteToAHostThatWentAwayEndsTheSessionAsEndedByItself() throws Exception {
        Fd fd = new Fd();
        Recorder listener = new Recorder();
        DeadAfterDrop out = new DeadAfterDrop();
        PipedOutputStream host = new PipedOutputStream();
        AccessoryTransport t = AccessoryTransport.openForTest(fd, new PipedInputStream(host, 65536), out, listener);
        t.start();
        host.write(line("held"));
        assertTrue(listener.requested.await(5, TimeUnit.SECONDS));
        assertEquals(AccessoryTransport.End.OPEN, t.end());
        assertFalse(t.endedByItself());

        out.dropped.set(true); // the host timed out / was killed and the bus reset under the session
        assertTrue(t.send(new JSONObject().put("id", "held").put("status", "rejected"))); // queued, never blocks
        assertTrue("the failed write is noticed", listener.disconnected.await(5, TimeUnit.SECONDS));
        assertEquals(AccessoryTransport.End.WRITE_FAILED, t.end());
        assertTrue("MainActivity reopens after this", t.endedByItself());
        assertTrue(listener.reasons.get(0), listener.reasons.get(0).contains("ENODEV"));
        assertTrue(t.isClosed());
        assertEquals("the descriptor is released (the accessory can be opened again)", 1, fd.closes.get());
        assertFalse(t.send(new JSONObject().put("id", "late")));
        host.close();
    }

    @Test public void aRequestReadOnAStaleDescriptorIsCarriedNotAnswered() throws Exception {
        Fd fd = new Fd();
        Recorder listener = new Recorder();
        AtomicBoolean writable = new AtomicBoolean(true);
        PipedOutputStream host = new PipedOutputStream();
        AccessoryTransport t = AccessoryTransport.openForTest(fd, new PipedInputStream(host, 65536), new ByteArrayOutputStream(),
                listener, writable::get);
        t.start();
        assertTrue(t.writable());
        writable.set(false); // the bus dropped: reads still work, writes would fail
        assertFalse(t.writable());
        host.write(line("next-client"));
        assertTrue(listener.disconnected.await(5, TimeUnit.SECONDS));
        assertEquals("never handed to the router on a session that cannot answer it", 0, listener.requests.size());
        assertEquals(AccessoryTransport.End.STALE, t.end());
        assertTrue(t.endedByItself());
        JSONObject carried = t.takeCarried();
        assertEquals("next-client", carried.getString("id"));
        assertNull("handed on once", t.takeCarried());
        assertEquals(1, fd.closes.get());
        assertFalse("closed: not writable", t.writable());
        host.close();
    }

    @Test public void failStaleEndsAnOpenSessionOnce() throws Exception {
        Fd fd = new Fd();
        Recorder listener = new Recorder();
        PipedOutputStream host = new PipedOutputStream();
        AccessoryTransport t = AccessoryTransport.openForTest(fd, new PipedInputStream(host), new ByteArrayOutputStream(), listener);
        t.start();
        t.failStale("USB bus was reset under the session");
        assertTrue(listener.disconnected.await(5, TimeUnit.SECONDS));
        assertEquals(AccessoryTransport.End.STALE, t.end());
        assertNull("nothing read: nothing to carry", t.takeCarried());
        t.failStale("again");
        t.close();
        assertEquals(1, listener.reasons.size());
        assertEquals(1, fd.closes.get());
        host.close();
    }

    @Test public void unplugAndLocalClosesAreNotEndsOfItsOwn() throws Exception {
        InputStream idle = new PipedInputStream(new PipedOutputStream());
        AccessoryTransport local = AccessoryTransport.openForTest(new Fd(), idle, new ByteArrayOutputStream(), new Recorder());
        local.close();
        assertEquals(AccessoryTransport.End.LOCAL, local.end());
        assertFalse(local.endedByItself());

        Recorder r = new Recorder();
        AccessoryTransport unplugged = AccessoryTransport.openForTest(new Fd(), new PipedInputStream(new PipedOutputStream()), new ByteArrayOutputStream(), r);
        unplugged.detached();
        assertEquals(AccessoryTransport.End.DETACHED, unplugged.end());
        assertFalse("an unplugged cable is never reopened", unplugged.endedByItself());
        assertFalse("no listener callback (the receiver reports it)", r.disconnected.await(100, TimeUnit.MILLISECONDS));

        AccessoryTransport refused = AccessoryTransport.openForTest(new Fd(), new PipedInputStream(new PipedOutputStream()), new ByteArrayOutputStream(), new Recorder());
        refused.closeAfter(new JSONObject().put("id", "x").put("status", "error"));
        assertEquals(AccessoryTransport.End.LOCAL, refused.end());

        for (AccessoryTransport.End e : AccessoryTransport.End.values()) {
            boolean own = e == AccessoryTransport.End.READ_ENDED || e == AccessoryTransport.End.READ_FAILED
                    || e == AccessoryTransport.End.WRITE_FAILED || e == AccessoryTransport.End.STALE;
            assertEquals(e.name(), own, AccessoryTransport.endedByItself(e));
        }
    }

    @Test public void aMalformedLineIsAnEndOfItsOwn() throws Exception {
        Recorder r = new Recorder();
        AccessoryTransport t = AccessoryTransport.openForTest(new Fd(),
                new java.io.ByteArrayInputStream("{not json\n".getBytes(StandardCharsets.UTF_8)), new ByteArrayOutputStream(), r);
        t.start();
        assertTrue(r.disconnected.await(5, TimeUnit.SECONDS));
        assertEquals(AccessoryTransport.End.READ_FAILED, t.end());
        assertTrue(t.endedByItself());
    }

    /** MainActivity: what it does with a session that ended by itself, and with a held request whose host left. */
    @Test public void activityWiring() throws Exception {
        String disc = SourceGuard.definition("public void onDisconnected(AccessoryTransport source, String reason) {");
        assertTrue(disc.contains("final boolean byItself = source.endedByItself();"));
        assertTrue("a request it could not answer is handed on", disc.contains("final JSONObject carried = source.takeCarried();"));
        assertTrue("held request dropped with the note", disc.contains("if (droppedHeld && byItself) gateUsbNote = MAC_STOPPED_WAITING;"));
        assertTrue("the accessory is opened again, without a replug", disc.contains("if (byItself) reopenAfterOwnEnd(carried);"));
        assertTrue("an undecided review says nothing was signed",
                disc.contains("if (undecided && byItself)") && disc.contains("Nothing was signed."));
        assertTrue(MainActivity.MAC_STOPPED_WAITING.contains("stopped waiting") && MainActivity.MAC_STOPPED_WAITING.contains("Nothing was signed"));

        String reopen = SourceGuard.definition("private void reopenAfterOwnEnd(JSONObject carried) {");
        assertTrue("bounded", reopen.contains("if (usbSelfReopens >= MAX_SELF_REOPENS) {"));
        assertTrue(reopen.contains("resumeAttachedAccessory(USB_RESUME_ATTEMPTS)"));

        String dispatch = SourceGuard.definition("private void dispatchHeldRequest() {");
        assertTrue("a held request whose host can no longer be answered is not reviewed",
                dispatch.indexOf("if (!held.source.writable()) {") < dispatch.indexOf("onRequest(held.source, held.request)"));
        assertTrue(dispatch.contains("held.source.failStale("));

        String carried = SourceGuard.definition("private void dispatchCarried(AccessoryTransport opened) {");
        assertTrue("only within the window", carried.contains("SystemClock.elapsedRealtime() > carriedUntil"));
        assertTrue("through the ordinary path (held behind the lock, or reviewed)", carried.contains("onRequest(opened, carried)"));
        String handle = SourceGuard.definition("private void handleIntent(Intent intent, boolean resumed) {");
        assertEquals("only onto a session reopened on the same attachment, locked and unlocked", 2,
                handle.split("if \\(resumed\\) dispatchCarried\\(opened\\);", -1).length - 1);
        assertTrue("a fresh attach while a request waited: its host gave up",
                handle.contains("if (hadHeld && !resumed) gateUsbNote = MAC_STOPPED_WAITING;"));
        assertTrue(handle.contains("Your Mac stopped waiting"));

        String state = SourceGuard.mainActivity();
        assertTrue("USB_STATE: a bus that came back under an open session is checked",
                state.contains("if (!live.writable()) live.failStale(\"USB bus was reset under the session\");"));
        assertTrue("unplug is told apart", state.contains("live.detached();"));
    }

    @Test public void theProbeIsAZeroLengthWriteOnTheRealDescriptor() throws Exception {
        String src = SourceGuard.source("AccessoryTransport.java");
        assertTrue(src.contains("android.system.Os.write(fd, new byte[0], 0, 0);"));
        assertTrue("checked before a request is handed on", src.indexOf("if (!probe.writable()) {") < src.indexOf("listener.onRequest(this, request);"));
        assertSame(AccessoryTransport.End.OPEN, AccessoryTransport.openForTest(new Fd(), new java.io.ByteArrayInputStream(new byte[0]),
                new ByteArrayOutputStream(), new Recorder()).end());
    }
}
