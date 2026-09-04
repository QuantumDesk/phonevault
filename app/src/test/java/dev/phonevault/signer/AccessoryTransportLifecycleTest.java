package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Resource-release behaviour of a USB session: every failure ends it exactly once, fully. */
public class AccessoryTransportLifecycleTest {

    private static final class Fd implements Closeable {
        final AtomicInteger closes = new AtomicInteger();
        @Override public void close() { closes.incrementAndGet(); }
    }

    private static final class Recorder implements AccessoryTransport.Listener {
        final List<String> disconnects = new ArrayList<>();
        final List<JSONObject> requests = new ArrayList<>();
        final CountDownLatch disconnected = new CountDownLatch(1);
        int connected;
        @Override public synchronized void onConnected(AccessoryTransport s) { connected++; }
        @Override public synchronized void onRequest(AccessoryTransport s, JSONObject r) { requests.add(r); }
        @Override public synchronized void onDisconnected(AccessoryTransport s, String reason) {
            disconnects.add(reason);
            disconnected.countDown();
        }
    }

    private static InputStream bytes(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test public void malformedRequestEndsSessionOnceAndReleasesDescriptor() throws Exception {
        Fd fd = new Fd();
        Recorder listener = new Recorder();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        AccessoryTransport t = AccessoryTransport.openForTest(fd, bytes("{not json\n"), out, listener);
        t.start();
        assertTrue(listener.disconnected.await(5, TimeUnit.SECONDS));
        Thread.sleep(50); // let the executor thread finish
        assertEquals(1, listener.connected);
        assertEquals(0, listener.requests.size());
        assertEquals("listener told exactly once", 1, listener.disconnects.size());
        assertEquals("descriptor closed exactly once", 1, fd.closes.get());
        assertTrue(t.isClosed());
        // A late send after failure is a silent no-op — nothing is written to a dead host.
        t.send(new JSONObject().put("id", "x"));
        assertEquals(0, out.size());
        // A later local close does not re-close or re-notify.
        t.close();
        assertEquals(1, fd.closes.get());
        assertEquals(1, listener.disconnects.size());
    }

    @Test public void cleanEofIsReportedAsCableDisconnect() throws Exception {
        Fd fd = new Fd();
        Recorder listener = new Recorder();
        AccessoryTransport.openForTest(fd, bytes("{\"method\":\"ping\"}\n"), new ByteArrayOutputStream(), listener).start();
        assertTrue(listener.disconnected.await(5, TimeUnit.SECONDS));
        assertEquals(1, listener.requests.size());
        assertEquals("USB cable disconnected", listener.disconnects.get(0));
        assertEquals(1, fd.closes.get());
    }

    @Test public void localCloseReleasesWithoutNotifyingListener() throws Exception {
        Fd fd = new Fd();
        Recorder listener = new Recorder();
        // An input that blocks forever, like an idle cable.
        InputStream idle = new InputStream() {
            @Override public int read() throws IOException {
                try { Thread.sleep(60_000); } catch (InterruptedException e) { throw new IOException("interrupted"); }
                return -1;
            }
        };
        AccessoryTransport t = AccessoryTransport.openForTest(fd, idle, new ByteArrayOutputStream(), listener);
        t.start();
        Thread.sleep(50);
        t.close(); // lock() / new session: local, deliberate
        Thread.sleep(100);
        assertTrue(t.isClosed());
        assertEquals(1, fd.closes.get());
        assertFalse("local close is not a host disconnect", listener.disconnected.await(200, TimeUnit.MILLISECONDS));
    }

    @Test public void oversizedRequestEndsSession() throws Exception {
        Fd fd = new Fd();
        Recorder listener = new Recorder();
        byte[] big = new byte[AccessoryTransport.MAX_REQUEST_BYTES + 10];
        java.util.Arrays.fill(big, (byte) 'a');
        AccessoryTransport.openForTest(fd, new ByteArrayInputStream(big), new ByteArrayOutputStream(), listener).start();
        assertTrue(listener.disconnected.await(5, TimeUnit.SECONDS));
        assertTrue(listener.disconnects.get(0).contains("32 KiB"));
        assertEquals(1, fd.closes.get());
    }

    @Test public void nothingFiresBeforeStartSoTheCallerCanPublishFirst() throws Exception {
        Fd fd = new Fd();
        Recorder listener = new Recorder();
        // An immediate disconnect (empty input): must NOT be delivered until start().
        AccessoryTransport t = AccessoryTransport.openForTest(fd, bytes(""), new ByteArrayOutputStream(), listener);
        Thread.sleep(150);
        assertEquals("no callback before start()", 0, listener.connected);
        assertEquals(0, listener.disconnects.size());
        assertFalse(t.isClosed());
        t.start();
        assertTrue(listener.disconnected.await(5, TimeUnit.SECONDS));
        assertEquals(1, listener.connected);
        t.start(); // idempotent
        Thread.sleep(50);
        assertEquals(1, listener.connected);
        assertEquals(1, fd.closes.get());
    }

    @Test public void throwingOnConnectedEndsTheSessionCleanly() throws Exception {
        Fd fd = new Fd();
        CountDownLatch done = new CountDownLatch(1);
        List<String> reasons = new ArrayList<>();
        AccessoryTransport.Listener hostile = new AccessoryTransport.Listener() {
            @Override public void onConnected(AccessoryTransport s) { throw new IllegalStateException("boom"); }
            @Override public void onRequest(AccessoryTransport s, JSONObject r) {}
            @Override public void onDisconnected(AccessoryTransport s, String reason) { reasons.add(reason); done.countDown(); }
        };
        AccessoryTransport t = AccessoryTransport.openForTest(fd, bytes("{}\n"), new ByteArrayOutputStream(), hostile);
        t.start();
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertEquals(1, reasons.size());
        assertEquals("boom", reasons.get(0));
        assertEquals(1, fd.closes.get());
        assertTrue(t.isClosed());
    }
}
