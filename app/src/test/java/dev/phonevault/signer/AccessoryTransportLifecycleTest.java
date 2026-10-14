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
import java.util.concurrent.atomic.AtomicReference;

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
        // A late send after failure is refused — nothing is written to a dead host.
        assertFalse(t.send(new JSONObject().put("id", "x")));
        Thread.sleep(300);
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

    /** An OutputStream that never completes a write — a host that stopped reading. */
    private static final class StuckOutput extends java.io.OutputStream {
        final CountDownLatch entered = new CountDownLatch(1);
        volatile boolean released;
        @Override public void write(int b) throws IOException { write(new byte[] {(byte) b}, 0, 1); }
        @Override public void write(byte[] b, int off, int len) throws IOException {
            entered.countDown();
            while (!released) {
                try { Thread.sleep(20); } catch (InterruptedException e) { throw new IOException("interrupted"); }
            }
        }
    }

    @Test public void sendNeverBlocksAndCloseIsPromptWithAStuckHost() throws Exception {
        // Signing must not perform blocking USB I/O under the activity's state lock, or a host
        // that stops reading could hold up lock(). send() only enqueues, and close() returns
        // promptly even while the writer thread is wedged in write().
        Fd fd = new Fd();
        Recorder listener = new Recorder();
        StuckOutput stuck = new StuckOutput();
        InputStream idle = new InputStream() {
            @Override public int read() throws IOException {
                try { Thread.sleep(60_000); } catch (InterruptedException e) { throw new IOException("interrupted"); }
                return -1;
            }
        };
        AccessoryTransport t = AccessoryTransport.openForTest(fd, idle, stuck, listener);
        t.start();
        long before = System.nanoTime();
        assertTrue(t.send(new JSONObject().put("id", "1")));
        long sendMillis = (System.nanoTime() - before) / 1_000_000;
        assertTrue("send must be non-blocking, took " + sendMillis + " ms", sendMillis < 200);
        assertTrue("writer must have entered the stuck write", stuck.entered.await(5, TimeUnit.SECONDS));
        // Queue up to the bound while the writer is stuck; the next one fails the session.
        for (int i = 0; i < AccessoryTransport.MAX_QUEUED_RESPONSES; i++) {
            assertTrue(t.send(new JSONObject().put("id", "q" + i)));
        }
        assertFalse("a host that never reads gets its session failed", t.send(new JSONObject().put("id", "overflow")));
        assertTrue(listener.disconnected.await(5, TimeUnit.SECONDS));
        assertTrue(listener.disconnects.get(0).contains("not reading"));
        assertTrue(t.isClosed());
        assertEquals(1, fd.closes.get());
        stuck.released = true;
    }

    @Test public void closeReturnsPromptlyWhileWriterIsStuck() throws Exception {
        Fd fd = new Fd();
        Recorder listener = new Recorder();
        StuckOutput stuck = new StuckOutput();
        InputStream idle = new InputStream() {
            @Override public int read() throws IOException {
                try { Thread.sleep(60_000); } catch (InterruptedException e) { throw new IOException("interrupted"); }
                return -1;
            }
        };
        AccessoryTransport t = AccessoryTransport.openForTest(fd, idle, stuck, listener);
        t.start();
        assertTrue(t.send(new JSONObject().put("id", "1")));
        assertTrue(stuck.entered.await(5, TimeUnit.SECONDS));
        long before = System.nanoTime();
        t.close(); // what lock()/deactivate() call under stateLock
        long closeMillis = (System.nanoTime() - before) / 1_000_000;
        assertTrue("close must not wait for the stuck write, took " + closeMillis + " ms", closeMillis < 500);
        assertTrue(t.isClosed());
        assertEquals(1, fd.closes.get());
        assertFalse("a send after close is refused", t.send(new JSONObject().put("id", "late")));
        assertFalse("local close is not a host disconnect", listener.disconnected.await(200, TimeUnit.MILLISECONDS));
        stuck.released = true;
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

    /**
     * The Android accessory device node returns one USB packet per read() and drops
     * whatever was not requested. Byte-wise reads therefore lose all but the first byte of every
     * request. This fake enforces that contract: a single-byte read() is a bug.
     */
    static final class PacketInputStream extends java.io.InputStream {
        private final java.util.ArrayDeque<byte[]> packets = new java.util.ArrayDeque<>();
        PacketInputStream(String... frames) { for (String f : frames) packets.add(f.getBytes(java.nio.charset.StandardCharsets.UTF_8)); }
        @Override public int read() { throw new AssertionError("byte-wise read() on the accessory node drops the rest of the USB packet"); }
        @Override public int read(byte[] b, int off, int len) {
            byte[] p = packets.poll();
            if (p == null) return -1;
            int n = Math.min(len, p.length); // the driver copies min(actual, count) and discards the remainder
            System.arraycopy(p, 0, b, off, n);
            return n;
        }
    }

    @Test public void wholeUsbPacketsAreConsumedNotByteWise() throws Exception {
        java.util.concurrent.CountDownLatch got = new java.util.concurrent.CountDownLatch(2);
        java.util.List<String> ids = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        AccessoryTransport.Listener listener = new AccessoryTransport.Listener() {
            @Override public void onConnected(AccessoryTransport s) {}
            @Override public void onRequest(AccessoryTransport s, org.json.JSONObject j) { ids.add(j.optString("id")); got.countDown(); }
            @Override public void onDisconnected(AccessoryTransport s, String reason) {}
        };
        java.io.Closeable fd = () -> {};
        AccessoryTransport t = AccessoryTransport.openForTest(fd,
                new PacketInputStream("{\"id\":\"a\",\"method\":\"getAddress\"}\n", "{\"id\":\"b\",\"method\":\"getAddress\"}\n"),
                new ByteArrayOutputStream(), listener);
        t.start();
        assertTrue("both framed requests must arrive intact from packet-sized reads", got.await(5, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(java.util.Arrays.asList("a", "b"), ids);
        t.close();
    }

    /** The reader catches Throwable: even an Error thrown by a listener ends the session and is reported. */
    @Test public void listenerErrorEndsTheSessionAndIsReported() throws Exception {
        CountDownLatch disconnected = new CountDownLatch(1);
        AtomicReference<String> reason = new AtomicReference<>();
        AccessoryTransport.Listener listener = new AccessoryTransport.Listener() {
            @Override public void onConnected(AccessoryTransport source) { }
            @Override public void onRequest(AccessoryTransport source, JSONObject json) {
                throw new StackOverflowError("listener blew its stack");
            }
            @Override public void onDisconnected(AccessoryTransport source, String why) { reason.set(why); disconnected.countDown(); }
        };
        byte[] line = (new JSONObject().put("id", "x").put("method", "getAddress").toString() + "\n").getBytes(StandardCharsets.UTF_8);
        Closeable fd = () -> { };
        AccessoryTransport t = AccessoryTransport.openForTest(fd, new ByteArrayInputStream(line), new ByteArrayOutputStream(), listener);
        t.start();
        assertTrue("session reports the failure", disconnected.await(5, TimeUnit.SECONDS));
        assertTrue(reason.get(), reason.get().contains("StackOverflowError"));
        assertTrue("transport closed", t.isClosed());
    }
}
