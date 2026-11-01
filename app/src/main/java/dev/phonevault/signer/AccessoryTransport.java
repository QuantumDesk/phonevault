package dev.phonevault.signer;

import android.hardware.usb.UsbAccessory;
import android.hardware.usb.UsbManager;
import android.os.ParcelFileDescriptor;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * One USB accessory session: a reader thread (framed JSON requests in) and a single writer
 * thread draining a small bounded queue (responses out).
 *
 * <p>{@link #send} never performs I/O: it enqueues and returns. A host that stops reading fills
 * the queue and the session is failed — it can never stall a caller that holds the activity's
 * state lock. {@link #close} is likewise non-blocking: it flips the closed flag, closes the
 * descriptor (which unblocks a stuck write on a released fd where the driver honours it) and
 * interrupts the writer.
 */
final class AccessoryTransport implements Closeable {
    static final int MAX_REQUEST_BYTES = 32_768;
    /**
     * btcSignPsbt alone may be longer: a PSBT of up to {@link Psbt#MAX_BYTES} (200 KiB) is ~267 KiB
     * of base64. A line may grow past {@link #MAX_REQUEST_BYTES} only if its first 32 KiB already
     * name that method ({@code "method":"btcSignPsbt"}, so the host sends "psbt" last), and a
     * long line that then parses as any other method is refused.
     */
    static final int MAX_PSBT_REQUEST_BYTES = 288 * 1024;
    private static final byte[] PSBT_METHOD = "\"method\":\"btcSignPsbt\"".getBytes(StandardCharsets.US_ASCII);
    /** ≥ the gadget's 16 KiB bulk buffer, so a single read() drains a whole USB packet. */
    static final int PACKET_BUFFER_BYTES = 16384;

    /** Responses a non-reading host may leave unread before the session is failed. */
    static final int MAX_QUEUED_RESPONSES = 4;

    interface Listener {
        void onConnected(AccessoryTransport source);
        void onRequest(AccessoryTransport source, JSONObject request);
        void onDisconnected(AccessoryTransport source, String reason);
    }

    /**
     * How the session ended. Only {@link #DETACHED} means the cable (the accessory) is gone; after
     * any end of its own ({@link #endedByItself}) the framework may still have the accessory
     * attached, and MainActivity opens it again so the next host finds a reader without a replug.
     */
    enum End {
        OPEN,
        /** Closed by the vault itself (lock, new session, deactivation). */
        LOCAL,
        /** USB_ACCESSORY_DETACHED: unplugged. */
        DETACHED,
        /** The accessory reported end of stream. */
        READ_ENDED,
        /** A read, a frame, a parse or a listener failed. */
        READ_FAILED,
        /** A response could not be written (the host went away: ENODEV, EIO), or the host stopped reading. */
        WRITE_FAILED,
        /** The descriptor can no longer write (see {@link WriteProbe}): the bus dropped under it. */
        STALE,
    }

    /**
     * Can this session's descriptor still send? f_accessory marks an open descriptor disconnected
     * on any bus reset or disconnect (a host that went away, a host-side port reset, a START that
     * re-enumerates the phone) and only a new open() clears that: reads may go on working while
     * every write fails with ENODEV, so a request read on it could never be answered. A zero-length
     * write() asks exactly that without sending anything (acc_write checks the state first and
     * returns 0 for no bytes). Never blocks.
     */
    interface WriteProbe { boolean writable(); }

    private final Closeable descriptor;
    private final InputStream input;
    private final OutputStream output;
    private final ExecutorService reader = Executors.newSingleThreadExecutor();
    private final BlockingQueue<byte[]> outbound = new ArrayBlockingQueue<>(MAX_QUEUED_RESPONSES);
    private final Thread writer;
    private final Listener listener;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean started = new AtomicBoolean(false);
    private final WriteProbe probe;
    private volatile End end = End.OPEN;
    /** Requests read and handed to the listener on this session. */
    private final java.util.concurrent.atomic.AtomicInteger requestsRead = new java.util.concurrent.atomic.AtomicInteger();
    /** A request read on a descriptor that could no longer answer it (see {@link #takeCarried}). */
    private volatile JSONObject carried;

    private AccessoryTransport(Closeable descriptor, InputStream input, OutputStream output,
                               Listener listener, WriteProbe probe) {
        this.descriptor = descriptor;
        this.probe = probe;
        // The accessory character device (f_accessory) delivers one USB packet per read() and
        // DISCARDS whatever the caller did not ask for: a byte-at-a-time read keeps the first
        // byte of every packet and silently drops the rest, so a framed request never completes.
        // Always pull whole packets into a buffer and parse from there.
        this.input = new BufferedInputStream(input, PACKET_BUFFER_BYTES);
        this.output = output;
        this.listener = listener;
        this.writer = new Thread(this::drainOutbound, "aoa-writer");
        this.writer.setDaemon(true);
    }

    /**
     * Open the accessory and return an INACTIVE session: no thread runs and no callback fires
     * until {@link #start()}. The caller publishes the reference first, then starts it, so an
     * immediate request/disconnect can never be attributed to "some other transport".
     */
    static AccessoryTransport open(UsbManager manager, UsbAccessory accessory, Listener listener) {
        ParcelFileDescriptor descriptor = manager.openAccessory(accessory);
        if (descriptor == null) throw new IllegalStateException("USB accessory permission was not granted");
        try {
            final java.io.FileDescriptor fd = descriptor.getFileDescriptor();
            return new AccessoryTransport(descriptor, new FileInputStream(fd), new FileOutputStream(fd), listener,
                    () -> descriptorWritable(fd));
        } catch (RuntimeException constructionFailure) {
            try { descriptor.close(); } catch (Exception ignored) {}
            throw constructionFailure;
        }
    }

    /**
     * The host identity res/xml/accessory_filter.xml lets in (manufacturer + model): what an
     * attach intent would have matched, so an accessory the framework still has attached may be
     * reopened without one (MainActivity#resumeAttachedAccessory). Never a new trust decision.
     */
    static final String HOST_MANUFACTURER = "PhoneVault";
    static final String HOST_MODEL = "EVM Signer";

    /** The first accessory in {@code attached} (UsbManager#getAccessoryList, may be null) that is our host, else null. */
    static UsbAccessory ourHost(UsbAccessory[] attached) {
        if (attached == null) return null;
        for (UsbAccessory accessory : attached) {
            if (accessory != null && isOurHost(accessory.getManufacturer(), accessory.getModel())) return accessory;
        }
        return null;
    }

    static boolean isOurHost(String manufacturer, String model) {
        return HOST_MANUFACTURER.equals(manufacturer) && HOST_MODEL.equals(model);
    }

    /** UsbManager.ACTION_USB_STATE (hidden): sticky, sent by UsbDeviceManager on every USB state change. */
    static final String ACTION_USB_STATE = "android.hardware.usb.action.USB_STATE";

    /** The sticky USB_STATE says: connected, configured, and the accessory function is in the configuration. */
    static boolean accessoryConfigured(android.content.Intent usbState) {
        return usbState != null && usbState.getBooleanExtra("connected", false)
                && usbState.getBooleanExtra("configured", false) && usbState.getBooleanExtra("accessory", false);
    }

    /** A zero-length write() on the accessory descriptor: false on ENODEV / EIO / EBADF / EPIPE. */
    private static boolean descriptorWritable(java.io.FileDescriptor fd) {
        try {
            android.system.Os.write(fd, new byte[0], 0, 0);
            return true;
        } catch (android.system.ErrnoException e) {
            return !deadErrno(e.errno);
        } catch (Exception other) {
            return true; // not a verdict on the session: carry on as before this check existed
        }
    }

    static boolean deadErrno(int errno) {
        return errno == android.system.OsConstants.ENODEV || errno == android.system.OsConstants.EIO
                || errno == android.system.OsConstants.EBADF || errno == android.system.OsConstants.EPIPE;
    }

    /** Test seam: an inactive session over arbitrary streams (no USB / ParcelFileDescriptor). */
    static AccessoryTransport openForTest(Closeable descriptor, InputStream input, OutputStream output,
                                          Listener listener) {
        return new AccessoryTransport(descriptor, input, output, listener, () -> true);
    }

    /** Test seam with a write probe. */
    static AccessoryTransport openForTest(Closeable descriptor, InputStream input, OutputStream output,
                                          Listener listener, WriteProbe probe) {
        return new AccessoryTransport(descriptor, input, output, listener, probe);
    }

    /** Begin the session loops. Idempotent; a no-op once closed. */
    void start() {
        if (closed.get() || !started.compareAndSet(false, true)) return;
        writer.start();
        reader.execute(() -> {
            try {
                listener.onConnected(this); // a throwing listener ends the session like any error
                String line;
                while ((line = readBoundedLine(input, MAX_REQUEST_BYTES)) != null) {
                    JSONObject request = parseStrictRequest(line);
                    if (line.getBytes(StandardCharsets.UTF_8).length > MAX_REQUEST_BYTES && !BtcRequest.SIGN_PSBT.equals(request.optString("method"))) {
                        throw new IllegalArgumentException("USB request exceeds 32 KiB");
                    }
                    if (!probe.writable()) {
                        // Read, but no answer could ever leave this descriptor: the bus dropped
                        // under it after it was opened. The sender is the host on the bus NOW
                        // (it wrote after the drop), so the request is handed to the session
                        // opened next on the same accessory (MainActivity), not lost.
                        carried = request;
                        fail(End.STALE, "USB session went stale (the phone could no longer answer on it)");
                        return;
                    }
                    requestsRead.incrementAndGet();
                    listener.onRequest(this, request);
                }
                fail(End.READ_ENDED, "USB cable disconnected");
            } catch (Throwable failure) {
                // Errors too (StackOverflowError, OutOfMemoryError from a hostile frame): the
                // session must end and be reported, never left open with a dead reader.
                fail(End.READ_FAILED, failure instanceof Exception ? failure.getMessage()
                        : "USB request could not be processed (" + failure.getClass().getSimpleName() + ")");
            }
        });
    }

    private void drainOutbound() {
        try {
            while (!closed.get()) {
                byte[] frame = outbound.poll(250, TimeUnit.MILLISECONDS);
                if (frame == null) continue;
                output.write(frame);
                output.flush();
            }
        } catch (InterruptedException interrupted) {
            // close() interrupted us: nothing to report, the session is already ending
        } catch (Exception exception) {
            // ENODEV / EIO: the host that was to read this went away (or the bus was reset under
            // the session). The session ends and is reported; MainActivity drops what it held
            // for that host and opens the still-attached accessory again.
            fail(End.WRITE_FAILED, "USB write failed: " + exception.getMessage());
        }
    }

    /**
     * Any read/parse/write failure ends the session: the descriptor and threads are released and
     * the listener is told exactly once. A malformed or non-reading host cannot keep a half-open
     * session alive.
     */
    private void fail(End how, String reason) {
        if (!closed.compareAndSet(false, true)) return;
        end = how;
        releaseResources();
        listener.onDisconnected(this, reason);
    }

    /** Requests this session read and handed on (a session that worked, as opposed to one that failed at once). */
    int requestsRead() { return requestsRead.get(); }

    /** How the session ended ({@link End#OPEN} while it is open). */
    End end() { return end; }

    /** The session ended on its own and the accessory may still be attached (not unplugged, not closed by the vault). */
    boolean endedByItself() { return endedByItself(end); }

    static boolean endedByItself(End e) {
        return e == End.READ_ENDED || e == End.READ_FAILED || e == End.WRITE_FAILED || e == End.STALE;
    }

    /** Open, and its descriptor can still send (see {@link WriteProbe}). Sends nothing. */
    boolean writable() { return !closed.get() && probe.writable(); }

    /**
     * The open session's descriptor can no longer send (the bus dropped under it): end it as
     * {@link End#STALE}, reported to the listener like any other failure. No-op once closed.
     */
    void failStale(String reason) { fail(End.STALE, reason); }

    /** The request read on a stale descriptor, once (null if none). */
    JSONObject takeCarried() {
        JSONObject c = carried;
        carried = null;
        return c;
    }

    private void releaseResources() {
        reader.shutdownNow();
        writer.interrupt();
        outbound.clear();
        try { input.close(); } catch (Exception ignored) {}
        try { output.close(); } catch (Exception ignored) {}
        try { descriptor.close(); } catch (Exception ignored) {}
    }

    static String readBoundedLine(InputStream input, int maximumBytes) throws Exception {
        ByteArrayOutputStream line = new ByteArrayOutputStream(Math.min(maximumBytes, 4096));
        while (true) {
            int value = input.read();
            if (value == -1) {
                if (line.size() == 0) return null;
                throw new IllegalArgumentException("USB request ended before newline");
            }
            if (value == '\n') {
                return StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(line.toByteArray()))
                        .toString();
            }
            if (line.size() >= maximumBytes) {
                if (maximumBytes == MAX_REQUEST_BYTES && namesPsbtMethod(line.toByteArray())) {
                    maximumBytes = MAX_PSBT_REQUEST_BYTES;
                } else {
                    throw new IllegalArgumentException(maximumBytes == MAX_REQUEST_BYTES
                            ? "USB request exceeds 32 KiB" : "USB request exceeds " + (MAX_PSBT_REQUEST_BYTES / 1024) + " KiB");
                }
            }
            line.write(value);
        }
    }

    private static boolean namesPsbtMethod(byte[] head) {
        outer:
        for (int i = 0; i + PSBT_METHOD.length <= head.length; i++) {
            for (int j = 0; j < PSBT_METHOD.length; j++) if (head[i + j] != PSBT_METHOD[j]) continue outer;
            return true;
        }
        return false;
    }

    /**
     * Parses the deliberately flat request schema without JSONObject's duplicate-key ambiguity.
     * The whole line goes through {@link StrictJson} (RFC 8259, the companion's rules): duplicate
     * keys, comments, invalid or non-ASCII {@code \\u} escapes, raw control characters, unpaired
     * surrogates and ANY data after the closing brace (a NUL included) are refused. Only JSON
     * whitespace may follow the object. Every value is a string, except the one nested object
     * {@link HostSimulation#FIELD} (the Mac's display-only simulation claim).
     */
    static JSONObject parseStrictRequest(String line) throws JSONException {
        Object parsed;
        try {
            parsed = StrictJson.parse(line);
        } catch (StrictJson.ParseException e) {
            throw new JSONException("Malformed USB request: " + e.getMessage());
        }
        if (!(parsed instanceof java.util.Map)) throw new JSONException("USB request must be a JSON object");
        JSONObject request = new JSONObject();
        for (java.util.Map.Entry<?, ?> e : ((java.util.Map<?, ?>) parsed).entrySet()) {
            String field = (String) e.getKey();
            Object value = e.getValue();
            if (value instanceof java.util.Map && HostSimulation.FIELD.equals(field)) {
                request.put(field, toOrgJson(value));
            } else if (value instanceof String) {
                request.put(field, value);
            } else {
                throw new JSONException("USB request values must be strings");
            }
        }
        return request;
    }

    private static Object toOrgJson(Object v) throws JSONException {
        if (v instanceof java.util.Map) {
            JSONObject o = new JSONObject();
            for (java.util.Map.Entry<?, ?> e : ((java.util.Map<?, ?>) v).entrySet()) o.put((String) e.getKey(), toOrgJson(e.getValue()));
            return o;
        }
        if (v instanceof java.util.List) {
            org.json.JSONArray a = new org.json.JSONArray();
            for (Object item : (java.util.List<?>) v) a.put(toOrgJson(item));
            return a;
        }
        if (v instanceof StrictJson.Num) {
            String literal = ((StrictJson.Num) v).literal;
            // Integers stay integers (exactly); anything with a fraction or exponent becomes a
            // Double, which the schema refuses where it wants an integer.
            if (literal.matches("-?[0-9]{1,18}")) {
                long n = Long.parseLong(literal);
                return n >= Integer.MIN_VALUE && n <= Integer.MAX_VALUE ? (Object) (int) n : (Object) n;
            }
            try { return Double.valueOf(literal); } catch (NumberFormatException e) { throw new JSONException("Invalid number"); }
        }
        return v; // String or Boolean
    }

    /**
     * Enqueue a response for the writer thread. Never blocks and never performs I/O. Returns
     * false if the session is closed or the host has stopped reading (queue full → session
     * failed).
     */
    boolean send(JSONObject response) {
        if (closed.get()) return false;
        byte[] frame = (response.toString() + "\n").getBytes(StandardCharsets.UTF_8);
        if (!outbound.offer(frame)) {
            fail(End.WRITE_FAILED, "USB host is not reading responses (" + MAX_QUEUED_RESPONSES + " unread)");
            return false;
        }
        return true;
    }

    boolean isClosed() { return closed.get(); }

    /** Local close (lock, replacement, new session): releases resources, no listener callback. */
    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        end = End.LOCAL;
        releaseResources();
    }

    /** USB_ACCESSORY_DETACHED: the cable is gone. Closes like {@link #close()}; no listener callback. */
    void detached() {
        if (!closed.compareAndSet(false, true)) return;
        end = End.DETACHED;
        releaseResources();
    }

    /** How long {@link #closeAfter} lets its last frame reach the host before releasing anyway. */
    static final long LAST_FRAME_WAIT_MS = 500;

    /**
     * Local close that first delivers {@code lastResponse} (a refusal) as the session's final frame.
     * The session counts as closed at once: no other response can be sent after this call and
     * queued ones are dropped, exactly as for {@link #close()}. Never blocks the caller; the
     * descriptor is released once the frame is written, or after {@link #LAST_FRAME_WAIT_MS} if
     * the host is not reading (so the accessory can be reopened). No listener callback.
     */
    void closeAfter(JSONObject lastResponse) {
        if (!closed.compareAndSet(false, true)) return;
        end = End.LOCAL;
        outbound.clear();
        final byte[] frame = (lastResponse.toString() + "\n").getBytes(StandardCharsets.UTF_8);
        Thread closer = new Thread(() -> {
            Thread last = new Thread(() -> {
                try {
                    output.write(frame);
                    output.flush();
                } catch (Exception ignored) {
                    // the host is gone: nothing to deliver
                }
            }, "aoa-last-frame");
            last.setDaemon(true);
            last.start();
            try { last.join(LAST_FRAME_WAIT_MS); } catch (InterruptedException ignored) { }
            releaseResources();
        }, "aoa-close");
        closer.setDaemon(true);
        closer.start();
    }
}
