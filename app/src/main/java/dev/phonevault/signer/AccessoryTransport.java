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

    private final Closeable descriptor;
    private final InputStream input;
    private final OutputStream output;
    private final ExecutorService reader = Executors.newSingleThreadExecutor();
    private final BlockingQueue<byte[]> outbound = new ArrayBlockingQueue<>(MAX_QUEUED_RESPONSES);
    private final Thread writer;
    private final Listener listener;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean started = new AtomicBoolean(false);

    private AccessoryTransport(Closeable descriptor, InputStream input, OutputStream output,
                               Listener listener) {
        this.descriptor = descriptor;
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
            return new AccessoryTransport(descriptor,
                    new FileInputStream(descriptor.getFileDescriptor()),
                    new FileOutputStream(descriptor.getFileDescriptor()), listener);
        } catch (RuntimeException constructionFailure) {
            try { descriptor.close(); } catch (Exception ignored) {}
            throw constructionFailure;
        }
    }

    /** Test seam: an inactive session over arbitrary streams (no USB / ParcelFileDescriptor). */
    static AccessoryTransport openForTest(Closeable descriptor, InputStream input, OutputStream output,
                                          Listener listener) {
        return new AccessoryTransport(descriptor, input, output, listener);
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
                    listener.onRequest(this, request);
                }
                fail("USB cable disconnected");
            } catch (Throwable failure) {
                // Errors too (StackOverflowError, OutOfMemoryError from a hostile frame): the
                // session must end and be reported, never left open with a dead reader.
                fail(failure instanceof Exception ? failure.getMessage()
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
            fail("USB write failed: " + exception.getMessage());
        }
    }

    /**
     * Any read/parse/write failure ends the session: the descriptor and threads are released and
     * the listener is told exactly once. A malformed or non-reading host cannot keep a half-open
     * session alive.
     */
    private void fail(String reason) {
        if (!closed.compareAndSet(false, true)) return;
        releaseResources();
        listener.onDisconnected(this, reason);
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
            fail("USB host is not reading responses (" + MAX_QUEUED_RESPONSES + " unread)");
            return false;
        }
        return true;
    }

    boolean isClosed() { return closed.get(); }

    /** Number of responses still waiting for the writer (tests / diagnostics). */
    int queuedResponses() { return outbound.size(); }

    /** Local close (lock, replacement, new session): releases resources, no listener callback. */
    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        releaseResources();
    }
}
