package dev.phonevault.signer;

import android.hardware.usb.UsbAccessory;
import android.hardware.usb.UsbManager;
import android.os.ParcelFileDescriptor;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class AccessoryTransport implements Closeable {
    static final int MAX_REQUEST_BYTES = 32_768;
    interface Listener {
        void onConnected(AccessoryTransport source);
        void onRequest(AccessoryTransport source, JSONObject request);
        void onDisconnected(AccessoryTransport source, String reason);
    }

    private final Closeable descriptor;
    private final InputStream input;
    private final OutputStream output;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Listener listener;
    private final java.util.concurrent.atomic.AtomicBoolean closed =
            new java.util.concurrent.atomic.AtomicBoolean(false);
    private final java.util.concurrent.atomic.AtomicBoolean started =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private AccessoryTransport(Closeable descriptor, InputStream input, OutputStream output,
                               Listener listener) {
        this.descriptor = descriptor;
        this.input = input;
        this.output = output;
        this.listener = listener;
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

    /** Begin the session loop. Idempotent; a no-op once closed. */
    void start() {
        if (closed.get() || !started.compareAndSet(false, true)) return;
        executor.execute(() -> {
            try {
                listener.onConnected(this); // a throwing listener ends the session like any error
                String line;
                while ((line = readBoundedLine(input, MAX_REQUEST_BYTES)) != null) {
                    listener.onRequest(this, parseStrictRequest(line));
                }
                fail("USB cable disconnected");
            } catch (Exception exception) {
                fail(exception.getMessage());
            }
        });
    }

    /**
     * Any read/parse/send failure ends the session: the descriptor and reader are released and
     * the listener is told exactly once. A malformed host cannot keep a half-open session alive.
     */
    private void fail(String reason) {
        if (!closed.compareAndSet(false, true)) return;
        releaseResources();
        listener.onDisconnected(this, reason);
    }

    private void releaseResources() {
        executor.shutdownNow();
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
                throw new IllegalArgumentException("USB request exceeds 32 KiB");
            }
            line.write(value);
        }
    }

    /** Parses the deliberately flat request schema without JSONObject's duplicate-key ambiguity. */
    static JSONObject parseStrictRequest(String line) throws JSONException {
        JSONTokener tokens = new JSONTokener(line);
        if (tokens.nextClean() != '{') throw new JSONException("USB request must be a JSON object");

        JSONObject request = new JSONObject();
        Set<String> fields = new HashSet<>();
        char next = tokens.nextClean();
        if (next == '}') {
            if (tokens.nextClean() != 0) throw new JSONException("Trailing data after USB request");
            return request;
        }

        while (true) {
            if (next != '"') throw new JSONException("USB request field names must be quoted");
            String field = tokens.nextString('"');
            if (!fields.add(field)) throw new JSONException("Duplicate USB request field: " + field);
            if (tokens.nextClean() != ':') throw new JSONException("Missing colon after USB request field");
            if (tokens.nextClean() != '"') throw new JSONException("USB request values must be strings");
            request.put(field, tokens.nextString('"'));

            next = tokens.nextClean();
            if (next == '}') break;
            if (next != ',') throw new JSONException("Missing comma between USB request fields");
            next = tokens.nextClean();
        }
        if (tokens.nextClean() != 0) throw new JSONException("Trailing data after USB request");
        return request;
    }

    synchronized void send(JSONObject response) {
        if (closed.get()) return;
        try {
            output.write((response.toString() + "\n").getBytes(StandardCharsets.UTF_8));
            output.flush();
        } catch (Exception exception) {
            fail(exception.getMessage());
        }
    }

    boolean isClosed() { return closed.get(); }

    /** Local close (lock, replacement, new session): releases resources, no listener callback. */
    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        releaseResources();
    }
}
