package dev.phonevault.signer;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * A request that arrived while the vault was LOCKED. The gate reads and decodes it for display
 * only (the phone answers nothing until the PIN is entered) and hands it to the normal request
 * path right after unlock: only on the connection it arrived on, and only while that connection is
 * still the live, open one. A new connection, that connection's disconnect, and a lock from
 * unlocked drop it (the lock answers it with {@link #lockedRefusal}); a relock while still locked
 * keeps it with its gate session.
 *
 * <p>Not synchronized itself: every call is made under MainActivity's stateLock (CredentialGateTest).
 */
final class HeldRequest {
    /** A request taken for dispatch, with the connection it arrived on. */
    static final class Taken {
        final AccessoryTransport source;
        final JSONObject request;
        Taken(AccessoryTransport source, JSONObject request) { this.source = source; this.request = request; }
    }

    private JSONObject request;
    private String summary;
    /** The connection {@link #request} arrived on. */
    private AccessoryTransport source;

    /**
     * Hold {@code request} (shown on the gate as {@code summary}) only while the vault is locked and
     * only from the live connection {@code live}. Replaces any request held before.
     *
     * @return whether it is now held
     */
    boolean holdIfLocked(boolean unlocked, AccessoryTransport live, AccessoryTransport from, JSONObject request, String summary) {
        if (unlocked || from != live) return false;
        this.request = request;
        this.summary = summary;
        this.source = from;
        return true;
    }

    /** What the gate shows for the held request, or null when nothing is held. */
    String summary() { return summary; }

    /**
     * After unlock: the held request, if its own connection is still {@code live} and open, else
     * null. Never re-targeted at another connection. Always forgets the request.
     */
    Taken take(AccessoryTransport live) {
        JSONObject held = request;
        AccessoryTransport from = source;
        boolean stillLive = from != null && from == live && !from.isClosed();
        clear();
        return held == null || !stillLive ? null : new Taken(from, held);
    }

    /** {@code closed} disconnected: forget the request if it came from there. Returns whether one was dropped. */
    boolean dropIfFrom(AccessoryTransport closed) {
        if (source != closed) return false;
        clear(); // its host is gone
        return true;
    }

    /**
     * The one answer a lock gives a held request it ends before review (MainActivity#lock): an
     * error for its id, never a signature, so the host does not wait for its timeout.
     */
    static JSONObject lockedRefusal(JSONObject request) {
        String id;
        try { id = Eip1559Request.validatedId(request.optString("id", null)); } catch (JSONException e) { id = "unknown"; }
        try {
            return new JSONObject().put("id", id).put("status", "error").put("error",
                    "The phone locked before this request was reviewed. Nothing was signed. Unlock the phone and send it again.");
        } catch (JSONException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    /** Forget the request and its source. */
    void clear() {
        request = null;
        summary = null;
        source = null;
    }
}
