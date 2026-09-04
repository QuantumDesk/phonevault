package dev.phonevault.signer;

/**
 * Wallet-replacement state machine, extracted from the activity so its transitions are
 * unit-tested. Every transition runs under the caller-supplied monitor (the activity's
 * {@code stateLock}) so it is linearized with lock()/deactivate()/publish.
 *
 * <pre>
 *   IDLE → PREPARING (candidate being generated)
 *        → PREPARED  (new phrase on screen; Cancel / timeout allowed)
 *        → COMMITTING (Activate pressed; Cancel / timeout refused; the commit owns the outcome)
 *        → IDLE
 * </pre>
 *
 * Each flow owns an op token; a stale callback (older token) can never change the state.
 */
final class ReplacementState {
    static final int IDLE = 0, PREPARING = 1, PREPARED = 2, COMMITTING = 3;

    private final Object monitor;
    private int state = IDLE;
    private int op;

    ReplacementState(Object monitor) {
        this.monitor = monitor;
    }

    int state() {
        synchronized (monitor) { return state; }
    }

    boolean active() {
        synchronized (monitor) { return state != IDLE; }
    }

    /** IDLE → PREPARING. Returns the owning op token, or -1 if a replacement is already active. */
    int begin() {
        synchronized (monitor) {
            if (state != IDLE) return -1;
            state = PREPARING;
            return ++op;
        }
    }

    /** PREPARING → PREPARED. */
    boolean markPrepared(int token) {
        synchronized (monitor) {
            if (token != op || state != PREPARING) return false;
            state = PREPARED;
            return true;
        }
    }

    /** PREPARED → COMMITTING: the single point of no return. */
    boolean beginCommit(int token) {
        synchronized (monitor) {
            if (token != op || state != PREPARED) return false;
            state = COMMITTING;
            return true;
        }
    }

    /** Is {@code token} the current owner and is the state COMMITTING? (checked inside the commit) */
    boolean owns(int token) {
        synchronized (monitor) { return token == op && state == COMMITTING; }
    }

    /** Explicit user cancel or timeout: refused once COMMITTING. */
    boolean cancel(int token) {
        synchronized (monitor) {
            if (token != op || state == COMMITTING || state == IDLE) return false;
            state = IDLE;
            op++;
            return true;
        }
    }

    /** Cancel whatever flow is current, if it has not reached COMMITTING (timeout / hide). */
    boolean cancelCurrent() {
        synchronized (monitor) {
            if (state == IDLE || state == COMMITTING) return false;
            state = IDLE;
            op++;
            return true;
        }
    }

    /** Terminal transition for the owner (success or failure): → IDLE. Stale tokens are no-ops. */
    boolean end(int token) {
        synchronized (monitor) {
            if (token != op) return false;
            state = IDLE;
            return true;
        }
    }

    /** lock()/deactivate(): discard whatever is in flight and invalidate every outstanding token. */
    void reset() {
        synchronized (monitor) {
            state = IDLE;
            op++;
        }
    }
}
