package dev.phonevault.signer;

/** One request owns one irreversible decision. The monitor also guards the vault session. */
final class ApprovalDecision {
    enum State { REVIEW, SIGNING, REJECTED, CANCELLED, FINISHED }
    private final Object monitor;
    private State state = State.REVIEW;

    ApprovalDecision(Object monitor) { this.monitor = monitor; }
    State state() { synchronized (monitor) { return state; } }
    boolean beginSigning() {
        synchronized (monitor) {
            if (state != State.REVIEW) return false;
            state = State.SIGNING;
            return true;
        }
    }
    boolean reject() {
        synchronized (monitor) {
            if (state != State.REVIEW) return false;
            state = State.REJECTED;
            return true;
        }
    }
    void cancel() {
        synchronized (monitor) {
            if (state == State.REVIEW || state == State.SIGNING) state = State.CANCELLED;
        }
    }
    boolean maySign() { synchronized (monitor) { return state == State.SIGNING; } }
    boolean finish() {
        synchronized (monitor) {
            if (state != State.SIGNING) return false;
            state = State.FINISHED;
            return true;
        }
    }
}
