package dev.phonevault.signer;

/** Exclusive ownership of PIN reauthentication, backup, and replacement screens. */
final class SensitiveFlow {
    private final Object monitor;
    private int generation;
    private boolean active;
    SensitiveFlow(Object monitor) { this.monitor = monitor; }
    int begin() {
        synchronized (monitor) {
            if (active) return -1;
            active = true;
            return ++generation;
        }
    }
    boolean owns(int token) { synchronized (monitor) { return active && token == generation; } }
    boolean active() { synchronized (monitor) { return active; } }
    boolean end(int token) {
        synchronized (monitor) {
            if (!owns(token)) return false;
            reset();
            return true;
        }
    }
    void reset() { synchronized (monitor) { active = false; generation++; } }
}
