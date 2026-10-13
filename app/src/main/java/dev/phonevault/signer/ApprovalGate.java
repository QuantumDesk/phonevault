package dev.phonevault.signer;

/**
 * When the Approve button of a review may be enabled (UI thread only). Always: the "I verified…"
 * checkbox is ticked and the review was scrolled to its end (or fits on the screen). A review with
 * a DANGER row also needs the second "I understand: …" checkbox. Nothing here can approve by
 * itself; {@link ApprovalDecision} still owns the one sign-or-reject decision.
 */
final class ApprovalGate {
    final boolean dangerRequired;
    private boolean reviewed;
    private boolean dangerAcknowledged;
    private boolean reachedEnd;

    ApprovalGate(boolean dangerRequired) { this.dangerRequired = dangerRequired; }

    void setReviewed(boolean checked) { reviewed = checked; }

    void setDangerAcknowledged(boolean checked) { dangerAcknowledged = checked; }

    /** The end of the review was on screen once. Latched: scrolling back up does not re-lock. */
    void reachedEnd() { reachedEnd = true; }

    boolean hasReachedEnd() { return reachedEnd; }

    boolean mayApprove() {
        return reviewed && reachedEnd && (!dangerRequired || dangerAcknowledged);
    }

    /** True when the bottom of content of height {@code contentHeight} is within {@code slop} px of view. */
    static boolean atEnd(int contentHeight, int scrollY, int viewportHeight, int slop) {
        return contentHeight - (scrollY + viewportHeight) <= slop;
    }
}
