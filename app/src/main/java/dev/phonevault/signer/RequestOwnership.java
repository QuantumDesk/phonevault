package dev.phonevault.signer;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Whether a USB request still owns its approval slot in the live session: the one predicate
 * behind every re-check before a review is drawn, an answer is sent or a signature is made.
 * Always required: the request's transport is the live one, its session is the current one, the
 * phone is unlocked, and its decision is the one holding the slot. Each path adds the checks it
 * has always made, named below; MainActivity reads the live state through {@link Live}.
 */
final class RequestOwnership {
    private RequestOwnership() {}

    enum Require {
        /** No sensitive flow (backup, restore, PIN change…) has the screen. */
        NO_SENSITIVE_FLOW,
        /** A wallet is loaded. */
        WALLET_LOADED,
        /** The backup of the loaded wallet has been verified. */
        BACKUP_VERIFIED,
        /** The phone finished its appliance setup. */
        OPERATIONAL,
        /** The request's USB connection has not closed. */
        CONNECTION_OPEN,
        /** The decision is still undecided (REVIEW). */
        IN_REVIEW,
        /** The decision is SIGNING: Sign was pressed for this request. */
        MAY_SIGN,
        /** Release build: never while USB or wireless debugging is on. */
        NO_ADB,
    }

    /** Sign was pressed: the request is still the live one (the gate is checked beside this). */
    static final Set<Require> SIGN_PRESSED = Collections.unmodifiableSet(EnumSet.noneOf(Require.class));
    /** An EVM transaction or message review may be drawn. */
    static final Set<Require> SHOW_REVIEW = Collections.unmodifiableSet(EnumSet.of(
            Require.NO_SENSITIVE_FLOW, Require.WALLET_LOADED, Require.BACKUP_VERIFIED));
    /** Under stateLock, right before (and after) a signature is made and sent. */
    static final Set<Require> SIGNING = Collections.unmodifiableSet(EnumSet.of(
            Require.OPERATIONAL, Require.NO_SENSITIVE_FLOW, Require.BACKUP_VERIFIED, Require.CONNECTION_OPEN,
            Require.MAY_SIGN, Require.NO_ADB));
    /** A Bitcoin request still owns an undecided slot (any answer, or opening the accounts). */
    static final Set<Require> BTC_UNDECIDED = Collections.unmodifiableSet(EnumSet.of(
            Require.IN_REVIEW, Require.NO_SENSITIVE_FLOW, Require.NO_ADB));
    /** A Bitcoin screen (share, address, PSBT review) may be drawn. */
    static final Set<Require> BTC_SHOW = Collections.unmodifiableSet(EnumSet.of(
            Require.IN_REVIEW, Require.NO_SENSITIVE_FLOW, Require.NO_ADB, Require.WALLET_LOADED, Require.BACKUP_VERIFIED));

    /** The live state the predicate reads. */
    interface Live {
        AccessoryTransport transport();
        int session();
        boolean unlocked();
        ApprovalDecision approvalDecision();
        boolean sensitiveFlowActive();
        boolean walletLoaded();
        boolean backupVerified();
        boolean operational();
        boolean debuggingRefused();
    }

    static boolean holds(Live live, AccessoryTransport source, int s, ApprovalDecision decision, Set<Require> need) {
        if (source != live.transport() || s != live.session() || !live.unlocked() || live.approvalDecision() != decision) return false;
        if (need.contains(Require.NO_SENSITIVE_FLOW) && live.sensitiveFlowActive()) return false;
        if (need.contains(Require.WALLET_LOADED) && !live.walletLoaded()) return false;
        if (need.contains(Require.BACKUP_VERIFIED) && !live.backupVerified()) return false;
        if (need.contains(Require.OPERATIONAL) && !live.operational()) return false;
        if (need.contains(Require.CONNECTION_OPEN) && source.isClosed()) return false;
        if (need.contains(Require.IN_REVIEW) && decision.state() != ApprovalDecision.State.REVIEW) return false;
        if (need.contains(Require.MAY_SIGN) && !decision.maySign()) return false;
        return !need.contains(Require.NO_ADB) || !live.debuggingRefused(); // last: it reads system settings
    }
}
