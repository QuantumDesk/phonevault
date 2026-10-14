package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.EnumSet;
import java.util.Set;

/** The one "does this request still own its slot" predicate, and the checks each path makes. */
public final class RequestOwnershipTest {
    private static final Object LOCK = new Object();

    /** Every condition true: the request owns its slot on every path. */
    private static final class FakeLive implements RequestOwnership.Live {
        AccessoryTransport transport = newTransport();
        int session = 7;
        boolean unlocked = true, sensitive, walletLoaded = true, backupVerified = true, operational = true, adb;
        ApprovalDecision decision = new ApprovalDecision(LOCK);

        @Override public AccessoryTransport transport() { return transport; }
        @Override public int session() { return session; }
        @Override public boolean unlocked() { return unlocked; }
        @Override public ApprovalDecision approvalDecision() { return decision; }
        @Override public boolean sensitiveFlowActive() { return sensitive; }
        @Override public boolean walletLoaded() { return walletLoaded; }
        @Override public boolean backupVerified() { return backupVerified; }
        @Override public boolean operational() { return operational; }
        @Override public boolean debuggingRefused() { return adb; }
    }

    private static AccessoryTransport newTransport() {
        return AccessoryTransport.openForTest(() -> { }, new ByteArrayInputStream(new byte[0]), new ByteArrayOutputStream(),
                new AccessoryTransport.Listener() {
                    @Override public void onConnected(AccessoryTransport source) { }
                    @Override public void onRequest(AccessoryTransport source, JSONObject request) { }
                    @Override public void onDisconnected(AccessoryTransport source, String reason) { }
                });
    }

    private static boolean holds(FakeLive l, Set<RequestOwnership.Require> need) {
        return RequestOwnership.holds(l, l.transport, l.session, l.decision, need);
    }

    @Test public void theSharedChecksApplyToEveryPath() {
        for (Set<RequestOwnership.Require> need : allSets()) {
            FakeLive l = new FakeLive();
            if (need.contains(RequestOwnership.Require.MAY_SIGN)) l.decision.beginSigning();
            assertTrue(need.toString(), holds(l, need));
            assertFalse("another transport", RequestOwnership.holds(l, newTransport(), l.session, l.decision, need));
            assertFalse("another session", RequestOwnership.holds(l, l.transport, l.session + 1, l.decision, need));
            assertFalse("another decision", RequestOwnership.holds(l, l.transport, l.session, new ApprovalDecision(LOCK), need));
            l.unlocked = false;
            assertFalse("locked", holds(l, need));
        }
    }

    /** Pins which checks each path has made: a set may not lose one. */
    @Test public void eachPathKeepsItsChecks() {
        assertEquals(EnumSet.noneOf(RequestOwnership.Require.class), RequestOwnership.SIGN_PRESSED);
        assertEquals(EnumSet.of(RequestOwnership.Require.NO_SENSITIVE_FLOW, RequestOwnership.Require.WALLET_LOADED,
                RequestOwnership.Require.BACKUP_VERIFIED), RequestOwnership.SHOW_REVIEW);
        assertEquals(EnumSet.of(RequestOwnership.Require.OPERATIONAL, RequestOwnership.Require.NO_SENSITIVE_FLOW,
                RequestOwnership.Require.BACKUP_VERIFIED, RequestOwnership.Require.CONNECTION_OPEN,
                RequestOwnership.Require.MAY_SIGN, RequestOwnership.Require.NO_ADB), RequestOwnership.SIGNING);
        assertEquals(EnumSet.of(RequestOwnership.Require.IN_REVIEW, RequestOwnership.Require.NO_SENSITIVE_FLOW,
                RequestOwnership.Require.NO_ADB), RequestOwnership.BTC_UNDECIDED);
        EnumSet<RequestOwnership.Require> btcShow = EnumSet.copyOf(RequestOwnership.BTC_UNDECIDED);
        btcShow.add(RequestOwnership.Require.WALLET_LOADED);
        btcShow.add(RequestOwnership.Require.BACKUP_VERIFIED);
        assertEquals(btcShow, RequestOwnership.BTC_SHOW);
    }

    @Test public void eachNamedCheckRefusesOnItsOwn() {
        FakeLive l = new FakeLive();
        l.sensitive = true;
        assertFalse(holds(l, EnumSet.of(RequestOwnership.Require.NO_SENSITIVE_FLOW)));
        assertTrue(holds(l, RequestOwnership.SIGN_PRESSED));

        l = new FakeLive();
        l.walletLoaded = false;
        assertFalse(holds(l, EnumSet.of(RequestOwnership.Require.WALLET_LOADED)));

        l = new FakeLive();
        l.backupVerified = false;
        assertFalse(holds(l, EnumSet.of(RequestOwnership.Require.BACKUP_VERIFIED)));

        l = new FakeLive();
        l.operational = false;
        assertFalse(holds(l, EnumSet.of(RequestOwnership.Require.OPERATIONAL)));

        l = new FakeLive();
        l.transport.close();
        assertFalse(holds(l, EnumSet.of(RequestOwnership.Require.CONNECTION_OPEN)));
        assertTrue("other paths do not ask", holds(l, RequestOwnership.BTC_UNDECIDED));

        l = new FakeLive();
        l.adb = true;
        assertFalse(holds(l, EnumSet.of(RequestOwnership.Require.NO_ADB)));
        assertFalse("never sign while debugging is on", holds(l, RequestOwnership.SIGNING));
        assertFalse("never answer Bitcoin while debugging is on", holds(l, RequestOwnership.BTC_UNDECIDED));
        assertFalse(holds(l, RequestOwnership.BTC_SHOW));
    }

    /** REVIEW for screens and Bitcoin answers; SIGNING (Sign pressed) for making the signature. */
    @Test public void decisionStateGatesByPath() {
        FakeLive l = new FakeLive();
        assertTrue(holds(l, EnumSet.of(RequestOwnership.Require.IN_REVIEW)));
        assertFalse(holds(l, EnumSet.of(RequestOwnership.Require.MAY_SIGN)));
        assertTrue(l.decision.beginSigning());
        assertFalse(holds(l, EnumSet.of(RequestOwnership.Require.IN_REVIEW)));
        assertTrue(holds(l, EnumSet.of(RequestOwnership.Require.MAY_SIGN)));
        l.decision.cancel();
        assertFalse("lock cancels a queued sign", holds(l, RequestOwnership.SIGNING));
    }

    private static Iterable<Set<RequestOwnership.Require>> allSets() {
        return java.util.Arrays.asList(RequestOwnership.SIGN_PRESSED, RequestOwnership.SHOW_REVIEW, RequestOwnership.SIGNING,
                RequestOwnership.BTC_UNDECIDED, RequestOwnership.BTC_SHOW);
    }
}
