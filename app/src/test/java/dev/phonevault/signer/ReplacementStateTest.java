package dev.phonevault.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** The replacement state machine: Cancel can never win after Activate; stale tokens are inert. */
public class ReplacementStateTest {

    @Test public void happyPathPrepareCommitEnd() {
        ReplacementState r = new ReplacementState(new Object());
        int op = r.begin();
        assertTrue(op > 0);
        assertTrue(r.active());
        assertEquals(-1, "a second replacement must be refused while one is active".length() > 0 ? r.begin() : 0);
        assertTrue(r.markPrepared(op));
        assertTrue(r.beginCommit(op));
        assertTrue(r.owns(op));
        assertTrue(r.end(op));
        assertFalse(r.active());
    }

    @Test public void cancelAfterActivateIsRefused() {
        ReplacementState r = new ReplacementState(new Object());
        int op = r.begin();
        assertTrue(r.markPrepared(op));
        assertTrue(r.beginCommit(op));
        assertFalse("Cancel must be inert once COMMITTING", r.cancel(op));
        assertTrue("the commit still owns the outcome", r.owns(op));
        assertEquals(ReplacementState.COMMITTING, r.state());
    }

    @Test public void cancelBeforeActivateWinsAndInvalidatesTheToken() {
        ReplacementState r = new ReplacementState(new Object());
        int op = r.begin();
        assertTrue(r.markPrepared(op));
        assertTrue(r.cancel(op));
        assertFalse(r.active());
        assertFalse("a late Activate with the cancelled token must fail", r.beginCommit(op));
        assertFalse(r.owns(op));
        assertFalse(r.end(op));
    }

    @Test public void staleTokenCannotTouchANewerFlow() {
        ReplacementState r = new ReplacementState(new Object());
        int old = r.begin();
        assertTrue(r.cancel(old));
        int fresh = r.begin();
        assertTrue(fresh > old);
        assertFalse(r.markPrepared(old));
        assertFalse(r.cancel(old));
        assertFalse(r.end(old));
        assertTrue("the newer flow is unaffected", r.markPrepared(fresh));
    }

    @Test public void resetDiscardsAnythingInFlight() {
        ReplacementState r = new ReplacementState(new Object());
        int op = r.begin();
        assertTrue(r.markPrepared(op));
        assertTrue(r.beginCommit(op));
        r.reset(); // lock()/deactivate()
        assertFalse(r.active());
        assertFalse("the commit no longer owns anything", r.owns(op));
        assertFalse(r.end(op));
    }

    @Test public void endIsOnlyForTheOwner() {
        ReplacementState r = new ReplacementState(new Object());
        int op = r.begin();
        assertFalse(r.end(op + 1));
        assertTrue(r.active());
        assertTrue(r.end(op));
        assertFalse(r.active());
    }
}
