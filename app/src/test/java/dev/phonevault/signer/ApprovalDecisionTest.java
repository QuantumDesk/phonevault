package dev.phonevault.signer;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class ApprovalDecisionTest {
    @Test public void rejectionPermanentlyPreventsSigning() {
        ApprovalDecision d = new ApprovalDecision(new Object());
        assertTrue(d.reject());
        assertFalse(d.beginSigning());
        assertFalse(d.maySign());
        assertFalse(d.finish());
        assertFalse(d.reject());
    }

    @Test public void signMakesRejectUnavailableAndCompletesOnlyOnce() {
        ApprovalDecision d = new ApprovalDecision(new Object());
        assertTrue(d.beginSigning());
        assertFalse(d.reject());
        assertFalse(d.beginSigning());
        assertTrue(d.maySign());
        assertTrue(d.finish());
        assertFalse(d.finish());
        assertFalse(d.reject());
        assertFalse(d.maySign());
    }

    @Test public void lockCancelsAQueuedSignBeforeCryptoStarts() throws Exception {
        Object monitor = new Object();
        ApprovalDecision d = new ApprovalDecision(monitor);
        assertTrue(d.beginSigning());
        CountDownLatch queued = new CountDownLatch(1), resume = new CountDownLatch(1);
        AtomicBoolean signed = new AtomicBoolean();
        Thread worker = new Thread(() -> {
            queued.countDown();
            try { if (!resume.await(2, TimeUnit.SECONDS)) return; }
            catch (InterruptedException e) { return; }
            synchronized (monitor) { if (d.maySign()) signed.set(true); }
        });
        worker.start();
        assertTrue(queued.await(2, TimeUnit.SECONDS));
        d.cancel();
        resume.countDown();
        worker.join(2000);
        assertFalse(worker.isAlive());
        assertFalse(signed.get());
        assertEquals(ApprovalDecision.State.CANCELLED, d.state());
    }

    @Test public void simultaneousSignAndRejectHaveOnlyOneWinner() throws Exception {
        for (int i = 0; i < 100; i++) {
            ApprovalDecision d = new ApprovalDecision(new Object());
            CountDownLatch start = new CountDownLatch(1);
            AtomicBoolean signed = new AtomicBoolean(), rejected = new AtomicBoolean();
            Thread signer = new Thread(() -> { await(start); signed.set(d.beginSigning()); });
            Thread rejecter = new Thread(() -> { await(start); rejected.set(d.reject()); });
            signer.start(); rejecter.start(); start.countDown();
            signer.join(2000); rejecter.join(2000);
            assertFalse(signer.isAlive()); assertFalse(rejecter.isAlive());
            assertTrue(signed.get() ^ rejected.get());
        }
    }

    private static void await(CountDownLatch latch) {
        try { latch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
