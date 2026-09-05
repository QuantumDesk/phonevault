package dev.phonevault.signer;

import org.junit.Test;
import static org.junit.Assert.*;

public class SensitiveFlowTest {
    @Test public void onlyOneSensitiveOperationCanOwnTheScreen() {
        SensitiveFlow flow = new SensitiveFlow(new Object());
        int first = flow.begin();
        assertTrue(first > 0);
        assertEquals(-1, flow.begin());
        assertTrue(flow.owns(first));
        assertTrue(flow.end(first));
        assertFalse(flow.active());
    }
    @Test public void oldPinResultCannotAuthorizeANewFlow() {
        SensitiveFlow flow = new SensitiveFlow(new Object());
        int first = flow.begin();
        flow.reset();
        int second = flow.begin();
        assertFalse(flow.owns(first));
        assertFalse(flow.end(first));
        assertTrue(flow.owns(second));
    }
}
