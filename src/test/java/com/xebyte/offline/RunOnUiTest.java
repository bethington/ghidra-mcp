package com.xebyte.offline;

import com.xebyte.core.SwingThreadingStrategy;
import com.xebyte.core.ThreadingStrategy;
import org.junit.Test;

import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/**
 * {@code runOnUi} is what the services call where they used to call
 * {@code SwingUtilities.invokeAndWait}: the event thread on the GUI, the caller headless.
 */
public class RunOnUiTest {

    @Test
    public void headlessRunsOnTheCallingThreadAndPropagatesFailures() throws Exception {
        ThreadingStrategy headless = new NoopThreadingStrategy();
        Thread caller = Thread.currentThread();
        AtomicReference<Thread> ranOn = new AtomicReference<>();
        headless.runOnUi(() -> ranOn.set(Thread.currentThread()));
        assertSame(caller, ranOn.get());

        try {
            headless.runOnUi(() -> { throw new IllegalStateException("boom"); });
            fail("the failure must reach the caller");
        } catch (IllegalStateException expected) {
            assertEquals("boom", expected.getMessage());
        }
    }

    @Test
    public void theGuiRunsOnTheEventThreadAndWaits() throws Exception {
        AtomicBoolean onEdt = new AtomicBoolean();
        new SwingThreadingStrategy().runOnUi(() -> onEdt.set(SwingUtilities.isEventDispatchThread()));
        assertTrue(onEdt.get());
    }

    @Test
    public void theGuiDoesNotDeadlockWhenAlreadyOnTheEventThread() throws Exception {
        AtomicBoolean ran = new AtomicBoolean();
        SwingUtilities.invokeAndWait(() -> {
            try {
                new SwingThreadingStrategy().runOnUi(() -> ran.set(true));
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        });
        assertTrue(ran.get());
    }
}
