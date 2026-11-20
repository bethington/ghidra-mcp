package com.xebyte.core;

import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Test;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

/**
 * Measured live on 2026-10-27: three save_program calls parked forever in
 * AutoAnalysisManager.scheduleWorker's untimed cmd.wait(), because the analysis tool never
 * ran the queued "Wait for Analysis" command and TaskMonitor.DUMMY cannot be cancelled. That
 * was the whole HTTP pool, so every endpoint hung until Ghidra restarted.
 */
public class ProgramSavesAnalysisWaitTest {

    @After
    public void clear() {
        ProgramSaves.IN_ANALYSIS_WAIT.remove();
    }

    /**
     * What scheduleWorker does when its command never runs: the command listens to the
     * worker monitor, the waiter sleeps on the command, and only a cancel wakes it.
     */
    private static void neverRunsUntilCancelled(TaskMonitor monitor) throws Exception {
        Object cmd = new Object();
        monitor.addCancelledListener(() -> {
            synchronized (cmd) {
                cmd.notifyAll();
            }
        });
        synchronized (cmd) {
            while (!monitor.isCancelled()) {
                cmd.wait();
            }
        }
        monitor.checkCancelled();
    }

    @Test(timeout = 10_000)
    public void aWaitTheToolNeverRunsIsAbandonedAtTheBound() {
        long start = System.nanoTime();
        assertFalse(ProgramSaves.boundedWait(ProgramSavesAnalysisWaitTest::neverRunsUntilCancelled, 200));
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertTrue("released after " + ms + " ms", ms >= 150 && ms < 5_000);
    }

    @Test
    public void theMonitorIsCancellableBecauseDummyIsWhatMadeThisUnrecoverable() {
        AtomicBoolean enabled = new AtomicBoolean();
        ProgramSaves.boundedWait(m -> enabled.set(m.isCancelEnabled()), 1_000);
        assertTrue(enabled.get());
    }

    @Test
    public void analysisThatFinishesInTimeIsNotCancelled() {
        AtomicBoolean cancelled = new AtomicBoolean(true);
        assertTrue(ProgramSaves.boundedWait(m -> {
            Thread.sleep(50);
            cancelled.set(m.isCancelled());
        }, 5_000));
        assertFalse(cancelled.get());
    }

    @Test
    public void noBoundMeansNoTimerForTheImportPath() {
        AtomicBoolean cancelled = new AtomicBoolean(true);
        assertTrue(ProgramSaves.boundedWait(m -> {
            Thread.sleep(300);
            cancelled.set(m.isCancelled());
        }, 0));
        assertFalse(cancelled.get());
    }

    @Test
    public void aFailingWaitIsNotATimeout() {
        assertTrue(ProgramSaves.boundedWait(m -> {
            throw new IllegalStateException("boom");
        }, 5_000));
    }

    @Test(timeout = 10_000)
    public void theReentrancyGuardIsReleasedAfterATimeout() {
        ProgramSaves.boundedWait(ProgramSavesAnalysisWaitTest::neverRunsUntilCancelled, 100);
        assertFalse(ProgramSaves.IN_ANALYSIS_WAIT.get());
        AtomicInteger ran = new AtomicInteger();
        assertTrue(ProgramSaves.boundedWait(m -> ran.incrementAndGet(), 1_000));
        assertEquals(1, ran.get());
    }

    @Test
    public void aNestedWaitStillReturnsAtOnce() {
        AtomicInteger inner = new AtomicInteger();
        ProgramSaves.boundedWait(m -> ProgramSaves.boundedWait(n -> inner.incrementAndGet(), 1_000), 1_000);
        assertEquals(0, inner.get());
    }

    @Test
    public void theSaveBoundIsShorterThanAnHttpRequestTimeout() {
        assertTrue(ProgramSaves.SAVE_ANALYSIS_WAIT_MS > 0);
        assertTrue(ProgramSaves.SAVE_ANALYSIS_WAIT_MS <= 30_000);
    }
}
