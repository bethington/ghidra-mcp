package com.xebyte.core;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.data.DomainFileProxy;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

import java.io.IOException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Saving a program without losing to Ghidra's own background analysis.
 *
 * <p>Three copies of this lived in {@code ProgramScriptService}, the GUI provider's
 * write-through cache and the headless provider's close path; they had drifted
 * (only one retried, only one waited, one skipped programs the others saved).
 *
 * <p><b>The race.</b> {@link AutoAnalysisManager} schedules its own "Auto Analysis"
 * task whenever a program changes, independent of anything this server calls. If
 * that task's transaction is still open when {@code save()} runs, the save throws
 * {@code IOException("Unable to lock due to active transaction")}. Waiting for
 * analysis first narrows the window but does not close it -- Ghidra logs the task as
 * complete and the save's lock failure in the same instant -- so the save retries
 * with a short backoff on exactly that message.
 */
public final class ProgramSaves {

    private ProgramSaves() {}

    private static final int MAX_ATTEMPTS = 4;
    private static final String LOCK_RACE = "Unable to lock due to active transaction";

    /**
     * Re-entrancy guard for {@link AutoAnalysisManager#waitForAnalysis}.
     *
     * <p>{@code waitForAnalysis(null, monitor)} can re-enter itself:
     * {@code scheduleWorker -> waitForAnalysis -> analysisWorkerCallback ->
     * AnalysisWorkerCommand.applyTo -> scheduleWorker}, with nothing bounding the loop.
     * Measured from a thread dump on 2026-08-11: all three GhidraMCP-HTTP threads --
     * the whole pool -- stuck 317 frames deep, ~9,400 CPU-seconds each, every endpoint
     * timing out and the only recovery a restart. A thread already inside a wait does
     * not need a second one, so a nested call returns at once and the recursion cannot
     * form. There must be exactly ONE of these: two guards would not guard each other,
     * and the recursion crosses class boundaries on a single thread.
     */
    static final ThreadLocal<Boolean> IN_ANALYSIS_WAIT = ThreadLocal.withInitial(() -> Boolean.FALSE);

    /**
     * Why edits to {@code program} cannot be saved, or null when they can.
     *
     * <p>A versioned file that is not checked out opens as an in-memory copy of its latest
     * version, behind a {@link DomainFileProxy}: every edit applies, and the save throws
     * "Location does not exist for a save operation!", which names neither the cause nor
     * the remedy. Measured on a shared project on 2026-10-01: an agent made dozens of renames
     * that way, every one reported success, and all of them vanished on close.
     */
    public static String unsaveableReason(Program program) {
        if (program == null || program.canSave()) {
            return null;
        }
        DomainFile df = program.getDomainFile();
        String path = df != null ? df.getPathname() : program.getName();
        if (df instanceof DomainFileProxy) {
            return path + " is not checked out: it is open as an in-memory copy of a versioned "
                + "file (or of a read-only project), so edits apply but cannot be saved and are "
                + "lost when it closes. Check it out with /server/version_control/checkout, which "
                + "reopens it writable when it has no edits yet.";
        }
        return path + " cannot be saved: its project file is read-only.";
    }

    /** A save call that may throw what {@code DomainFile.save}/{@code Program.save} throw. */
    @FunctionalInterface
    public interface Save {
        void run() throws IOException, CancelledException;
    }

    /**
     * How long a save waits for analysis before saving anyway.
     *
     * <p>{@code waitForAnalysis} in a tool queues a "Wait for Analysis" command on the
     * analysis tool and then calls {@code cmd.wait()} with no timeout. If that tool never
     * runs the command, the caller waits forever. Measured from a thread dump on 2026-10-27:
     * three {@code save_program} calls, each parked there at ~0 CPU with no analysis thread
     * alive -- the whole 3-thread HTTP pool, so even {@code /mcp/health} hung until Ghidra
     * restarted. (Not the 2026-08-11 recursion; {@link #IN_ANALYSIS_WAIT} holds.) The wait
     * only narrows a race {@link #withRetry} already retries, so it must never outlive this.
     */
    static final long SAVE_ANALYSIS_WAIT_MS = 20_000L;

    private static final ScheduledExecutorService WAIT_TIMER =
        Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "GhidraMCP-AnalysisWaitTimer");
            t.setDaemon(true);
            return t;
        });

    /** One wait for analysis, given a monitor that cancelling must release. */
    @FunctionalInterface
    interface AnalysisWait {
        void await(TaskMonitor monitor) throws Exception;
    }

    /**
     * Wait for pending auto-analysis, unless this thread is already waiting. Best-effort.
     *
     * <p>Unbounded: for callers that started analysis themselves and need it finished
     * (the import/auto-analyze path). A save must use {@link #withRetry}, which bounds it.
     */
    public static void awaitAnalysis(Program program) {
        awaitAnalysis(program, 0L);
    }

    /**
     * Wait at most {@code timeoutMs} (0 = no bound) for pending auto-analysis.
     *
     * @return false only when the bound expired and the wait was abandoned
     */
    static boolean awaitAnalysis(Program program, long timeoutMs) {
        return boundedWait(
            monitor -> AutoAnalysisManager.getAnalysisManager(program).waitForAnalysis(null, monitor),
            timeoutMs);
    }

    /**
     * Run {@code wait} under {@link #IN_ANALYSIS_WAIT}, cancelling its monitor after
     * {@code timeoutMs}. Cancelling is what releases {@code scheduleWorker}: the queued
     * command listens to the monitor and wakes the waiter, so the monitor must be
     * cancel-enabled -- {@code TaskMonitor.DUMMY} is not, which is why the old call could
     * not be released by anything.
     */
    static boolean boundedWait(AnalysisWait wait, long timeoutMs) {
        if (Boolean.TRUE.equals(IN_ANALYSIS_WAIT.get())) {
            return true;
        }
        IN_ANALYSIS_WAIT.set(Boolean.TRUE);
        TaskMonitor monitor = new TaskMonitorAdapter(true);
        AtomicBoolean timedOut = new AtomicBoolean();
        ScheduledFuture<?> timer = timeoutMs > 0
            ? WAIT_TIMER.schedule(() -> {
                timedOut.set(true);
                monitor.cancel();
            }, timeoutMs, TimeUnit.MILLISECONDS)
            : null;
        try {
            wait.await(monitor);
        } catch (Exception | LinkageError e) {
            if (!timedOut.get()) {
                // Let the save itself surface any real failure rather than mask it here.
                Msg.warn(ProgramSaves.class, "Waiting for analysis failed, saving anyway: " + e.getMessage());
            }
        } finally {
            if (timer != null) {
                timer.cancel(false);
            }
            IN_ANALYSIS_WAIT.set(Boolean.FALSE);
        }
        if (timedOut.get()) {
            Msg.warn(ProgramSaves.class, "Auto-analysis did not finish within " + timeoutMs
                + " ms (Ghidra's analysis tool never ran the wait); saving anyway");
            return false;
        }
        return true;
    }

    /** Run {@code save}, waiting (bounded) for analysis first and retrying the lock race. */
    public static void withRetry(Program program, Save save) throws IOException, CancelledException {
        boolean waitable = true;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            // One abandoned wait means the analysis tool is not running waits at all;
            // another would only cost the same bound again for nothing.
            if (waitable) {
                waitable = awaitAnalysis(program, SAVE_ANALYSIS_WAIT_MS);
            }
            try {
                save.run();
                return;
            } catch (IOException e) {
                String msg = e.getMessage();
                if (msg == null || !msg.contains(LOCK_RACE) || attempt == MAX_ATTEMPTS) {
                    throw e;
                }
                Msg.warn(ProgramSaves.class, "Save raced Ghidra's own auto-analysis transaction "
                    + "(attempt " + attempt + "/" + MAX_ATTEMPTS + "), retrying: " + msg);
                try {
                    Thread.sleep(150L * attempt);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
        }
    }

    /**
     * Save a program's unsaved changes to its DomainFile before its handle is released.
     *
     * <p>Deliberately NOT gated on {@code Program.canSave()}: that is false for a program
     * upgraded on open (its DBHandle cannot update in place), which
     * {@code DomainFile.save()} handles fine. Skipping it would silently discard edits an
     * endpoint already reported as done; attempting it either saves or says it could not.
     * The save lands in the local working copy only -- a check-in stays explicit.
     *
     * @return false only when there were changes and they could not be saved
     */
    public static boolean saveIfChanged(Program program, TaskMonitor monitor) {
        if (program == null || program.isClosed() || !program.isChanged()) {
            return true;
        }
        DomainFile df = program.getDomainFile();
        if (df == null) {
            Msg.error(ProgramSaves.class, "Unsaved changes LOST in " + program.getName()
                + ": it has no project file to save to");
            return false;
        }
        try {
            withRetry(program, () -> df.save(monitor));
            Msg.info(ProgramSaves.class, "Saved " + df.getPathname() + " before release");
            return true;
        } catch (Exception e) {
            Msg.error(ProgramSaves.class, "Unsaved changes LOST in " + df.getPathname() + ": "
                + e.getMessage(), e);
            return false;
        }
    }
}
