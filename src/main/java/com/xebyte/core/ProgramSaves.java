package com.xebyte.core;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

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

    /** A save call that may throw what {@code DomainFile.save}/{@code Program.save} throw. */
    @FunctionalInterface
    public interface Save {
        void run() throws IOException, CancelledException;
    }

    /** Wait for pending auto-analysis, unless this thread is already waiting. Best-effort. */
    public static void awaitAnalysis(Program program) {
        if (Boolean.TRUE.equals(IN_ANALYSIS_WAIT.get())) {
            return;
        }
        IN_ANALYSIS_WAIT.set(Boolean.TRUE);
        try {
            AutoAnalysisManager.getAnalysisManager(program).waitForAnalysis(null, TaskMonitor.DUMMY);
        } catch (Exception | LinkageError e) {
            // Let the save itself surface any real failure rather than mask it here.
            Msg.warn(ProgramSaves.class, "Waiting for analysis failed, saving anyway: " + e.getMessage());
        } finally {
            IN_ANALYSIS_WAIT.set(Boolean.FALSE);
        }
    }

    /** Run {@code save}, waiting for analysis first and retrying the lock race. */
    public static void withRetry(Program program, Save save) throws IOException, CancelledException {
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            awaitAnalysis(program);
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
