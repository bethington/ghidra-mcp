package com.xebyte.core.tree;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Immutable, lock-free progress snapshot for a tree sweep.
 *
 * <p>Swapped onto a {@code volatile} field so {@code /decompile_tree_status} never
 * needs a lock. {@code statusRevision} is monotonic and is the bridge poller's
 * change key — bump it on every swap.
 *
 * <p>{@code eligibleFunctions} is {@link com.xebyte.core.partition.PartitionContext}'s
 * floor; {@code functionsInScope} is after exclusion/includeOnly. Reporting both
 * makes a surprising exclusion visible rather than mysterious.
 *
 * <p>{@code splicedSinceSweep} counts every block rewritten since the last full sweep
 * (replaced, inserted or removed), so a tree kept current by splicing never claims to
 * be the sweep's output. {@code structuralSinceSweep} counts only inserts and removes:
 * containment placement is a local approximation of a global decision, and that number
 * makes the drift visible. Neither triggers an auto-resweep.
 *
 * <p>{@code sweptAtModification} is the program modification number the last complete
 * sweep captured; {@code reconciledAtModification} the one the tree reflects now (the
 * sweep's, advanced by each reconcile or splice). Both are null until a sweep completes.
 */
public record SweepProgress(
        Phase phase,
        int functionsTotal,
        int functionsDone,
        int functionsFailed,
        long bytesWritten,
        String currentPartition,
        long startedEpochMs,
        Long etaSeconds,
        int rootRecreated,
        String lastError,
        long statusRevision,
        int eligibleFunctions,
        int functionsInScope,
        Map<String, Integer> exclusionRemovals,
        int splicedSinceSweep,
        int structuralSinceSweep,
        Long sweptAtModification,
        Long reconciledAtModification,
        int disassembledOnDemand,
        int disassemblyFailed,
        int bodiesRecomputed,
        int bodyRecomputeFailed) {

    public enum Phase {
        IDLE,
        QUEUED,
        WAITING_FOR_ANALYSIS,
        PARTITIONING,
        DECOMPILING,
        COMPLETE,
        CANCELLED,
        FAILED,
        STALE
    }

    public SweepProgress {
        if (phase == null) {
            phase = Phase.IDLE;
        }
        functionsTotal = Math.max(0, functionsTotal);
        functionsDone = Math.max(0, functionsDone);
        functionsFailed = Math.max(0, functionsFailed);
        bytesWritten = Math.max(0, bytesWritten);
        rootRecreated = Math.max(0, rootRecreated);
        statusRevision = Math.max(0, statusRevision);
        eligibleFunctions = Math.max(0, eligibleFunctions);
        functionsInScope = Math.max(0, functionsInScope);
        splicedSinceSweep = Math.max(0, splicedSinceSweep);
        structuralSinceSweep = Math.max(0, structuralSinceSweep);
        disassembledOnDemand = Math.max(0, disassembledOnDemand);
        disassemblyFailed = Math.max(0, disassemblyFailed);
        bodiesRecomputed = Math.max(0, bodiesRecomputed);
        bodyRecomputeFailed = Math.max(0, bodyRecomputeFailed);
        exclusionRemovals = exclusionRemovals == null
                ? Map.of()
                : Map.copyOf(exclusionRemovals);
    }

    public static SweepProgress idle() {
        return new SweepProgress(
                Phase.IDLE, 0, 0, 0, 0L, null, 0L, null, 0, null, 0L,
                0, 0, Map.of(), 0, 0, null, null, 0, 0, 0, 0);
    }

    public SweepProgress withPhase(Phase newPhase) {
        return edit(b -> b.phase = newPhase);
    }

    public SweepProgress withCounts(int total, int done, int failed) {
        return edit(b -> {
            b.functionsTotal = total;
            b.functionsDone = done;
            b.functionsFailed = failed;
        });
    }

    public SweepProgress withBytesWritten(long bytes) {
        return edit(b -> b.bytesWritten = bytes);
    }

    public SweepProgress withCurrentPartition(String partition) {
        return edit(b -> b.currentPartition = partition);
    }

    public SweepProgress withStartedEpochMs(long epochMs) {
        return edit(b -> b.startedEpochMs = epochMs);
    }

    public SweepProgress withEtaSeconds(Long eta) {
        return edit(b -> b.etaSeconds = eta);
    }

    public SweepProgress withRootRecreated(int count) {
        return edit(b -> b.rootRecreated = count);
    }

    public SweepProgress withLastError(String error) {
        return edit(b -> b.lastError = error);
    }

    public SweepProgress withScope(int eligible, int inScope, Map<String, Integer> removals) {
        Map<String, Integer> map = removals == null ? Map.of() : new LinkedHashMap<>(removals);
        return edit(b -> {
            b.eligibleFunctions = eligible;
            b.functionsInScope = inScope;
            b.exclusionRemovals = map;
        });
    }

    public SweepProgress withSplicedSinceSweep(int count) {
        return edit(b -> b.splicedSinceSweep = count);
    }

    /** A complete sweep at {@code modification}: the tree is the sweep's output again. */
    public SweepProgress sweptAt(Long modification) {
        return edit(b -> {
            b.sweptAtModification = modification;
            b.reconciledAtModification = modification;
            b.splicedSinceSweep = 0;
            b.structuralSinceSweep = 0;
        });
    }

    /**
     * The tree now reflects {@code modification}, after {@code rewritten} blocks were
     * replaced, inserted or removed ({@code structural} of them inserted or removed).
     */
    public SweepProgress reconciledAt(Long modification, int rewritten, int structural) {
        return edit(b -> {
            b.reconciledAtModification = modification;
            b.splicedSinceSweep = splicedSinceSweep + rewritten;
            b.structuralSinceSweep = structuralSinceSweep + structural;
        });
    }

    public SweepProgress withDisassemblyCounts(int succeeded, int failed) {
        return edit(b -> {
            b.disassembledOnDemand = succeeded;
            b.disassemblyFailed = failed;
        });
    }

    public SweepProgress withBodyReflowCounts(int recomputed, int failed) {
        return edit(b -> {
            b.bodiesRecomputed = recomputed;
            b.bodyRecomputeFailed = failed;
        });
    }

    /** Every change is a copy with the status revision bumped: the bridge poller keys on it. */
    private SweepProgress edit(java.util.function.Consumer<Draft> change) {
        Draft d = new Draft(this);
        change.accept(d);
        return new SweepProgress(
                d.phase, d.functionsTotal, d.functionsDone, d.functionsFailed, d.bytesWritten,
                d.currentPartition, d.startedEpochMs, d.etaSeconds, d.rootRecreated, d.lastError,
                statusRevision + 1, d.eligibleFunctions, d.functionsInScope, d.exclusionRemovals,
                d.splicedSinceSweep, d.structuralSinceSweep, d.sweptAtModification,
                d.reconciledAtModification, d.disassembledOnDemand, d.disassemblyFailed,
                d.bodiesRecomputed, d.bodyRecomputeFailed);
    }

    private static final class Draft {
        Phase phase;
        int functionsTotal;
        int functionsDone;
        int functionsFailed;
        long bytesWritten;
        String currentPartition;
        long startedEpochMs;
        Long etaSeconds;
        int rootRecreated;
        String lastError;
        int eligibleFunctions;
        int functionsInScope;
        Map<String, Integer> exclusionRemovals;
        int splicedSinceSweep;
        int structuralSinceSweep;
        Long sweptAtModification;
        Long reconciledAtModification;
        int disassembledOnDemand;
        int disassemblyFailed;
        int bodiesRecomputed;
        int bodyRecomputeFailed;

        Draft(SweepProgress p) {
            phase = p.phase;
            functionsTotal = p.functionsTotal;
            functionsDone = p.functionsDone;
            functionsFailed = p.functionsFailed;
            bytesWritten = p.bytesWritten;
            currentPartition = p.currentPartition;
            startedEpochMs = p.startedEpochMs;
            etaSeconds = p.etaSeconds;
            rootRecreated = p.rootRecreated;
            lastError = p.lastError;
            eligibleFunctions = p.eligibleFunctions;
            functionsInScope = p.functionsInScope;
            exclusionRemovals = p.exclusionRemovals;
            splicedSinceSweep = p.splicedSinceSweep;
            structuralSinceSweep = p.structuralSinceSweep;
            sweptAtModification = p.sweptAtModification;
            reconciledAtModification = p.reconciledAtModification;
            disassembledOnDemand = p.disassembledOnDemand;
            disassemblyFailed = p.disassemblyFailed;
            bodiesRecomputed = p.bodiesRecomputed;
            bodyRecomputeFailed = p.bodyRecomputeFailed;
        }
    }
}
