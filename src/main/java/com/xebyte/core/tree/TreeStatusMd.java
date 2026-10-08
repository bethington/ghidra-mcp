package com.xebyte.core.tree;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Locale;

/**
 * STATUS.md renderer — shared by create/start/stop endpoints and {@link SweepJob}.
 *
 * <p>Answers "is this tree trustworthy?" with zero Ghidra calls. Written
 * <em>before</em> any rewrite as {@code dirty} and again after; a crash leaves {@code dirty}.
 *
 * <p>States once settled: {@code clean} is exactly the last sweep's output; {@code spliced}
 * has been kept current block by block since that sweep ({@code spliced_since_sweep} says how
 * many); {@code stale} is known to diverge from the program ({@code last_error} says why);
 * {@code empty} was never swept. The modification numbers never go blank once a sweep has
 * completed: every writer reads them from the tree's progress.
 */
public final class TreeStatusMd {

    private TreeStatusMd() {
    }

    /** The state of a sweep in flight or just ended. */
    public static String stateForPhase(SweepProgress.Phase phase) {
        return switch (phase) {
            case QUEUED, WAITING_FOR_ANALYSIS, PARTITIONING, DECOMPILING -> "dirty";
            case COMPLETE -> "clean";
            case CANCELLED -> "cancelled";
            case FAILED -> "failed";
            case STALE -> "stale";
            case IDLE -> "empty";
        };
    }

    /** The state once a reconcile or splice has finished writing. */
    public static String settledState(SweepProgress p) {
        if (p.phase() == SweepProgress.Phase.COMPLETE
                || (p.phase() == SweepProgress.Phase.IDLE && p.splicedSinceSweep() > 0)) {
            return p.splicedSinceSweep() > 0 ? "spliced" : "clean";
        }
        return stateForPhase(p.phase());
    }

    public static String render(DecompTree decompTree, String state) {
        SweepProgress p = decompTree.progress();
        StringBuilder sb = new StringBuilder();
        sb.append("# DecompTree STATUS\n\n");
        sb.append("state: ").append(state).append('\n');
        sb.append("phase: ").append(p.phase().name().toLowerCase(Locale.ROOT)).append('\n');
        sb.append("tree_id: ").append(decompTree.id()).append('\n');
        // Modification numbers start over on every open: they compare only within `session`.
        // saved_time / file_version name the saved program the tree reflects across restarts.
        DecompTree.Session session = decompTree.session();
        if (session != null) {
            sb.append("session: ").append(session.epoch()).append('\n');
        }
        sb.append("swept_at_modification_number: ").append(orBlank(p.sweptAtModification())).append('\n');
        sb.append("reconciled_at_modification_number: ")
                .append(orBlank(p.reconciledAtModification())).append('\n');
        if (session != null) {
            sb.append("saved_time: ").append(Instant.ofEpochMilli(session.savedTime())).append('\n');
            if (session.fileVersion() != null) {
                sb.append("file_version: ").append(session.fileVersion()).append('\n');
            }
            sb.append("includes_unsaved_edits: ").append(session.unsavedEdits()).append('\n');
        }
        sb.append("functions_total: ").append(p.functionsTotal()).append('\n');
        sb.append("functions_done: ").append(p.functionsDone()).append('\n');
        sb.append("functions_failed: ").append(p.functionsFailed()).append('\n');
        sb.append("disassembled_on_demand: ").append(p.disassembledOnDemand()).append('\n');
        sb.append("disassembly_failed: ").append(p.disassemblyFailed()).append('\n');
        sb.append("bodies_recomputed: ").append(p.bodiesRecomputed()).append('\n');
        sb.append("body_recompute_failed: ").append(p.bodyRecomputeFailed()).append('\n');
        sb.append("bytes_written: ").append(p.bytesWritten()).append('\n');
        sb.append("spliced_since_sweep: ").append(p.splicedSinceSweep()).append('\n');
        sb.append("structural_since_sweep: ").append(p.structuralSinceSweep()).append('\n');
        if (p.lastError() != null) {
            sb.append("last_error: ").append(p.lastError().replace('\n', ' ')).append('\n');
        }
        sb.append("updated: ").append(Instant.now()).append('\n');
        return sb.toString();
    }

    public static void write(DecompTree decompTree, String state) throws IOException {
        decompTree.root().writeFile(Path.of(TreeLayout.statusMd()), render(decompTree, state));
    }

    private static String orBlank(Long value) {
        return value != null ? value.toString() : "";
    }
}
