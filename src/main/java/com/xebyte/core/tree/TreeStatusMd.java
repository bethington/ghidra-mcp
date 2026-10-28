package com.xebyte.core.tree;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

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
        if (phase.isBusy()) {
            return "dirty";
        }
        return switch (phase) {
            case COMPLETE -> "clean";
            case CANCELLED -> "cancelled";
            case FAILED -> "failed";
            case STALE -> "stale";
            case IDLE -> "empty";
            default -> "dirty"; // busy phases already handled
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
        p.appendStatusFields((k, v) -> sb.append(k).append(": ").append(v).append('\n'), false);
        p.appendStatusFields((k, v) -> sb.append(k).append(": ").append(v).append('\n'), true);
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

    /** STATUS.md's {@code key: value} lines; a blank value reads as absent. */
    public record StatusFile(Map<String, String> fields) {
        public String state() {
            return fields.get("state");
        }

        public Long number(String key) {
            try {
                return fields.containsKey(key) ? Long.parseLong(fields.get(key)) : null;
            } catch (NumberFormatException e) {
                return null;
            }
        }

        public int count(String key) {
            Long n = number(key);
            return n == null ? 0 : n.intValue();
        }

        public Long sweptAtModificationNumber() {
            return number("swept_at_modification_number");
        }

        /** What the tree reflects: the last reconcile, else the sweep (older files lack it). */
        public Long reconciledAtModificationNumber() {
            Long reconciled = number("reconciled_at_modification_number");
            return reconciled != null ? reconciled : sweptAtModificationNumber();
        }
    }

    public static StatusFile read(Path root) {
        Path statusPath = root.resolve(TreeLayout.statusMd());
        Map<String, String> fields = new LinkedHashMap<>();
        if (Files.isRegularFile(statusPath)) {
            try {
                for (String line : Files.readString(statusPath, StandardCharsets.UTF_8).split("\n")) {
                    int colon = line.indexOf(':');
                    if (colon > 0 && !line.startsWith("#")) {
                        String value = line.substring(colon + 1).trim();
                        if (!value.isEmpty()) {
                            fields.put(line.substring(0, colon).trim(), value);
                        }
                    }
                }
            } catch (IOException e) {
                // unreadable reads as absent
            }
        }
        return new StatusFile(fields);
    }
}
