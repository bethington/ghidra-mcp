package com.xebyte.core.partition;

import com.xebyte.core.JsonHelper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs partitioners in precedence order over a shrinking pool of functions.
 *
 * <p>Records both what was placed and what was <em>skipped and why</em>, because
 * the tree's {@code index.md} has to be able to tell an agent that RTTI was
 * tried and found to cover 1.6% of the binary. "This strategy did not apply" is a
 * fact about the binary and belongs in the output.
 *
 * @since 7.2.0
 */
public final class PartitionCascade {

    /** Matches {@link com.xebyte.core.PartitionService}'s default band width. */
    public static final int DEFAULT_BAND_SIZE = 20;

    private final List<Partitioner> partitioners;

    public PartitionCascade(List<Partitioner> partitioners) {
        this.partitioners = new ArrayList<>(partitioners);
        this.partitioners.sort(Comparator.comparingInt(Partitioner::precedence));
    }

    /**
     * Shared cascade chain for {@code /partition_program} and tree sweeps.
     *
     * <p>Empty / null {@code strategyNames} means the full cascade. Unknown names
     * are ignored (callers that need a hard error on an empty selection check
     * the result themselves — the HTTP endpoint does, the sweep falls through
     * to address bands only when every named strategy was unknown).
     */
    public static List<Partitioner> buildChain(int bandSize, Collection<String> strategyNames) {
        int band = bandSize > 0 ? bandSize : DEFAULT_BAND_SIZE;
        List<Partitioner> all = List.of(
                new QualifiedNamePartitioner(),
                new MmioPagePartitioner(),
                new LiteralLocalityPartitioner(),
                new AddressBandPartitioner(band));
        if (strategyNames == null || strategyNames.isEmpty()) {
            return all;
        }
        List<Partitioner> chosen = new ArrayList<>();
        for (Partitioner p : all) {
            if (strategyNames.contains(p.name())) {
                chosen.add(p);
            }
        }
        return chosen;
    }

    public Result run(PartitionContext ctx) {
        List<Partition> all = new ArrayList<>();
        Map<String, Object> log = new LinkedHashMap<>();

        for (Partitioner p : partitioners) {
            int poolBefore = ctx.size() - ctx.assignedCount();
            if (poolBefore == 0) {
                log.put(p.name(), JsonHelper.mapOf("status", "skipped", "reason", "nothing left unassigned"));
                continue;
            }
            Applicability a = p.probe(ctx);
            if (!a.applicable()) {
                log.put(p.name(), JsonHelper.mapOf("status", "not_applicable", "reason", a.reason()));
                continue;
            }
            List<Partition> produced = p.partition(ctx);
            int placed = 0;
            for (Partition part : produced) {
                List<Integer> idx = new ArrayList<>(part.size());
                for (var f : part.members()) {
                    Integer i = ctx.indexOf(f.getEntryPoint());
                    // Already claimed by an earlier, higher-evidence strategy: that
                    // claim wins. Overlap is expected, not an error — a class-named
                    // function is also inside some address band.
                    if (i != null && !ctx.isAssigned(i)) idx.add(i);
                }
                if (idx.isEmpty()) continue;
                ctx.markAssigned(idx);
                placed += idx.size();
                all.add(part);
            }
            log.put(p.name(), JsonHelper.mapOf(
                    "status", "ran",
                    "expected_coverage", a.expectedCoverage(),
                    "reason", a.reason(),
                    "partitions", produced.size(),
                    "functions_placed", placed,
                    "pool_before", poolBefore));
        }
        return new Result(all, log, ctx.size(), ctx.assignedCount());
    }

    public record Result(
            List<Partition> partitions,
            Map<String, Object> strategyLog,
            int totalFunctions,
            int assignedFunctions) {
    }
}
