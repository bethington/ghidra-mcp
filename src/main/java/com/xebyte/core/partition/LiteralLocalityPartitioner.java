package com.xebyte.core.partition;

import ghidra.program.model.listing.Function;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Cuts the address space where consecutive functions' referenced constants jump.
 *
 * <p>A linker collects input sections by name and concatenates them in object
 * order, so an object file's code and its {@code .rodata} advance together. Two
 * adjacent functions therefore reference nearby constants, and a large jump marks
 * an object boundary. Measured: the median gap between adjacent functions' median
 * referenced-string address is 384 bytes on a PE driver and 160 bytes on a static
 * ELF, against 243 KB and 576 KB for the same functions shuffled — 634x and 3600x.
 *
 * <p>This is a module-scale detector and cannot be pushed to file scale. Cut points
 * exist only where a function references a literal (40% of functions on the driver,
 * 10% on the ELF), so lowering the threshold shatters sparse regions into slivers
 * while dense ones stay whole — measured, a 1180-function region survived intact at
 * every threshold because it contains no cut points at all.
 *
 * @since 7.2.0
 */
public final class LiteralLocalityPartitioner implements Partitioner {

    /**
     * Multiple of the median inter-function gap that counts as an object boundary.
     * At 64x this produced 10 coherent compartments on a 3,230-function driver.
     */
    private static final long BOUNDARY_MULTIPLE = 64;

    private static final long MIN_BOUNDARY_BYTES = 2048;

    /**
     * Enough cut points to carve compartments at all. This is an absolute count, not
     * a share of the program: a share floor is the wrong test and measurably so. The
     * static ELF carries the signal on only 9.9% of its functions but that is 2,495
     * of them — twice the driver's 1,299 — and a 15% share floor excluded exactly
     * the specimen where the signal is strongest, dropping 25,231 functions into
     * blind address bands.
     */
    private static final int MIN_SIGNAL_FUNCTIONS = 100;

    /**
     * How much tighter adjacent functions' referenced constants must be than the same
     * functions shuffled. This is the real applicability test, because it measures
     * whether the linker's object ordering is actually visible. Measured: 3600x on a
     * static ELF, 634x on a PE driver, 58x on an RTOS firmware whose 44 signal
     * functions are too few to cut with anyway.
     */
    private static final double MIN_COHERENCE_RATIO = 10.0;

    private static final int MIN_PARTITION_SIZE = 3;

    @Override
    public String name() {
        return "literal-locality";
    }

    @Override
    public int precedence() {
        return 40;
    }

    @Override
    public Applicability probe(PartitionContext ctx) {
        List<Integer> signal = signalFunctions(ctx);
        int pool = ctx.size() - ctx.assignedCount();
        if (pool == 0) return Applicability.no("nothing left unassigned");
        double share = signal.size() / (double) ctx.size();
        if (signal.size() < MIN_SIGNAL_FUNCTIONS) {
            return Applicability.no(String.format(
                    "only %d function(s) reference a string — too few cut points to segment "
                            + "(need %d)", signal.size(), MIN_SIGNAL_FUNCTIONS));
        }
        double coherence = coherenceRatio(ctx, signal);
        if (coherence < MIN_COHERENCE_RATIO) {
            return Applicability.no(String.format(
                    "referenced constants are only %.1fx tighter than a shuffled baseline "
                            + "(need %.0fx) — no visible object ordering to cut on",
                    coherence, MIN_COHERENCE_RATIO));
        }
        return Applicability.yes(1.0, String.format(
                "%d of %d functions program-wide (%.1f%%) carry the signal, %.0fx tighter than "
                        + "shuffled; %d still unassigned",
                signal.size(), ctx.size(), share * 100, coherence, pool));
    }

    @Override
    public List<Partition> partition(PartitionContext ctx) {
        List<Integer> signal = signalFunctions(ctx);
        long[] med = ctx.literals().medianStringAddress();

        List<Long> deltas = new ArrayList<>();
        for (int k = 1; k < signal.size(); k++) {
            deltas.add(Math.abs(med[signal.get(k)] - med[signal.get(k - 1)]));
        }
        List<Long> sorted = new ArrayList<>(deltas);
        Collections.sort(sorted);
        long medianDelta = sorted.isEmpty() ? 0 : sorted.get(sorted.size() / 2);
        long threshold = Math.max(MIN_BOUNDARY_BYTES, medianDelta * BOUNDARY_MULTIPLE);

        // Cuts land on signal-carrying functions; everything between two cuts joins
        // the earlier one by address containment, which is a weaker claim and is
        // recorded as such in the evidence.
        List<Integer> cuts = new ArrayList<>();
        for (int k = 1; k < signal.size(); k++) {
            if (Math.abs(med[signal.get(k)] - med[signal.get(k - 1)]) > threshold) {
                cuts.add(signal.get(k));
            }
        }

        List<Integer> pool = ctx.unassigned();
        List<Function> fns = ctx.functions();
        List<Partition> out = new ArrayList<>();
        int seq = 0;
        int cutPtr = 0;
        List<Integer> current = new ArrayList<>();
        int evidenced = 0;

        for (int idx : pool) {
            while (cutPtr < cuts.size() && idx >= cuts.get(cutPtr)) {
                if (current.size() >= MIN_PARTITION_SIZE) {
                    out.add(build(seq++, current, evidenced, fns, threshold, medianDelta));
                }
                current = new ArrayList<>();
                evidenced = 0;
                cutPtr++;
            }
            current.add(idx);
            if (med[idx] >= 0) evidenced++;
        }
        if (current.size() >= MIN_PARTITION_SIZE) {
            out.add(build(seq, current, evidenced, fns, threshold, medianDelta));
        }
        return out;
    }

    private Partition build(int seq, List<Integer> members, int evidenced,
                            List<Function> fns, long threshold, long medianDelta) {
        List<Function> memberFns = new ArrayList<>(members.size());
        for (int i : members) memberFns.add(fns.get(i));
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("span", fns.get(members.get(0)).getEntryPoint()
                + "-" + fns.get(members.get(members.size() - 1)).getEntryPoint());
        evidence.put("evidence_backed_members", evidenced);
        evidence.put("members_by_containment", members.size() - evidenced);
        evidence.put("boundary_threshold_bytes", threshold);
        evidence.put("median_gap_bytes", medianDelta);
        // Confidence is the share of members that carried the signal themselves,
        // floored: a compartment where most members were swept in by address is a
        // real boundary around a poorly-evidenced interior.
        double conf = members.isEmpty() ? 0 : 0.4 + 0.5 * (evidenced / (double) members.size());
        return new Partition(String.format("c%02d", seq), name(), Math.min(0.9, conf), memberFns, evidence);
    }

    /**
     * Signal-carrying functions across the <em>whole</em> program, not just the
     * unassigned pool.
     *
     * <p>Object boundaries are a fact about how the linker laid out the image; they
     * do not move because an earlier strategy claimed some functions. Restricting
     * this to leftovers measurably destroyed them: on a 3,230-function driver the
     * standalone detector found 10 compartments, and the same detector run after
     * two earlier strategies had removed 597 functions found 6, one of which held
     * 866 functions with only 49 carrying any evidence.
     */
    /**
     * Median adjacent gap against the median gap of the same values shuffled.
     *
     * <p>A ratio near 1 means the referenced constants are in no particular order and
     * any boundary found would be an artefact. Shuffling with a fixed seed keeps a
     * rerun reproducible, which matters because this decides whether a strategy runs.
     */
    private double coherenceRatio(PartitionContext ctx, List<Integer> signal) {
        long[] med = ctx.literals().medianStringAddress();
        List<Long> ordered = new ArrayList<>(signal.size());
        for (int i : signal) ordered.add(med[i]);

        List<Long> adjacent = gaps(ordered);
        List<Long> shuffledValues = new ArrayList<>(ordered);
        java.util.Collections.shuffle(shuffledValues, new java.util.Random(42));
        List<Long> shuffled = gaps(shuffledValues);
        if (adjacent.isEmpty() || shuffled.isEmpty()) return 0;

        Collections.sort(adjacent);
        Collections.sort(shuffled);
        long a = Math.max(1, adjacent.get(adjacent.size() / 2));
        long s = shuffled.get(shuffled.size() / 2);
        return s / (double) a;
    }

    private static List<Long> gaps(List<Long> values) {
        List<Long> out = new ArrayList<>(Math.max(0, values.size() - 1));
        for (int k = 1; k < values.size(); k++) {
            out.add(Math.abs(values.get(k) - values.get(k - 1)));
        }
        return out;
    }

    private List<Integer> signalFunctions(PartitionContext ctx) {
        long[] med = ctx.literals().medianStringAddress();
        List<Integer> out = new ArrayList<>();
        for (int i = 0; i < ctx.size(); i++) if (med[i] >= 0) out.add(i);
        return out;
    }
}
