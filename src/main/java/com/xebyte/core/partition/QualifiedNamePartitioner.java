package com.xebyte.core.partition;

import ghidra.program.model.listing.Function;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Groups by {@code Class::Method} names found in referenced log and trace strings.
 *
 * <p>This exists because RTTI usually is not there. Measured on a Windows driver:
 * RTTI recovered 22 classes covering 1.6% of functions and every one of them was a
 * CRT internal, while the driver's own class names — {@code CBiometricDevice},
 * {@code CeivMode}, {@code CBiometricDeviceUSB} — were sitting in trace strings,
 * because the binary was built {@code /GR-} but kept its logging. 231 functions
 * across 12 real classes, from a regex.
 *
 * <p>Span closure is gated on member density. {@code CEohMohEIV} occupied a solid
 * address run (density 1.00) so the unnamed functions inside its span are almost
 * certainly members; {@code CBiometricDevice} was scattered at 0.35, where closing
 * over the span would have swallowed ~140 functions belonging to something else.
 *
 * @since 7.2.0
 */
public final class QualifiedNamePartitioner implements Partitioner {

    private static final Pattern QUALIFIED =
            Pattern.compile("\\b([A-Za-z_][A-Za-z0-9_]{2,40})::([A-Za-z_~][A-Za-z0-9_]{1,40})");

    /** Below this share of members-per-span, the class is too scattered to close over. */
    private static final double CLOSURE_DENSITY_FLOOR = 0.8;

    private static final int MIN_CLASSES = 2;
    private static final double MIN_COVERAGE = 0.02;

    @Override
    public String name() {
        return "qualified-name";
    }

    @Override
    public int precedence() {
        return 20;
    }

    @Override
    public Applicability probe(PartitionContext ctx) {
        Map<Integer, String> votes = classify(ctx);
        if (votes.isEmpty()) {
            return Applicability.no("no Class::Method strings referenced by any function");
        }
        long classes = votes.values().stream().distinct().count();
        int pool = ctx.size() - ctx.assignedCount();
        double coverage = pool == 0 ? 0 : votes.size() / (double) pool;
        if (classes < MIN_CLASSES || coverage < MIN_COVERAGE) {
            return Applicability.no(String.format(
                    "only %d function(s) across %d class name(s) — below the %.0f%% floor",
                    votes.size(), classes, MIN_COVERAGE * 100));
        }
        return Applicability.yes(coverage, String.format(
                "%d functions reference %d distinct Class::Method names", votes.size(), classes));
    }

    @Override
    public List<Partition> partition(PartitionContext ctx) {
        Map<Integer, String> votes = classify(ctx);
        Map<String, List<Integer>> byClass = new TreeMap<>();
        votes.forEach((idx, cls) -> byClass.computeIfAbsent(cls, k -> new ArrayList<>()).add(idx));

        List<Function> fns = ctx.functions();
        List<Partition> out = new ArrayList<>();
        int seq = 0;
        for (Map.Entry<String, List<Integer>> e : byClass.entrySet()) {
            List<Integer> members = e.getValue();
            if (members.size() < 2) continue;
            Collections.sort(members);
            int lo = members.get(0), hi = members.get(members.size() - 1);
            double density = members.size() / (double) (hi - lo + 1);

            List<Integer> claimed = new ArrayList<>(members);
            boolean closed = density >= CLOSURE_DENSITY_FLOOR;
            if (closed) {
                for (int i = lo; i <= hi; i++) {
                    if (!ctx.isAssigned(i) && !claimed.contains(i)) claimed.add(i);
                }
                Collections.sort(claimed);
            }

            List<Function> memberFns = new ArrayList<>(claimed.size());
            for (int i : claimed) memberFns.add(fns.get(i));

            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("class_name", e.getKey());
            evidence.put("seeded_from_strings", members.size());
            evidence.put("member_density", round2(density));
            evidence.put("span_closed", closed);
            evidence.put("span", fns.get(lo).getEntryPoint() + "-" + fns.get(hi).getEntryPoint());

            out.add(new Partition(
                    String.format("q%02d", seq++),
                    name(),
                    // Density is the honest confidence here: a solid run is near-certain,
                    // a scattered one is a set of individually-evidenced functions.
                    closed ? Math.min(0.95, density) : 0.75,
                    memberFns,
                    evidence));
        }
        return out;
    }

    /** Function index to its majority-vote class name, for functions that have one. */
    private Map<Integer, String> classify(PartitionContext ctx) {
        PartitionContext.LiteralIndex li = ctx.literals();
        Map<Integer, String> out = new HashMap<>();
        for (int i : ctx.unassigned()) {
            Map<String, Integer> votes = new HashMap<>();
            for (String s : li.rawStrings().get(i)) {
                Matcher m = QUALIFIED.matcher(s);
                while (m.find()) votes.merge(m.group(1), 1, Integer::sum);
            }
            if (votes.isEmpty()) continue;
            String best = null;
            int bestCount = -1;
            for (Map.Entry<String, Integer> e : votes.entrySet()) {
                // Ties break on the lexically smaller name so a rerun is reproducible.
                if (e.getValue() > bestCount
                        || (e.getValue() == bestCount && best != null && e.getKey().compareTo(best) < 0)) {
                    bestCount = e.getValue();
                    best = e.getKey();
                }
            }
            out.put(i, best);
        }
        return out;
    }

    private static double round2(double v) {
        return Math.round(v * 100.0) / 100.0;
    }
}
