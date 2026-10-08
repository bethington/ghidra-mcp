package com.xebyte.core.partition;

import ghidra.program.model.listing.Function;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Groups firmware by the set of peripheral register pages each function touches.
 *
 * <p>The signal firmware has instead of strings. An RTOS image logs little — the
 * TC-Helicon Blender firmware referenced strings from 6.5% of its functions, too
 * sparse to segment — but it drives hardware constantly: 23% of its functions touch
 * a peripheral page. Measured, this recovers drivers that project had identified by
 * hand, including {@code 0xC2} (PLL) and {@code 0xC9} (board revision).
 *
 * <p><b>Grouped by page <em>set</em>, not by a single page.</b> An earlier version
 * required a function to touch exactly one page, on the theory that a function
 * poking several peripherals is glue. That rule deleted the single best group in
 * the corpus: seven adjacent functions at member-density 1.00 driving
 * {@code 0xca} and {@code 0xcb} together — one driver over two register banks,
 * which is ordinary hardware design and not glue at all. Functions sharing an
 * identical set are grouped; the glue case is handled by capping how many pages a
 * signature may contain.
 *
 * <p>Discriminating pages only, by two independent filters. A page touched by a
 * large share of the program is a constant rather than a peripheral — on a PE,
 * {@code 0x80000000} appeared in 262 functions because it is a sign bit. And a page
 * whose members are scattered across the whole image is a sentinel that slipped
 * under that ceiling: {@code 0xff000000} claimed 158 functions at density 0.05,
 * where a real driver measures 0.67 to 1.00.
 *
 * @since 7.2.0
 */
public final class MmioPagePartitioner implements Partitioner {

    /** A page this common is a constant, not a peripheral. */
    private static final double PAGE_UBIQUITY_CEILING = 0.10;

    /** A real driver is spatially clustered; a scattered set is a shared sentinel. */
    private static final double MIN_MEMBER_DENSITY = 0.20;

    /** Beyond this many distinct peripherals, a function is glue rather than a driver. */
    private static final int MAX_SIGNATURE_PAGES = 3;

    private static final double MIN_COVERAGE = 0.08;
    private static final int MIN_MEMBERS = 2;

    @Override
    public String name() {
        return "mmio-page";
    }

    @Override
    public int precedence() {
        return 30;
    }

    @Override
    public Applicability probe(PartitionContext ctx) {
        int pool = ctx.size() - ctx.assignedCount();
        if (pool == 0) return Applicability.no("nothing left unassigned");

        Map<String, Group> groups = groupBySignature(ctx);
        if (groups.isEmpty()) {
            return Applicability.no("no high constants that discriminate between functions");
        }
        int placeable = 0;
        int kept = 0;
        for (Group g : groups.values()) {
            if (!g.qualifies()) continue;
            placeable += g.members.size();
            kept++;
        }
        if (kept == 0) {
            return Applicability.no(String.format(
                    "%d candidate page-set(s), none spatially clustered enough to be a driver "
                            + "(all below density %.2f)", groups.size(), MIN_MEMBER_DENSITY));
        }
        double coverage = placeable / (double) pool;
        return Applicability.yes(coverage, String.format(
                "%d peripheral page-set(s) covering %.1f%% of the pool%s",
                kept, coverage * 100,
                coverage < MIN_COVERAGE ? " (sparse, but each is spatially clustered)" : ""));
    }

    @Override
    public List<Partition> partition(PartitionContext ctx) {
        Map<String, Group> groups = groupBySignature(ctx);
        List<Function> fns = ctx.functions();
        List<Partition> out = new ArrayList<>();
        int seq = 0;
        for (Map.Entry<String, Group> e : groups.entrySet()) {
            Group g = e.getValue();
            if (!g.qualifies()) continue;
            List<Integer> members = g.members;

            List<Function> memberFns = new ArrayList<>(members.size());
            for (int i : members) memberFns.add(fns.get(i));

            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("peripheral_pages", e.getKey());
            evidence.put("page_count", g.pages.size());
            evidence.put("member_density", round2(g.density()));
            evidence.put("span", fns.get(members.get(0)).getEntryPoint()
                    + "-" + fns.get(members.get(members.size() - 1)).getEntryPoint());
            evidence.put("note", "functions touching exactly this set of peripheral pages");

            out.add(new Partition(
                    String.format("m%02d", seq++), name(),
                    Math.min(0.9, 0.5 + g.density() / 2), memberFns, evidence));
        }
        return out;
    }

    /**
     * Signature string to the unassigned functions carrying exactly that page set.
     *
     * <p>An identical signature is the evidence: two functions poking the same pair
     * of register banks and nothing else are almost certainly the same driver.
     */
    private Map<String, Group> groupBySignature(PartitionContext ctx) {
        PartitionContext.LiteralIndex li = ctx.literals();
        List<Integer> pool = ctx.unassigned();

        Map<Long, Integer> touchCount = new TreeMap<>();
        for (int i : pool) {
            for (long pg : li.highPages().get(i)) touchCount.merge(pg, 1, Integer::sum);
        }
        int poolSize = Math.max(1, pool.size());

        Map<String, Group> out = new TreeMap<>();
        for (int i : pool) {
            Set<Long> signature = new TreeSet<>();
            for (long pg : li.highPages().get(i)) {
                if (touchCount.get(pg) / (double) poolSize > PAGE_UBIQUITY_CEILING) continue;
                signature.add(pg);
            }
            if (signature.isEmpty() || signature.size() > MAX_SIGNATURE_PAGES) continue;
            out.computeIfAbsent(render(signature), k -> new Group(signature)).members.add(i);
        }
        for (Group g : out.values()) Collections.sort(g.members);
        return out;
    }

    private static String render(Set<Long> pages) {
        StringJoiner j = new StringJoiner("+");
        for (long p : pages) j.add(String.format("0x%02x000000", p));
        return j.toString();
    }

    private static double round2(double v) {
        return Math.round(v * 100.0) / 100.0;
    }

    /** Candidate group: the functions sharing one page-set signature. */
    private static final class Group {
        final Set<Long> pages;
        final List<Integer> members = new ArrayList<>();

        Group(Set<Long> pages) {
            this.pages = pages;
        }

        double density() {
            if (members.isEmpty()) return 0;
            int lo = members.get(0), hi = members.get(members.size() - 1);
            return members.size() / (double) (hi - lo + 1);
        }

        boolean qualifies() {
            return members.size() >= MIN_MEMBERS && density() >= MIN_MEMBER_DENSITY;
        }
    }
}
