package com.xebyte.core.tree;

import com.xebyte.core.ServiceUtils;
import com.xebyte.core.partition.Partition;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Single answer to "is this function in scope for this tree?".
 *
 * <p>Sweep and {@code /decompile_tree_configure} both call here so they cannot disagree.
 * PARTITION rules need a slug from the cascade — callers must not evaluate them
 * before partitioning. TAG/RANGE need only the function (and a compiled range).
 *
 * <p>{@code includeOnly} is applied first (keep only matches when non-empty);
 * exclusions then subtract. Neither re-implements {@link
 * com.xebyte.core.partition.PartitionContext}'s eligibility floor.
 */
public final class ExclusionEvaluator {

    private final List<ExclusionRule> includeOnly;
    private final List<ExclusionRule> exclusions;
    private final Map<ExclusionRule, RangeBounds> ranges;

    private ExclusionEvaluator(
            List<ExclusionRule> includeOnly,
            List<ExclusionRule> exclusions,
            Map<ExclusionRule, RangeBounds> ranges) {
        this.includeOnly = includeOnly;
        this.exclusions = exclusions;
        this.ranges = ranges;
    }

    /**
     * Compile config rules against {@code program}. RANGE bounds are resolved
     * here via the program's {@code AddressFactory} so a bad range fails at
     * configure/create time, not mid-sweep.
     *
     * @throws IllegalArgumentException when a RANGE rule cannot be resolved
     */
    public static ExclusionEvaluator of(Program program, TreeConfig config) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(config, "config");
        Map<ExclusionRule, RangeBounds> ranges = new LinkedHashMap<>();
        compileRanges(program, config.exclusions(), ranges);
        compileRanges(program, config.includeOnly(), ranges);
        return new ExclusionEvaluator(
                List.copyOf(config.includeOnly()),
                List.copyOf(config.exclusions()),
                Map.copyOf(ranges));
    }

    /** Validate RANGE rules without building a full evaluator (create path). */
    public static void validateRanges(Program program, TreeConfig config) {
        of(program, config);
    }

    public boolean matches(ExclusionRule rule, Function func, String partitionSlug) {
        Objects.requireNonNull(rule, "rule");
        Objects.requireNonNull(func, "func");
        return switch (rule.kind()) {
            case TAG -> hasTag(func, rule.value());
            case PARTITION -> rule.value().equals(partitionSlug);
            case RANGE -> entryInRange(func, ranges.get(rule));
        };
    }

    /**
     * {@code includeOnly} first, then exclusions. A function with an unknown
     * partition slug simply fails every PARTITION predicate — safe for
     * TAG/RANGE-only decisions, and correct once the cascade has assigned slugs.
     */
    public boolean isInScope(Function func, String partitionSlug) {
        if (!includeOnly.isEmpty()) {
            boolean any = false;
            for (ExclusionRule rule : includeOnly) {
                if (matches(rule, func, partitionSlug)) {
                    any = true;
                    break;
                }
            }
            if (!any) {
                return false;
            }
        }
        for (ExclusionRule rule : exclusions) {
            if (matches(rule, func, partitionSlug)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Filter cascade output. Call only after partitioning — PARTITION rules
     * read the slug. Empty compartments are dropped so the sweep never writes
     * an empty {@code .c}.
     */
    public FilterResult filterPartitions(List<Partition> partitions, int eligibleFunctions) {
        Map<String, Integer> removed = new LinkedHashMap<>();
        // Preserve rule order in the report so agents can match config ↔ counts.
        for (ExclusionRule rule : includeOnly) {
            removed.put(spec(rule), 0);
        }
        if (!includeOnly.isEmpty()) {
            removed.put("include_only_miss", 0);
        }
        for (ExclusionRule rule : exclusions) {
            removed.put(spec(rule), 0);
        }

        List<Partition> kept = new ArrayList<>();
        int inScope = 0;

        for (Partition part : partitions) {
            List<Function> members = new ArrayList<>();
            for (Function func : part.members()) {
                Decision d = decide(func, part.slug());
                if (d.inScope()) {
                    members.add(func);
                    inScope++;
                } else if (d.reasonKey() != null) {
                    removed.merge(d.reasonKey(), 1, Integer::sum);
                }
            }
            if (!members.isEmpty()) {
                kept.add(new Partition(
                        part.slug(), part.method(), part.confidence(),
                        List.copyOf(members), part.evidence()));
            }
        }

        // Drop zero counters so the status payload stays readable when a rule
        // matched nothing — a surprising exclusion is the one with N>0.
        Map<String, Integer> nonzero = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> e : removed.entrySet()) {
            if (e.getValue() > 0) {
                nonzero.put(e.getKey(), e.getValue());
            }
        }

        return new FilterResult(
                List.copyOf(kept),
                new ScopeStats(eligibleFunctions, inScope, Map.copyOf(nonzero)));
    }

    private Decision decide(Function func, String partitionSlug) {
        if (!includeOnly.isEmpty()) {
            boolean any = false;
            for (ExclusionRule rule : includeOnly) {
                if (matches(rule, func, partitionSlug)) {
                    any = true;
                    break;
                }
            }
            if (!any) {
                return Decision.out("include_only_miss");
            }
        }
        for (ExclusionRule rule : exclusions) {
            if (matches(rule, func, partitionSlug)) {
                return Decision.out(spec(rule));
            }
        }
        return Decision.in();
    }

    private static boolean hasTag(Function func, String tagName) {
        Set<FunctionTag> tags = func.getTags();
        if (tags == null || tags.isEmpty()) {
            return false;
        }
        for (FunctionTag tag : tags) {
            if (tag != null && tagName.equals(tag.getName())) {
                return true;
            }
        }
        return false;
    }

    private static boolean entryInRange(Function func, RangeBounds bounds) {
        if (bounds == null) {
            return false;
        }
        Address entry = func.getEntryPoint();
        if (entry == null) {
            return false;
        }
        // Inclusive both ends: "contained in" for agent-authored hex ranges.
        return entry.compareTo(bounds.start()) >= 0 && entry.compareTo(bounds.end()) <= 0;
    }

    private static void compileRanges(
            Program program, List<ExclusionRule> rules, Map<ExclusionRule, RangeBounds> into) {
        for (ExclusionRule rule : rules) {
            if (rule.kind() != ExclusionRule.Kind.RANGE) {
                continue;
            }
            if (into.containsKey(rule)) {
                continue;
            }
            into.put(rule, parseRange(program, rule));
        }
    }

    /**
     * Resolve {@code lo-hi} through the program's address factory. Syntax is
     * already gated by {@link ExclusionRule#parse}; this catches "hex that is
     * not an address in this program" before a sweep would silently match nothing.
     */
    static RangeBounds parseRange(Program program, ExclusionRule rule) {
        String value = rule.value();
        int dash = splitRangeDash(value);
        if (dash < 0) {
            throw new IllegalArgumentException(
                    "malformed range exclusion 'range:" + value + "' "
                            + "(accepted forms: tag:<name>, partition:<slug>, range:<lo>-<hi>)");
        }
        String lo = value.substring(0, dash).trim();
        String hi = value.substring(dash + 1).trim();
        if (lo.isEmpty() || hi.isEmpty()) {
            throw new IllegalArgumentException(
                    "malformed range exclusion 'range:" + value + "' "
                            + "(accepted forms: tag:<name>, partition:<slug>, range:<lo>-<hi>)");
        }
        Address start = ServiceUtils.parseAddress(program, lo);
        if (start == null) {
            throw new IllegalArgumentException(
                    "malformed range exclusion 'range:" + value + "': cannot resolve start '"
                            + lo + "'"
                            + (ServiceUtils.getLastParseError() != null
                            ? " (" + ServiceUtils.getLastParseError() + ")"
                            : ""));
        }
        Address end = ServiceUtils.parseAddress(program, hi);
        if (end == null) {
            throw new IllegalArgumentException(
                    "malformed range exclusion 'range:" + value + "': cannot resolve end '"
                            + hi + "'"
                            + (ServiceUtils.getLastParseError() != null
                            ? " (" + ServiceUtils.getLastParseError() + ")"
                            : ""));
        }
        if (start.getAddressSpace() != end.getAddressSpace()) {
            throw new IllegalArgumentException(
                    "malformed range exclusion 'range:" + value
                            + "': start and end must be in the same address space");
        }
        if (start.compareTo(end) > 0) {
            throw new IllegalArgumentException(
                    "malformed range exclusion 'range:" + value
                            + "': start is after end");
        }
        return new RangeBounds(start, end);
    }

    /**
     * Split on the dash that separates lo/hi. Prefer the last {@code -} so a
     * space-qualified form like {@code mem:1000-mem:2000} still works; a lone
     * leading/trailing dash is rejected by the empty-side check.
     */
    static int splitRangeDash(String value) {
        if (value == null) {
            return -1;
        }
        return value.lastIndexOf('-');
    }

    static String spec(ExclusionRule rule) {
        return rule.kind().name().toLowerCase() + ":" + rule.value();
    }

    public record RangeBounds(Address start, Address end) {}

    public record ScopeStats(
            int eligibleFunctions,
            int functionsInScope,
            Map<String, Integer> removedByRule) {}

    public record FilterResult(List<Partition> partitions, ScopeStats stats) {}

    private record Decision(boolean inScope, String reasonKey) {
        static Decision in() {
            return new Decision(true, null);
        }

        static Decision out(String reasonKey) {
            return new Decision(false, reasonKey);
        }
    }
}
