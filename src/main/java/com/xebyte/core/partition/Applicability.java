package com.xebyte.core.partition;

/**
 * A partitioner's own answer to "can I run here, and how much would I cover?".
 *
 * <p>The cascade probes before it partitions because <em>which strategy works is
 * binary-specific</em>, and measurably so: RTTI covered 1.6% of a Windows driver
 * (all of it CRT internals) and 0% of two firmware images; MMIO pages covered 23%
 * of an ARM firmware and produced nothing but noise on the same driver. A fixed
 * priority order would apply whichever strategy happened to be first rather than
 * whichever one has evidence.
 *
 * <p>{@code reason} is printed verbatim into the tree's {@code index.md} when
 * a strategy is skipped, so it must read as an explanation and not a status code.
 *
 * @since 7.2.0
 */
public record Applicability(boolean applicable, double expectedCoverage, String reason) {

    /** Not usable here; {@code reason} says why, for the record in index.md. */
    public static Applicability no(String reason) {
        return new Applicability(false, 0.0, reason);
    }

    /** Usable, expecting to place {@code coverage} (0..1) of the unassigned pool. */
    public static Applicability yes(double coverage, String reason) {
        return new Applicability(true, coverage, reason);
    }
}
