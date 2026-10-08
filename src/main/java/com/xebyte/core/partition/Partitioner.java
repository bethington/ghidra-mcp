package com.xebyte.core.partition;

import java.util.List;

/**
 * One strategy for grouping a program's functions.
 *
 * <p>Implementations run in a cascade, each seeing only what earlier ones left
 * unassigned, so a strategy must never assume it is looking at the whole program.
 *
 * <p>The contract that matters is {@link #probe}: a strategy has to be able to say
 * "not here" cheaply and honestly. Measured across four specimens, no single
 * strategy worked on more than two of them — RTTI is dead on stripped C, MMIO pages
 * are noise on a PE, and literal locality needs a density of string references that
 * an RTOS firmware does not have. A cascade that assumed instead of probing would
 * confidently mis-group three binaries out of four.
 *
 * @since 7.2.0
 */
public interface Partitioner {

    /** Stable identifier, recorded per function so the tree can say what placed it. */
    String name();

    /**
     * Run order, ascending. Specific, high-evidence strategies go first so that the
     * generic ones only ever see leftovers; {@link AddressBandPartitioner} sits at
     * the end because it always succeeds and would otherwise consume everything.
     */
    int precedence();

    /** Cheap self-assessment; the cascade skips this strategy when not applicable. */
    Applicability probe(PartitionContext ctx);

    /**
     * Group whatever is still unassigned. Implementations must not mark assignment
     * themselves — the cascade does that, so a partitioner cannot claim functions it
     * did not return.
     */
    List<Partition> partition(PartitionContext ctx);
}
