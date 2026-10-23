package com.xebyte.core.partition;

import ghidra.program.model.listing.Function;

import java.util.List;
import java.util.Map;

/**
 * One group of functions, plus the evidence that justifies grouping them.
 *
 * <p>{@code slug} is deliberately machine-generated and meaningless ({@code c05},
 * never {@code crypto}). Naming a compartment is interpretation, and interpretation
 * belongs to whatever renames it afterwards — an agent, or a human in the Ghidra
 * GUI. A slug that reads like a claim invites trusting a guess; {@code c05} is
 * visibly scaffolding.
 *
 * <p>{@code confidence} and {@code evidence} exist because partitions are not
 * equally trustworthy and the tree must say so: a group formed from a class name at
 * member-density 1.00 is a different claim from a group formed by cutting the
 * address space into fixed bands.
 *
 * @since 7.2.0
 */
public record Partition(
        String slug,
        String method,
        double confidence,
        List<Function> members,
        Map<String, Object> evidence) {

    public int size() {
        return members.size();
    }
}
