package com.xebyte.core.partition;

import ghidra.program.model.listing.Function;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The terminal fallback: fixed-size runs of address-ordered functions.
 *
 * <p>Deliberately not clever. Every attempt to group the remainder by structure was
 * measured and failed: single-caller absorption compressed 1,285 functions to 771,
 * label propagation produced one community of 703 out of 906, and finer
 * literal-locality thresholds shattered sparse regions while leaving dense ones
 * monolithic. There is no reliable file-scale signal in a stripped binary.
 *
 * <p>What banding does give is uniform, predictable file sizes, stability across
 * resweeps, preservation of object order — the one property actually demonstrated
 * to be real — and no false claim of semantic grouping. The structural layer only
 * has to make the first look navigable; a model rewrites it into semantic modules
 * afterwards, so accuracy invested here is discarded.
 *
 * @since 7.2.0
 */
public final class AddressBandPartitioner implements Partitioner {

    /**
     * ~20 functions at a measured mean of 1,564 bytes of C is ~31 KB, roughly 8K
     * tokens — one comfortable read.
     */
    private final int bandSize;

    public AddressBandPartitioner(int bandSize) {
        this.bandSize = Math.max(1, bandSize);
    }

    @Override
    public String name() {
        return "address-band";
    }

    @Override
    public int precedence() {
        return 100;
    }

    @Override
    public Applicability probe(PartitionContext ctx) {
        int pool = ctx.size() - ctx.assignedCount();
        if (pool == 0) return Applicability.no("nothing left unassigned");
        return Applicability.yes(1.0, String.format(
                "fallback: %d unassigned function(s) banded %d per file, address-ordered",
                pool, bandSize));
    }

    @Override
    public List<Partition> partition(PartitionContext ctx) {
        List<Integer> pool = ctx.unassigned();
        List<Function> fns = ctx.functions();
        List<Partition> out = new ArrayList<>();
        for (int start = 0; start < pool.size(); start += bandSize) {
            int end = Math.min(pool.size(), start + bandSize);
            List<Function> members = new ArrayList<>(end - start);
            for (int k = start; k < end; k++) members.add(fns.get(pool.get(k)));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("span", members.get(0).getEntryPoint()
                    + "-" + members.get(members.size() - 1).getEntryPoint());
            evidence.put("note", "no structural evidence — grouped by address order only");
            out.add(new Partition(
                    String.format("b%03d", start / bandSize), name(), 0.1, members, evidence));
        }
        return out;
    }
}
