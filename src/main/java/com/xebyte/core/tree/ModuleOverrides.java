package com.xebyte.core.tree;

import com.xebyte.core.WriteTx;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.DuplicateNameException;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Agent-pinned compartment membership, stored on the program — not the tree.
 *
 * <p>A resweep wipes the tree and re-runs the cascade; anything that lived only
 * in tree config would be forgotten. The override is knowledge about the
 * <em>binary</em> (this function belongs in that module), so it lives in a
 * Ghidra string property map keyed at the function entry and survives deleting
 * the tree, recreating it, and every future sweep.
 *
 * <p>Consulted <em>before</em> the partitioner cascade so a pinned function is
 * never classified. One code path for sweep and (later) reconcile.
 *
 * @since 7.2.0
 */
public final class ModuleOverrides {

    /** Property map name — visible via {@code list_property_maps} / {@code get_property}. */
    public static final String MAP_NAME = "TreeModule";

    /** Placement method recorded in the block {@code // part:} header. */
    public static final String METHOD = "pinned";

    private ModuleOverrides() {
    }

    /**
     * Compartment slug pinned at {@code entryAddress}, if any.
     * Missing map or missing key → empty; never throws.
     */
    public static Optional<String> slugFor(Program program, Address entryAddress) {
        if (program == null || entryAddress == null) {
            return Optional.empty();
        }
        try {
            StringPropertyMap map = program.getUsrPropertyManager()
                    .getStringPropertyMap(MAP_NAME);
            if (map == null || !map.hasProperty(entryAddress)) {
                return Optional.empty();
            }
            String slug = map.getString(entryAddress);
            if (slug == null || slug.isBlank()) {
                return Optional.empty();
            }
            return Optional.of(slug.trim());
        } catch (Exception e) {
            // A corrupt / wrong-typed map must not abort a sweep.
            return Optional.empty();
        }
    }

    /**
     * Pin {@code entryAddress} to {@code slug}, or unpin when {@code slug} is
     * null/blank. Creates the map on first write. Needs a transaction.
     */
    public static void set(Program program, Address entryAddress, String slug) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(entryAddress, "entryAddress");
        WriteTx tx = WriteTx.begin(program, "DecompTree module override");
        boolean commit = false;
        try {
            StringPropertyMap map = ensureMap(program);
            if (slug == null || slug.isBlank()) {
                map.remove(entryAddress);
            } else {
                String cleaned = slug.trim();
                // The tree layout's rule: a pin that cannot become a directory is useless.
                if (!TreeLayout.isValidSlug(cleaned)) {
                    throw new IllegalArgumentException(
                            "module slug must be a plain name of letters, digits, '_', '.' and '-': "
                                    + cleaned);
                }
                map.add(entryAddress, cleaned);
            }
            commit = true;
        } finally {
            tx.end(commit);
        }
    }

    /**
     * Claim every overridden function out of the cascade pool.
     *
     * <p>Must run <em>before</em> {@link com.xebyte.core.partition.PartitionCascade#run}:
     * once marked assigned, no partitioner — including the terminal address-band
     * fallback — can reclassify them. Returns one partition per distinct slug,
     * method {@link #METHOD}, confidence 1.0.
     */
    public static List<Partition> claimPinned(PartitionContext ctx) {
        Objects.requireNonNull(ctx, "ctx");
        Program program = ctx.program();
        Map<String, List<Function>> bySlug = new LinkedHashMap<>();
        List<Integer> claimed = new ArrayList<>();

        List<Function> fns = ctx.functions();
        for (int i = 0; i < fns.size(); i++) {
            if (ctx.isAssigned(i)) {
                continue;
            }
            Function f = fns.get(i);
            Optional<String> slug = slugFor(program, f.getEntryPoint());
            if (slug.isEmpty()) {
                continue;
            }
            bySlug.computeIfAbsent(slug.get(), s -> new ArrayList<>()).add(f);
            claimed.add(i);
        }

        if (claimed.isEmpty()) {
            return List.of();
        }
        ctx.markAssigned(claimed);

        List<Partition> out = new ArrayList<>(bySlug.size());
        for (Map.Entry<String, List<Function>> e : bySlug.entrySet()) {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("source", MAP_NAME);
            evidence.put("note", "agent/human pin — never reclassified by the cascade");
            evidence.put("members", e.getValue().size());
            out.add(new Partition(
                    e.getKey(), METHOD, 1.0, List.copyOf(e.getValue()), evidence));
        }
        return out;
    }

    private static StringPropertyMap ensureMap(Program program) {
        StringPropertyMap existing = program.getUsrPropertyManager()
                .getStringPropertyMap(MAP_NAME);
        if (existing != null) {
            return existing;
        }
        try {
            return program.getUsrPropertyManager().createStringPropertyMap(MAP_NAME);
        } catch (DuplicateNameException e) {
            // Race with another writer — re-read.
            StringPropertyMap raced = program.getUsrPropertyManager()
                    .getStringPropertyMap(MAP_NAME);
            if (raced != null) {
                return raced;
            }
            throw new IllegalStateException(
                    "failed to create property map " + MAP_NAME, e);
        }
    }
}
