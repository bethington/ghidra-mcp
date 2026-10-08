package com.xebyte.core.tree;

import com.xebyte.core.AddressKeys;
import com.xebyte.core.FunctionFacts;
import com.xebyte.core.ServiceUtils;
import com.xebyte.core.partition.PartitionContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Reconcile the on-disk decompilation tree with the live program.
 *
 * <p>Events are hints about where to look; this class is the thing that acts.
 * Ghidra can suppress, coalesce, or replace change events — so splicing driven
 * purely by events silently goes wrong. Three primitives are closed under every
 * change the program can make, which is what lets {@code mark_stale} die:
 *
 * <ul>
 *   <li>{@code replace} — in tree and in program → re-decompile, swap block
 *   <li>{@code insert} — in program, not in tree → place, insert in address
 *       order, split the file if over budget
 *   <li>{@code remove} — in tree, not in program → delete block; delete the
 *       file if it empties
 * </ul>
 *
 * <p>Never routes through {@code ThreadingStrategy} (same EDT/global-lock rule
 * as {@link SweepJob}). One pooled {@link DecompInterface} for the whole pass.
 *
 * @since 7.2.0
 */
public final class TreeReconciler {

    /** Placement method when the pin map did not claim the function. */
    public static final String METHOD_CONTAINMENT = "containment";

    private TreeReconciler() {
    }

    // -------------------------------------------------------------------------
    // Public entry points
    // -------------------------------------------------------------------------

    /** Full reconcile: address-set diff + ifp compare; decompile only mismatches. */
    public static ReconcileResult reconcile(DecompTree decompTree, Program program)
            throws IOException {
        return reconcile(decompTree, program, null);
    }

    /**
     * Targeted reconcile over {@code addresses}. {@code null} addresses means
     * full (index-driven). An empty set is a no-op that still reports counts.
     */
    public static ReconcileResult reconcile(
            DecompTree decompTree, Program program, Set<String> addresses) throws IOException {
        Objects.requireNonNull(decompTree, "decompTree");
        Objects.requireNonNull(program, "program");
        decompTree.treeLock().lock();
        try {
            return reconcileLocked(decompTree, program, addresses);
        } finally {
            decompTree.treeLock().unlock();
        }
    }

    private static ReconcileResult reconcileLocked(
            DecompTree decompTree, Program program, Set<String> addresses) throws IOException {
        long started = System.currentTimeMillis();
        // What the tree will reflect when this pass ends; edits arriving meanwhile queue
        // another pass, so claiming a later number would overstate it.
        long reconcilingAt = program.getModificationNumber();

        // A full pass must leave the tree a fresh sweep would write. A tree swept before the
        // grouping and the address index were kept cannot be brought there without the
        // sweep's own work (partitioning, a decompile of every function), so do that instead.
        PartitionMeta meta = PartitionMeta.read(decompTree);
        if (addresses == null && meta == null) {
            TreeRegistry.getInstance().requestSweep(decompTree, program);
            return ReconcileResult.sweepQueued(System.currentTimeMillis() - started,
                    decompTree.progress().splicedSinceSweep());
        }
        if (addresses == null && meta != null) {
            // Stored as this build writes it (a tree swept by an older build may order its
            // strategy log differently); unchanged content is not rewritten.
            meta.write(decompTree);
        }

        Path indexPath = decompTree.root().path().resolve(TreeLayout.byAddressTsv());
        List<TreeFiles.IndexEntry> indexRows = Files.isRegularFile(indexPath)
                ? TreeFiles.readIndex(indexPath)
                : List.of();
        Map<String, TreeFiles.IndexEntry> indexByHex = new LinkedHashMap<>();
        for (TreeFiles.IndexEntry row : indexRows) {
            indexByHex.put(AddressKeys.normalize(row.addressHex()), row);
        }

        PartitionContext ctx = new PartitionContext(program);
        ExclusionEvaluator evaluator = ExclusionEvaluator.of(program, decompTree.config());

        Map<String, Function> programByHex = new LinkedHashMap<>();
        for (Function f : ctx.functions()) {
            programByHex.put(
                    AddressKeys.of(f), f);
        }

        WorkPlan plan = planWork(indexByHex, programByHex, addresses);
        // A full pass also drops what the current exclusions put out of scope: a fresh sweep
        // would not write it. That is all narrowing a tree's config is.
        Set<String> outOfScope = addresses == null
                ? outOfScope(decompTree, indexByHex, programByHex, evaluator, meta)
                : Set.of();

        Accumulators acc = new Accumulators();
        decompTree.setProgress(decompTree.progress().withLastError(null));
        TreeStatusMd.write(decompTree, "dirty");

        DecompInterface decomp = null;
        int decompileCalls = 0;
        try {
            Map<String, TreeFiles.IndexEntry> working =
                    new LinkedHashMap<>(indexByHex);

            // Pre-filter full-reconcile replaces by ifp so an unchanged tree
            // creates no DecompInterface and reports decompile_calls=0.
            Set<String> replaceNow = new LinkedHashSet<>();
            if (addresses == null) {
                for (String hex : plan.replace) {
                    if (outOfScope.contains(hex)) {
                        continue;
                    }
                    TreeFiles.IndexEntry row = working.get(hex);
                    Function func = programByHex.get(hex);
                    if (row == null || func == null) {
                        acc.failed.add(hex);
                        acc.failedReasons.add("replace_missing");
                        continue;
                    }
                    String liveIfp = InputFingerprint.of(func);
                    if (!needsRedecompile(row.ifp(), liveIfp)) {
                        acc.unchanged.add(hex);
                    } else {
                        replaceNow.add(hex);
                    }
                }
            } else {
                replaceNow.addAll(plan.replace);
            }

            boolean needsDecomp = !replaceNow.isEmpty() || !plan.insert.isEmpty();
            if (needsDecomp) {
                decomp = ServiceUtils.createConfiguredDecompiler(program, FunctionFacts::configureDecompiler);
            }
            int timeout = decompTree.config().decompileTimeoutSeconds();

            Set<String> touchedSlugs = new LinkedHashSet<>();
            Set<String> seedForNeighbours = new LinkedHashSet<>();
            // Rebuilt blocks, by key, waiting to be packed into their compartment's files.
            Map<String, String> rebuilt = new LinkedHashMap<>();
            Map<String, String> oldFile = new LinkedHashMap<>();
            working.forEach((k, r) -> oldFile.put(k, r.file()));
            TreeText tree = new TreeText(decompTree);

            Set<String> removeNow = new LinkedHashSet<>(plan.remove);
            removeNow.addAll(outOfScope);
            for (String hex : removeNow) {
                TreeFiles.IndexEntry row = working.remove(hex);
                if (row == null) {
                    continue;
                }
                acc.removed.add(hex);
                touchedSlugs.add(row.slug());
                seedForNeighbours.add(hex);
            }

            for (String hex : replaceNow) {
                TreeFiles.IndexEntry row = working.get(hex);
                Function func = programByHex.get(hex);
                if (row == null || func == null) {
                    acc.failed.add(hex);
                    acc.failedReasons.add("replace_missing");
                    continue;
                }
                String existing = tree.block(row.file(), hex);
                FunctionBlock.Built built = BlockSplicer.decompileBlock(decomp, func,
                        partitionOf(existing, row, meta), timeout, program.getName());
                decompileCalls++;
                working.put(hex, row.withIfp(InputFingerprint.of(func)).withName(func.getName()));
                if (existing != null && BlockSplicer.sameBlock(existing, built.text())) {
                    acc.unchanged.add(hex);
                    continue;
                }
                rebuilt.put(hex, built.text());
                acc.replaced.add(hex);
                touchedSlugs.add(row.slug());
                seedForNeighbours.add(hex);
            }

            for (String hex : plan.insert) {
                Function func = programByHex.get(hex);
                if (func == null) {
                    acc.failed.add(hex);
                    acc.failedReasons.add("function_not_found");
                    continue;
                }
                Placement placement = place(func, program, working);
                if (!evaluator.isInScope(func, placement.slug())) {
                    // Out of scope under current exclusions — tree must not claim it.
                    continue;
                }
                FunctionBlock.Built built = BlockSplicer.decompileBlock(decomp, func,
                        new BlockSplicer.PartitionMeta(placement.slug(), placement.method(),
                                placement.confidence(), placement.evidenceBacked()),
                        timeout, program.getName());
                decompileCalls++;
                working.put(hex, new TreeFiles.IndexEntry(hex, func.getName(),
                        placement.slug(), "", placement.evidenceBacked(), InputFingerprint.of(func)));
                rebuilt.put(hex, built.text());
                acc.inserted.add(hex);
                touchedSlugs.add(placement.slug());
                seedForNeighbours.add(hex);
            }

            // Neighbours of every change need their calls/callers header lines patched.
            patchNeighbourHeaders(program, ctx, working, tree, seedForNeighbours, rebuilt,
                    touchedSlugs, acc);

            // A full pass re-packs every compartment: whatever the files say now, they end as
            // the sweep would lay these blocks out, and a block missing from them is rebuilt.
            if (addresses == null) {
                working.values().forEach(r -> touchedSlugs.add(r.slug()));
            }
            Repack repack = new Repack(decompTree, program, meta, working, rebuilt, oldFile, tree, timeout);
            for (String slug : touchedSlugs) {
                repack.compartment(slug, acc);
            }
            decompileCalls += repack.decompileCalls;
            repack.close();

            // Every pass ends with the derived files rendered as the sweep renders them, so
            // whatever got the tree here, it reads the same. Unchanged files are not rewritten.
            List<TreeFiles.IndexEntry> finalRows = new ArrayList<>(working.values());
            // outOfScope may have recounted the scope into partitions.json.
            DerivedFiles.writeAll(decompTree, program, finalRows,
                    outOfScope.isEmpty() ? meta : PartitionMeta.read(decompTree), ctx);

        } finally {
            if (decomp != null) {
                try {
                    decomp.dispose();
                } catch (Exception ignored) {
                    // must not mask reconcile outcome
                }
            }
        }

        int structural = acc.inserted.size() + acc.removed.size();
        int rewritten = acc.replaced.size() + structural;
        SweepProgress before = decompTree.progress();
        SweepProgress after = before
                .withLastError(before.phase() == SweepProgress.Phase.STALE ? before.lastError() : null)
                .reconciledAt(reconcilingAt, rewritten, structural);
        if (addresses == null && decompTree.recoverOnReattach()) {
            // The full pass after a stale close re-diffed every block against the program
            // as it reopened: the divergence that made it stale is gone.
            decompTree.setRecoverOnReattach(false);
            after = after
                    .withPhase(after.sweptAtModification() != null
                            ? SweepProgress.Phase.COMPLETE : SweepProgress.Phase.IDLE)
                    .withLastError(null);
        }
        decompTree.setProgress(after);
        decompTree.noteSession(program);
        TreeStatusMd.write(decompTree, TreeStatusMd.settledState(decompTree.progress()));

        return ReconcileResult.of(
                acc.replaced, acc.inserted, acc.removed, acc.headerPatched, acc.unchanged,
                acc.failed, acc.failedReasons,
                acc.filesWritten, acc.filesDeleted,
                decompileCalls, System.currentTimeMillis() - started,
                decompTree.progress().splicedSinceSweep());
    }

    /**
     * Entry addresses of blocks whose decompiled body (not the header) uses one of
     * {@code names} as a whole identifier. A rename's old name is printed wherever the
     * decompiler resolved the symbol, including calls it worked out through a register or
     * a literal pool, where the program records no reference to look up.
     */
    public static Set<String> blocksMentioning(DecompTree decompTree, Collection<String> names)
            throws IOException {
        Set<String> found = new LinkedHashSet<>();
        if (names == null || names.isEmpty()) {
            return found;
        }
        Pattern any = Pattern.compile("(?<![A-Za-z0-9_])(?:"
                + names.stream().map(Pattern::quote).collect(java.util.stream.Collectors.joining("|"))
                + ")(?![A-Za-z0-9_])");
        Path modules = decompTree.root().path().resolve("modules");
        if (!Files.isDirectory(modules)) {
            return found;
        }
        try (java.util.stream.Stream<Path> files = Files.walk(modules)) {
            for (Path file : (Iterable<Path>) files.filter(p -> p.toString().endsWith(".c"))::iterator) {
                for (String chunk : TreeFiles.splitFunctionChunks(
                        Files.readString(file, StandardCharsets.UTF_8))) {
                    String hex = TreeFiles.addressFromChunk(chunk);
                    if (hex != null && bodyMatches(chunk, any)) {
                        found.add(AddressKeys.normalize(hex));
                    }
                }
            }
        }
        return found;
    }

    private static boolean bodyMatches(String chunk, Pattern names) {
        return names.matcher(BlockSplicer.bodyAfterLeadingComments(chunk)).find();
    }

    // -------------------------------------------------------------------------
    // Pure planning / placement (offline-tested)
    // -------------------------------------------------------------------------

    /**
     * Classify addresses into replace / insert / remove.
     *
     * <p>Full mode ({@code addresses == null}): set-diff plus ifp. Empty ifp is
     * UNKNOWN — never "unchanged" — so a 5-column pre-Stage-A tree is re-checked.
     * Targeted mode: every requested address is classified by presence alone;
     * ifp skip happens later at replace time only for full mode.
     */
    public static WorkPlan planWork(
            Map<String, TreeFiles.IndexEntry> indexByHex,
            Map<String, Function> programByHex,
            Set<String> addresses) {

        Set<String> replace = new LinkedHashSet<>();
        Set<String> insert = new LinkedHashSet<>();
        Set<String> remove = new LinkedHashSet<>();

        if (addresses == null) {
            Set<String> tree = indexByHex.keySet();
            Set<String> prog = programByHex.keySet();
            for (String hex : prog) {
                if (!tree.contains(hex)) {
                    insert.add(hex);
                } else {
                    replace.add(hex); // ifp filter applied at execute time
                }
            }
            for (String hex : tree) {
                if (!prog.contains(hex)) {
                    remove.add(hex);
                }
            }
        } else {
            for (String raw : addresses) {
                if (raw == null || raw.isBlank()) {
                    continue;
                }
                String hex = AddressKeys.normalize(raw);
                boolean inTree = indexByHex.containsKey(hex);
                boolean inProg = programByHex.containsKey(hex);
                if (inTree && inProg) {
                    replace.add(hex);
                } else if (inProg) {
                    insert.add(hex);
                } else if (inTree) {
                    remove.add(hex);
                }
                // else: neither — ignore (hint about a non-function address)
            }
        }
        return new WorkPlan(replace, insert, remove);
    }

    /**
     * Whether a surviving address needs a decompile under full reconcile.
     * Empty/blank ifp ⇒ yes (unknown). Mismatch ⇒ yes. Match ⇒ no.
     */
    public static boolean needsRedecompile(String storedIfp, String liveIfp) {
        if (storedIfp == null || storedIfp.isBlank()) {
            return true;
        }
        return !storedIfp.equals(liveIfp);
    }

    /**
     * Pin first (same {@link ModuleOverrides#slugFor} the sweep consults), else
     * containment: the compartment whose address span covers the entry.
     */
    public static Placement place(
            Function func,
            Program program,
            Map<String, TreeFiles.IndexEntry> indexByHex) {
        Address entry = func.getEntryPoint();
        Optional<String> pinned = ModuleOverrides.slugFor(program, entry);
        if (pinned.isPresent()) {
            // Inherit confidence from an existing member of that slug when present;
            // a brand-new slug still records pinned/1.0 — the pin IS the evidence.
            double conf = 1.0;
            for (TreeFiles.IndexEntry row : indexByHex.values()) {
                if (pinned.get().equals(row.slug())) {
                    conf = 1.0;
                    break;
                }
            }
            return new Placement(pinned.get(), ModuleOverrides.METHOD, conf, true);
        }
        return placeByContainment(AddressKeys.of(func), indexByHex);
    }

    /**
     * Compartment whose [min,max] entry span covers {@code addressHex}; on a
     * tie, the tightest span. Outside every span → nearest by distance.
     * Method {@link #METHOD_CONTAINMENT}, {@code evidence_backed=false}.
     */
    public static Placement placeByContainment(
            String addressHex, Map<String, TreeFiles.IndexEntry> indexByHex) {
        String want = AddressKeys.normalize(addressHex);
        long addr = AddressKeys.offset(want);
        // Offsets compare only within one address space; an overlay function placed by a
        // default-space span would land beside code it has nothing to do with.
        String space = AddressKeys.space(want);
        boolean anyInSpace = indexByHex.values().stream()
                .anyMatch(r -> AddressKeys.space(r.addressHex()).equals(space));

        Map<String, long[]> spans = new LinkedHashMap<>();
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (TreeFiles.IndexEntry row : indexByHex.values()) {
            if (anyInSpace && !AddressKeys.space(row.addressHex()).equals(space)) {
                continue;
            }
            long a = AddressKeys.offset(row.addressHex());
            long[] span = spans.get(row.slug());
            if (span == null) {
                spans.put(row.slug(), new long[]{a, a});
                counts.put(row.slug(), 1);
            } else {
                span[0] = Math.min(span[0], a);
                span[1] = Math.max(span[1], a);
                counts.merge(row.slug(), 1, Integer::sum);
            }
        }

        String bestCover = null;
        long bestCoverWidth = Long.MAX_VALUE;
        for (Map.Entry<String, long[]> e : spans.entrySet()) {
            long min = e.getValue()[0];
            long max = e.getValue()[1];
            if (addr >= min && addr <= max) {
                long width = max - min;
                if (bestCover == null || width < bestCoverWidth) {
                    bestCover = e.getKey();
                    bestCoverWidth = width;
                }
            }
        }
        if (bestCover != null) {
            return new Placement(bestCover, METHOD_CONTAINMENT, 0.1, false);
        }

        String nearest = null;
        long bestDist = Long.MAX_VALUE;
        for (Map.Entry<String, long[]> e : spans.entrySet()) {
            long min = e.getValue()[0];
            long max = e.getValue()[1];
            long dist = addr < min ? min - addr : addr - max;
            if (dist < bestDist) {
                bestDist = dist;
                nearest = e.getKey();
            }
        }
        if (nearest != null) {
            return new Placement(nearest, METHOD_CONTAINMENT, 0.1, false);
        }
        // Empty tree — mint a band-shaped slug so insert still has a home.
        return new Placement("b000", METHOD_CONTAINMENT, 0.1, false);
    }

    // -------------------------------------------------------------------------
    // Disk mutation helpers
    // -------------------------------------------------------------------------

    /**
     * Patch the {@code calls:}/{@code callers:} lines of every neighbour of {@code seeds} to the
     * live graph. Patched blocks join {@code rebuilt} and their compartments are re-packed, like
     * any other changed block.
     */
    private static void patchNeighbourHeaders(
            Program program,
            PartitionContext ctx,
            Map<String, TreeFiles.IndexEntry> working,
            TreeText tree,
            Set<String> seeds,
            Map<String, String> rebuilt,
            Set<String> touchedSlugs,
            Accumulators acc) throws IOException {
        if (seeds.isEmpty()) {
            return;
        }
        Set<String> neighbours = BlockSplicer.neighbourAddresses(ctx, program, seeds);
        neighbours.removeAll(seeds);
        for (String hex : neighbours) {
            TreeFiles.IndexEntry row = working.get(hex);
            Function func = AddressKeys.function(program, hex);
            if (row == null || func == null || rebuilt.containsKey(hex)) {
                continue;
            }
            String oldBlock = tree.block(row.file(), hex);
            if (oldBlock == null) {
                continue;
            }
            String[] now = FunctionBlock.neighbourValues(func);
            String[] existing = BlockSplicer.neighbourhoodValuesFromBlock(oldBlock);
            if (Objects.equals(now[0], existing[0]) && Objects.equals(now[1], existing[1])) {
                continue;
            }
            rebuilt.put(hex, FunctionBlock.withFingerprint(
                    BlockSplicer.patchNeighbourhoodLines(oldBlock, now[0], now[1])));
            touchedSlugs.add(row.slug());
            acc.headerPatched.add(hex);
        }
    }

    // -------------------------------------------------------------------------
    // Result types
    // -------------------------------------------------------------------------

    public record WorkPlan(Set<String> replace, Set<String> insert, Set<String> remove) {
        public WorkPlan {
            replace = Set.copyOf(replace);
            insert = Set.copyOf(insert);
            remove = Set.copyOf(remove);
        }
    }

    public record Placement(
            String slug, String method, double confidence, boolean evidenceBacked) {}

    public record ReconcileResult(
            List<String> replaced,
            List<String> inserted,
            List<String> removed,
            List<String> headerPatched,
            List<String> unchanged,
            List<String> failed,
            List<String> failedReasons,
            int filesWritten,
            int filesDeleted,
            int decompileCalls,
            long elapsedMs,
            int splicedSinceSweep,
            boolean sweepQueued) {

        /**
         * A full pass that found a tree it cannot rebuild exactly (swept before
         * {@code partitions.json} was kept) and queued a sweep.
         */
        static ReconcileResult sweepQueued(long elapsedMs, int splicedSinceSweep) {
            return new ReconcileResult(List.of(), List.of(), List.of(), List.of(), List.of(),
                    List.of(), List.of(), 0, 0, 0, elapsedMs, splicedSinceSweep, true);
        }

        public static ReconcileResult of(
                List<String> replaced,
                List<String> inserted,
                List<String> removed,
                List<String> headerPatched,
                List<String> unchanged,
                List<String> failed,
                List<String> failedReasons,
                int filesWritten,
                int filesDeleted,
                int decompileCalls,
                long elapsedMs,
                int splicedSinceSweep) {
            return new ReconcileResult(
                    List.copyOf(replaced),
                    List.copyOf(inserted),
                    List.copyOf(removed),
                    List.copyOf(headerPatched),
                    List.copyOf(unchanged),
                    List.copyOf(failed),
                    List.copyOf(failedReasons),
                    filesWritten, filesDeleted,
                    decompileCalls, elapsedMs, splicedSinceSweep, false);
        }

        public Map<String, Object> toMap(String treeId, boolean busy, String phase) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("tree_id", treeId);
            out.put("busy", busy);
            if (phase != null) {
                out.put("phase", phase);
            }
            out.put("replaced", replaced.size());
            out.put("inserted", inserted.size());
            out.put("removed", removed.size());
            out.put("header_patched", headerPatched.size());
            out.put("unchanged", unchanged.size());
            out.put("failed", failed.size());
            out.put("files_written", filesWritten);
            out.put("files_deleted", filesDeleted);
            out.put("decompile_calls", decompileCalls);
            out.put("elapsed_ms", elapsedMs);
            out.put("spliced_since_sweep", splicedSinceSweep);
            if (sweepQueued) {
                out.put("sweep_queued", true);
                out.put("sweep_reason", "the tree predates index/partitions.json, "
                        + "which only a sweep can write; reconciling would "
                        + "leave a tree a fresh sweep would not produce");
            }
            if (!failed.isEmpty()) {
                List<Map<String, String>> rows = new ArrayList<>();
                for (int i = 0; i < failed.size(); i++) {
                    Map<String, String> row = new LinkedHashMap<>();
                    row.put("address", failed.get(i));
                    row.put("reason",
                            i < failedReasons.size() ? failedReasons.get(i) : "failed");
                    rows.add(row);
                }
                out.put("failed_detail", rows);
            }
            return out;
        }
    }

    private static final class Accumulators {
        final List<String> replaced = new ArrayList<>();
        final List<String> inserted = new ArrayList<>();
        final List<String> removed = new ArrayList<>();
        final List<String> headerPatched = new ArrayList<>();
        final List<String> unchanged = new ArrayList<>();
        final List<String> failed = new ArrayList<>();
        final List<String> failedReasons = new ArrayList<>();
        int filesWritten;
        int filesDeleted;
    }

    // -------------------------------------------------------------------------
    // The shared base: blocks in, compartment files out
    // -------------------------------------------------------------------------

    /** The block text on disk, read once per file. */
    private static final class TreeText {
        private final DecompTree decompTree;
        private final Map<String, Map<String, String>> byFile = new LinkedHashMap<>();

        TreeText(DecompTree decompTree) {
            this.decompTree = decompTree;
        }

        /** {@code key}'s block in {@code file}, or null when either is missing. */
        String block(String file, String key) throws IOException {
            if (file == null || file.isEmpty()) {
                return null;
            }
            Map<String, String> blocks = byFile.get(file);
            if (blocks == null) {
                blocks = new LinkedHashMap<>();
                Path abs = decompTree.root().path().resolve(file);
                if (Files.isRegularFile(abs)) {
                    for (String chunk : TreeFiles.splitFunctionChunks(
                            Files.readString(abs, StandardCharsets.UTF_8))) {
                        String addr = TreeFiles.addressFromChunk(chunk);
                        if (addr != null) {
                            blocks.put(AddressKeys.normalize(addr), chunk);
                        }
                    }
                }
                byFile.put(file, blocks);
            }
            return blocks.get(AddressKeys.normalize(key));
        }

    }

    /**
     * Re-pack compartments with {@link CompartmentPacker}, the sweep's layout rule, from the
     * rebuilt blocks and the blocks already on disk. A block the files no longer hold (a file
     * deleted or edited by hand) is rebuilt, so a full pass restores it.
     */
    private static final class Repack {
        private final DecompTree decompTree;
        private final Program program;
        private final PartitionMeta meta;
        private final Map<String, TreeFiles.IndexEntry> working;
        private final Map<String, String> rebuilt;
        private final Map<String, String> oldFile;
        private final TreeText tree;
        private final int timeout;
        private DecompInterface decomp;
        int decompileCalls;

        Repack(DecompTree decompTree, Program program, PartitionMeta meta,
                Map<String, TreeFiles.IndexEntry> working, Map<String, String> rebuilt,
                Map<String, String> oldFile, TreeText tree, int timeout) {
            this.decompTree = decompTree;
            this.program = program;
            this.meta = meta;
            this.working = working;
            this.rebuilt = rebuilt;
            this.oldFile = oldFile;
            this.tree = tree;
            this.timeout = timeout;
        }

        void compartment(String slug, Accumulators acc) throws IOException {
            List<String> keys = new ArrayList<>();
            working.forEach((k, r) -> {
                if (slug.equals(r.slug())) {
                    keys.add(k);
                }
            });
            keys.sort(Comparator.comparing((String k) -> addressOf(k)).thenComparing(k -> k));
            List<Map.Entry<String, String>> blocks = new ArrayList<>(keys.size());
            for (String key : keys) {
                String text = rebuilt.get(key);
                if (text == null) {
                    text = tree.block(oldFile.get(key), key);
                }
                // Missing, or no longer the block that was written: rebuild it.
                if (text == null || !FunctionBlock.intact(text)) {
                    text = restore(key, text, acc);
                }
                if (text != null) {
                    blocks.add(Map.entry(key, text));
                }
            }
            Set<String> produced = new LinkedHashSet<>();
            for (CompartmentPacker.PackedFile f : CompartmentPacker.pack(slug,
                    decompTree.config().maxFileBytes(), program.getDefaultPointerSize(), blocks)) {
                produced.add(f.path());
                if (DerivedFiles.writeIfContentChanged(decompTree, f.path(), f.body())) {
                    acc.filesWritten++;
                }
                for (String key : f.keys()) {
                    working.put(key, working.get(key).withFile(f.path()));
                }
            }
            Path dir = decompTree.root().path().resolve(TreeLayout.moduleReadme(slug)).getParent();
            if (Files.isDirectory(dir, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                try (java.nio.file.DirectoryStream<Path> files = Files.newDirectoryStream(dir, "*.c")) {
                    for (Path file : files) {
                        String rel = decompTree.root().path().relativize(file).toString().replace('\\', '/');
                        if (!produced.contains(rel) && decompTree.root().deleteFile(rel)) {
                            acc.filesDeleted++;
                        }
                    }
                }
            }
        }

        /** Rebuild a block the files lost. */
        private String restore(String key, String damaged, Accumulators acc) throws IOException {
            Function func = AddressKeys.function(program, key);
            TreeFiles.IndexEntry row = working.get(key);
            if (func == null || row == null) {
                acc.failed.add(key);
                acc.failedReasons.add("block_missing_and_function_gone");
                return null;
            }
            if (decomp == null) {
                decomp = ServiceUtils.createConfiguredDecompiler(program, FunctionFacts::configureDecompiler);
            }
            FunctionBlock.Built built = BlockSplicer.decompileBlock(decomp, func,
                    partitionOf(damaged, row, meta), timeout, program.getName());
            decompileCalls++;
            acc.replaced.add(key);
            return built.text();
        }

        private ghidra.program.model.address.Address addressOf(String key) {
            ghidra.program.model.address.Address a = ServiceUtils.parseAddress(program, key);
            return a != null ? a : program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
        }

        void close() {
            if (decomp != null) {
                try {
                    decomp.dispose();
                } catch (Exception ignored) {
                    // must not mask the reconcile outcome
                }
            }
        }
    }

    /**
     * The tree rows the current exclusions put out of scope. Counts them into the sweep's
     * scope stats the way the sweep's own filter would, and saves those, so
     * {@code modules/index.md} reports what a fresh sweep under the new config reports.
     */
    private static Set<String> outOfScope(DecompTree decompTree,
            Map<String, TreeFiles.IndexEntry> index, Map<String, Function> program,
            ExclusionEvaluator evaluator, PartitionMeta meta) throws IOException {
        Map<String, List<Function>> bySlug = new LinkedHashMap<>();
        index.forEach((k, r) -> {
            Function f = program.get(k);
            if (f != null) {
                bySlug.computeIfAbsent(r.slug(), x -> new ArrayList<>()).add(f);
            }
        });
        List<com.xebyte.core.partition.Partition> parts = new ArrayList<>();
        bySlug.forEach((slug, fns) -> parts.add(
                new com.xebyte.core.partition.Partition(slug, "", 0.0, fns, Map.of())));
        ExclusionEvaluator.FilterResult kept = evaluator.filterPartitions(parts,
                meta.eligibleFunctions());
        Set<String> keep = new java.util.HashSet<>();
        kept.partitions().forEach(p -> p.members().forEach(f -> keep.add(AddressKeys.of(f))));
        Set<String> out = new LinkedHashSet<>();
        for (String k : index.keySet()) {
            if (program.containsKey(k) && !keep.contains(k)) {
                out.add(k);
            }
        }
        if (!out.isEmpty()) {
            Map<String, String> removed = new LinkedHashMap<>(meta.removedByRule());
            kept.stats().removedByRule().forEach((rule, n) -> removed.merge(rule, String.valueOf(n),
                    (a, b) -> String.valueOf(Integer.parseInt(a) + Integer.parseInt(b))));
            new PartitionMeta(meta.eligibleFunctions(), keep.size(), meta.assignedFunctions(),
                    meta.functionsWithStrings(), removed, meta.strategyLog(), meta.partitions())
                    .write(decompTree);
        }
        return out;
    }

    /**
     * How a rebuilt block records its compartment: as its existing block did, else as the
     * sweep formed the compartment, else as an unexplained address band.
     */
    static BlockSplicer.PartitionMeta partitionOf(String existingBlock,
            TreeFiles.IndexEntry row, PartitionMeta meta) {
        BlockSplicer.PartitionMeta fromBlock = existingBlock != null
                ? BlockSplicer.partitionMetaFromBlock(existingBlock) : null;
        if (fromBlock != null) {
            return fromBlock;
        }
        PartitionMeta.Part part = meta != null ? meta.part(row.slug()) : null;
        return part != null
                ? new BlockSplicer.PartitionMeta(row.slug(), part.method(), part.confidence(), row.evidenceBacked())
                : new BlockSplicer.PartitionMeta(row.slug(), "address-band", 0.0, row.evidenceBacked());
    }
}
