package com.xebyte.core.tree;

import com.xebyte.core.AddressKeys;
import com.xebyte.core.FunctionFacts;
import com.xebyte.core.ServiceUtils;
import com.xebyte.core.WriteTx;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionCascade;
import com.xebyte.core.partition.PartitionContext;
import com.xebyte.core.partition.Partitioner;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Background sweep that materialises a partitioned decompilation tree.
 *
 * <p><b>Threading:</b> runs on {@link TreeRegistry}'s single daemon thread.
 * Never route through {@code ThreadingStrategy} — under Swing that freezes the
 * GUI for the whole sweep; under Direct it takes the global read lock and
 * serialises every other HTTP request. Same escape hatch
 * {@link com.xebyte.core.PartitionService} documents.
 *
 * <p><b>Decompiler:</b> one pooled {@link DecompInterface} for the entire sweep.
 * Measured: fresh interface per function = 238 ms ({@code openProgram} alone
 * 218 ms); already-open = 5.7–10 ms (~23×). {@code ParallelDecompiler} with 10
 * threads is 1.01× — ProgramDB-lock-bound — do not add threads.
 *
 * @since 7.2.0
 */
public final class SweepJob implements Runnable {

    /** Interactive yield quantum — release ProgramDB lock regularly. */
    public static final int SLICE_MS = 250;

    /** Re-check auto-analysis this often; {@code /reanalyze} can fire mid-sweep. */
    private static final int ANALYSIS_POLL_EVERY = 64;

    /**
     * Secondary per-file cap: a compartment of tiny stubs must not produce one
     * enormous-count file even when each stub is well under the byte budget.
     */
    private static final String FAILED_MARKER_PREFIX = "// DECOMPILATION FAILED: ";

    private final DecompTree decompTree;
    private final Program program;

    private final CancelSignal cancel = new CancelSignal();
    private volatile DecompInterface decomp;
    private volatile String cancelReason;

    public SweepJob(DecompTree decompTree, Program program) {
        this.decompTree = Objects.requireNonNull(decompTree, "decompTree");
        this.program = Objects.requireNonNull(program, "program");
    }

    public String treeId() {
        return decompTree.id();
    }

    /**
     * Three cancel levers: the volatile flag (checked between functions), the
     * {@link TaskMonitor} whose {@code isCancelled()} returns it (so the C++
     * decompiler sees it), and {@link DecompInterface#stopProcess()} so stop
     * does not wait out {@code decompileTimeoutSeconds} on the in-flight call.
     */
    public void requestCancel(String reason) {
        cancelReason = reason != null ? reason : "cancelled";
        cancel.cancel();
        DecompInterface d = decomp;
        if (d != null) {
            try {
                d.stopProcess();
            } catch (Exception ignored) {
                // Best-effort — the flag still stops the outer loop.
            }
        }
    }

    /** Exposed for offline cancel plumbing tests. */
    TaskMonitor monitor() {
        return cancel.monitor();
    }

    @Override
    public void run() {
        // One writer at a time: a reconcile (refresh, narrowing, the dirty queue) waits for
        // the sweep, and the sweep for a reconcile already under way.
        decompTree.treeLock().lock();
        try {
            runLocked();
        } finally {
            decompTree.treeLock().unlock();
        }
    }

    private void runLocked() {
        // Queued jobs cancelled before they ever ran — honour without touching the program.
        if (cancel.isCancelled()) {
            finishTerminal(SweepProgress.Phase.CANCELLED,
                    cancelReason != null ? cancelReason : "cancelled before start",
                    null);
            return;
        }

        // Pin so the DB cannot close under us; still poll isClosed between
        // functions in case the user asked to close despite the consumer.
        // release(this) in finally — DomainObject has no removeConsumer.
        program.addConsumer(this);
        DecompInterface localDecomp = null;
        long sweptMod = program.getModificationNumber();
        try {
            publish(decompTree.progress()
                    .withPhase(SweepProgress.Phase.QUEUED)
                    .withStartedEpochMs(System.currentTimeMillis())
                    .withRootRecreated(decompTree.root().rootRecreated())
                    .withLastError(null), "dirty");

            if (!waitForAnalysisIfNeeded()) {
                return;
            }
            if (cancel.isCancelled() || !ensureProgramOpen()) {
                return;
            }

            publish(decompTree.progress().withPhase(SweepProgress.Phase.PARTITIONING),
                    "dirty");

            TreeConfig cfg = decompTree.config();
            if (cfg.disassembleMissing()) {
                DisassemblyPassResult disasm = disassembleMissingAtEntries(
                        program, cancel, cfg.throttlePercent(), SweepJob::disassembleAtEntry);
                publish(decompTree.progress()
                        .withDisassemblyCounts(
                                disasm.disassembledOnDemand(), disasm.disassemblyFailed())
                        .withBodyReflowCounts(
                                disasm.bodiesRecomputed(), disasm.bodyRecomputeFailed()),
                        "dirty");
                if (cancel.isCancelled() || !ensureProgramOpen()) {
                    return;
                }
            }

            List<Partitioner> chain = PartitionCascade.buildChain(
                    cfg.bandSize(), cfg.enabledStrategies());
            if (chain.isEmpty()) {
                // Fall back to bands only — a mis-typed strategies list must not
                // leave the tree empty with no explanation.
                chain = PartitionCascade.buildChain(cfg.bandSize(), List.of("address-band"));
            }

            PartitionContext ctx = new PartitionContext(program);
            // Pins first — a claimed function is marked assigned so the cascade
            // (including the terminal address-band) never reclassifies it.
            List<Partition> pinned = ModuleOverrides.claimPinned(ctx);
            PartitionCascade.Result cascade = new PartitionCascade(chain).run(ctx);
            List<Partition> partitions = new ArrayList<>(pinned.size() + cascade.partitions().size());
            partitions.addAll(pinned);
            partitions.addAll(cascade.partitions());
            partitions.sort(Comparator.comparing(p -> p.members().get(0).getEntryPoint()));

            // Partition → PARTITION exclusions (need slugs) → TAG/RANGE + includeOnly
            // → decompile. One evaluator so /decompile_tree_configure cannot disagree.
            ExclusionEvaluator evaluator = ExclusionEvaluator.of(program, cfg);
            ExclusionEvaluator.FilterResult filtered =
                    evaluator.filterPartitions(partitions, ctx.size());
            partitions = new ArrayList<>(filtered.partitions());
            ExclusionEvaluator.ScopeStats scope = filtered.stats();

            int total = scope.functionsInScope();
            publish(decompTree.progress()
                    .withPhase(SweepProgress.Phase.DECOMPILING)
                    .withCounts(total, 0, 0)
                    .withBytesWritten(0L)
                    .withScope(scope.eligibleFunctions(), scope.functionsInScope(),
                            scope.removedByRule()),
                    "dirty");


            localDecomp = ServiceUtils.createConfiguredDecompiler(program, FunctionFacts::configureDecompiler);
            decomp = localDecomp;

            SweepAccum accum = new SweepAccum();
            List<IndexRow> indexRows = new ArrayList<>(total);
            long sliceStartNs = System.nanoTime();
            int functionsSinceAnalysisCheck = 0;

            for (Partition part : partitions) {
                if (cancel.isCancelled() || !ensureProgramOpen()) {
                    return;
                }

                publish(decompTree.progress()
                        .withPhase(SweepProgress.Phase.DECOMPILING)
                        .withCurrentPartition(part.slug())
                        .withCounts(total, accum.done, accum.failed)
                        .withBytesWritten(accum.bytes)
                        .withRootRecreated(decompTree.root().rootRecreated())
                        .withEtaSeconds(etaSeconds(accum.done, total,
                                decompTree.progress().startedEpochMs())),
                        "dirty");

                List<Function> members = new ArrayList<>(part.members());
                members.sort(Comparator.comparing(Function::getEntryPoint));

                // The compartment's files, laid out by the same packer a reconcile uses.
                CompartmentPacker packer = new CompartmentPacker(part.slug(), cfg.maxFileBytes(),
                        program.getDefaultPointerSize());

                for (Function func : members) {
                    if (cancel.isCancelled()) {
                        writePackedBestEffort(packer.finish());
                        finishTerminal(SweepProgress.Phase.CANCELLED,
                                cancelReason != null ? cancelReason : "cancelled",
                                null);
                        return;
                    }
                    if (!ensureProgramOpen()) {
                        writePackedBestEffort(packer.finish());
                        return;
                    }

                    if (functionsSinceAnalysisCheck >= ANALYSIS_POLL_EVERY) {
                        functionsSinceAnalysisCheck = 0;
                        if (!waitForAnalysisIfNeeded()) {
                            writePackedBestEffort(packer.finish());
                            return;
                        }
                    }

                    boolean evidenceBacked = isEvidenceBacked(part, func, ctx);
                    FunctionEmit emit = decompileOne(func, part, evidenceBacked, ctx);
                    String addrHex = AddressKeys.of(func);
                    writePacked(packer.add(addrHex, emit.text()));
                    String relativeFile = packer.currentPath();

                    indexRows.add(new IndexRow(
                            addrHex,
                            func.getName(),
                            part.slug(),
                            relativeFile,
                            evidenceBacked,
                            InputFingerprint.of(func)));

                    accum.done++;
                    if (emit.failed()) {
                        accum.failed++;
                    }
                    accum.bytes += emit.text().getBytes(StandardCharsets.UTF_8).length;
                    functionsSinceAnalysisCheck++;

                    sliceStartNs = maybeThrottle(sliceStartNs, cfg.throttlePercent());
                }

                writePacked(packer.finish());
                publish(decompTree.progress()
                        .withCounts(total, accum.done, accum.failed)
                        .withBytesWritten(accum.bytes)
                        .withCurrentPartition(part.slug())
                        .withRootRecreated(decompTree.root().rootRecreated())
                        .withEtaSeconds(etaSeconds(accum.done, total,
                                decompTree.progress().startedEpochMs())),
                        "dirty");
            }

            // The grouping first: every derived file below is rendered from it and the rows,
            // by the same code a reconcile uses, so either path writes the same tree.
            PartitionMeta meta = PartitionMeta.of(cascade, partitions, scope,
                    ctx.literals().functionsWithStrings());
            meta.write(decompTree);
            List<TreeFiles.IndexEntry> entries = new ArrayList<>(indexRows.size());
            for (IndexRow r : indexRows) {
                entries.add(new TreeFiles.IndexEntry(r.addressHex(), r.name(), r.slug(),
                        r.file(), r.evidenceBacked(), r.ifp()));
            }
            DerivedFiles.deleteUnreferenced(decompTree, entries);
            DerivedFiles.writeAll(decompTree, program, entries, meta, ctx);

            if (cancel.isCancelled()) {
                finishTerminal(SweepProgress.Phase.CANCELLED,
                        cancelReason != null ? cancelReason : "cancelled",
                        null);
                return;
            }

            sweptMod = program.getModificationNumber();
            finishTerminal(SweepProgress.Phase.COMPLETE, null, sweptMod);
        } catch (Exception e) {
            finishTerminal(SweepProgress.Phase.FAILED,
                    e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName(),
                    null);
        } finally {
            // Belt: no path may leave the sweep without a terminal phase. Several
            // early returns exit on cancel (the outer partition-loop check
            // short-circuits before ensureProgramOpen, and waitForAnalysisIfNeeded
            // ends with `return !cancel.isCancelled()`), and each one left STATUS.md
            // saying "dirty" — which reads as "a sweep died", not "someone stopped
            // it". Found by tests/integration/test_decompile_tree.py, intermittently:
            // cancelling BETWEEN partitions took the bare-return path.
            SweepProgress.Phase reached = decompTree.progress().phase();
            if (reached != SweepProgress.Phase.COMPLETE
                    && reached != SweepProgress.Phase.CANCELLED
                    && reached != SweepProgress.Phase.FAILED) {
                finishTerminal(
                        cancel.isCancelled()
                                ? SweepProgress.Phase.CANCELLED
                                : SweepProgress.Phase.FAILED,
                        cancel.isCancelled()
                                ? (cancelReason != null ? cancelReason : "cancelled")
                                : "sweep ended without reaching a terminal state",
                        null);
            }
            decomp = null;
            if (localDecomp != null) {
                try {
                    localDecomp.dispose();
                } catch (Exception ignored) {
                    // dispose must not mask the sweep outcome
                }
            }
            try {
                program.release(this);
            } catch (Exception ignored) {
                // program may already be closed
            }
            TreeRegistry.getInstance().clearActiveJob(decompTree.id(), this);
        }
    }

    // -------------------------------------------------------------------------
    // Pure helpers (offline-tested)
    // -------------------------------------------------------------------------

    public static String renderFailedBody(String reason) {
        String safe = reason == null || reason.isBlank() ? "unknown" : reason.trim();
        return FAILED_MARKER_PREFIX + safe + "\n";
    }

    public static String functionResourceUri(String programName, String addressHex) {
        return "ghidra://function/"
                + encodeUriSegment(programName)
                + "/"
                + addressHex;
    }

    /**
     * Columns: address, name, partition_slug, file, evidence_backed, ifp.
     * {@code ifp} is the DB-cheap input fingerprint — not in the block header,
     * because the header is agent-read on every Read and must stay 9 lines.
     */
    public static String formatByAddressRow(
            String addressHex,
            String name,
            String partitionSlug,
            String file,
            boolean evidenceBacked,
            String ifp) {
        return addressHex + "\t" + name + "\t" + partitionSlug + "\t"
                + file + "\t" + evidenceBacked + "\t"
                + (ifp != null ? ifp : "") + "\n";
    }

    public static String byAddressHeader() {
        return "address\tname\tpartition_slug\tfile\tevidence_backed\tifp\n";
    }

    public static String shortContentHash(String content) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(content.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 6); // 12 hex chars
        } catch (NoSuchAlgorithmException e) {
            return "000000000000";
        }
    }

    /**
     * Percent-encode a URI path segment the way the bridge's
     * {@code quote(s, safe='')} does — every byte outside unreserved is escaped.
     */
    public static String encodeUriSegment(String raw) {
        if (raw == null || raw.isEmpty()) {
            return raw == null ? "" : raw;
        }
        StringBuilder out = new StringBuilder(raw.length() + 8);
        byte[] bytes = raw.getBytes(StandardCharsets.UTF_8);
        for (byte b : bytes) {
            int c = b & 0xff;
            if (isUnreserved(c)) {
                out.append((char) c);
            } else {
                out.append('%');
                out.append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xf, 16)));
                out.append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
            }
        }
        return out.toString();
    }

    private static boolean isUnreserved(int c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '-' || c == '.' || c == '_' || c == '~';
    }

    // -------------------------------------------------------------------------
    // Sweep internals
    // -------------------------------------------------------------------------

    private FunctionEmit decompileOne(
            Function func, Partition part, boolean evidenceBacked,
            PartitionContext ctx) {
        FunctionBlock.Built block = FunctionBlock.build(func, decomp,
                decompTree.config().decompileTimeoutSeconds(), cancel.monitor(), part.slug(),
                part.method(), part.confidence(), evidenceBacked, program.getName());
        return new FunctionEmit(block.text(), block.failed());
    }

    private static long functionSize(Function func) {
        try {
            return func.getBody().getNumAddresses();
        } catch (Exception e) {
            return 0L;
        }
    }

    /**
     * Whether this member carried the partition's own signal, vs being swept in
     * by address containment (literal-locality interiors, qualified-name span
     * closure). Address bands never have structural evidence.
     */
    static boolean isEvidenceBacked(Partition part, Function func, PartitionContext ctx) {
        String method = part.method();
        // A pin IS the evidence — a human/agent stated the compartment.
        if (ModuleOverrides.METHOD.equals(method)) {
            return true;
        }
        if ("address-band".equals(method)) {
            return false;
        }
        Integer idx = ctx.indexOf(func.getEntryPoint());
        if (idx == null) {
            return false;
        }
        if ("literal-locality".equals(method)) {
            return ctx.literals().medianStringAddress()[idx] >= 0;
        }
        if ("qualified-name".equals(method)) {
            Object className = part.evidence().get("class_name");
            if (className == null) {
                return false;
            }
            String needle = className.toString();
            for (String s : ctx.literals().rawStrings().get(idx)) {
                if (s != null && s.contains(needle)) {
                    return true;
                }
            }
            return false;
        }
        // mmio-page (and any future signal-exact strategy): membership IS the evidence.
        return true;
    }

    private boolean waitForAnalysisIfNeeded() {
        AutoAnalysisManager mgr;
        try {
            mgr = AutoAnalysisManager.getAnalysisManager(program);
        } catch (Exception e) {
            return true; // no manager — nothing to wait for
        }
        if (mgr == null || !mgr.isAnalyzing()) {
            return true;
        }

        publish(decompTree.progress().withPhase(SweepProgress.Phase.WAITING_FOR_ANALYSIS),
                "dirty");

        long deadline = System.nanoTime()
                + decompTree.config().analysisWaitSeconds() * 1_000_000_000L;
        while (mgr.isAnalyzing()) {
            if (cancel.isCancelled()) {
                finishTerminal(SweepProgress.Phase.CANCELLED,
                        cancelReason != null ? cancelReason : "cancelled",
                        null);
                return false;
            }
            if (!ensureProgramOpen()) {
                return false;
            }
            if (System.nanoTime() > deadline) {
                // Cap reached — proceed anyway; a stuck analyzer must not block forever.
                break;
            }
            try {
                Thread.sleep(200L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                requestCancel("interrupted");
                finishTerminal(SweepProgress.Phase.CANCELLED, "interrupted", null);
                return false;
            }
        }
        return !cancel.isCancelled();
    }

    private boolean ensureProgramOpen() {
        if (program.isClosed()) {
            requestCancel("program_closed");
            finishTerminal(SweepProgress.Phase.CANCELLED, "program_closed", null);
            return false;
        }
        return true;
    }

    private long maybeThrottle(long sliceStartNs, int throttlePercent) {
        return maybeThrottleSlice(sliceStartNs, throttlePercent, cancel);
    }

    /**
     * PE {@code .pdata} creates function entries without disassembly; partition
     * eligibility requires an instruction at the entry. Entry-only disassembly —
     * no auto-analysis, no new functions elsewhere.
     *
     * <p>Disassembly alone leaves the PE-loader body at one byte
     * ({@code body_start == body_end}). Every partitioner reads strings/scalars
     * out of the body, so that 1-byte body yields only address-band fallbacks.
     * After each successful entry disassembly we reflow the body via
     * {@link CreateFunctionCmd#getFunctionBody} + {@link Function#setBody} —
     * never {@code CreateFunctionCmd(..., recreate=true)}, which would discard
     * curated names/comments/signatures.
     */
    public static DisassemblyPassResult disassembleMissingAtEntries(
            Program program,
            CancelSignal cancel,
            int throttlePercent,
            EntryDisassembler disassembler) {
        return disassembleMissingAtEntries(
                program, cancel, throttlePercent, disassembler, SweepJob::defaultBodyComputer);
    }

    /**
     * Same as {@link #disassembleMissingAtEntries(Program, CancelSignal, int, EntryDisassembler)}
     * with an injectable body computer for offline tests.
     */
    public static DisassemblyPassResult disassembleMissingAtEntries(
            Program program,
            CancelSignal cancel,
            int throttlePercent,
            EntryDisassembler disassembler,
            BodyComputer bodyComputer) {
        int succeeded = 0;
        int failed = 0;
        int bodiesRecomputed = 0;
        int bodyRecomputeFailed = 0;
        long sliceStartNs = System.nanoTime();
        Listing listing = program.getListing();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            if (cancel.isCancelled()) {
                break;
            }
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) {
                continue;
            }
            Address entry = f.getEntryPoint();
            if (listing.getInstructionAt(entry) != null) {
                continue;
            }
            if (disassembler.disassemble(program, entry)) {
                succeeded++;
                BodyReflowOutcome bodyOutcome = recomputeBodyIfDegenerate(
                        program, f, cancel.monitor(), bodyComputer);
                if (bodyOutcome == BodyReflowOutcome.RECOMPUTED) {
                    bodiesRecomputed++;
                } else if (bodyOutcome == BodyReflowOutcome.FAILED) {
                    bodyRecomputeFailed++;
                }
            } else {
                failed++;
            }
            sliceStartNs = maybeThrottleSlice(sliceStartNs, throttlePercent, cancel);
        }
        return new DisassemblyPassResult(
                succeeded, failed, bodiesRecomputed, bodyRecomputeFailed);
    }

    /** Disassemble one known entry; package-visible for offline injection tests. */
    @FunctionalInterface
    public interface EntryDisassembler {
        boolean disassemble(Program program, Address entry);
    }

    /**
     * Computes a candidate body by following flow — creates nothing.
     * Injectable so offline tests do not need a live listing.
     */
    @FunctionalInterface
    public interface BodyComputer {
        AddressSetView compute(Program program, Address entry, TaskMonitor monitor);
    }

    public enum BodyReflowOutcome {
        SKIPPED,
        RECOMPUTED,
        FAILED
    }

    public record DisassemblyPassResult(
            int disassembledOnDemand,
            int disassemblyFailed,
            int bodiesRecomputed,
            int bodyRecomputeFailed) {
    }

    private static AddressSetView defaultBodyComputer(
            Program program, Address entry, TaskMonitor monitor) {
        return CreateFunctionCmd.getFunctionBody(monitor, program, entry);
    }

    /**
     * Reflow a PE-loader stub body after disassembly. Never shrinks a real body;
     * never recreates the function. Overlap with a neighbour is counted, not thrown.
     */
    public static BodyReflowOutcome recomputeBodyIfDegenerate(
            Program program,
            Function function,
            TaskMonitor monitor,
            BodyComputer bodyComputer) {
        AddressSetView current = function.getBody();
        // PE .pdata stubs are one address (start == end). A real body is larger —
        // leave it alone; curated extents must not be "fixed".
        if (current == null || current.getNumAddresses() > 1) {
            return BodyReflowOutcome.SKIPPED;
        }
        Address entry = function.getEntryPoint();
        AddressSetView body;
        try {
            body = bodyComputer.compute(program, entry, monitor);
        } catch (Exception e) {
            return BodyReflowOutcome.FAILED;
        }
        if (body == null || body.getNumAddresses() <= current.getNumAddresses()) {
            return BodyReflowOutcome.SKIPPED;
        }
        WriteTx tx = WriteTx.begin(program, "DecompTree recompute function body");
        try {
            function.setBody(body);
            tx.end(true);
            return BodyReflowOutcome.RECOMPUTED;
        } catch (OverlappingFunctionException e) {
            // One bad neighbour must not abort the sweep — count and continue.
            tx.end(false);
            return BodyReflowOutcome.FAILED;
        } catch (Exception e) {
            tx.end(false);
            return BodyReflowOutcome.FAILED;
        }
    }

    private static boolean disassembleAtEntry(Program program, Address entry) {
        Listing listing = program.getListing();
        if (listing.getInstructionAt(entry) != null) {
            return true;
        }
        WriteTx tx = WriteTx.begin(program, "DecompTree disassemble entry");
        try {
            AddressSet addrSet = new AddressSet(entry, entry);
            DisassembleCommand cmd = new DisassembleCommand(addrSet, null, true);
            // Follow flow from the entry only — do not pull in auto-analysis or
            // rename anything beyond what disassembly requires.
            cmd.setSeedContext(null);
            cmd.setInitialContext(null);
            cmd.enableCodeAnalysis(false);
            if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
                tx.end(false);
                return false;
            }
            tx.end(true);
            return listing.getInstructionAt(entry) != null;
        } catch (Exception e) {
            tx.end(false);
            return false;
        }
    }

    private static long maybeThrottleSlice(
            long sliceStartNs, int throttlePercent, CancelSignal cancel) {
        if (throttlePercent <= 0) {
            return sliceStartNs;
        }
        long heldMs = (System.nanoTime() - sliceStartNs) / 1_000_000L;
        if (heldMs < SLICE_MS) {
            return sliceStartNs;
        }
        long sleepMs = Math.max(1L, (long) SLICE_MS * throttlePercent / (100 - throttlePercent));
        try {
            Thread.sleep(sleepMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            cancel.cancel();
        }
        return System.nanoTime();
    }

    private void writePacked(CompartmentPacker.PackedFile file) throws IOException {
        if (file != null) {
            DerivedFiles.writeIfContentChanged(decompTree, file.path(), file.body());
        }
    }

    private void writePackedBestEffort(CompartmentPacker.PackedFile file) {
        try {
            writePacked(file);
        } catch (IOException ignored) {
            // Cancel/close path — best effort so Grep still sees what finished.
        }
    }

    /**
     * Full callgraph TSV, one row per call edge, by the same rule as the block headers'
     * {@code // calls:} lines ({@link FunctionFacts#calleesOf}): a header capped with
     * {@code +N more} and this file never disagree. Shared by sweep and reconcile.
     */
    public static String renderCallgraphTsv(PartitionContext ctx) {
        StringBuilder sb = new StringBuilder("caller\tcallee\tcaller_name\tcallee_name\n");
        for (Function caller : ctx.functions()) {
            String callerAddr = AddressKeys.of(caller);
            for (Function callee : FunctionFacts.calleesOf(caller)) {
                sb.append(callerAddr).append('\t')
                        .append(AddressKeys.of(callee)).append('\t')
                        .append(caller.getName()).append('\t')
                        .append(callee.getName()).append('\n');
            }
        }
        return sb.toString();
    }

    private void publish(SweepProgress progress, String state) {
        // decompile_tree_run(action=stop) may have already stamped CANCELLED; never let a mid-sweep
        // DECOMPILING publish clobber that — the agent is polling for cancel.
        if (cancel.isCancelled()) {
            SweepProgress.Phase p = progress.phase();
            if (p != SweepProgress.Phase.CANCELLED
                    && p != SweepProgress.Phase.FAILED
                    && p != SweepProgress.Phase.COMPLETE) {
                progress = progress
                        .withPhase(SweepProgress.Phase.CANCELLED)
                        .withLastError(cancelReason != null ? cancelReason : "cancelled");
                state = "cancelled";
            }
        }
        decompTree.setProgress(progress);
        try {
            TreeStatusMd.write(decompTree, state);
        } catch (IOException e) {
            // Progress is still in memory for /decompile_tree_status; disk is best-effort
            // mid-sweep (root may be recreating).
        }
    }

    private void finishTerminal(SweepProgress.Phase phase, String error, Long sweptAt) {
        if (cancel.isCancelled() && phase == SweepProgress.Phase.COMPLETE) {
            phase = SweepProgress.Phase.CANCELLED;
            error = cancelReason != null ? cancelReason : "cancelled";
            sweptAt = null;
        }
        SweepProgress.Phase current = decompTree.progress().phase();
        // Don't clobber an already-published cancel with a later failure from finally.
        if (current == SweepProgress.Phase.CANCELLED
                && phase != SweepProgress.Phase.CANCELLED) {
            return;
        }
        SweepProgress next = decompTree.progress()
                .withPhase(phase)
                .withLastError(error)
                .withCurrentPartition(null)
                .withEtaSeconds(null)
                .withRootRecreated(decompTree.root().rootRecreated());
        // A fresh sweep is the new ground truth — splice drift starts at zero. A
        // failed or cancelled one leaves a partly rewritten tree that matches no
        // modification number.
        next = phase == SweepProgress.Phase.COMPLETE ? next.sweptAt(sweptAt) : next.sweptAt(null);
        if (!program.isClosed()) {
            decompTree.noteSession(program);
        }
        String state = TreeStatusMd.stateForPhase(phase);
        publish(next, state);
    }

    private static Long etaSeconds(int done, int total, long startedEpochMs) {
        if (done <= 0 || total <= done || startedEpochMs <= 0) {
            return null;
        }
        long elapsed = System.currentTimeMillis() - startedEpochMs;
        if (elapsed <= 0) {
            return null;
        }
        double perFn = elapsed / (double) done;
        return Math.max(0L, Math.round(perFn * (total - done) / 1000.0));
    }

    // -------------------------------------------------------------------------
    // Nested types
    // -------------------------------------------------------------------------

    /**
     * Cancel flag + TaskMonitor whose {@code isCancelled()} returns the same
     * flag, so the native decompiler aborts without waiting out the timeout.
     */
    public static final class CancelSignal {
        private final SweepMonitor monitor = new SweepMonitor();

        public void cancel() {
            monitor.cancel();
        }

        public boolean isCancelled() {
            return monitor.isCancelled();
        }

        public TaskMonitor monitor() {
            return monitor;
        }
    }

    private static final class SweepMonitor extends TaskMonitorAdapter {
        SweepMonitor() {
            super(true);
        }
    }

    private record FunctionEmit(String text, boolean failed) {}

    private record IndexRow(
            String addressHex,
            String name,
            String slug,
            String file,
            boolean evidenceBacked,
            String ifp) {}

    private static final class SweepAccum {
        int done;
        int failed;
        long bytes;
    }
}
