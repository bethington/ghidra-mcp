package com.xebyte.core.tree;

import com.xebyte.core.AddressKeys;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * Coalesces observer dirty hints into debounced reconcile passes.
 *
 * <p>Drains on {@link TreeRegistry}'s existing single-thread
 * {@code GhidraMCP-DecompTree-Sweep} executor — one decompile stream JVM-wide is
 * a measured constraint, not a style choice. A second pool would interleave
 * with sweeps and thrash the ProgramDB lock.
 *
 * <p>{@code setEventsEnabled(false)} means events can be missed entirely; the
 * reconciler (not this queue) is the source of truth. RESTORED and the address
 * bound both collapse to a full reconcile for that reason.
 *
 * @since 7.2.0
 */
public final class DirtyQueue {

    /** Past this, an analysis-sized storm collapses to needsReconcile. */
    public static final int ADDRESS_BOUND = 2000;

    /** Coalesce a batch rename into one pass (250–500 ms band). */
    public static final long DEBOUNCE_MS = 300L;

    private final TreeRegistry registry;
    private final Function<DecompTree, Program> programLookup;
    private final Predicate<String> sweepActive;
    private final BiPredicate<Program, String> analyzing;
    private final ReconcileAction reconcileAction;
    private final Supplier<Long> clock;
    private final java.util.function.Consumer<Runnable> enqueue;

    private final Map<String, Bucket> buckets = new LinkedHashMap<>();

    /** Production constructor — wires registry sweep thread + live analysis. */
    public DirtyQueue(TreeRegistry registry) {
        this(
                registry,
                null,
                id -> registry.isSweepActive(id),
                (program, ignored) -> isAnalyzing(program),
                (decompTree, program, addrs) -> TreeReconciler.reconcile(decompTree, program, addrs),
                System::currentTimeMillis,
                registry::enqueue);
    }

    /**
     * Injectable constructor for offline tests (clock, gates, reconcile sink).
     * Production code uses {@link #DirtyQueue(TreeRegistry)}.
     */
    public DirtyQueue(
            TreeRegistry registry,
            Function<DecompTree, Program> programLookup,
            Predicate<String> sweepActive,
            BiPredicate<Program, String> analyzing,
            ReconcileAction reconcileAction,
            Supplier<Long> clock,
            java.util.function.Consumer<Runnable> enqueue) {
        this.registry = Objects.requireNonNull(registry, "registry");
        this.programLookup = programLookup;
        this.sweepActive = Objects.requireNonNull(sweepActive, "sweepActive");
        this.analyzing = Objects.requireNonNull(analyzing, "analyzing");
        this.reconcileAction = Objects.requireNonNull(reconcileAction, "reconcileAction");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.enqueue = Objects.requireNonNull(enqueue, "enqueue");
    }

    public synchronized void markDirty(String treeId, Collection<String> addresses) {
        if (treeId == null || addresses == null || addresses.isEmpty()) {
            return;
        }
        Bucket b = buckets.computeIfAbsent(treeId, id -> new Bucket());
        if (b.needsReconcile) {
            // Already collapsed — just keep the debounce alive.
            arm(treeId, b);
            return;
        }
        for (String raw : addresses) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            b.addresses.add(AddressKeys.normalize(raw));
            if (b.addresses.size() >= ADDRESS_BOUND) {
                // Bound is a safety valve: splicing thousands of analysis
                // births one-by-one is pathological. Fall back to full reconcile.
                b.needsReconcile = true;
                b.addresses.clear();
                break;
            }
        }
        arm(treeId, b);
    }

    /**
     * Names symbols were renamed away from. The drain re-decompiles every block whose body
     * still prints one, which covers uses the program records no reference for.
     */
    public synchronized void markRetiredNames(String treeId, Collection<String> names) {
        if (treeId == null || names == null || names.isEmpty()) {
            return;
        }
        Bucket b = buckets.computeIfAbsent(treeId, id -> new Bucket());
        b.retiredNames.addAll(names);
        arm(treeId, b);
    }

    public synchronized void markNeedsReconcile(String treeId) {
        if (treeId == null) {
            return;
        }
        Bucket b = buckets.computeIfAbsent(treeId, id -> new Bucket());
        b.needsReconcile = true;
        b.addresses.clear();
        arm(treeId, b);
    }

    /** Test helper — pending address count (0 when collapsed to full). */
    public synchronized int pendingAddressCount(String treeId) {
        Bucket b = buckets.get(treeId);
        return b == null ? 0 : b.addresses.size();
    }

    /** Any work at all for this tree: queued addresses, names, a full pass, or one running. */
    /** Re-arm a drain for work left pending while a sweep held the tree. */
    public synchronized void resume(String treeId) {
        Bucket b = buckets.get(treeId);
        if (b != null && (b.needsReconcile || !b.addresses.isEmpty() || !b.retiredNames.isEmpty())) {
            arm(treeId, b);
        }
    }

    public synchronized boolean hasPending(String treeId) {
        Bucket b = buckets.get(treeId);
        return b != null && (b.needsReconcile || !b.addresses.isEmpty() || !b.retiredNames.isEmpty()
                || b.reconciling);
    }

    public synchronized boolean pendingNeedsReconcile(String treeId) {
        Bucket b = buckets.get(treeId);
        return b != null && b.needsReconcile;
    }

    public synchronized void clear(String treeId) {
        if (treeId != null) {
            buckets.remove(treeId);
        }
    }

    public synchronized void clearAll() {
        buckets.clear();
    }

    private void arm(String treeId, Bucket b) {
        b.deadlineMs = clock.get() + DEBOUNCE_MS;
        if (b.drainQueued) {
            return;
        }
        b.drainQueued = true;
        final String id = treeId;
        enqueue.accept(() -> drain(id));
    }

    private void drain(String treeId) {
        try {
            while (true) {
                long waitMs;
                synchronized (this) {
                    Bucket b = buckets.get(treeId);
                    if (b == null || (!b.needsReconcile && b.addresses.isEmpty()
                            && b.retiredNames.isEmpty())) {
                        if (b != null) {
                            b.drainQueued = false;
                        }
                        return;
                    }
                    waitMs = b.deadlineMs - clock.get();
                }
                if (waitMs > 0) {
                    Thread.sleep(waitMs);
                    continue; // dirt may have extended the deadline
                }

                DecompTree decompTree = registry.byId(treeId);
                if (decompTree == null) {
                    synchronized (this) {
                        buckets.remove(treeId);
                    }
                    return;
                }
                Program program = resolveProgram(decompTree);
                if (program == null || program.isClosed()) {
                    // Dropping dirty work silently is how this went unnoticed
                    // headless for a whole stage: observers attached, addresses
                    // queued, and every drain returned here because no lookup
                    // was registered. Say so -- an unreconciled tree is a tree
                    // that lies to Grep.
                    Msg.warn(this, "DecompTree " + treeId + ": dropping dirty work, "
                            + (program == null
                                    ? "no Program could be resolved (is a program lookup registered?)"
                                    : "the Program is closed"));
                    synchronized (this) {
                        Bucket b = buckets.get(treeId);
                        if (b != null) {
                            b.drainQueued = false;
                        }
                    }
                    return;
                }

                // A sweep of this tree is queued or running. Give the thread back: drains
                // and sweeps share one executor, so waiting here kept a QUEUED sweep from ever
                // starting and the two waited on each other forever (measured: an adoption's
                // queued reconcile plus a decompile_tree_run start). The sweep re-arms
                // whatever is still pending when it ends (resume()).
                if (sweepActive.test(treeId)) {
                    synchronized (this) {
                        Bucket b = buckets.get(treeId);
                        if (b != null) {
                            b.drainQueued = false;
                        }
                    }
                    return;
                }
                // Initial analysis creates thousands of functions; splice once it settles.
                if (analyzing.test(program, treeId)) {
                    synchronized (this) {
                        Bucket b = buckets.get(treeId);
                        if (b != null) {
                            b.deadlineMs = clock.get() + DEBOUNCE_MS;
                        }
                    }
                    continue;
                }

                final boolean full;
                final Set<String> targeted;
                final Set<String> retired;
                synchronized (this) {
                    Bucket b = buckets.get(treeId);
                    if (b == null) {
                        return;
                    }
                    // Deadline extended while we checked gates?
                    if (b.deadlineMs > clock.get()) {
                        continue;
                    }
                    full = b.needsReconcile;
                    targeted = full ? null : Set.copyOf(b.addresses);
                    retired = Set.copyOf(b.retiredNames);
                    b.reconciling = true;
                    b.needsReconcile = false;
                    b.addresses.clear();
                    b.retiredNames.clear();
                    b.drainQueued = false;
                }

                try {
                    // A full pass compares input fingerprints, which a use the program has no
                    // reference for does not change, so the name search runs either way.
                    Set<String> mentioning = TreeReconciler.blocksMentioning(decompTree, retired);
                    if (full) {
                        reconcileAction.reconcile(decompTree, program, null);
                        if (!mentioning.isEmpty()) {
                            reconcileAction.reconcile(decompTree, program, mentioning);
                        }
                    } else {
                        Set<String> all = new LinkedHashSet<>(targeted);
                        all.addAll(mentioning);
                        reconcileAction.reconcile(decompTree, program, all);
                    }
                } catch (Exception e) {
                    Msg.error(this, "DecompTree dirty-queue reconcile failed for "
                            + treeId + ": " + e.getMessage(), e);
                } finally {
                    synchronized (this) {
                        Bucket b = buckets.get(treeId);
                        if (b != null) {
                            b.reconciling = false;
                        }
                    }
                }
                // More dirt may have arrived during reconcile — if so, arm()
                // already queued another drain on this same executor.
                return;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            synchronized (this) {
                Bucket b = buckets.get(treeId);
                if (b != null) {
                    b.drainQueued = false;
                }
            }
        }
    }

    private Program resolveProgram(DecompTree decompTree) {
        if (programLookup != null) {
            return programLookup.apply(decompTree);
        }
        Function<DecompTree, Program> lookup = registry.programLookup();
        return lookup != null ? lookup.apply(decompTree) : null;
    }

    private static boolean isAnalyzing(Program program) {
        if (program == null) {
            return false;
        }
        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            return mgr != null && mgr.isAnalyzing();
        } catch (Exception e) {
            return false;
        }
    }

    @FunctionalInterface
    public interface ReconcileAction {
        void reconcile(DecompTree decompTree, Program program, Set<String> addresses)
                throws Exception;
    }

    private static final class Bucket {
        final Set<String> addresses = new LinkedHashSet<>();
        final Set<String> retiredNames = new LinkedHashSet<>();
        boolean reconciling;
        boolean needsReconcile;
        long deadlineMs;
        boolean drainQueued;
    }
}
