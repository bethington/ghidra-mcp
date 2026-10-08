package com.xebyte.core.tree;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * JVM-wide tree registry — {@link com.xebyte.core.NamingPolicy}-shaped
 * {@code private static final INSTANCE}, never nulled.
 *
 * <p>Contrast {@code ServerManager}, which nulls its instance on last-tool
 * deregister: hanging trees off that lifecycle would drop in-flight state
 * and orphan on-disk trees whenever the last tool closed. Services are also
 * constructed at three independent sites, so an instance field would be three
 * registries in one GUI JVM. Only a static singleton is JVM-wide.
 *
 * <p>One single-thread daemon executor runs sweeps <em>and</em> the
 * {@link DirtyQueue} drain; throughput is {@code ProgramDB}-lock-bound, so a
 * second concurrent decompile stream would only thrash the first.
 * {@link SweepJob} submits via {@link #enqueueSweep(SweepJob)}.
 */
public final class TreeRegistry {

    private static final TreeRegistry INSTANCE = new TreeRegistry();

    private final Map<String, DecompTree> byId = new LinkedHashMap<>();
    private final Map<String, SweepJob> activeJobs = new ConcurrentHashMap<>();
    private final Map<String, TreeObserver> observers = new ConcurrentHashMap<>();
    private final Map<String, Program> observerPrograms = new ConcurrentHashMap<>();
    private final ExecutorService sweepExecutor;
    private final DirtyQueue dirtyQueue;
    private volatile Function<DecompTree, Program> programLookup;
    private volatile Consumer<Program> adoptOnOpen;
    private final Map<Program, Boolean> adoptChecked =
            Collections.synchronizedMap(new WeakHashMap<>());
    private final ExecutorService adoptExecutor;

    private TreeRegistry() {
        ThreadFactory factory = runnable -> {
            Thread t = new Thread(runnable, "GhidraMCP-DecompTree-Sweep");
            t.setDaemon(true);
            t.setPriority(Thread.MIN_PRIORITY);
            return t;
        };
        this.sweepExecutor = Executors.newSingleThreadExecutor(factory);
        // Not the sweep executor: adoption would otherwise wait behind a sweep of another
        // program for minutes, unobserved.
        this.adoptExecutor = Executors.newSingleThreadExecutor(runnable -> {
            Thread t = new Thread(runnable, "GhidraMCP-DecompTree-Adopt");
            t.setDaemon(true);
            return t;
        });
        this.dirtyQueue = new DirtyQueue(this);
    }

    public static TreeRegistry getInstance() {
        return INSTANCE;
    }

    public DirtyQueue dirtyQueue() {
        return dirtyQueue;
    }

    /**
     * How the dirty queue re-resolves a Program without the observer holding
     * one. Set by {@code FrontEndProgramProvider} (cache owner); null means
     * auto-reconcile cannot run.
     */
    public void setProgramLookup(Function<DecompTree, Program> lookup) {
        this.programLookup = lookup;
    }

    /**
     * Install a fallback lookup only when nothing better is registered.
     *
     * <p>{@code DecompTreeService} registers one derived from its
     * {@code ProgramProvider}, which exists in every mode. Without it,
     * auto-reconcile was silently dead outside the GUI: the only caller of
     * {@link #setProgramLookup} is the FrontEnd cache, so a headless server
     * attached observers, queued dirty addresses, and then dropped every one
     * of them because no Program could be resolved.
     *
     * <p>Kept as a distinct entry point so the GUI's richer, cache-aware
     * lookup always wins the race regardless of construction order.
     */
    public synchronized void setProgramLookupIfAbsent(Function<DecompTree, Program> lookup) {
        if (programLookup == null) {
            programLookup = lookup;
        }
    }

    /**
     * How a program's trees on disk are adopted when it opens. Set by {@code DecompTreeService},
     * which owns adoption; the first registration wins, as for the lookup.
     */
    public synchronized void setAdoptOnOpenIfAbsent(Consumer<Program> hook) {
        if (adoptOnOpen == null) {
            adoptOnOpen = hook;
        }
    }

    /**
     * A program was resolved. The first time this Program instance is seen, its trees on disk
     * are adopted (off the caller's thread, which may hold the provider's locks); every time,
     * the registered trees are observed. Before, a restart left every tree unregistered
     * until an agent called {@code decompile_tree_create} again, and edits made meanwhile
     * never reached it.
     */
    public void programOpened(Program program) {
        if (program == null || program.isClosed()) {
            return;
        }
        Consumer<Program> hook = adoptOnOpen;
        if (hook != null && adoptChecked.putIfAbsent(program, Boolean.TRUE) == null) {
            adoptExecutor.execute(() -> {
                if (program.isClosed()) {
                    return;
                }
                try {
                    hook.accept(program);
                } catch (Exception e) {
                    Msg.warn(this, "Adopting trees of " + program.getName() + " failed: "
                            + e.getMessage(), e);
                }
            });
        }
        ensureObserver(program);
    }

    Function<DecompTree, Program> programLookup() {
        return programLookup;
    }

    boolean isSweepActive(String treeId) {
        return treeId != null && activeJobs.containsKey(treeId);
    }

    /**
     * Attach a {@link TreeObserver} when this program has a registered
     * tree. Idempotent. Holds the observer by tree id — never stores
     * the Program on the observer itself.
     */
    public void ensureObserver(Program program) {
        if (program == null || program.isClosed()) {
            return;
        }
        for (DecompTree decompTree : checkoutsFor(program)) {
            attach(decompTree, program);
        }
    }

    private void attach(DecompTree decompTree, Program program) {
        String id = decompTree.id();
        if (observers.containsKey(id)) {
            // Same tree, possibly a different Program instance after
            // orphan recovery — rebind the listener to the live object.
            Program prior = observerPrograms.get(id);
            if (prior == program) {
                return;
            }
            detachObserver(id);
        }
        TreeObserver obs = new TreeObserver(id, dirtyQueue);
        try {
            program.addListener(obs);
            observers.put(id, obs);
            observerPrograms.put(id, program);
            // A program that opens unchanged is its saved state.
            decompTree.setSavedAtModification(program.isChanged() ? null : program.getModificationNumber());
            if (decompTree.recoverOnReattach()) {
                // Closed while the tree held discarded edits or missed saved ones: re-diff
                // against the program as it reopened instead of waiting for the next edit.
                // Names the discarded session introduced are searched in the bodies too, for
                // the uses a fingerprint compare cannot see.
                dirtyQueue.markRetiredNames(id, java.util.Set.copyOf(decompTree.namesSinceSave()));
                decompTree.namesSinceSave().clear();
                dirtyQueue.markNeedsReconcile(id);
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to attach tree observer for " + id
                    + ": " + e.getMessage());
        }
    }

    /** Detach every observer bound to this Program (cache release / evict). */
    public void detachObservers(Program program) {
        if (program == null) {
            return;
        }
        List<String> ids = new ArrayList<>();
        for (Map.Entry<String, Program> e : observerPrograms.entrySet()) {
            if (e.getValue() == program) {
                ids.add(e.getKey());
            }
        }
        for (String id : ids) {
            noteClosing(id, program);
            detachObserver(id);
        }
    }

    /**
     * The tree is known to diverge from the program in a way only a resweep fixes. Called
     * on the event thread: progress changes now, STATUS.md is written on the tree
     * executor.
     */
    public void markStale(String treeId, String reason) {
        DecompTree decompTree = byId(treeId);
        if (decompTree == null) {
            return;
        }
        decompTree.setProgress(decompTree.progress()
                .withPhase(SweepProgress.Phase.STALE)
                .withLastError(reason));
        enqueue(() -> {
            try {
                TreeStatusMd.write(decompTree, "stale");
            } catch (IOException e) {
                Msg.warn(this, "DecompTree " + treeId + ": could not mark STATUS.md stale: "
                        + e.getMessage());
            }
        });
    }

    /** The program was saved at {@code modification}: that is what a reopen will show. */
    public void noteSaved(String treeId, long modification) {
        DecompTree decompTree = byId(treeId);
        if (decompTree != null) {
            decompTree.setSavedAtModification(modification);
            decompTree.namesSinceSave().clear();
        }
    }

    /** Symbols were renamed to {@code names} since the last save. */
    public void noteIntroducedNames(String treeId, Collection<String> names) {
        DecompTree decompTree = byId(treeId);
        if (decompTree != null) {
            decompTree.namesSinceSave().addAll(names);
        }
    }

    /**
     * The tree's program is closing. If the tree no longer matches what a reopen will
     * show, mark it stale and reconcile on reopen: either the close discards edits the tree
     * already took in, or saved edits are still queued and detaching drops them.
     */
    public void noteClosing(String treeId, Program program) {
        DecompTree decompTree = byId(treeId);
        if (decompTree == null || program == null) {
            return;
        }
        SweepProgress p = decompTree.progress();
        Long tree = p.reconciledAtModification();
        Long saved = decompTree.savedAtModification();
        String why = null;
        boolean discarding;
        try {
            discarding = program.isChanged();
        } catch (Exception e) {
            discarding = false;
        }
        if (discarding && tree != null && (saved == null || tree > saved)) {
            why = "the program closed without saving edits the tree had already taken in; "
                    + "it may show changes the program no longer has";
        } else if (!discarding && dirtyQueue.hasPending(treeId)) {
            why = "the program closed before saved changes reached the tree";
        }
        if (why == null) {
            return;
        }
        decompTree.setProgress(p.withPhase(SweepProgress.Phase.STALE).withLastError(why));
        decompTree.setRecoverOnReattach(true);
        try {
            TreeStatusMd.write(decompTree, "stale");
        } catch (IOException e) {
            Msg.warn(this, "DecompTree " + treeId + ": could not mark STATUS.md stale: "
                    + e.getMessage());
        }
    }

    /** Detach by tree id (delete path / CLOSED). */
    public void detachObserver(String treeId) {
        if (treeId == null) {
            return;
        }
        TreeObserver obs = observers.remove(treeId);
        Program program = observerPrograms.remove(treeId);
        dirtyQueue.clear(treeId);
        if (obs != null && program != null && !program.isClosed()) {
            try {
                program.removeListener(obs);
            } catch (Exception e) {
                Msg.warn(this, "Failed to detach tree observer for "
                        + treeId + ": " + e.getMessage());
            }
        }
    }

    /**
     * Every tree of this program. By domain path when the program has one: a name is
     * not unique in a project ({@code D2Common.dll} sits in every version folder), and the
     * first match alone left a second tree of the same program unobserved.
     */
    private List<DecompTree> checkoutsFor(Program program) {
        DomainFile df = program.getDomainFile();
        String domain = df != null ? df.getPathname() : null;
        String name = program.getName();
        List<DecompTree> out = new ArrayList<>();
        synchronized (this) {
            for (DecompTree c : byId.values()) {
                if (domain != null ? domain.equals(c.domainPath()) : Objects.equals(name, c.programName())) {
                    out.add(c);
                }
            }
        }
        return out;
    }

    /**
     * Default-root parent used in the key so hashing is non-circular:
     * {@code id} / directory suffix = SHA-256({@code domain|parent})[0:8],
     * files live at {@code parent/<basename>-<hash>/}.
     */
    private final KnownRoots knownRoots = KnownRoots.forThisInstance();

    /** Explicit roots created on this instance, for the status scan. */
    public KnownRoots knownRoots() {
        return knownRoots;
    }

    public static Path defaultParent() {
        return Path.of(System.getProperty("java.io.tmpdir"), "ghidra-mcp-tree")
                .toAbsolutePath()
                .normalize();
    }

    /**
     * Create (or return existing-by-id) a tree for {@code domainPath}.
     * Does not start a sweep.
     */
    public synchronized DecompTree create(
            String domainPath, String programName, TreeConfig config) throws IOException {
        Objects.requireNonNull(domainPath, "domainPath");
        Objects.requireNonNull(programName, "programName");
        TreeConfig cfg = config != null ? config : TreeConfig.defaults();

        // Key material uses the shared parent (not the unique child dir) so the
        // directory suffix can be the same 8 hex chars as id().
        TreeKey defaultKey = TreeKey.of(domainPath, defaultParent().toString());
        TreeRoot defaultRoot = TreeRoot.defaultRoot(defaultKey.directoryName(programName));

        final TreeKey key;
        final TreeRoot root;
        if (cfg.rootPath() != null) {
            root = TreeRoot.explicit(cfg.rootPath());
            // An explicit root that IS this program's default root must key the same
            // way the default branch does. Otherwise one tree acquires two identities
            // — measured: creating with no root and then re-creating from a config
            // that had been persisted with the resolved absolute root produced
            // tree_7de33ad7 and tree_adeb2a7d for the same directory, each with its own
            // resource URI, so a client subscribed to the first stopped being told
            // about changes.
            key = root.path().equals(defaultRoot.path())
                    ? defaultKey
                    : TreeKey.of(domainPath, root.path());
        } else {
            key = defaultKey;
            root = defaultRoot;
        }

        DecompTree existing = byId.get(key.id());
        if (existing != null) {
            return existing;
        }

        TreeConfig resolved = cfg.withRootPath(root.path().toString());
        root.ensureExists();
        DecompTree decompTree = new DecompTree(key, programName, resolved, root);
        byId.put(decompTree.id(), decompTree);
        if (!root.path().getParent().equals(defaultParent())) {
            knownRoots.add(root.path());
        }
        return decompTree;
    }

    /** Register an already-built tree (tests / adopt path). */
    public synchronized DecompTree register(DecompTree decompTree) {
        Objects.requireNonNull(decompTree, "decompTree");
        byId.put(decompTree.id(), decompTree);
        return decompTree;
    }

    public synchronized DecompTree byId(String id) {
        if (id == null) {
            return null;
        }
        return byId.get(id);
    }

    public synchronized Collection<DecompTree> all() {
        return List.copyOf(byId.values());
    }

    /**
     * Resolve by tree id, program name, or domain path.
     *
     * <p>On ambiguity returns an error naming both candidates rather than
     * guessing — the same failure mode {@code switch_program} has when
     * matching by name across versioned project folders.
     */
    public synchronized ResolveResult resolve(String selector) {
        if (selector == null || selector.isBlank()) {
            return ResolveResult.error("tree selector must not be blank");
        }
        String sel = selector.trim();

        DecompTree byExactId = byId.get(sel);
        if (byExactId != null) {
            return ResolveResult.ok(byExactId);
        }

        List<DecompTree> matches = new ArrayList<>();
        for (DecompTree c : byId.values()) {
            if (sel.equals(c.id())
                    || sel.equals(c.programName())
                    || sel.equals(c.domainPath())
                    || basenameEquals(sel, c.programName())
                    || basenameEquals(sel, c.domainPath())) {
                matches.add(c);
            }
        }

        if (matches.isEmpty()) {
            return ResolveResult.error("no tree matches selector: " + sel);
        }
        if (matches.size() == 1) {
            return ResolveResult.ok(matches.get(0));
        }
        DecompTree a = matches.get(0);
        DecompTree b = matches.get(1);
        return ResolveResult.error(
                "ambiguous tree selector '" + sel + "': matches "
                        + a.id() + " (" + a.domainPath() + ") and "
                        + b.id() + " (" + b.domainPath() + ")");
    }

    /**
     * Deregister {@code id}, and with {@code deleteFiles} remove the files it wrote
     * ({@link TreeRoot#deleteTree}). Null when no tree has that id.
     */
    public synchronized TreeRoot.DeleteResult delete(String id, boolean deleteFiles)
            throws IOException {
        DecompTree removed = byId.remove(id);
        if (removed == null) {
            return null;
        }
        // Drop the listener before the tree — a deleted tree must not keep
        // splicing into a path that no longer exists.
        detachObserver(id);
        knownRoots.remove(removed.root().path());
        return deleteFiles
                ? removed.root().deleteTree()
                : new TreeRoot.DeleteResult(0, List.of());
    }

    /**
     * Enqueue a {@link SweepJob} on the single JVM-wide sweep thread.
     * Tracks the job so {@link #cancelSweep} can flip its flag and
     * {@code stopProcess()} the in-flight decompile.
     */
    /** Queue a sweep of {@code tree}, unless one is already queued or running. */
    public void requestSweep(DecompTree decompTree, ghidra.program.model.listing.Program program)
            throws IOException {
        SweepProgress.Phase phase = decompTree.progress().phase();
        if (phase == SweepProgress.Phase.QUEUED
                || phase == SweepProgress.Phase.WAITING_FOR_ANALYSIS
                || phase == SweepProgress.Phase.PARTITIONING
                || phase == SweepProgress.Phase.DECOMPILING) {
            return;
        }
        decompTree.setProgress(decompTree.progress().withPhase(SweepProgress.Phase.QUEUED));
        TreeStatusMd.write(decompTree, "dirty");
        enqueueSweep(new SweepJob(decompTree, program));
    }

    public void enqueueSweep(SweepJob job) {
        Objects.requireNonNull(job, "job");
        activeJobs.put(job.treeId(), job);
        sweepExecutor.execute(job);
    }

    /**
     * Cancel a queued or running sweep. A job still queued is marked cancelled
     * before {@link SweepJob#run()} does any work.
     */
    public void cancelSweep(String treeId, String reason) {
        if (treeId == null) {
            return;
        }
        SweepJob job = activeJobs.get(treeId);
        if (job != null) {
            job.requestCancel(reason != null ? reason : "cancelled by decompile_tree_run(action=stop)");
        }
    }

    /** Called from {@link SweepJob} finally — only clears if still this job. */
    void clearActiveJob(String treeId, SweepJob job) {
        if (activeJobs.remove(treeId, job)) {
            dirtyQueue.resume(treeId);
        }
    }

    /** Test / raw hook: enqueue arbitrary work on the sweep thread. */
    public void enqueue(Runnable job) {
        Objects.requireNonNull(job, "job");
        sweepExecutor.execute(job);
    }

    /** Test helper: drop all registrations without touching disk. */
    public synchronized void clearForTests() {
        for (String id : new ArrayList<>(observers.keySet())) {
            detachObserver(id);
        }
        byId.clear();
        activeJobs.clear();
        dirtyQueue.clearAll();
        programLookup = null;
        adoptOnOpen = null;
        adoptChecked.clear();
    }

    private static boolean basenameEquals(String selector, String pathOrName) {
        if (pathOrName == null) {
            return false;
        }
        return selector.equals(com.xebyte.core.SafePaths.safeBasename(pathOrName));
    }

    /**
     * Result of {@link TreeRegistry#resolve(String)} — either a single
     * tree or an error message (not found / ambiguous).
     */
    public record ResolveResult(DecompTree decompTree, String error) {
        public static ResolveResult ok(DecompTree decompTree) {
            return new ResolveResult(Objects.requireNonNull(decompTree), null);
        }

        public static ResolveResult error(String message) {
            return new ResolveResult(null, Objects.requireNonNull(message));
        }

        public boolean isOk() {
            return decompTree != null;
        }
    }
}
