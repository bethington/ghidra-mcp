package com.xebyte.core.tree;

import java.util.Objects;

/**
 * One registered tree: identity, display name, config, progress, and root.
 *
 * <p>Must <em>not</em> hold a {@code ghidra.program.model.listing.Program}
 * reference — that would pin a {@code ProgramDB} and break program close.
 * The key stores domain path and root as strings only; callers re-resolve
 * through {@code ProgramProvider} when they need a live Program. Only a
 * running sweep job pins via {@code addConsumer}/{@code release}.
 */
public final class DecompTree {

    private final TreeKey key;
    private final String programName;
    private final TreeRoot root;
    private volatile TreeConfig config;
    private volatile SweepProgress progress;
    /** Program modification number at its last save (or clean open); null while unknown. */
    private volatile Long savedAtModification;
    /** The tree went stale when its program closed; reconcile in full when it reopens. */
    private volatile boolean recoverOnReattach;
    /** Names given to symbols since the last save: what a discarded session may leave behind. */
    private final java.util.Set<String> namesSinceSave = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /**
     * Held by every writer of the tree (a sweep, a reconcile) for its whole run. Each reads the
     * index and files, computes, then writes; two at once each work from a view the other is
     * changing, and the later write undoes the earlier one. Measured: a refresh racing the
     * full reconcile an adoption queues left deleted files unrestored.
     */
    private final java.util.concurrent.locks.ReentrantLock treeLock =
            new java.util.concurrent.locks.ReentrantLock();

    public java.util.concurrent.locks.ReentrantLock treeLock() {
        return treeLock;
    }

    /**
     * The program state the tree's progress numbers belong to. Modification numbers start over
     * on every open, so they compare only within one {@code epoch}
     * ({@link com.xebyte.core.ProgramRevision}); {@code savedTime}/{@code fileVersion} name the
     * saved program the tree reflects, and survive restarts.
     */
    public record Session(String epoch, long savedTime, Integer fileVersion, boolean unsavedEdits) {
        public static Session of(ghidra.program.model.listing.Program program) {
            return new Session(com.xebyte.core.ProgramRevision.epoch(program),
                    com.xebyte.core.ProgramRevision.savedTime(program),
                    com.xebyte.core.ProgramRevision.fileVersion(program),
                    program.isChanged());
        }
    }

    private volatile Session session;

    public Session session() {
        return session;
    }

    /** Record the program state the progress just written describes. */
    public void noteSession(ghidra.program.model.listing.Program program) {
        this.session = Session.of(program);
    }

    private volatile String programUrl;

    /**
     * The program's project URL ({@code ghidra://host/repo/path} when versioned, the local
     * project's URL otherwise), recorded in {@code tree.json}. The domain path alone does
     * not identify a program: two projects on one machine can both hold {@code /fw.bin}, and
     * share the default root's parent.
     */
    public String programUrl() {
        return programUrl;
    }

    public void setProgramUrl(String programUrl) {
        this.programUrl = programUrl;
    }

    public DecompTree(TreeKey key, String programName, TreeConfig config, TreeRoot root) {
        this.key = Objects.requireNonNull(key, "key");
        this.programName = Objects.requireNonNull(programName, "programName");
        this.root = Objects.requireNonNull(root, "root");
        this.config = Objects.requireNonNull(config, "config");
        this.progress = SweepProgress.idle();
    }

    public TreeKey key() {
        return key;
    }

    public String id() {
        return key.id();
    }

    public String programName() {
        return programName;
    }

    public String domainPath() {
        return key.domainPath();
    }

    public TreeRoot root() {
        return root;
    }

    public TreeConfig config() {
        return config;
    }

    public void setConfig(TreeConfig config) {
        this.config = Objects.requireNonNull(config, "config");
    }

    public SweepProgress progress() {
        return progress;
    }

    public void setProgress(SweepProgress progress) {
        this.progress = Objects.requireNonNull(progress, "progress");
    }

    public Long savedAtModification() {
        return savedAtModification;
    }

    public void setSavedAtModification(Long modification) {
        this.savedAtModification = modification;
    }

    public java.util.Set<String> namesSinceSave() {
        return namesSinceSave;
    }

    public boolean recoverOnReattach() {
        return recoverOnReattach;
    }

    public void setRecoverOnReattach(boolean recover) {
        this.recoverOnReattach = recover;
    }
}
