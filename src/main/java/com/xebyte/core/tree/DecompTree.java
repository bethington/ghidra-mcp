package com.xebyte.core.tree;

import java.io.IOException;
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
     * saved program the tree reflects, and survive restarts. {@code memoryMap} is the block
     * layout the tree was decompiled against: no input fingerprint covers it.
     */
    public record Session(String epoch, long savedTime, Integer fileVersion, boolean unsavedEdits,
            String memoryMap) {
        public static Session of(ghidra.program.model.listing.Program program) {
            return of(program, memoryMapOf(program));
        }

        /** The program as it is now, decompiled against {@code memoryMap}. */
        public static Session of(ghidra.program.model.listing.Program program, String memoryMap) {
            return new Session(com.xebyte.core.ProgramRevision.epoch(program),
                    com.xebyte.core.ProgramRevision.savedTime(program),
                    com.xebyte.core.ProgramRevision.fileVersion(program),
                    program.isChanged(), memoryMap);
        }

        /** The saved program another open of it shows, unless this one held unsaved edits. */
        public boolean sameSavedState(ghidra.program.model.listing.Program program) {
            return !unsavedEdits && !program.isChanged()
                    && savedTime == com.xebyte.core.ProgramRevision.savedTime(program)
                    && Objects.equals(fileVersion, com.xebyte.core.ProgramRevision.fileVersion(program));
        }

        /** Short hash of {@link #memoryMap}, as STATUS.md records it across restarts. */
        public static String memoryMapHash(String memoryMap) {
            return InputFingerprint.shortHash(memoryMap, 6);
        }

        /** Each block's name, range and permissions: what decides how every load decompiles. */
        public static String memoryMapOf(ghidra.program.model.listing.Program program) {
            ghidra.program.model.mem.Memory memory = program.getMemory();
            if (memory == null) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            for (ghidra.program.model.mem.MemoryBlock b : memory.getBlocks()) {
                sb.append(b.getName()).append('@').append(b.getStart()).append('-').append(b.getEnd())
                        .append(':').append(b.getFlags()).append(b.isInitialized() ? 'i' : 'u').append(';');
            }
            return sb.toString();
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

    /**
     * Record the program state, with the blocks decompiled against {@code memoryMap} rather
     * than the live map: a pass that did not follow a change of the map leaves it to the next.
     */
    public void noteSession(ghidra.program.model.listing.Program program, String memoryMap) {
        this.session = Session.of(program, memoryMap);
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

    /** Update in-memory progress and STATUS.md together. */
    public void publish(SweepProgress progress, String state) throws IOException {
        setProgress(progress);
        TreeStatusMd.write(this, state);
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
