package com.xebyte.core.tree;

import ghidra.program.model.listing.Program;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Minimal registry surface so {@link SweepJob} and {@link TreeReconciler} compile
 * before the full singleton, DirtyQueue and TreeObserver land. Expanded in the
 * registry commit; this stub is not tip-identical.
 */
public final class TreeRegistry {

    private static final TreeRegistry INSTANCE = new TreeRegistry();

    private TreeRegistry() {
    }

    public static TreeRegistry getInstance() {
        return INSTANCE;
    }

    /** Default parent for tree roots: {@code $HOME/ghidra-decomp-trees}. */
    public static Path defaultParent() {
        String home = Objects.requireNonNullElse(System.getProperty("user.home"), ".");
        return Path.of(home, "ghidra-decomp-trees");
    }

    /** No-op until DirtyQueue exists — reconcile requests a sweep after repair. */
    public void requestSweep(DecompTree decompTree, Program program) {
        // stub
    }

    /** Package-visible: SweepJob clears itself when a pass ends. */
    void clearActiveJob(String treeId, SweepJob job) {
        // stub
    }
}
