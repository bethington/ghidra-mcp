package com.xebyte.offline;

import com.xebyte.core.tree.DecompTree;
import com.xebyte.core.tree.TreeConfig;
import com.xebyte.core.tree.TreeKey;
import com.xebyte.core.tree.TreeRegistry;
import com.xebyte.core.tree.TreeRoot;
import com.xebyte.core.tree.SweepProgress;
import ghidra.program.model.listing.Program;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Found in a live RE session: close_program(save=false) kept the discarded edits in the
 * tree, and STATUS.md went on saying clean. A close that leaves the tree describing
 * something a reopen will not show marks it stale, with a reason, for a reconcile on reopen.
 */
public class TreeStaleOnCloseTest {

    private Path tempRoot;
    private DecompTree decompTree;
    private final TreeRegistry registry = TreeRegistry.getInstance();

    @Before
    public void setUp() throws IOException {
        registry.clearForTests();
        tempRoot = Files.createTempDirectory("stale-on-close");
        decompTree = new DecompTree(TreeKey.of("/fw", tempRoot.toString()), "fw",
                TreeConfig.defaults(), TreeRoot.ofResolved(tempRoot));
        registry.register(decompTree);
        // Swept at 4, saved at 4, then one comment spliced at 5.
        decompTree.setProgress(decompTree.progress().withPhase(SweepProgress.Phase.COMPLETE).sweptAt(4L));
        decompTree.setSavedAtModification(4L);
    }

    @After
    public void tearDown() {
        registry.clearForTests();
    }

    private static Program program(boolean changed) {
        Program p = mock(Program.class);
        when(p.isChanged()).thenReturn(changed);
        return p;
    }

    @Test
    public void discardingEditsTheTreeTookInMakesItStale() throws IOException {
        decompTree.setProgress(decompTree.progress().reconciledAt(5L, 1, 0));

        registry.noteClosing(decompTree.id(), program(true));

        assertEquals(SweepProgress.Phase.STALE, decompTree.progress().phase());
        assertTrue(decompTree.progress().lastError(), decompTree.progress().lastError().contains("without saving"));
        assertTrue(decompTree.recoverOnReattach());
        String status = Files.readString(tempRoot.resolve("STATUS.md"));
        assertTrue(status, status.contains("state: stale"));
    }

    @Test
    public void discardingEditsTheTreeNeverSawLeavesItAlone() {
        // Edited after the last splice, closed before the drain ran: the tree still shows
        // the saved state, which is exactly what a reopen shows.
        registry.noteClosing(decompTree.id(), program(true));

        assertEquals(SweepProgress.Phase.COMPLETE, decompTree.progress().phase());
        assertFalse(decompTree.recoverOnReattach());
    }

    @Test
    public void savedEditsStillQueuedAtCloseMakeItStale() {
        registry.dirtyQueue().markDirty(decompTree.id(), List.of("00100000"));

        registry.noteClosing(decompTree.id(), program(false));

        assertEquals(SweepProgress.Phase.STALE, decompTree.progress().phase());
        assertTrue(decompTree.progress().lastError(), decompTree.progress().lastError().contains("before saved changes"));
        assertTrue(decompTree.recoverOnReattach());
    }

    @Test
    public void aSaveMovesTheBaseline() {
        decompTree.setProgress(decompTree.progress().reconciledAt(5L, 1, 0));
        registry.noteSaved(decompTree.id(), 5L);

        registry.noteClosing(decompTree.id(), program(false));

        assertEquals(SweepProgress.Phase.COMPLETE, decompTree.progress().phase());
        assertFalse(decompTree.recoverOnReattach());
    }
}
