package com.xebyte.offline;

import com.xebyte.core.tree.DecompTree;
import com.xebyte.core.tree.TreeConfig;
import com.xebyte.core.tree.TreeKey;
import com.xebyte.core.tree.TreeRegistry;
import com.xebyte.core.tree.TreeRoot;
import com.xebyte.core.tree.DirtyQueue;
import ghidra.program.model.listing.Program;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Debounce coalesce, analysis gate, sweep-wins, and address-bound collapse
 * for {@link DirtyQueue}.
 */
public class DirtyQueueTest {

    private Path tempRoot;
    private DecompTree decompTree;
    private AtomicLong clock;
    private List<Runnable> queued;
    private List<Set<String>> reconciles;
    private AtomicBoolean sweepActive;
    private AtomicBoolean analyzing;
    private DirtyQueue queue;

    @Before
    public void setUp() throws IOException {
        TreeRegistry.getInstance().clearForTests();
        tempRoot = Files.createTempDirectory("dirty-queue-test");
        TreeKey key = TreeKey.of("/proj/app.exe", tempRoot.toString());
        TreeRoot root = TreeRoot.ofResolved(tempRoot);
        decompTree = new DecompTree(key, "app.exe", TreeConfig.defaults(), root);
        TreeRegistry.getInstance().register(decompTree);

        clock = new AtomicLong(1_000_000L);
        queued = new CopyOnWriteArrayList<>();
        reconciles = new CopyOnWriteArrayList<>();
        sweepActive = new AtomicBoolean(false);
        analyzing = new AtomicBoolean(false);

        Program program = mock(Program.class);
        when(program.isClosed()).thenReturn(false);

        queue = new DirtyQueue(
                TreeRegistry.getInstance(),
                c -> program,
                id -> sweepActive.get(),
                (p, id) -> analyzing.get(),
                (c, p, addrs) -> reconciles.add(addrs),
                clock::get,
                queued::add);
    }

    @After
    public void tearDown() throws IOException {
        TreeRegistry.getInstance().clearForTests();
        if (tempRoot != null && Files.exists(tempRoot)) {
            try (Stream<Path> walk = Files.walk(tempRoot)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (IOException ignored) {
                        // best-effort
                    }
                });
            }
        }
    }

    @Test
    public void debounceCoalescesBurstIntoOnePass() throws Exception {
        queue.markDirty(decompTree.id(), List.of("00100000"));
        queue.markDirty(decompTree.id(), List.of("00100100", "00100200"));
        queue.markDirty(decompTree.id(), List.of("00100000")); // dup

        assertEquals(1, queued.size());
        assertEquals(3, queue.pendingAddressCount(decompTree.id()));

        runDrainAdvancingClock(queued.get(0), () -> !reconciles.isEmpty());

        assertEquals(1, reconciles.size());
        assertEquals(Set.of("00100000", "00100100", "00100200"), reconciles.get(0));
        assertEquals(0, queue.pendingAddressCount(decompTree.id()));
    }

    @Test
    public void analysisGateDefersUntilSettled() throws Exception {
        analyzing.set(true);
        queue.markDirty(decompTree.id(), List.of("00100000"));
        assertEquals(1, queued.size());

        AtomicBoolean finished = new AtomicBoolean(false);
        Thread runner = new Thread(() -> {
            queued.get(0).run();
            finished.set(true);
        }, "test-drain-analyzing");
        runner.start();

        // While analyzing, advancing the clock must not produce a reconcile.
        for (int i = 0; i < 5; i++) {
            clock.addAndGet(DirtyQueue.DEBOUNCE_MS + 10);
            Thread.sleep(40);
        }
        assertTrue("must not reconcile while analyzing", reconciles.isEmpty());
        assertTrue(runner.isAlive());

        analyzing.set(false);
        runDrainAdvancingClock(runner, finished::get);

        assertEquals(1, reconciles.size());
        assertEquals(Set.of("00100000"), reconciles.get(0));
    }

    /**
     * Found live: drains and sweeps share one thread, and a drain that waited for a QUEUED
     * sweep kept it from ever starting. The drain now hands the thread back, keeps the work,
     * and the sweep re-arms it when it ends.
     */
    @Test
    public void aDrainDuringASweepYieldsTheThreadAndResumesAfterIt() throws Exception {
        sweepActive.set(true);
        queue.markDirty(decompTree.id(), List.of("00100000"));
        clock.addAndGet(DirtyQueue.DEBOUNCE_MS + 10);

        queued.get(0).run();   // returns at once: the thread is free for the sweep

        assertTrue(reconciles.isEmpty());
        assertTrue("the work is kept", queue.hasPending(decompTree.id()));

        sweepActive.set(false);
        queue.resume(decompTree.id());
        assertEquals("resume arms a new drain", 2, queued.size());
        clock.addAndGet(DirtyQueue.DEBOUNCE_MS + 10);
        queued.get(1).run();

        assertEquals(List.of(Set.of("00100000")), reconciles);
    }

    @Test
    public void boundCollapsesStormToNeedsReconcile() throws Exception {
        List<String> storm = new ArrayList<>();
        for (int i = 0; i < DirtyQueue.ADDRESS_BOUND + 50; i++) {
            storm.add(String.format("%08x", 0x100000 + i));
        }
        queue.markDirty(decompTree.id(), storm);

        assertTrue(queue.pendingNeedsReconcile(decompTree.id()));
        assertEquals(0, queue.pendingAddressCount(decompTree.id()));

        runDrainAdvancingClock(queued.get(0), () -> !reconciles.isEmpty());

        assertEquals(1, reconciles.size());
        // null addresses ⇒ full reconcile
        assertNull(reconciles.get(0));
    }

    @Test
    public void markNeedsReconcileClearsPendingAddresses() {
        queue.markDirty(decompTree.id(), List.of("00100000", "00100100"));
        assertEquals(2, queue.pendingAddressCount(decompTree.id()));
        queue.markNeedsReconcile(decompTree.id());
        assertTrue(queue.pendingNeedsReconcile(decompTree.id()));
        assertEquals(0, queue.pendingAddressCount(decompTree.id()));
        // Still a single drain queued (coalesced).
        assertEquals(1, queued.size());
    }

    /**
     * Fake clock does not move during {@code Thread.sleep}; poke it forward
     * while the drain is blocked so the deadline can expire.
     */
    /** The retired name is looked up in the tree, and its blocks join the targeted pass. */
    @Test
    public void aRetiredNameAddsTheBlocksThatStillPrintIt() throws Exception {
        decompTree.root().writeFile(java.nio.file.Path.of("modules/c05/00100000.c"),
                TestBlocks.block("Caller", "00100400", "void Caller(void) {\n  OldName();\n}\n"));
        queue.markDirty(decompTree.id(), List.of("00100000"));
        queue.markRetiredNames(decompTree.id(), List.of("OldName"));

        runDrainAdvancingClock(queued.get(0), () -> !reconciles.isEmpty());

        assertEquals(Set.of("00100000", "00100400"), reconciles.get(0));
    }

    private void runDrainAdvancingClock(Runnable drain, java.util.function.BooleanSupplier done)
            throws InterruptedException {
        AtomicBoolean finished = new AtomicBoolean(false);
        Thread runner = new Thread(() -> {
            drain.run();
            finished.set(true);
        }, "test-drain");
        runner.start();
        runDrainAdvancingClock(runner, () -> finished.get() || done.getAsBoolean());
    }

    private void runDrainAdvancingClock(Thread runner, java.util.function.BooleanSupplier done)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + 5_000;
        while (System.currentTimeMillis() < deadline) {
            clock.addAndGet(DirtyQueue.DEBOUNCE_MS + 10);
            if (done.getAsBoolean() && !runner.isAlive()) {
                return;
            }
            runner.join(40);
            if (done.getAsBoolean() && !runner.isAlive()) {
                return;
            }
        }
        runner.interrupt();
        runner.join(1_000);
        assertTrue("drain did not finish in time", done.getAsBoolean());
    }
}
