package com.xebyte.core;

import com.xebyte.core.tree.DecompTree;
import com.xebyte.core.tree.MemoryMapChange;
import com.xebyte.core.tree.SweepJob;
import com.xebyte.core.tree.SweepProgress;
import com.xebyte.core.tree.TreeConfig;
import com.xebyte.core.tree.TreeFiles;
import com.xebyte.core.tree.TreeKey;
import com.xebyte.core.tree.TreeLayout;
import com.xebyte.core.tree.TreeReconciler;
import com.xebyte.core.tree.TreeRegistry;
import com.xebyte.core.tree.TreeRoot;
import com.xebyte.core.tree.TreeStatusMd;
import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

/**
 * A change of the memory map re-decompiles the blocks it can change and no others. Before,
 * any block event marked the whole tree stale until a resweep, a data-only block moved or a
 * block added that nothing references included, and a new image base, which re-keys every
 * function, went unnoticed.
 */
public class TreeMemoryMapGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private Path tmp;
    private DecompTree decompTree;
    private final TreeRegistry registry = TreeRegistry.getInstance();
    private final DirectThreadingStrategy threading = new DirectThreadingStrategy();

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
    }

    /** Four functions; the first two read writable .data ({@code MOV EAX,[0x3000+i*4]; RET}), the others return. */
    @Before
    public void setUp() throws Exception {
        registry.clearForTests();
        registry.setThreadingStrategyIfAbsent(threading);
        tmp = Files.createTempDirectory("tree-memory-map");
        builder = new ProgramBuilder("memmap", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x1000);
        builder.createMemory(".data", "0x3000", 0x100);
        builder.createMemory(".spare", "0x6000", 0x100);
        for (int i = 0; i < 4; i++) {
            long at = 0x1000 + i * 0x100L;
            builder.setBytes(hex(at), i < 2 ? String.format("8b 04 25 %02x 30 00 00 c3", i * 4) : "c3");
        }
        builder.setBytes("0x3000", "11 22 33 44 55 66 77 88");
        builder.withTransaction(() -> {
            // ProgramBuilder's blocks are read-only; .data is data the program writes.
            program.getMemory().getBlock(".data").setWrite(true);
            for (int i = 0; i < 4; i++) {
                long at = 0x1000 + i * 0x100L;
                new DisassembleCommand(builder.addr(hex(at)),
                    new AddressSet(builder.addr(hex(at)), builder.addr(hex(at + 0x10))), true)
                    .applyTo(program, TaskMonitor.DUMMY);
            }
            for (int i = 0; i < 2; i++) {
                program.getReferenceManager().addMemoryReference(builder.addr(hex(0x1000 + i * 0x100L)),
                    builder.addr(hex(0x3000 + i * 4L)), RefType.READ, SourceType.USER_DEFINED, 0);
            }
        });
        for (int i = 3; i >= 0; i--) {
            builder.createFunction(hex(0x1000 + i * 0x100L));
        }
        Path root = tmp.resolve("tree");
        Files.createDirectories(root);
        decompTree = new DecompTree(TreeKey.of("/memmap", root.toString()), "memmap",
            TreeConfig.defaults().withRootPath(root.toString()), TreeRoot.ofResolved(root));
        registry.register(decompTree);
        new SweepJob(decompTree, program, threading).run();
    }

    @After
    public void tearDown() throws Exception {
        try {
            CountDownLatch drained = new CountDownLatch(1);
            registry.enqueue(drained::countDown);
            assertTrue("queued work did not finish", drained.await(30, TimeUnit.SECONDS));
        } finally {
            registry.clearForTests();
            if (builder != null) {
                builder.dispose();
            }
            if (tmp != null) {
                try (Stream<Path> walk = Files.walk(tmp)) {
                    walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
                }
            }
        }
    }

    private static String hex(long address) {
        return "0x" + Long.toHexString(address);
    }

    private String key(long address) {
        return AddressKeys.of(program.getFunctionManager().getFunctionAt(builder.addr(hex(address))));
    }

    private MemoryBlock block(String name) {
        return program.getMemory().getBlock(name);
    }

    private Set<String> treeKeys() throws Exception {
        Path index = decompTree.root().path().resolve(TreeLayout.byAddressTsv());
        return TreeFiles.readIndex(index).stream().map(TreeFiles.IndexEntry::addressHex)
            .collect(Collectors.toCollection(TreeSet::new));
    }

    private Set<String> liveKeys() {
        Set<String> keys = new TreeSet<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            keys.add(AddressKeys.of(f));
        }
        return keys;
    }

    private String body(long address) throws Exception {
        Path root = decompTree.root().path();
        try (Stream<Path> walk = Files.walk(root.resolve("modules"))) {
            String key = key(address);
            for (Path p : walk.filter(f -> f.toString().endsWith(".c")).toList()) {
                String text = Files.readString(p);
                int at = text.indexOf("// " + key);
                if (at < 0) {
                    at = text.indexOf(key);
                }
                if (at >= 0) {
                    return text;
                }
            }
        }
        return null;
    }

    private void assertInSync() {
        assertNotEquals(decompTree.progress().lastError(), SweepProgress.Phase.STALE, decompTree.progress().phase());
    }

    @Test
    public void aReadOnlyDataBlockRedecompilesItsReadersOnly() throws Exception {
        builder.tx(() -> block(".data").setWrite(false));

        Set<String> readers = Set.of(key(0x1000), key(0x1100));
        assertEquals(readers, MemoryMapChange.since(decompTree.session().memoryMap(), program, liveKeys()).keys());
        TreeReconciler.ReconcileResult r = TreeReconciler.reconcile(decompTree, program, null);
        assertEquals(2, r.decompileCalls());
        assertEquals(new TreeSet<>(readers), new TreeSet<>(r.replaced()));
        // The load folds to the constant the read-only block holds.
        assertTrue(body(0x1000), body(0x1000).contains("0x44332211"));
        assertInSync();
        // The tree now reflects the live map: the next pass has nothing to do.
        assertEquals(0, TreeReconciler.reconcile(decompTree, program, null).decompileCalls());
    }

    @Test
    public void aBlockNothingReferencesCostsNothing() throws Exception {
        builder.tx(() -> {
            block(".spare").setWrite(false);
            block(".spare").setName("renamed");
            program.getMemory().split(block(".text"), builder.addr("0x1800"));
            builder.createMemory(".new", "0x8000", 0x10);
        });

        TreeReconciler.ReconcileResult r = TreeReconciler.reconcile(decompTree, program, null);
        assertEquals(0, r.decompileCalls());
        assertInSync();
    }

    @Test
    public void aMovedDataBlockRedecompilesItsReaders() throws Exception {
        builder.tx(() -> program.getMemory()
            .moveBlock(block(".data"), builder.addr("0x5000"), TaskMonitor.DUMMY));

        // Their references moved with the block; the other two functions are not decompiled.
        TreeReconciler.ReconcileResult r = TreeReconciler.reconcile(decompTree, program, null);
        assertEquals(2, r.decompileCalls());
        assertTrue(r.unchanged().containsAll(List.of(key(0x1200), key(0x1300))));
        assertInSync();
    }

    @Test
    public void aNewImageBaseReKeysEveryFunction() throws Exception {
        Set<String> before = treeKeys();
        builder.tx(() -> program.setImageBase(builder.addr("0x10000"), true));

        TreeReconciler.ReconcileResult r = TreeReconciler.reconcile(decompTree, program, null);
        assertEquals(before, new TreeSet<>(r.removed()));
        assertEquals(liveKeys(), new TreeSet<>(r.inserted()));
        assertEquals(liveKeys(), treeKeys());
        assertNotNull(body(0x11000));
        assertInSync();
    }

    @Test
    public void anAdoptionAfterARestartComparesTheMapItWasDecompiledAgainst() throws Exception {
        String swept = decompTree.session().memoryMap();
        TreeStatusMd.StatusFile status = TreeStatusMd.read(decompTree.root().path());
        assertEquals(swept, status.memoryMap());

        builder.tx(() -> block(".data").setWrite(false));
        // An open with no session of its own takes the map from the files.
        decompTree.noteSession(program, status.memoryMap());
        TreeReconciler.ReconcileResult r = TreeReconciler.reconcile(decompTree, program, null);
        assertEquals(2, r.decompileCalls());
        assertNotNull(TreeStatusMd.read(decompTree.root().path()).memoryMap());
        assertEquals(DecompTree.Session.memoryMapOf(program),
            TreeStatusMd.read(decompTree.root().path()).memoryMap());
    }

    @Test
    public void aTargetedPassLeavesTheMapChangeToTheFullOne() throws Exception {
        String swept = decompTree.session().memoryMap();
        builder.tx(() -> block(".data").setWrite(false));

        TreeReconciler.reconcile(decompTree, program, new LinkedHashSet<>(Set.of(key(0x1200))));
        assertEquals(swept, decompTree.session().memoryMap());
        assertEquals(2, TreeReconciler.reconcile(decompTree, program, null).decompileCalls());
    }
}
