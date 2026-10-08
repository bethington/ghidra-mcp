package com.xebyte.core;

import com.xebyte.core.tree.DecompTree;
import com.xebyte.core.tree.TreeConfig;
import com.xebyte.core.tree.TreeKey;
import com.xebyte.core.tree.TreeLayout;
import com.xebyte.core.tree.TreeRoot;
import com.xebyte.core.tree.ExclusionRule;
import com.xebyte.core.tree.SweepJob;
import com.xebyte.core.tree.TreeReconciler;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * Sweep, reconcile and rebuild converge: whichever path wrote a tree, once it is in sync
 * it is the tree a fresh sweep at that point writes, byte for byte, apart from the render
 * stamp ({@code // dts:}), the status files, and the tree's own root and
 * id. Found broken live: a full reconcile of a tree swept before {@code addresses.tsv}
 * existed rewrote all 339 blocks and left the index missing, and the reconciler rendered its
 * own thinner {@code modules/index.md} and module READMEs.
 */
public class TreeConvergenceGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private Path tmp;

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

    @Before
    public void setUp() throws Exception {
        tmp = Files.createTempDirectory("tree-convergence");
        builder = new ProgramBuilder("converge", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x1000);
        builder.createMemory(".data", "0x3000", 0x100);
        // Six functions, each calling the next: CALL rel32; MOV EAX,[0x3000+i*4]; RET
        for (int i = 0; i < 6; i++) {
            long at = 0x1000 + i * 0x100L;
            long next = at + 0x100;
            int rel = (int) (next - (at + 5));
            String call = i < 5 ? String.format("e8 %02x %02x %02x %02x ", rel & 0xff, (rel >> 8) & 0xff,
                (rel >> 16) & 0xff, (rel >> 24) & 0xff) : "";
            String load = String.format("8b 04 25 %02x 30 00 00 ", i * 4);
            builder.setBytes("0x" + Long.toHexString(at), call + load + "c3");
        }
        builder.withTransaction(() -> {
            for (int i = 0; i < 6; i++) {
                long at = 0x1000 + i * 0x100L;
                new DisassembleCommand(builder.addr("0x" + Long.toHexString(at)),
                    new AddressSet(builder.addr("0x" + Long.toHexString(at)),
                        builder.addr("0x" + Long.toHexString(at + 0x10))), true)
                    .applyTo(program, TaskMonitor.DUMMY);
            }
        });
        for (int i = 5; i >= 0; i--) {
            builder.createFunction("0x" + Long.toHexString(0x1000 + i * 0x100L));
        }
    }

    @After
    public void tearDown() throws IOException {
        if (builder != null) {
            builder.dispose();
        }
        try (Stream<Path> walk = Files.walk(tmp)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    private DecompTree decompTree(String name, TreeConfig config) throws IOException {
        Path root = tmp.resolve(name);
        Files.createDirectories(root);
        return new DecompTree(TreeKey.of("/converge", root.toString()), "converge",
            config.withRootPath(root.toString()), TreeRoot.ofResolved(root));
    }

    private DecompTree swept(String name, TreeConfig config) throws IOException {
        DecompTree c = decompTree(name, config);
        new SweepJob(c, program).run();
        return c;
    }

    /** Every file but the status files, stamps dropped, root and id replaced. */
    private static Map<String, String> tree(DecompTree c) throws IOException {
        Path root = c.root().path();
        Map<String, String> out = new TreeMap<>();
        try (Stream<Path> walk = Files.walk(root)) {
            for (Path p : walk.filter(Files::isRegularFile).collect(Collectors.toList())) {
                String rel = root.relativize(p).toString();
                if (rel.equals(TreeLayout.statusMd()) || rel.equals(TreeLayout.treeJson())) {
                    continue;
                }
                String text = Files.readString(p, StandardCharsets.UTF_8)
                    .replace(root.toString(), "<root>").replace(c.id(), "<id>");
                out.put(rel, text.lines()
                    .filter(l -> !l.startsWith("// dts: "))
                    .collect(Collectors.joining("\n")));
            }
        }
        return out;
    }

    private static void assertSameTree(String what, DecompTree expected, DecompTree actual) throws IOException {
        Map<String, String> a = tree(expected);
        Map<String, String> b = tree(actual);
        List<String> diffs = new ArrayList<>();
        for (String k : new java.util.TreeSet<>(Set.copyOf(concat(a.keySet(), b.keySet())))) {
            if (!a.containsKey(k)) {
                diffs.add("only after " + what + ": " + k);
            } else if (!b.containsKey(k)) {
                diffs.add("missing after " + what + ": " + k);
            } else if (!a.get(k).equals(b.get(k))) {
                diffs.add("differs after " + what + ": " + k + "\n--- sweep\n" + a.get(k) + "\n--- " + what + "\n" + b.get(k));
            }
        }
        assertTrue(String.join("\n", diffs), diffs.isEmpty());
    }

    private static List<String> concat(Set<String> a, Set<String> b) {
        List<String> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
    }

    @Test
    public void twoSweepsWriteTheSameTree() throws IOException {
        assertSameTree("second sweep", swept("a", TreeConfig.defaults()), swept("b", TreeConfig.defaults()));
    }

    /**
     * Reported by the stealth session: content was stable, but a sweep over an unchanged
     * program rewrote all 329 files to move their dts/mod stamps.
     */
    @Test
    public void resweepingAnUnchangedProgramWritesNoFile() throws Exception {
        DecompTree a = swept("a", TreeConfig.defaults());
        Map<String, java.nio.file.attribute.FileTime> before = mtimes(a);
        Thread.sleep(1100);
        new SweepJob(a, program).run();
        Map<String, java.nio.file.attribute.FileTime> after = mtimes(a);
        before.keySet().removeIf(k -> k.equals(TreeLayout.statusMd()) || k.equals(TreeLayout.treeJson()));
        after.keySet().removeIf(k -> k.equals(TreeLayout.statusMd()) || k.equals(TreeLayout.treeJson()));
        assertEquals(before, after);
    }

    private static Map<String, java.nio.file.attribute.FileTime> mtimes(DecompTree c) throws IOException {
        Map<String, java.nio.file.attribute.FileTime> out = new TreeMap<>();
        try (Stream<Path> walk = Files.walk(c.root().path())) {
            for (Path p : walk.filter(Files::isRegularFile).collect(Collectors.toList())) {
                out.put(c.root().path().relativize(p).toString(), Files.getLastModifiedTime(p));
            }
        }
        return out;
    }

    /** Found live: a refresh racing an adoption's reconcile left deleted files unrestored. */
    @Test
    public void aReconcileWaitsForAnotherWriterOfTheSameTree() throws Exception {
        DecompTree a = swept("a", TreeConfig.defaults());
        Files.delete(a.root().path().resolve(TreeLayout.agentsMd()));
        a.treeLock().lock();
        Thread pass = new Thread(() -> {
            try {
                TreeReconciler.reconcile(a, program, null);
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        });
        try {
            pass.start();
            pass.join(500);
            assertTrue("the reconcile must wait for the lock", pass.isAlive());
            assertFalse(Files.exists(a.root().path().resolve(TreeLayout.agentsMd())));
        } finally {
            a.treeLock().unlock();
        }
        pass.join(30_000);
        assertTrue(Files.exists(a.root().path().resolve(TreeLayout.agentsMd())));
    }

    @Test
    public void aFullReconcileOfAnInSyncTreeChangesNothing() throws IOException {
        DecompTree a = swept("a", TreeConfig.defaults());
        Map<String, String> before = tree(a);
        TreeReconciler.ReconcileResult r = TreeReconciler.reconcile(a, program, null);
        assertEquals("nothing rewritten", 0, r.filesWritten());
        assertEquals(before, tree(a));
    }

    @Test
    public void aFullReconcileRestoresWhatWasDeletedOrEdited() throws IOException {
        DecompTree a = swept("a", TreeConfig.defaults());
        Path root = a.root().path();
        Files.delete(root.resolve(TreeLayout.agentsMd()));
        Files.delete(root.resolve(TreeLayout.readmeMd()));
        Files.delete(root.resolve(TreeLayout.modulesIndexMd()));
        Files.delete(root.resolve(TreeLayout.callgraphTsv()));
        Path cFile;
        try (Stream<Path> modules = Files.walk(root.resolve("modules"))) {
            cFile = modules.filter(p -> p.toString().endsWith(".c")).sorted().findFirst().orElseThrow();
        }
        Files.writeString(cFile, "// hand edit\n", java.nio.file.StandardOpenOption.APPEND);
        try (Stream<Path> readmes = Files.walk(root.resolve("modules"))) {
            for (Path p : readmes.filter(p -> p.getFileName().toString().equals("README.md")).collect(Collectors.toList())) {
                Files.delete(p);
            }
        }

        TreeReconciler.reconcile(a, program, null);
        DecompTree fresh = swept("b", TreeConfig.defaults());
        assertSameTree("full reconcile", fresh, a);

        Files.delete(cFile);
        TreeReconciler.reconcile(a, program, null);
        assertSameTree("full reconcile after deleting a compartment file", fresh, a);
    }

    @Test
    public void aTreeMissingWhatOnlyASweepWritesIsSweptNotPatched() throws IOException {
        DecompTree a = swept("a", TreeConfig.defaults());
        Files.delete(a.root().path().resolve(TreeLayout.partitionsJson()));
        assertTrue(TreeReconciler.reconcile(a, program, null).sweepQueued());
    }

    @Test
    public void reconcilingARenameEndsWhereASweepAfterItStarts() throws Exception {
        DecompTree a = swept("a", TreeConfig.defaults());
        Function f = program.getFunctionManager().getFunctionAt(builder.addr("0x1200"));
        builder.withTransaction(() -> {
            try {
                f.setName("renamed_once", SourceType.USER_DEFINED);
                f.setName("renamed_twice", SourceType.USER_DEFINED);
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        });

        // What the observer would queue: the function, and those that show its name.
        TreeReconciler.reconcile(a, program, Set.of("00001100", "00001200", "00001300"));

        assertSameTree("targeted reconcile", swept("b", TreeConfig.defaults()), a);
        assertSameTree("full reconcile", swept("c", TreeConfig.defaults()), reconciledFully(a));
    }

    private DecompTree reconciledFully(DecompTree c) throws IOException {
        TreeReconciler.reconcile(c, program, null);
        return c;
    }

    @Test
    public void narrowingTheConfigEndsWhereASweepUnderItStarts() throws IOException {
        DecompTree a = swept("a", TreeConfig.defaults());
        TreeConfig narrowed = TreeConfig.defaults()
            .withExclusions(List.of(ExclusionRule.parse("range:0x1300-0x14ff")));
        a.setConfig(narrowed.withRootPath(a.root().path().toString()));

        TreeReconciler.reconcile(a, program, null);

        assertSameTree("narrowing", swept("b", narrowed), a);
    }
}
