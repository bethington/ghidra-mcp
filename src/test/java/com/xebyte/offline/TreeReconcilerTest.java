package com.xebyte.offline;

import com.xebyte.core.tree.BlockSplicer;
import com.xebyte.core.tree.DecompTree;
import com.xebyte.core.tree.TreeConfig;
import com.xebyte.core.tree.TreeKey;
import com.xebyte.core.tree.TreeLayout;
import com.xebyte.core.tree.TreeRoot;
import com.xebyte.core.tree.TreeFiles;
import com.xebyte.core.tree.ModuleOverrides;
import com.xebyte.core.tree.SweepJob;
import com.xebyte.core.tree.SweepProgress;
import com.xebyte.core.tree.TreeReconciler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Offline tests for the three reconcile primitives, file split/delete, pin vs
 * containment placement, empty-ifp re-check, and zero-decompile full pass.
 */
public class TreeReconcilerTest {

    private Path tempRoot;
    private DecompTree decompTree;

    @Before
    public void setUp() throws IOException {
        tempRoot = Files.createTempDirectory("tree-reconciler-test");
        TreeKey key = TreeKey.of("/proj/app.exe", tempRoot.toString());
        TreeRoot root = TreeRoot.ofResolved(tempRoot);
        decompTree = new DecompTree(key, "app.exe", TreeConfig.defaults(), root);
        decompTree.setProgress(SweepProgress.idle().withPhase(SweepProgress.Phase.COMPLETE));
    }

    @After
    public void tearDown() throws IOException {
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

    // -------------------------------------------------------------------------
    // planWork / ifp — the cheap full-reconcile gate
    // -------------------------------------------------------------------------

    @Test
    public void planWork_classifiesReplaceInsertRemove() {
        Map<String, TreeFiles.IndexEntry> index = new LinkedHashMap<>();
        index.put("00100000", entry("00100000", "Foo", "c05", "modules/c05/00100000.c", "aaa"));
        index.put("00100100", entry("00100100", "Bar", "c05", "modules/c05/00100000.c", "bbb"));

        Map<String, Function> prog = new LinkedHashMap<>();
        prog.put("00100000", mock(Function.class)); // surviving → replace
        prog.put("00100200", mock(Function.class)); // new → insert
        // 00100100 absent → remove

        TreeReconciler.WorkPlan plan = TreeReconciler.planWork(index, prog, null);
        assertEquals(Set.of("00100000"), plan.replace());
        assertEquals(Set.of("00100200"), plan.insert());
        assertEquals(Set.of("00100100"), plan.remove());
    }

    @Test
    public void emptyIfpForcesRecheck() {
        assertTrue(TreeReconciler.needsRedecompile("", "abcdefabcdef"));
        assertTrue(TreeReconciler.needsRedecompile(null, "abcdefabcdef"));
        assertTrue(TreeReconciler.needsRedecompile("   ", "abcdefabcdef"));
        assertTrue(TreeReconciler.needsRedecompile("oldoldoldold", "newnewnewnew"));
        assertFalse(TreeReconciler.needsRedecompile("samefpsamefp", "samefpsamefp"));
    }

    @Test
    public void fullReconcileUnchangedTreeNeedsZeroDecompiles() {
        // The gate the full pass uses: matching non-empty ifp → skip.
        Map<String, TreeFiles.IndexEntry> index = new LinkedHashMap<>();
        index.put("00100000", entry("00100000", "Foo", "c05", "modules/c05/00100000.c", "aaa111aaa111"));
        index.put("00100100", entry("00100100", "Bar", "c05", "modules/c05/00100000.c", "bbb222bbb222"));

        int needing = 0;
        Map<String, String> live = Map.of(
                "00100000", "aaa111aaa111",
                "00100100", "bbb222bbb222");
        for (String hex : index.keySet()) {
            if (TreeReconciler.needsRedecompile(index.get(hex).ifp(), live.get(hex))) {
                needing++;
            }
        }
        assertEquals("unchanged ifps must produce zero decompiles", 0, needing);

        // Empty ifp on a surviving address still counts as needing work.
        index.put("00100000", entry("00100000", "Foo", "c05", "modules/c05/00100000.c", ""));
        assertTrue(TreeReconciler.needsRedecompile(
                index.get("00100000").ifp(), live.get("00100000")));
    }

    // -------------------------------------------------------------------------
    // Placement
    // -------------------------------------------------------------------------

    @Test
    public void insertWithoutPinRecordsContainmentAndNotEvidenceBacked() {
        Map<String, TreeFiles.IndexEntry> index = new LinkedHashMap<>();
        index.put("00100000", entry("00100000", "Foo", "c05", "modules/c05/00100000.c", "a"));
        index.put("00100200", entry("00100200", "Baz", "c05", "modules/c05/00100000.c", "c"));
        index.put("00200000", entry("00200000", "Other", "b001", "modules/b001/00200000.c", "d"));

        TreeReconciler.Placement p =
                TreeReconciler.placeByContainment("00100100", index);
        assertEquals("c05", p.slug());
        assertEquals(TreeReconciler.METHOD_CONTAINMENT, p.method());
        assertFalse(p.evidenceBacked());
    }

    @Test
    public void insertRespectsPin() {
        Program program = mock(Program.class);
        PropertyMapManager propMgr = mock(PropertyMapManager.class);
        StringPropertyMap map = mock(StringPropertyMap.class);
        when(program.getUsrPropertyManager()).thenReturn(propMgr);
        when(propMgr.getStringPropertyMap(ModuleOverrides.MAP_NAME)).thenReturn(map);

        Address entry = mock(Address.class);
        when(entry.toString(false)).thenReturn("00100150");
        when(map.hasProperty(entry)).thenReturn(true);
        when(map.getString(entry)).thenReturn("driver_usb");

        Function func = mock(Function.class);
        when(func.getEntryPoint()).thenReturn(entry);

        Map<String, TreeFiles.IndexEntry> index = new LinkedHashMap<>();
        index.put("00100000", entry("00100000", "Foo", "c05", "modules/c05/00100000.c", "a"));

        TreeReconciler.Placement p = TreeReconciler.place(func, program, index);
        assertEquals("driver_usb", p.slug());
        assertEquals(ModuleOverrides.METHOD, p.method());
        assertTrue(p.evidenceBacked());
    }

    // -------------------------------------------------------------------------
    // Pure block insert / remove / split
    // -------------------------------------------------------------------------

    /**
     * The reconciler used to write its own short README, so the first edit that touched a
     * compartment dropped method, confidence and evidence (peripheral_pages among them) and
     * stamped it "narrowed by /decompile_tree_configure".
     */
    /**
     * Found live: a function renamed a second time kept its intermediate name in its
     * callees' header lines. The splice judged "unchanged" by {@code // fp:}, a hash of the
     * C alone, so a change only the header shows was computed and dropped.
     */
    @Test
    public void statusMdTracksSplicedSinceSweep() {
        decompTree.setProgress(decompTree.progress().withSplicedSinceSweep(3));
        String rendered = com.xebyte.core.tree.TreeStatusMd.render(decompTree, "spliced");
        assertTrue(rendered.contains("spliced_since_sweep: 3"));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static TreeFiles.IndexEntry entry(
            String addr, String name, String slug, String file, String ifp) {
        return new TreeFiles.IndexEntry(addr, name, slug, file, false, ifp);
    }

    private static String twoBlocks(String a1, String n1, String a2, String n2) {
        return rebuildBlock(n1, a1, "void " + n1 + "(void) {}\n")
                + "\n"
                + rebuildBlock(n2, a2, "void " + n2 + "(void) {}\n")
                + "\n";
    }

    /**
     * A caller the decompiler resolved through a literal pool has no reference to the
     * callee, so only its text says it uses the name: the old name must be found in the
     * body, and a header line or a longer identifier must not count.
     */
    @Test
    public void blocksMentioningFindsBodiesThatStillPrintAName() throws IOException {
        String file = rebuildBlock("Caller", "00100000", "void Caller(void) {\n  ws2812_set_pixel(1,2);\n}\n")
                + "\n" + rebuildBlock("Other", "00100100", "void Other(void) {\n  ws2812_set_pixel_fast(1);\n}\n")
                + "\n" + rebuildBlock("ws2812_set_pixel", "00100200", "void x(void) {}\n");
        decompTree.root().writeFile(Path.of("modules/c05/00100000.c"), file);

        assertEquals(Set.of("00100000"),
                TreeReconciler.blocksMentioning(decompTree, List.of("ws2812_set_pixel")));
        assertEquals(Set.of(), TreeReconciler.blocksMentioning(decompTree, List.of()));
    }

    private static String rebuildBlock(String name, String addr, String body) {
        return TestBlocks.block(name, addr, body);
    }
}
