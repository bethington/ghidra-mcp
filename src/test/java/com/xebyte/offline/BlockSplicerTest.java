package com.xebyte.offline;

import com.xebyte.core.tree.BlockSplicer;
import com.xebyte.core.tree.FunctionBlock;
import com.xebyte.core.tree.TreeFiles;
import com.xebyte.core.tree.SweepJob;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Offline tests for tree block splicing — locate, fingerprint-skip, fail
 * closed on missing blocks, header-only neighbourhood patches, and ignore
 * {@code // fn:} inside string literals.
 */
public class BlockSplicerTest {

    private static final String THREE_BLOCKS = ""
            + "// fn: Foo @ 00100000 size=16\n"
            + "// calls: Bar\n"
            + "// callers: (none — entry)\n"
            + "// part: c05 address-band conf=0.50 evidence_backed=false\n"
            + "// fp:aaaaaaaaaaaa\n"
            + "// dts:2026-01-01T00:00:00Z\n"
            + "// mod:1\n"
            + "// uri: ghidra://function/x/00100000\n"
            + "// see: modules/c05/README.md\n"
            + "void Foo(void) {\n"
            + "  puts(\"// fn: not a header\");\n"
            + "}\n"
            + "\n"
            + "// fn: Bar @ 00100100 size=16\n"
            + "// calls: (none)\n"
            + "// callers: Foo\n"
            + "// part: c05 address-band conf=0.50 evidence_backed=false\n"
            + "// fp:bbbbbbbbbbbb\n"
            + "// dts:2026-01-01T00:00:00Z\n"
            + "// mod:1\n"
            + "// uri: ghidra://function/x/00100100\n"
            + "// see: modules/c05/README.md\n"
            + "void Bar(void) {}\n"
            + "\n"
            + "// fn: Baz @ 00100200 size=16\n"
            + "// calls: (none)\n"
            + "// callers: (none — entry)\n"
            + "// part: c05 address-band conf=0.50 evidence_backed=false\n"
            + "// fp:cccccccccccc\n"
            + "// dts:2026-01-01T00:00:00Z\n"
            + "// mod:1\n"
            + "// uri: ghidra://function/x/00100200\n"
            + "// see: modules/c05/README.md\n"
            + "void Baz(void) {}\n"
            + "\n";

    @Test
    public void findBlock_firstLastAndSingle() {
        String first = BlockSplicer.findBlock(THREE_BLOCKS, "00100000");
        assertNotNull(first);
        assertTrue(first.startsWith("// fn: Foo @ 00100000"));
        assertTrue("string literal must stay inside Foo's block",
                first.contains("puts(\"// fn: not a header\")"));

        String last = BlockSplicer.findBlock(THREE_BLOCKS, "00100200");
        assertNotNull(last);
        assertTrue(last.startsWith("// fn: Baz @ 00100200"));

        String alone = TestBlocks.block("Only", "deadbeef", List.of(), List.of(), "void Only(void) {}\n");
        String found = BlockSplicer.findBlock(alone, "deadbeef");
        assertNotNull(found);
        assertEquals(1, TreeFiles.splitFunctionChunks(alone).size());
        assertTrue(found.contains("void Only"));
    }

    @Test
    public void stringLiteralContainingFnMarkerDoesNotCreateBlock() {
        // Three real headers — the puts line must not split Foo.
        List<String> chunks = TreeFiles.splitFunctionChunks(THREE_BLOCKS);
        assertEquals(3, chunks.size());
        assertEquals("00100000", TreeFiles.addressFromChunk(chunks.get(0)));
        assertTrue(chunks.get(0).contains("puts(\"// fn: not a header\")"));
        assertNull(BlockSplicer.findBlock(THREE_BLOCKS, "not_an_address"));
    }

    @Test
    public void headerOnlyPatchChangesOnlyNeighbourhoodLines() {
        String bar = BlockSplicer.findBlock(THREE_BLOCKS, "00100100");
        assertNotNull(bar);
        String bodyBefore = BlockSplicer.bodyAfterLeadingComments(bar);
        String patched = BlockSplicer.patchNeighbourhoodLines(
                bar, "(none)", "FooRenamed");
        assertTrue(patched.contains("// callers: FooRenamed\n"));
        assertTrue(patched.contains("// calls: (none)\n"));
        assertEquals(bodyBefore, BlockSplicer.bodyAfterLeadingComments(patched));
        assertTrue(patched.contains("void Bar(void) {}"));
        // fp/uri/see untouched
        assertTrue(patched.contains("// fp:bbbbbbbbbbbb\n"));
        assertTrue(patched.contains("// uri: ghidra://function/x/00100100\n"));
    }

    @Test
    public void headerOnlyPatchInsertsLinesIntoLegacySevenLineHeader() {
        String legacy = ""
                + "// fn: Legacy @ 00100300 size=4\n"
                + "// part: c00 address-band conf=0.10 evidence_backed=false\n"
                + "// fp:123456789abc\n"
                + "// dts:2026-01-01T00:00:00Z\n"
                + "// mod:1\n"
                + "// uri: ghidra://function/x/00100300\n"
                + "// see: modules/c00/README.md\n"
                + "void Legacy(void) { return; }\n";
        String bodyBefore = BlockSplicer.bodyAfterLeadingComments(legacy);
        String patched = BlockSplicer.patchNeighbourhoodLines(
                legacy, "Helper", "(none — entry)");
        assertTrue(patched.contains("// calls: Helper\n"));
        assertTrue(patched.contains("// callers: (none — entry)\n"));
        assertEquals(bodyBefore, BlockSplicer.bodyAfterLeadingComments(patched));
    }

    /**
     * Found live: a function renamed a second time kept its intermediate name in its callees'
     * header lines, because "unchanged" was decided by a hash of the C alone.
     */
    @Test
    public void aHeaderOnlyChangeIsAChange() {
        String body = "void Callee(void) {}\n";
        String before = TestBlocks.block("Callee", "00100100", List.of(), List.of("syna_eiv_moc_enrollment_update"), body);
        String after = TestBlocks.block("Callee", "00100100", List.of(), List.of("syna_enroll_onchip_update"), body);
        assertFalse(BlockSplicer.sameBlock(before, after));
    }

    @Test
    public void aRerenderThatOnlyMovesTheStampsIsNotAChange() {
        String block = TestBlocks.block("Callee", "00100100", "void Callee(void) {}\n");
        String rerendered = block.replace("// dts: 2026-01-01T00:00:00Z", "// dts: 2026-10-02T09:00:00Z");
        assertNotEquals(block, rerendered);
        assertTrue(BlockSplicer.sameBlock(block, rerendered));
        assertTrue("stamps are outside the fingerprint", FunctionBlock.intact(rerendered));
    }

    @Test
    public void anEditAnywhereInABlockBreaksItsFingerprint() {
        String block = TestBlocks.block("F", "00100100", "void F(void) {}\n");
        assertTrue(FunctionBlock.intact(block));
        assertFalse(FunctionBlock.intact(block.replace("void F(void) {}", "void F(void) { /* edit */ }")));
        assertFalse(FunctionBlock.intact(block.replace("// fn: F", "// fn: G")));
    }

    /** A block from a build that still stamped // mod: is rebuilt, so old trees converge. */
    @Test
    public void aBlockWithTheRetiredModStampIsNotIntact() {
        String block = TestBlocks.block("F", "00100100", "void F(void) {}\n");
        assertTrue(FunctionBlock.intact(block));
        String legacy = block.replace("// dts: ", "// mod: 7\n// dts: ");
        assertFalse(FunctionBlock.intact(legacy));
    }
}
