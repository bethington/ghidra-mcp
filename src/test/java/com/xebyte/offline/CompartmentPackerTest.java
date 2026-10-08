package com.xebyte.offline;

import com.xebyte.core.tree.CompartmentPacker;
import com.xebyte.core.tree.CompartmentPacker.PackedFile;
import com.xebyte.core.tree.FunctionBlock;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/** The one layout rule, shared by the sweep and the reconciler. */
public class CompartmentPackerTest {

    private static Map.Entry<String, String> block(String key, int bodyBytes) {
        return Map.entry(key, TestBlocks.block("f_" + key, key, "x".repeat(bodyBytes) + "\n"));
    }

    @Test
    public void aFileClosesBeforeTheBlockThatWouldOverflowIt() {
        List<Map.Entry<String, String>> blocks = List.of(
            block("00001000", 400), block("00001100", 400), block("00001200", 400));
        int one = CompartmentPacker.pack("c00", 100_000, 4, List.of(blocks.get(0))).get(0).body().length();

        List<PackedFile> files = CompartmentPacker.pack("c00", one * 2, 4, blocks);

        assertEquals(2, files.size());
        assertEquals(List.of("00001000", "00001100"), files.get(0).keys());
        assertEquals(List.of("00001200"), files.get(1).keys());
        assertTrue(files.get(0).body().length() <= one * 2);
    }

    @Test
    public void filesAreNamedForTheirFirstFunction() {
        List<PackedFile> files = CompartmentPacker.pack("c00", 1, 4,
            List.of(block("00001000", 10), block("00001100", 10)));
        assertEquals("modules/c00/00001000.c", files.get(0).path());
        assertEquals("modules/c00/00001100.c", files.get(1).path());
    }

    @Test
    public void anOversizedFunctionGetsAFileOfItsOwnAndIsNeverSplit() {
        List<PackedFile> files = CompartmentPacker.pack("c00", 100, 4,
            List.of(block("00001000", 5000)));
        assertEquals(1, files.size());
        assertTrue(files.get(0).body().contains("x".repeat(5000)));
    }

    @Test
    public void aFileHoldsAtMostTheFunctionCap() {
        List<Map.Entry<String, String>> blocks = new ArrayList<>();
        for (int i = 0; i < CompartmentPacker.MAX_FUNCTIONS_PER_FILE + 1; i++) {
            blocks.add(block(String.format("%08x", 0x1000 + i * 0x10), 1));
        }
        List<PackedFile> files = CompartmentPacker.pack("c00", Integer.MAX_VALUE, 4, blocks);
        assertEquals(2, files.size());
        assertEquals(CompartmentPacker.MAX_FUNCTIONS_PER_FILE, files.get(0).keys().size());
    }

    @Test
    public void aBlockReadBackFromAFilePacksToTheSameBytes() {
        Map.Entry<String, String> fresh = block("00001000", 10);
        String file = CompartmentPacker.pack("c00", 100_000, 4, List.of(fresh)).get(0).body();
        String readBack = com.xebyte.core.tree.TreeFiles.splitFunctionChunks(file).get(0);
        assertEquals(file, CompartmentPacker.pack("c00", 100_000, 4,
            List.of(Map.entry("00001000", readBack))).get(0).body());
        assertTrue("a packed block is still intact", FunctionBlock.intact(readBack));
    }
}
