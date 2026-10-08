package com.xebyte.offline;

import com.xebyte.core.tree.BlockSplicer;
import com.xebyte.core.tree.FunctionBlock;
import org.junit.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * A tree block is {@code /get_functions}' facts written as grep-able header lines. These
 * pin the format, and that {@link FunctionBlock#parse} reads back exactly what
 * {@link FunctionBlock#render} wrote: the parity test leans on that round trip.
 */
public class FunctionBlockTest {

    private static Map<String, Object> facts() {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("name", "gpio_set");
        f.put("size", 24L);
        f.put("signature", "void gpio_set(uint * port, ushort pins)");
        f.put("classification", "leaf");
        f.put("return_type", "void");
        f.put("return_type_resolved", true);
        f.put("entry_point", "08004000");
        f.put("body_start", "08004000");
        f.put("body_end", "08004017");
        f.put("tags", List.of("gpio", "hal"));
        f.put("plate_comment", "Sets pins.\nAlgorithm: write BSRR");
        f.put("plate_comment_issues", List.of("missing Parameters section"));
        f.put("callees", List.of());
        f.put("callers", List.of(Map.of("name", "led_on", "address", "08005000")));
        f.put("caller_count", 1);
        f.put("refs", List.of("0x08004100", "0x40020000"));
        f.put("parameters", List.of(Map.of("ordinal", 0, "name", "port", "type", "uint *", "storage", "r0:4")));
        f.put("locals", List.of(Map.of("name", "extraout_r0", "type", "int", "storage", "r0", "is_phantom", true,
                "in_decompiled_code", true)));
        f.put("labels", List.of(Map.of("relative_offset", 20L, "name", "done", "source", "USER_DEFINED")));
        f.put("comments", List.of(Map.of("relative_offset", 4L, "kind", "eol", "text", "BSRR write")));
        f.put("xrefs", List.of(Map.of("from", "08005010", "type", "UNCONDITIONAL_CALL", "from_function", "led_on")));
        f.put("jump_targets", List.of("08004014"));
        return f;
    }

    private static FunctionBlock.Placement where() {
        return new FunctionBlock.Placement("m01", "mmio-page", 0.9, true,
                Instant.parse("2026-10-01T00:00:00Z"), "ghidra://function/fw/08004000");
    }

    @Test
    public void everyFactIsAHeaderLineAndTheHeaderEndsBeforeTheBody() {
        String body = "// Sets pins.\nvoid gpio_set(uint *port,ushort pins)\n{\n  *port = pins;\n}\n";
        String block = FunctionBlock.render(facts(), body, where());
        String[] lines = block.split("\n");

        assertEquals("// fn: gpio_set @ 08004000 size=24", lines[0]);
        assertTrue(block.contains("\n// signature: void gpio_set(uint * port, ushort pins)\n"));
        assertTrue(block.contains("\n// tags: gpio, hal\n"));
        assertTrue("a multi-line value stays on one line",
                block.contains("\n// plate: Sets pins.\\nAlgorithm: write BSRR\n"));
        assertTrue(block.contains("\n// callers: led_on@08005000\n"));
        assertTrue(block.contains("\n// calls: (none)\n"));
        assertTrue(block.contains("\n// refs: 0x08004100 0x40020000\n"));
        assertTrue(block.contains("\n// param: #0 uint * port @r0:4\n"));
        assertTrue(block.contains("\n// local: int extraout_r0 @r0 [phantom]\n"));
        assertTrue(block.contains("\n// label: +0x14 done (USER_DEFINED)\n"));
        assertTrue(block.contains("\n// comment: +0x4 eol BSRR write\n"));
        assertTrue(block.contains("\n// xref: 08005010 UNCONDITIONAL_CALL led_on\n"));
        assertTrue(block.contains("\n// jump: 08004014\n"));
        assertTrue(block.contains("\n// uri: ghidra://function/fw/08004000\n"));
        assertTrue("the decompiler's own // lines are body, after the terminator",
                block.contains("\n" + FunctionBlock.HEADER_END + "\n// Sets pins.\nvoid gpio_set"));
        assertEquals(body, FunctionBlock.body(block));
        assertEquals(body, BlockSplicer.bodyAfterLeadingComments(block));
    }

    @Test
    public void parseReadsBackWhatRenderWrote() {
        Map<String, Object> parsed = FunctionBlock.parse(
                FunctionBlock.render(facts(), "void f(void) {}\n", where()));
        assertEquals("gpio_set @ 08004000 size=24", parsed.get("fn"));
        assertEquals("gpio, hal", parsed.get("tags"));
        assertEquals("led_on@08005000", parsed.get("callers"));
        assertEquals(List.of("#0 uint * port @r0:4"), parsed.get("param"));
        assertEquals(List.of("missing Parameters section"), parsed.get("plate_issue"));
        assertEquals("void f(void) {}\n", parsed.get("body"));
        assertFalse("a body line is never read as a header field", parsed.containsKey("void f(void) {}"));
    }

    @Test
    public void aCappedNeighbourListSaysHowManyMore() {
        Map<String, Object> f = facts();
        List<Map<String, Object>> callers = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            callers.add(Map.of("name", "c" + i, "address", String.format("%08x", i)));
        }
        f.put("callers", callers);
        f.put("caller_count", 73);
        String block = FunctionBlock.render(f, "x\n", where());
        assertTrue(block.contains(", c49@00000031 +23 more\n"));
    }

    @Test
    public void aFailedDecompileSaysWhyInTheHeader() {
        Map<String, Object> f = facts();
        f.put("decompile_failed", true);
        f.put("decompile_error", "timed out");
        String block = FunctionBlock.render(f, "// DECOMPILATION FAILED: timed out\n", where());
        assertTrue(block.contains("\n// decompile_error: timed out\n"));
    }
}
