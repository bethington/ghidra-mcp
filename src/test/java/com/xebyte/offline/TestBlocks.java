package com.xebyte.offline;

import com.xebyte.core.tree.FunctionBlock;
import com.xebyte.core.tree.SweepJob;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Builds tree blocks for offline tests the way the sweep does: from a facts map. */
final class TestBlocks {

    private TestBlocks() {
    }

    static String block(String name, String addr, List<String> calls,
            List<String> callers, String body) {
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("name", name);
        facts.put("size", 16L);
        facts.put("entry_point", addr);
        facts.put("callees", neighbours(calls));
        facts.put("callers", neighbours(callers));
        return FunctionBlock.render(facts, body, new FunctionBlock.Placement("c05", "address-band",
                0.50, false, Instant.parse("2026-01-01T00:00:00Z"),
                SweepJob.functionResourceUri("x", addr)));
    }

    static String block(String name, String addr, String body) {
        return block(name, addr, List.of(), List.of(), body);
    }

    private static List<Map<String, Object>> neighbours(List<String> names) {
        List<Map<String, Object>> out = new ArrayList<>();
        int i = 0;
        for (String n : names) {
            out.add(Map.of("name", n, "address", String.format("%08x", 0x100000 + 0x100 * i++)));
        }
        return out;
    }
}
