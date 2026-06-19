package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.*;
import org.junit.Test;
import java.util.List;
import java.util.Map;
import static org.junit.Assert.*;

public class TaintResultTest {
    @Test @SuppressWarnings("unchecked")
    public void toJson_withSource_emitsAllFields() {
        CatalogEntry src = new CatalogEntry("recv","source","network",
            Map.of("out_arg",1), false, List.of(), List.of(), List.of());
        TaintStep s1 = new TaintStep("F","00401000","param","param_2 → caller arg");
        TaintResult r = new TaintResult(src, List.of(s1), "source", 3, 2);
        Map<String,Object> j = r.toJson();
        Map<String,Object> jsrc = (Map<String,Object>) j.get("source");
        assertEquals("recv", jsrc.get("id"));
        assertEquals("network", jsrc.get("class"));
        assertEquals("source", j.get("terminal_reason"));
        assertEquals(3, j.get("functions_visited"));
        assertEquals(2, j.get("call_depth_reached"));
        List<?> path = (List<?>) j.get("path");
        assertEquals(1, path.size());
        assertEquals("param", ((Map<?,?>)path.get(0)).get("kind"));
    }

    @Test
    public void toJson_nullSource_emitsNull() {
        TaintResult r = new TaintResult(null, List.of(), "budget", 64, 10);
        assertNull(r.toJson().get("source"));
        assertEquals("budget", r.toJson().get("terminal_reason"));
    }

    @Test @SuppressWarnings("unchecked")
    public void toJson_truncatesPathTo32() {
        var steps = new java.util.ArrayList<TaintStep>();
        for (int i = 0; i < 50; i++) steps.add(new TaintStep("F","0","op","step"+i));
        TaintResult r = new TaintResult(null, steps, "budget", 1, 1);
        List<?> path = (List<?>) r.toJson().get("path");
        assertEquals(32, path.size());
        assertTrue((Boolean) r.toJson().get("path_truncated"));
    }
}
