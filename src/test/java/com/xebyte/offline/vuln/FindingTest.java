package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.Finding;
import org.junit.Test;
import java.util.List;
import java.util.Map;
import static org.junit.Assert.*;

public class FindingTest {
    @Test
    public void finding_toJson_emitsAllFields() {
        Finding f = new Finding("format_string", "format", "cli.Initial::00010000",
            "HandleRequest", "printf", "high",
            List.of("arg0 <- param_1 (non-constant)"),
            "format argument reaches printf without constant-only def chain");
        Map<String, Object> j = f.toJson();
        assertEquals("format_string", j.get("detector_id"));
        assertEquals("format", j.get("vuln_class"));
        assertEquals("cli.Initial::00010000", j.get("address"));
        assertEquals("HandleRequest", j.get("function"));
        assertEquals("printf", j.get("sink"));
        assertEquals("high", j.get("confidence"));
        assertEquals(1, ((List<?>) j.get("evidence")).size());
        assertTrue(((String) j.get("why")).contains("printf"));
    }
}
