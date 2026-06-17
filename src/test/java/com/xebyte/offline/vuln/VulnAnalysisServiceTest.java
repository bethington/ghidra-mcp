package com.xebyte.offline.vuln;

import com.xebyte.core.FunctionService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.vuln.VulnAnalysisService;
import com.xebyte.offline.NoopThreadingStrategy;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class VulnAnalysisServiceTest {

    private VulnAnalysisService svc(Program p) {
        ProgramProvider pp = mock(ProgramProvider.class);
        when(pp.getCurrentProgram()).thenReturn(p);
        FunctionService fs = mock(FunctionService.class);
        return new VulnAnalysisService(pp, new NoopThreadingStrategy(), fs);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void listVulnDetectors_returnsAllFour() {
        Response r = svc(mock(Program.class)).listVulnDetectors("");
        assertTrue(r instanceof Response.Ok);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) r).data();
        List<?> ds = (List<?>) body.get("detectors");
        assertEquals(4, ds.size());
        Set<String> ids = new HashSet<>();
        for (Object d : ds) ids.add((String) ((Map<?, ?>) d).get("id"));
        assertTrue(ids.containsAll(Set.of("format_string", "command_injection",
            "unbounded_copy", "integer_overflow_alloc")));
        assertNotNull(body.get("catalog"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void detectVulnPatterns_noFunctions_returnsEmptyWithCounts() {
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        FunctionIterator empty = mock(FunctionIterator.class);
        when(empty.hasNext()).thenReturn(false);
        when(fm.getFunctions(true)).thenReturn(empty);

        Response r = svc(p).detectVulnPatterns("", "", "", false, 0);
        assertTrue(r instanceof Response.Ok);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals(0, ((List<?>) body.get("findings")).size());
        assertEquals(0, ((Number) body.get("scanned_functions")).intValue());
        assertEquals(0, ((Number) body.get("decompile_failures")).intValue());
        List<?> ran = (List<?>) body.get("detectors_run");
        assertEquals(4, ran.size());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void detectVulnPatterns_classesFilter_limitsDetectorsRun() {
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        FunctionIterator empty = mock(FunctionIterator.class);
        when(empty.hasNext()).thenReturn(false);
        when(fm.getFunctions(true)).thenReturn(empty);

        Response r = svc(p).detectVulnPatterns("", "format_string,unbounded_copy", "", false, 0);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) r).data();
        List<?> ran = (List<?>) body.get("detectors_run");
        assertEquals(2, ran.size());
        assertTrue(ran.contains("format_string"));
        assertTrue(ran.contains("unbounded_copy"));
    }
}
