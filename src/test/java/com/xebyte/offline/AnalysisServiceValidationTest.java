package com.xebyte.offline;

import com.xebyte.core.AnalysisService;
import com.xebyte.core.FunctionService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.framework.options.Options;
import java.util.List;
import java.util.Map;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import junit.framework.TestCase;

/**
 * Validation + graceful-degradation coverage for AnalysisService (the largest service in the
 * repo, ~5.2K LOC, previously no behavioral tests). Exercises the input-validation branches
 * that run before any program access, plus the no-program degradation path.
 */
public class AnalysisServiceValidationTest extends TestCase {

    private final Program programStub = mock(Program.class);

    private AnalysisService analysis;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        com.xebyte.core.ProgramProvider provider = ServiceFactory.stubProvider();
        analysis = new AnalysisService(provider, ts, new FunctionService(provider, ts));
    }

    // --- validate-first branches (run before the program lookup) ---

    public void testGetFieldAccessContextRejectsNegativeOffset() {
        Response r = analysis.getFieldAccessContext(mock(Address.class), -1, 5, programStub);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Field offset must be between 0 and"));
    }

    public void testBatchAnalyzeCompletenessRejectsMissingAddresses() {
        Response r = analysis.batchAnalyzeCompleteness(null, programStub);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Missing required parameter: addresses"));
    }

    // --- analyzer descriptions ---

    private Program programWithAnalyzers(Options options) {
        Program program = mock(Program.class);
        when(program.getOptions(Program.ANALYSIS_PROPERTIES)).thenReturn(options);
        return program;
    }

    @SuppressWarnings("unchecked")
    public void testListAnalyzersReportsDescriptionWhenPresent() {
        Options options = mock(Options.class);
        when(options.getOptionNames()).thenReturn(List.of("Stock", "NoDoc"));
        when(options.getBoolean("Stock", false)).thenReturn(false);
        when(options.getBoolean("NoDoc", false)).thenReturn(true);
        when(options.getDescription("Stock")).thenReturn("Finds non-returning functions");
        when(options.getDescription("NoDoc")).thenReturn(null);

        Response r = analysis.listAnalyzers(programWithAnalyzers(options));
        assertTrue(r instanceof Response.Ok);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) r).data();
        List<Map<String, Object>> entries = (List<Map<String, Object>>) body.get("analyzers");
        assertEquals("Finds non-returning functions", entries.get(0).get("description"));
        assertEquals(false, entries.get(0).get("enabled"));
        assertFalse(entries.get(1).containsKey("description"));
    }

    @SuppressWarnings("unchecked")
    public void testConfigureAnalyzerEchoesDescription() {
        Options options = mock(Options.class);
        when(options.contains("Stock")).thenReturn(true);
        when(options.getBoolean("Stock", false)).thenReturn(false);
        when(options.getDescription("Stock")).thenReturn("Finds non-returning functions");

        Response r = analysis.configureAnalyzer("Stock", null, programWithAnalyzers(options));
        assertTrue(r instanceof Response.Ok);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals("Finds non-returning functions", body.get("description"));
        assertEquals(false, body.get("changed"));
    }
}
