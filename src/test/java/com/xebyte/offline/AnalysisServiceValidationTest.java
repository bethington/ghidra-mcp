package com.xebyte.offline;

import com.xebyte.core.AnalysisService;
import com.xebyte.core.FunctionService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

/**
 * Validation + graceful-degradation coverage for AnalysisService (the largest service in the
 * repo, ~5.2K LOC, previously no behavioral tests). Exercises the input-validation branches
 * that run before any program access, plus the no-program degradation path.
 */
public class AnalysisServiceValidationTest extends TestCase {

    private AnalysisService analysis;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        com.xebyte.core.ProgramProvider provider = ServiceFactory.stubProvider();
        analysis = new AnalysisService(provider, ts, new FunctionService(provider, ts));
    }

    // --- validate-first branches (run before the program lookup) ---

    public void testGetFieldAccessContextRejectsNegativeOffset() {
        Response r = analysis.getFieldAccessContext("0x401000", -1, 5);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Field offset must be between 0 and"));
    }

    public void testBatchAnalyzeCompletenessRejectsMissingAddresses() {
        Response r = analysis.batchAnalyzeCompleteness(null, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Missing required parameter: addresses"));
    }

    // --- graceful degradation past validation, with no program loaded ---

    public void testGetFieldAccessContextDegradesGracefullyWithValidArgs() {
        Response r = analysis.getFieldAccessContext("0x401000", 0, 5);
        assertNotNull(r);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }
}
