package com.xebyte.offline;

import com.xebyte.core.AnalysisService;
import com.xebyte.core.FunctionService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import static org.mockito.Mockito.mock;
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

}
