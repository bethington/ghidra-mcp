package com.xebyte.offline;

import com.xebyte.core.FunctionService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.listing.Program;
import static org.mockito.Mockito.mock;
import junit.framework.TestCase;

/**
 * Validation + graceful-degradation coverage for the /clear_flow_and_repair endpoint.
 * Range validation (end > start, same space) requires a program, so it is covered by the
 * integration tests in tests/integration/test_clear_flow_and_repair.py.
 */
public class FunctionServiceClearFlowAndRepairTest extends TestCase {

    private final Program programStub = mock(Program.class);

    private FunctionService functions;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        functions = new FunctionService(ServiceFactory.stubProvider(), ts);
    }

    public void testRejectsMissingStartAddress() {
        Response r = functions.clearFlowAndRepair(null, null, programStub);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("start_address parameter required"));

    }

}
