package com.xebyte.offline;

import com.xebyte.core.FunctionService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

/**
 * Validation + graceful-degradation coverage for the /clear_flow_and_repair endpoint.
 * Range validation (end > start, same space) requires a program, so it is covered by the
 * integration tests in tests/integration/test_clear_flow_and_repair.py.
 */
public class FunctionServiceClearFlowAndRepairTest extends TestCase {

    private FunctionService functions;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        functions = new FunctionService(ServiceFactory.stubProvider(), ts);
    }

    public void testRejectsMissingStartAddress() {
        Response r = functions.clearFlowAndRepair(null, "", "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("start_address parameter required"));

        r = functions.clearFlowAndRepair("", "", "");
        assertTrue(r instanceof Response.Err);
    }

    public void testDegradesGracefullyWithNoProgram() {
        Response r = functions.clearFlowAndRepair("0x401000", "", "");
        assertTrue(r instanceof Response.Err);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }
}
