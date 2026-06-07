package com.xebyte.offline;

import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.core.XrefCallGraphService;
import junit.framework.TestCase;

/**
 * Graceful-degradation coverage for XrefCallGraphService (~1.3K LOC, previously no behavioral
 * tests). With a stub provider and no program loaded, every program-scoped tool must return a
 * clean error rather than throw — these assert the "No program loaded" contract and that the
 * methods don't NPE when invoked without a binary.
 */
public class XrefCallGraphServiceValidationTest extends TestCase {

    private XrefCallGraphService xref;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        xref = new XrefCallGraphService(ServiceFactory.stubProvider(), ts);
    }

    private static void assertNoProgram(Response r) {
        assertNotNull("method returned null instead of an error Response", r);
        assertTrue("expected a graceful 'No program loaded' error, got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }

    public void testGetXrefsToDegradesGracefully() {
        assertNoProgram(xref.getXrefsTo("0x401000", 0, 100, ""));
    }

    public void testGetXrefsFromDegradesGracefully() {
        assertNoProgram(xref.getXrefsFrom("0x401000", 0, 100, ""));
    }

    public void testGetFunctionJumpTargetsDegradesGracefully() {
        assertNoProgram(xref.getFunctionJumpTargets("FUN_00401000", 0, 100));
    }

    public void testProgramNotFoundWhenNamedProgramMissing() {
        Response r = xref.getXrefsTo("0x401000", 0, 100, "Nonexistent.dll");
        assertTrue("expected program-not-found error, got: " + r.toJson(),
                r.toJson().contains("Program not found: Nonexistent.dll"));
    }
}
