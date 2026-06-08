package com.xebyte.offline;

import com.xebyte.core.FunctionService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

/**
 * Validation + graceful-degradation coverage for /list_class_members (the new C++
 * class-member listing tool, issue #275). Runs offline with a stub provider.
 */
public class FunctionServiceClassMembersTest extends TestCase {

    private FunctionService functions;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        functions = new FunctionService(ServiceFactory.stubProvider(), ts);
    }

    public void testRequiresClassName() {
        Response r = functions.listClassMembers("", 0, 200, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("class_name is required"));
    }

    public void testRequiresClassNameWhenWhitespace() {
        Response r = functions.listClassMembers("   ", 0, 200, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("class_name is required"));
    }

    public void testDegradesGracefullyWithNoProgram() {
        Response r = functions.listClassMembers("UnitAny", 0, 200, "");
        assertNotNull(r);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }
}
