package com.xebyte.offline;

import com.xebyte.core.FunctionService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.listing.Program;
import static org.mockito.Mockito.mock;
import junit.framework.TestCase;

/**
 * Validation + graceful-degradation coverage for /list_class_members (the new C++
 * class-member listing tool, issue #275). Runs offline with a stub provider.
 */
public class FunctionServiceClassMembersTest extends TestCase {

    private final Program programStub = mock(Program.class);

    private FunctionService functions;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        functions = new FunctionService(ServiceFactory.stubProvider(), ts);
    }

    public void testRequiresClassName() {
        Response r = functions.listClassMembers("", 0, 200, programStub);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("class_name is required"));
    }

    public void testRequiresClassNameWhenWhitespace() {
        Response r = functions.listClassMembers("   ", 0, 200, programStub);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("class_name is required"));
    }

}
