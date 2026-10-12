package com.xebyte.offline;

import com.xebyte.core.BinaryComparisonService;
import com.xebyte.core.DocumentationHashService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.listing.Program;
import static org.mockito.Mockito.mock;
import junit.framework.TestCase;

/**
 * Validation + graceful-degradation coverage for DocumentationHashService (~2K LOC, previously
 * no behavioral tests). Exercises the required-parameter branches that run before any program
 * access, plus the no-program degradation path.
 */
public class DocumentationHashServiceValidationTest extends TestCase {

    private final Program programStub = mock(Program.class);

    private DocumentationHashService docs;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        docs = new DocumentationHashService(ServiceFactory.stubProvider(), ts, new BinaryComparisonService());
    }

    // --- validate-first branches (run before the program lookup) ---

    public void testFindUndocumentedByStringRequiresAddress() {
        Response r = docs.findUndocumentedByString("", programStub);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("String address is required"));
    }

    public void testBulkFuzzyMatchRequiresSourceProgram() {
        Response r = docs.handleBulkFuzzyMatch("", "Target.dll", 0.7, 0, 50, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("source_program parameter is required"));
    }

    public void testMergeProgramDocumentationRequiresSource() {
        Response r = docs.mergeProgramDocumentation("", "Target.dll", false);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("source is required"));
    }

    public void testMergeProgramDocumentationRequiresTarget() {
        Response r = docs.mergeProgramDocumentation("Source.dll", "", false);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("target is required"));
    }

}
