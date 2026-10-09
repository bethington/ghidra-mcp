package com.xebyte.offline;

import com.xebyte.core.FunctionBundleService;
import com.xebyte.core.FunctionService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import ghidra.program.model.listing.Program;
import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@code fields=} on {@code /get_functions}: subset reads must not pay
 * for a decompile when they only need listing-level facts.
 */
public class FunctionBundleFieldsEndpointTest extends TestCase {

    public void testRequiresTargetDecompileOnlyForDecompiledCodeOrFullBundle() {
        assertTrue(FunctionBundleService.requiresTargetDecompile(null));
        assertTrue(FunctionBundleService.requiresTargetDecompile(
                Set.of("decompiled_code")));
        assertFalse(FunctionBundleService.requiresTargetDecompile(
                Set.of("callers", "callees", "signature", "labels")));
        assertFalse(FunctionBundleService.requiresTargetDecompile(
                Set.of("entry_point", "body_start", "body_end")));
    }

    public void testUnknownFieldErrorsWithValidList() {
        Program program = mock(Program.class);
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(program);
        FunctionBundleService svc = new FunctionBundleService(
                provider, new NoopThreadingStrategy(), mock(FunctionService.class));
        Response r = svc.getFunctions("401000", "", "callers,nope", false, 0, 3, false, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Unknown field"));
        assertTrue(((Response.Err) r).message().contains("callers"));
    }

    public void testRemovedEndpointsGoneFromSourceAndCatalog() throws IOException {
        String catalog = ProjectSource.readProjectFile("tests/endpoints.json");
        String functionSvc = ProjectSource.readMainSource("core", "FunctionService.java");
        String xref = ProjectSource.readMainSource("core", "XrefCallGraphService.java");
        String symbol = ProjectSource.readMainSource("core", "SymbolLabelService.java");
        String docs = ProjectSource.readMainSource("core", "DocumentationHashService.java");
        for (String gone : new String[] {
                "/get_function_callees",
                "/get_function_callers",
                "/get_function_labels",
                "/get_function_signature",
                "/get_function_by_address",
                "/get_function_variables",
                "/get_function_xrefs",
                "/decompile_function" }) {
            assertFalse("must not register " + gone,
                    functionSvc.contains("path = \"" + gone + "\"")
                            || xref.contains("path = \"" + gone + "\"")
                            || symbol.contains("path = \"" + gone + "\"")
                            || docs.contains("path = \"" + gone + "\""));
            assertFalse("catalog must not list " + gone,
                    catalog.contains("\"path\": \"" + gone + "\""));
        }
        String bundle = ProjectSource.readMainSource("core", "FunctionBundleService.java");
        assertTrue(bundle.contains("path = \"/get_functions\""));
        assertTrue(bundle.contains("fields"));
        assertTrue(bundle.contains("functions"));
        assertFalse("standalone jump-targets tool should be gone",
                xref.contains("path = \"/get_function_jump_targets\""));
        String facts = ProjectSource.readMainSource("core", "FunctionFacts.java");
        assertTrue("bundle must expose jump_targets as a field",
                facts.contains("\"jump_targets\""));
    }
}
