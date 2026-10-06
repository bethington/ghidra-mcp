package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.symbol.*;
import org.junit.*;
import java.util.*;
import static org.junit.Assert.*;

public class BatchEditingGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private FunctionService functions;
    private SymbolLabelService symbols;
    private DataTypeService types;
    private CommentService comments;
    private AnalysisService analysis;
    private HeadlessProgramProvider provider;
    @BeforeClass public static void initialize() throws Exception { OverrideServiceGhidraTest.initialize(); }
    @Before public void setUp() throws Exception {
        builder = new ProgramBuilder("batch-editing", ProgramBuilder._X86, "windows", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 256);
        builder.setBytes("0x1000", "c3");
        builder.setBytes("0x1010", "c3");
        builder.disassemble("0x1000", 1);
        builder.disassemble("0x1010", 1);
        builder.createFunction("0x1000");
        builder.createFunction("0x1010");
        provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        DirectThreadingStrategy threading = new DirectThreadingStrategy();
        functions = new FunctionService(provider, threading);
        symbols = new SymbolLabelService(provider, threading);
        types = new DataTypeService(provider, threading);
        comments = new CommentService(provider, threading);
        analysis = new AnalysisService(provider, threading, functions);
    }
    @After public void tearDown() { builder.dispose(); }
    private static void ok(Response response) { assertTrue(response.toJson(), response instanceof Response.Ok); }

    @Test public void bulkFunctionRenameAndCreationRollBackTogether() {
        ok(functions.renameFunctionByAddress("", "", "", "off", List.of(
            Map.of("address", "0x1000", "new_name", "First"), Map.of("address", "0x1010", "new_name", "Second"))));
        assertEquals("First", program.getFunctionManager().getFunctionAt(builder.addr("0x1000")).getName());
        Response failed = functions.renameFunctionByAddress("", "", "", "off", List.of(
            Map.of("address", "0x1000", "new_name", "Changed"), Map.of("address", "0x1050", "new_name", "Missing")));
        assertTrue(failed.toJson(), failed instanceof Response.Err);
        assertEquals("First", program.getFunctionManager().getFunctionAt(builder.addr("0x1000")).getName());
        ok(functions.createFunctionAtAddress("", "", true, "", List.of(
            Map.of("address", "0x1000", "name", "GetFirstValue"), Map.of("address", "0x1010", "name", "GetSecondValue"))));
        assertEquals("GetFirstValue", program.getFunctionManager().getFunctionAt(builder.addr("0x1000")).getName());
    }

    @Test public void primaryNamespacedLabelsNamespaceRenameAndBulkSymbolRename() {
        ok(symbols.createLabel("0x1040", "old_label", List.of(), ""));
        ok(symbols.createLabel("", "", List.of(Map.of("address", "0x1040", "name", "new_label")), "", true, "Outer::Inner"));
        Symbol primary = program.getSymbolTable().getPrimarySymbol(builder.addr("0x1040"));
        assertEquals("Outer::Inner::new_label", primary.getName(true));
        assertEquals(1, program.getSymbolTable().getSymbols(builder.addr("0x1040")).length);
        ok(symbols.renameSymbol("Outer::Inner", "Renamed", "namespace", "", ""));
        assertEquals("Outer::Renamed::new_label", primary.getName(true));
        ok(symbols.renameSymbol("", "", "label", "", "", List.of(Map.of("address", "0x1040", "old_name", "new_label", "new_name", "final_label"))));
        assertEquals("final_label", program.getSymbolTable().getPrimarySymbol(builder.addr("0x1040")).getName());
    }

    @Test public void guiBatchesRunOnEdtWithoutRecursiveInvokeAndWait() throws Exception {
        SymbolLabelService gui = new SymbolLabelService(provider, new SwingThreadingStrategy());
        ok(gui.createLabel("0x1040", "before_label", List.of(), ""));
        ok(gui.renameSymbol("", "", "label", "", "", List.of(
            Map.of("address", "0x1040", "old_name", "before_label", "new_name", "after_label"))));
        assertEquals("after_label", program.getSymbolTable().getPrimarySymbol(builder.addr("0x1040")).getName());
        new SwingThreadingStrategy().executeRead(() -> {
            ok(gui.createLabel("", "", List.of(Map.of("address", "0x1048", "name", "primary_label")), "", true, ""));
            return null;
        });
    }

    @Test public void malformedHttpBatchEntriesRejectTheWholeRequest() throws Exception {
        AnnotationScanner scanner = new AnnotationScanner(provider, new DirectThreadingStrategy(), functions, types, comments, symbols);
        String before = program.getFunctionManager().getFunctionAt(builder.addr("0x1000")).getName();
        EndpointDef rename = scanner.getEndpoints().stream().filter(e -> e.path().equals("/rename_function")).findFirst().orElseThrow();
        for (Object bad : Arrays.asList(null, 42, "invalid", List.of())) {
            List<Object> entries = Arrays.asList(Map.of("address", "0x1000", "new_name", "GetFirstValue"), bad);
            for (Object payload : List.of(entries, JsonHelper.toJson(entries))) {
                Response response = rename.handler().handle(Map.of(), Map.of("renames", payload));
                assertTrue(response.toJson(), response instanceof Response.Err);
                assertEquals(before, program.getFunctionManager().getFunctionAt(builder.addr("0x1000")).getName());
            }
        }
    }

    @Test public void existingFunctionCreationHonorsRenamePolicyAndBatchRollback() {
        String before = program.getFunctionManager().getFunctionAt(builder.addr("0x1000")).getName();
        Response response = functions.createFunctionAtAddress("", "", true, "", List.of(
            Map.of("address", "0x1000", "name", "GetFirstValue"), Map.of("address", "0x1010", "name", "Get")));
        assertTrue(response.toJson(), response instanceof Response.Err);
        assertEquals(before, program.getFunctionManager().getFunctionAt(builder.addr("0x1000")).getName());
    }

    @Test public void namespaceRenameDoesNotRenameAQualifiedFunction() throws Exception {
        var function = program.getFunctionManager().getFunctionAt(builder.addr("0x1000"));
        builder.withTransaction(() -> {
            try {
                Namespace outer = program.getSymbolTable().createNameSpace(program.getGlobalNamespace(), "Outer", SourceType.USER_DEFINED);
                function.setParentNamespace(outer);
                function.setName("GetOriginalValue", SourceType.USER_DEFINED);
            } catch (Exception e) { throw new RuntimeException(e); }
        });
        Response response = symbols.renameSymbol("Outer::GetOriginalValue", "Get", "namespace", "", "");
        assertTrue(response.toJson(), response instanceof Response.Err);
        assertEquals("GetOriginalValue", function.getName());
        var labelTool = new AnnotationScanner(symbols).getDescriptors().stream()
            .filter(d -> d.path().equals("/create_label")).findFirst().orElseThrow();
        assertTrue(labelTool.access().isDestructive());
    }
}
