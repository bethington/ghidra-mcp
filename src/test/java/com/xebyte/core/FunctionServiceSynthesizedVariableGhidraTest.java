package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import org.junit.*;

import java.io.File;
import java.util.*;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;
import static org.mockito.Mockito.*;

/** Real decompiler + temporary in-memory program, never a user's saved project. */
public class FunctionServiceSynthesizedVariableGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private Function function;
    private FunctionService service;

    @BeforeClass public static void initializeGhidra() throws Exception {
        String install = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR required for real Ghidra tests", install != null && !install.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration config = new ApplicationConfiguration();
            config.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(install)), config);
        }
        // Plain ApplicationConfiguration does not discover built-ins. Without
        // this, their IDs all alias BAD_DATATYPE_ID and HighFunction's decoded
        // types are bogus even when the native C text is correct.
        ClassSearcher.search(TaskMonitor.DUMMY);
        assertTrue("native fixtures require discovered builtin types",
            ClassSearcher.getClasses(ghidra.program.model.data.BuiltInDataType.class)
                .contains(IntegerDataType.class));
    }

    @Before public void setUp() throws Exception {
        builder = new ProgramBuilder("ssa-type-fixture", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x1100);
        // Save source()'s result, null-check and pass it to consume(), then return it.
        builder.setBytes("0x1000", "53 e8 fa 0f 00 00 48 89 c3 48 85 c0 74 08 48 89 c7 e8 fa 0f 00 00 48 89 d8 5b c3");
        builder.setBytes("0x2000", "c3");
        builder.setBytes("0x2010", "c3");
        builder.disassemble("0x2000", 1);
        builder.disassemble("0x2010", 1);
        builder.createFunction("0x2000");
        builder.createFunction("0x2010");
        builder.disassemble("0x1000", 27);
        function = builder.createFunction("0x1000");
        builder.withTransaction(() -> function.setComment("[RE] Keep this existing plate."));
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.trackOpenProgram(program);
        service = new FunctionService(provider, new DirectThreadingStrategy());
    }

    @After public void tearDown() {
        if (builder != null) builder.dispose();
    }

    private HighFunction high() {
        var result = service.decompileFunctionNoRetry(function, program);
        assertNotNull("real native decompiler returned no result", result);
        assertTrue(result.getErrorMessage(), result.decompileCompleted());
        return result.getHighFunction();
    }

    private String synthesizedName() {
        assertEquals("fixture must start with no DB locals", 0, function.getLocalVariables().length);
        var symbols = high().getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            if (!symbol.isParameter() && !symbol.getName().startsWith("unaff_")
                    && !symbol.getName().startsWith("in_") && !symbol.getName().startsWith("extraout_")) {
                return symbol.getName();
            }
        }
        fail("fixture did not recover a synthesized local");
        return null;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> data(Response response) {
        assertTrue(response.toJson(), response instanceof Response.Ok);
        return (Map<String, Object>) ((Response.Ok) response).data();
    }

    @Test public void oneBatchRetypesAndRenamesDecompilerOnlyLocal() {
        String name = synthesizedName();
        String changes = JsonHelper.toJson(Map.of(name, Map.of("name", "pLoadedResult", "type", "int *")));
        Map<String, Object> result = data(service.setVariables(function, changes, program));
        assertEquals(result.toString(), true, result.get("success"));
        assertEquals(1, result.get("types_set"));
        assertEquals(1, result.get("names_set"));
        HighSymbol updated = service.findSymbolByName(high(), "pLoadedResult");
        assertNotNull(updated);
        assertTrue(updated.getDataType().toString(), updated.getDataType() instanceof Pointer);
        assertTrue(((Pointer) updated.getDataType()).getDataType().isEquivalent(IntegerDataType.dataType));
        assertEquals("[RE] Keep this existing plate.", function.getComment());
    }

    @Test public void invalidBatchDoesNotApplyTheValidSubset() {
        String name = synthesizedName();
        Response result = service.setVariables(function, JsonHelper.toJson(Map.of(
            name, Map.of("name", "pLoadedResult", "type", "void *"),
            "missing_local", Map.of("type", "int"))), program);
        assertTrue(result.toJson(), result instanceof Response.Err);
        assertEquals(0, function.getLocalVariables().length);
        assertNull(service.findSymbolByName(high(), "pLoadedResult"));
        assertEquals("[RE] Keep this existing plate.", function.getComment());
    }

    @Test public void successfulSingleRetypeMustMatchFreshDecompiler() {
        String name = synthesizedName();
        Response response = service.setLocalVariableType(function, name, "int *", program);
        assertTrue(response.toJson(), response instanceof Response.Ok);
        HighSymbol updated = service.findSymbolByName(high(), name);
        assertNotNull(updated);
        assertTrue(updated.getDataType().toString(), updated.getDataType() instanceof Pointer);
        assertTrue(((Pointer) updated.getDataType()).getDataType().isEquivalent(IntegerDataType.dataType));
        assertEquals("[RE] Keep this existing plate.", function.getComment());
    }

    @Test public void establishedApiProducesConcretePointerAfterCommit() throws Exception {
        String name = synthesizedName();
        HighSymbol symbol = service.findSymbolByName(high(), name);
        int transaction = program.startTransaction("Established API test");
        try {
            HighFunctionDBUtil.updateDBVariable(symbol, "pDirectResult",
                new PointerDataType(IntegerDataType.dataType, program.getDataTypeManager()),
                SourceType.USER_DEFINED);
            for (var local : function.getLocalVariables()) {
                System.out.println("DB local: " + local.getName() + ": " + local.getDataType());
            }
        } finally { program.endTransaction(transaction, true); }
        var result = service.decompileFunctionNoRetry(function, program);
        System.out.println(result.getDecompiledFunction().getC());
        HighSymbol updated = service.findSymbolByName(result.getHighFunction(), "pDirectResult");
        assertNotNull(updated);
        assertTrue(updated.getDataType().toString(), updated.getDataType() instanceof Pointer);
        assertTrue(updated.getDataType().toString(),
            ((Pointer) updated.getDataType()).getDataType().isEquivalent(IntegerDataType.dataType));
    }

    @Test public void failedFreshReadbackRollsBackBatchTypeWrite() {
        String name = synthesizedName();
        var original = service.decompileFunctionNoRetry(function, program);
        FunctionService checked = spy(service);
        // Simulate a native dynamic/SSA mapping that fails to recover the new
        // annotation. The DB write is real; its stale readback must not succeed.
        doReturn(original).when(checked).decompileFunctionNoRetry(function, program);
        Response result = checked.setVariables(function, JsonHelper.toJson(Map.of(
            name, Map.of("type", "int *"))), program);
        assertTrue(result.toJson(), result instanceof Response.Err);
        assertEquals(0, function.getLocalVariables().length);
        assertEquals("[RE] Keep this existing plate.", function.getComment());
    }

    @Test public void failedFreshReadbackRollsBackSingleTypeWrite() {
        String name = synthesizedName();
        var original = service.decompileFunctionNoRetry(function, program);
        FunctionService checked = spy(service);
        doReturn(original).when(checked).decompileFunctionNoRetry(function, program);
        Response result = checked.setLocalVariableType(function, name, "int *", program);
        assertTrue(result.toJson(), result instanceof Response.Err);
        assertTrue(result.toJson(), result.toJson().contains("persisted DB variable") || result.toJson().contains("did not survive fresh decompilation"));
        assertEquals(0, function.getLocalVariables().length);
        assertEquals("[RE] Keep this existing plate.", function.getComment());
    }

    @Test public void ambientOwnerRetainsWorkAndReceivesTruthfulPartialFailure() {
        String name = synthesizedName();
        var original = service.decompileFunctionNoRetry(function, program);
        FunctionService checked = spy(service);
        doReturn(original).when(checked).decompileFunctionNoRetry(function, program);
        int outer = program.startTransaction("Unrelated outer work");
        try {
            function.setComment("[RE] Outer owner's existing work.");
            Response result = checked.setVariables(function, JsonHelper.toJson(Map.of(
                name, Map.of("type", "int *"))), program);
            assertTrue(result.toJson(), result instanceof Response.Err);
            assertTrue(result.toJson(), result.toJson().contains("surrounding transaction"));
            assertEquals(1, function.getLocalVariables().length);
        } finally { program.endTransaction(outer, true); }
        assertEquals("[RE] Outer owner's existing work.", function.getComment());
    }

    @Test public void opaquePointerReadbackIsStillPointerStorage() {
        String name = synthesizedName();
        Response response = service.setLocalVariableType(function, name, "void *", program);
        assertTrue(response.toJson(), response instanceof Response.Ok);
        HighSymbol updated = service.findSymbolByName(high(), name);
        assertNotNull(updated);
        assertTrue(updated.getDataType().toString(), updated.getDataType() instanceof Pointer);
        System.out.println("Opaque pointer fresh readback: " + updated.getDataType());
    }
    @Test public void renameOnlyDoesNotRequireAnExplicitType() {
        String name = synthesizedName();
        Map<String, Object> result = data(service.setVariables(function,
            JsonHelper.toJson(Map.of(name, Map.of("name", "loadedResult"))), program));
        assertEquals(true, result.get("success"));
        assertEquals(0, result.get("types_set"));
        assertEquals(1, result.get("names_set"));
        assertNotNull(service.findSymbolByName(high(), "loadedResult"));
        assertEquals("[RE] Keep this existing plate.", function.getComment());
    }

    @Test public void inferredParameterCanBeTypedAndNamedInOneBatch() throws Exception {
        builder.setBytes("0x1100", "48 8b 07 48 85 c0 74 03 48 8b 00 c3");
        builder.disassemble("0x1100", 12);
        Function target = builder.createFunction("0x1100");
        var before = service.decompileFunctionNoRetry(target, program).getHighFunction();
        HighSymbol parameter = before.getLocalSymbolMap().getParamSymbol(0);
        assertNotNull("fixture needs a recovered RDI parameter", parameter);
        Map<String, Object> result = data(service.setVariables(target,
            JsonHelper.toJson(Map.of(parameter.getName(), Map.of("name", "pInput", "type", "int *"))), program));
        assertEquals(true, result.get("success"));
        var fresh = service.decompileFunctionNoRetry(target, program).getHighFunction();
        HighSymbol updated = service.findSymbolByName(fresh, "pInput");
        assertNotNull(updated);
        var stored = HighFunctionDBUtil.getFunctionVariable(updated);
        assertNotNull(stored);
        assertTrue(stored instanceof ghidra.program.model.listing.Parameter);
        assertTrue(stored.getDataType() instanceof Pointer);
        assertTrue(((Pointer) stored.getDataType()).getDataType().isEquivalent(IntegerDataType.dataType));
        assertEquals(SourceType.USER_DEFINED, stored.getSource());
    }
}
