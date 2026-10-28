package com.xebyte.core;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import org.junit.*;
import java.io.File;
import java.util.*;
import java.util.concurrent.Callable;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

/** Real database storage and transaction behavior, rather than mocked frame semantics. */
public class VariableConsolidationGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private Function function;
    private FunctionService service;
    private ThreadingStrategy threading;

    @BeforeClass public static void initialize() throws Exception {
        String install = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue(install != null && !install.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration config = new ApplicationConfiguration();
            config.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(install)), config);
        }
    }
    @Before public void setup() throws Exception {
        builder = new ProgramBuilder("variable-consolidation", ProgramBuilder._X86, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 32);
        builder.setBytes("0x1000", "c3");
        function = builder.createFunction("0x1000");
        threading = new ThreadingStrategy() {
            public <T> T executeRead(Callable<T> action) throws Exception { return action.call(); }
            public <T> T executeWrite(Program p, String name, Callable<T> action) throws Exception {
                int tx = p.startTransaction(name);
                boolean commit = false;
                try { T result = action.call(); commit = true; return result; }
                finally { p.endTransaction(tx, commit); }
            }
        };
        service = new FunctionService(null, threading);
    }
    @After public void close() { if (builder != null) builder.dispose(); }
    private Response set(Function target, String key, String name, String type, boolean replace) {
        return service.setVariables(target, "{\"" + key + "\":{\"name\":\"" + name
            + "\",\"type\":\"" + type + "\",\"create\":true,\"replace\":" + replace + "}}", program);
    }
    private void local(String name, int offset) {
        builder.withTransaction(() -> {
            try { function.getStackFrame().createVariable(name, offset, IntegerDataType.dataType, SourceType.USER_DEFINED); }
            catch (Exception e) { throw new AssertionError(e); }
        });
    }
    private Set<String> names() {
        Set<String> names = new TreeSet<>();
        for (Variable v : function.getLocalVariables()) names.add(v.getName());
        return names;
    }
    @Test public void createsAtRequestedNegativeFrameOffset() {
        Response result = set(function, "Stack[-0x10]", "nCount", "int", false);
        assertTrue(result.toJson(), names().contains("nCount"));
        Variable variable = function.getStackFrame().getVariableContaining(-16);
        assertEquals(-16, variable.getStackOffset());
        assertEquals("int", variable.getDataType().getName());
    }
    @Test public void replacesEntireIntervalKeepingAdjacentLocal() {
        local("nFirst", -16); local("nSecond", -12); local("nNeighbor", -8);
        Response result = set(function, "Stack[-16]", "llCount", "longlong", true);
        assertEquals(result.toJson(), Set.of("llCount", "nNeighbor"), names());
        assertEquals(8, function.getStackFrame().getVariableContaining(-16).getLength());
    }
    @Test public void invalidNamePreservesOriginalLocal() {
        local("nOriginal", -8);
        set(function, "Stack[-8]", "bad name", "int", true);
        assertEquals(Set.of("nOriginal"), names());
    }
    @Test public void unknownTypePreservesOriginalLocal() {
        local("nOriginal", -8);
        set(function, "Stack[-8]", "nCount", "NoSuchType620", true);
        assertEquals(Set.of("nOriginal"), names());
    }
    @Test public void overlappingParameterIsNeverRemoved() {
        builder.withTransaction(() -> {
            try { function.addParameter(new ParameterImpl("nArgument", IntegerDataType.dataType, 4, program), SourceType.USER_DEFINED); }
            catch (Exception e) { throw new AssertionError(e); }
        });
        Response result = set(function, "Stack[0]", "llCount", "longlong", true);
        assertEquals(result.toJson(), 1, function.getParameterCount());
        assertEquals("nArgument", function.getParameter(0).getName());
        assertTrue(result.toJson(), names().isEmpty());
    }
    @Test public void failedCreationRollsBackRemovedLocals() throws Exception {
        local("nOriginal", -8);
        Function failing = spy(function);
        StackFrame frame = mock(StackFrame.class);
        when(failing.getStackFrame()).thenReturn(frame);
        when(frame.createVariable(anyString(), anyInt(), any(), any())).thenThrow(new ghidra.util.exception.InvalidInputException("forced creation failure"));
        Response result = set(failing, "Stack[-8]", "nCount", "int", true);
        assertTrue(result.toJson(), result instanceof Response.Err);
        assertEquals(Set.of("nOriginal"), names());
    }

    @Test public void scannerDryRunRollsBackRealReplacement() throws Exception {
        local("nOriginal", -8);
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(program);
        when(provider.getProgram(program.getName())).thenReturn(program);
        AnnotationScanner scanner = new AnnotationScanner(provider, threading, new Object[]{service});
        EndpointDef endpoint = scanner.getEndpoints().stream()
            .filter(ep -> ep.path().equals("/set_variables")).findFirst().orElseThrow();
        Response result = endpoint.handler().handle(Map.of("program", program.getName()),
            Map.of("function", "0x1000", "variables",
                Map.of("Stack[-8]", Map.of("name", "nCount", "type", "int", "create", true, "replace", true)),
                "dry_run", true));
        assertFalse(result.toJson(), result instanceof Response.Err);
        assertTrue(result.toJson(), result.toJson().contains("dry_run"));
        assertEquals(Set.of("nOriginal"), names());
        // A real write using the same handler demonstrates the preview performed work.
        Response applied = endpoint.handler().handle(Map.of("program", program.getName()),
            Map.of("function", "0x1000", "variables",
                Map.of("Stack[-8]", Map.of("name", "nCount", "type", "int", "create", true, "replace", true))));
        assertFalse(applied.toJson(), applied instanceof Response.Err);
        assertEquals(applied.toJson(), Set.of("nCount"), names());
    }

    @Test public void oldObjectAndPositionalTypeMappingsStillWork() throws Exception {
        local("nOriginal", -8);
        Response object = service.setVariables(function, "{\"nOriginal\":{\"type\":\"uint\"}}", program);
        assertFalse(object.toJson(), object instanceof Response.Err);
        assertEquals("uint", function.getStackFrame().getVariableContaining(-8).getDataType().getName());
        Response positional = service.setVariables(function, "{\"nOriginal\":[null,\"int\"]}", program);
        assertFalse(positional.toJson(), positional instanceof Response.Err);
        assertEquals("int", function.getStackFrame().getVariableContaining(-8).getDataType().getName());
    }

    @Test public void emptyParameterSlotCannotCreateParameterOrEnableCustomStorage() {
        assertTrue(function.getStackFrame().isParameterOffset(4));
        assertEquals(0, function.getParameterCount());
        assertFalse(function.hasCustomVariableStorage());
        Response result = set(function, "Stack[4]", "nCount", "int", false);
        assertEquals(result.toJson(), 0, function.getParameterCount());
        assertFalse(result.toJson(), function.hasCustomVariableStorage());
        assertTrue(result.toJson(), names().isEmpty());
        assertTrue(result.toJson(), result.toJson().toLowerCase().contains("parameter"));
    }

    @Test public void localIntervalCannotEndInEmptyParameterRegion() {
        StackFrame frame = function.getStackFrame();
        assertFalse(frame.isParameterOffset(-4));
        assertTrue(frame.isParameterOffset(11));
        Response result = set(function, "Stack[-4]", "anCounts", "int[4]", false);
        assertEquals(result.toJson(), 0, function.getParameterCount());
        assertFalse(result.toJson(), function.hasCustomVariableStorage());
        assertTrue(result.toJson(), names().isEmpty());
        assertTrue(result.toJson(), result.toJson().toLowerCase().contains("parameter"));
    }

    private Response mixedReplacement(String namedJson) {
        return service.setVariables(function,
            "{\"Stack[-8]\":{\"name\":\"nReplacement\",\"type\":\"int\",\"create\":true,\"replace\":true},"
                + namedJson + "}", program);
    }

    @Test public void mixedMissingNamedTypeRollsBackDestructiveReplacement() {
        local("nOriginal", -8);
        Response result = mixedReplacement("\"missingVariable\":{\"type\":\"int\"}");
        assertEquals(result.toJson(), Set.of("nOriginal"), names());
        assertTrue(result.toJson(), result instanceof Response.Err);
        assertTrue(result.toJson(), result.toJson().contains("missingVariable"));
    }

    @Test public void mixedMissingNamedRenameRollsBackDestructiveReplacement() {
        local("nOriginal", -8);
        Response result = mixedReplacement("\"missingVariable\":\"nRenamed\"");
        assertEquals(result.toJson(), Set.of("nOriginal"), names());
        assertTrue(result.toJson(), result instanceof Response.Err);
    }

    @Test public void mixedDuplicateRenameToCreatedLocalRollsBackReplacement() {
        local("nOriginal", -8);
        local("nOther", -16);
        Response result = mixedReplacement("\"nOther\":{\"name\":\"nReplacement\"}");
        assertEquals(result.toJson(), Set.of("nOriginal", "nOther"), names());
        assertTrue(result.toJson(), result instanceof Response.Err);
    }

    @Test public void mixedNamedTypeErrorRollsBackOtherSuccessfulNamedChangesToo() {
        local("nOriginal", -8);
        local("nOther", -16);
        Response result = mixedReplacement("\"nOther\":{\"type\":\"uint\"},\"missingVariable\":{\"type\":\"int\"}");
        assertEquals(result.toJson(), Set.of("nOriginal", "nOther"), names());
        assertEquals("int", function.getStackFrame().getVariableContaining(-16).getDataType().getName());
        assertTrue(result.toJson(), result instanceof Response.Err);
    }
}
