package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import org.junit.*;
import static org.junit.Assert.*;

public class DataTypeEditingGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private DataTypeService service;
    @BeforeClass public static void initialize() throws Exception { OverrideServiceGhidraTest.initialize(); }
    @Before public void setUp() throws Exception {
        builder = new ProgramBuilder("type-editing", ProgramBuilder._X86, "windows", this);
        program = builder.getProgram();
        builder.createMemory(".data", "0x1000", 256);
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        service = new DataTypeService(provider, new DirectThreadingStrategy());
    }
    @After public void tearDown() { builder.dispose(); }
    private static void ok(Response response) { assertTrue(response.toJson(), response instanceof Response.Ok); }
    private Structure structure() { return (Structure) program.getDataTypeManager().getDataType("/Types/S"); }

    @Test public void functionDefinitionsKeepNamedParametersConventionAndIdentity() {
        ok(service.createFunctionSignature("Callback", "int", "[{\"name\":\"self\",\"type\":\"void *\"},{\"name\":\"count\",\"type\":\"int\"}]", "", "stdcall", "/Types"));
        FunctionDefinition original = (FunctionDefinition) program.getDataTypeManager().getDataType("/Types/Callback");
        assertEquals("self", original.getArguments()[0].getName());
        assertEquals("__stdcall", original.getCallingConventionName());
        ok(service.createFunctionSignature("Callback", "void", "[]", "", "cdecl", "/Types"));
        assertSame(original, program.getDataTypeManager().getDataType("/Types/Callback"));
        assertEquals(0, original.getArguments().length);
        assertTrue(service.createFunctionSignature("Callback", "int", "[{\"type\":\"nonexistent\"}]", "", "", "/Types") instanceof Response.Err);
        assertEquals("void", ((FunctionDefinition) program.getDataTypeManager().getDataType("/Types/Callback")).getReturnType().getName());
    }

    @Test public void explicitCategoriesScopeCreationAndQualifiedLookup() {
        String fields = "[{\"name\":\"value\",\"type\":\"uint\"}]";
        ok(service.createStruct("S", fields, false, "", "/Types"));
        ok(service.createStruct("S", fields, false, "", "/Other"));
        ok(service.addStructField("/Other/S", "tail", "uint", -1, ""));
        assertEquals(4, structure().getLength());
        assertEquals(8, program.getDataTypeManager().getDataType("/Other/S").getLength());
        assertTrue(service.getTypeSize("/Other/S", "").toJson().contains("\"size\":8"));
    }

    @Test public void unresolvedPointerTargetsDoNotSilentlyBecomeVoidPointers() {
        Response response = service.createStruct("S", "[{\"name\":\"value\",\"type\":\"NoSuchType *\"}]", false, "", "/Types");
        assertTrue(response.toJson(), response instanceof Response.Err);
        assertNull(structure());
    }

    @Test public void pointerAndLongSizesFollowTheTargetAbi() throws Exception {
        ProgramBuilder wide = new ProgramBuilder("wide-types", ProgramBuilder._X64, "gcc", this);
        try {
            HeadlessProgramProvider provider = new HeadlessProgramProvider();
            provider.setCurrentProgram(wide.getProgram());
            DataTypeService wideService = new DataTypeService(provider, new DirectThreadingStrategy());
            ok(wideService.createStruct("Wide", "[{\"name\":\"pointers\",\"type\":\"void *[2]\",\"size\":16},{\"name\":\"count\",\"type\":\"long\",\"size\":8}]", false, ""));
            assertEquals(24, wide.getProgram().getDataTypeManager().getDataType("/Wide").getLength());
        } finally { wide.dispose(); }
    }

    @Test public void invalidReplacementLeavesThePlaceholderIntact() {
        ok(service.createStruct("S", "[{\"name\":\"stub\",\"type\":\"uchar\"}]", false, "", "/Types"));
        assertTrue(service.createStruct("S", "[{\"name\":\"value\",\"type\":\"uint\",\"size\":1}]", true, "", "/Types") instanceof Response.Err);
        assertEquals(1, structure().getLength());
        assertTrue(service.createStruct("S", "[{\"name\":\"first\",\"type\":\"uint\",\"offset\":0},{\"name\":\"second\",\"type\":\"uint\",\"offset\":0}]", true, "", "/Types") instanceof Response.Err);
        assertEquals(1, structure().getLength());
    }
}
