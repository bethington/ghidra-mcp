package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import org.junit.*;
import java.io.File;
import static org.junit.Assume.assumeTrue;
import static org.junit.Assert.*;

public class DataTypeEditingGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private DataTypeService service;
    private HeadlessProgramProvider scannerProvider;
    @BeforeClass public static void initialize() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests", installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)), configuration);
        }
    }
    @Before public void setUp() throws Exception {
        builder = new ProgramBuilder("type-editing", ProgramBuilder._X86, "windows", this);
        program = builder.getProgram();
        builder.createMemory(".data", "0x1000", 256);
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        provider.trackOpenProgram(program);
        service = new DataTypeService(provider, new DirectThreadingStrategy());
        scannerProvider = provider;
    }
    @After public void tearDown() { builder.dispose(); }
    private static void ok(Response response) { assertTrue(response.toJson(), response instanceof Response.Ok); }
    private Structure structure() { return (Structure) program.getDataTypeManager().getDataType("/Types/S"); }

    @Test public void categoryCommentsArraySizesAndAtomicFieldAdditions() {
        ok(service.createStruct("S", "[{\"name\":\"bytes\",\"type\":\"uchar[4]\",\"comment\":\"a,b:c\"}]", false, program, "/Types"));
        Structure struct = structure();
        assertEquals(4, struct.getLength());
        assertEquals("a,b:c", struct.getComponent(0).getComment());
        String fields = "[{\"name\":\"next\",\"type\":\"uint\",\"offset\":\"0x8\"},{\"name\":\"bad\",\"type\":\"unknown_type\"}]";
        assertTrue(service.addStructField("S", "", "", -1, program, fields, false) instanceof Response.Err);
        assertEquals(4, structure().getLength());
        ok(service.addStructField("S", "", "", -1, program, "[{\"name\":\"next\",\"type\":\"uint\",\"offset\":\"0x8\"}]", false));
        assertEquals(12, structure().getLength());
        assertTrue(service.addStructField("S", "", "", -1, program, "[{\"name\":\"conflict\",\"type\":\"uint\",\"offset\":0}]", false) instanceof Response.Err);
        ok(service.addStructField("S", "", "", -1, program, "[{\"name\":\"padding\",\"type\":\"uint\",\"offset\":4}]", false));
        ok(service.removeStructField("S", "0x4", program, false));
        assertEquals(12, structure().getLength());
        assertEquals(8, structure().getComponentAt(8).getOffset());
        ok(service.removeStructField("S", "0x0", program, true));
        assertEquals(8, structure().getLength());
        assertTrue(service.createStruct("Bad", "[{\"name\":\"x\",\"type\":\"uchar\",\"size\":4}]", false, program, "") instanceof Response.Err);
    }

    @Test public void functionDefinitionsKeepNamedParametersConventionAndIdentity() {
        ok(service.createFunctionSignature("Callback", "int", "[{\"name\":\"self\",\"type\":\"void *\"},{\"name\":\"count\",\"type\":\"int\"}]", program, "stdcall", "/Types"));
        FunctionDefinition original = (FunctionDefinition) program.getDataTypeManager().getDataType("/Types/Callback");
        assertEquals("self", original.getArguments()[0].getName());
        assertEquals("__stdcall", original.getCallingConventionName());
        ok(service.createFunctionSignature("Callback", "void", "[]", program, "cdecl", "/Types"));
        assertSame(original, program.getDataTypeManager().getDataType("/Types/Callback"));
        assertEquals(0, original.getArguments().length);
        assertTrue(service.createFunctionSignature("Callback", "int", "[{\"type\":\"nonexistent\"}]", program, "", "/Types") instanceof Response.Err);
        assertEquals("void", ((FunctionDefinition) program.getDataTypeManager().getDataType("/Types/Callback")).getReturnType().getName());
    }

    @Test public void namedUndefinedPaddingCanBeCarvedAndTailFieldsCanGrow() {
        ok(service.createStruct("S", "[{\"name\":\"padding\",\"type\":\"undefined[16]\"}]", false, program, "/Types"));
        ok(service.addStructField("S", "", "", -1, program, "[{\"name\":\"inside\",\"type\":\"uint\",\"offset\":4}]", false));
        assertEquals(16, structure().getLength());
        assertEquals("uint", structure().getComponentAt(4).getDataType().getName());
        ok(service.addStructField("S", "", "", -1, program, "[{\"name\":\"tail\",\"type\":\"uchar\",\"offset\":16}]", false));
        ok(service.modifyStructField("S", "0x10", "uchar[4]", "", program));
        assertEquals(20, structure().getLength());
        assertEquals(4, structure().getComponentAt(16).getLength());
        DataType matrix = ServiceUtils.resolveDataType(program.getDataTypeManager(), "int[2][3]");
        assertEquals(24, matrix.getLength());
        assertEquals(2, ((Array) matrix).getNumElements());
        assertEquals(3, ((Array) ((Array) matrix).getDataType()).getNumElements());
    }

    @Test public void insertionCarvesAllPaddingAndOverwriteClearsIntersectingFields() {
        ok(service.createStruct("S", "[{\"name\":\"first\",\"type\":\"undefined[4]\"},{\"name\":\"second\",\"type\":\"undefined[4]\"},{\"name\":\"tail\",\"type\":\"uint\"}]", false, program, "/Types"));
        ok(service.addStructField("S", "wide", "uchar[6]", 1, program, "[]", false));
        assertEquals(12, structure().getLength());
        assertEquals(6, structure().getComponentAt(1).getLength());
        assertEquals("uint", structure().getComponentAt(8).getDataType().getName());
        assertTrue(service.addStructField("S", "replacement", "uchar[12]", 0, program, "[]", false) instanceof Response.Err);
        ok(service.addStructField("S", "replacement", "uchar[12]", 0, program, "[]", true));
        assertEquals(1, structure().getNumDefinedComponents());
        assertEquals(12, structure().getLength());
    }

    @Test public void growingAFieldConsumesNamedPaddingWithoutMovingItsNeighbour() {
        ok(service.createStruct("S", "[{\"name\":\"first\",\"type\":\"uint\"},{\"name\":\"padding\",\"type\":\"undefined[4]\"},{\"name\":\"tail\",\"type\":\"uint\"}]", false, program, "/Types"));
        ok(service.modifyStructField("S", "0x0", "uchar[8]", "", program));
        assertEquals(12, structure().getLength());
        assertEquals(8, structure().getComponentAt(0).getLength());
        assertEquals("uint", structure().getComponentAt(8).getDataType().getName());
    }

    @Test public void explicitCategoriesScopeCreationAndQualifiedLookup() {
        String fields = "[{\"name\":\"value\",\"type\":\"uint\"}]";
        ok(service.createStruct("S", fields, false, program, "/Types"));
        ok(service.createStruct("S", fields, false, program, "/Other"));
        ok(service.addStructField("/Other/S", "tail", "uint", -1, program, "[]", false));
        assertEquals(4, structure().getLength());
        assertEquals(8, program.getDataTypeManager().getDataType("/Other/S").getLength());
        assertTrue(service.getTypeSize("/Other/S", program).toJson().contains("\"size\":8"));
    }

    @Test public void unresolvedPointerTargetsDoNotSilentlyBecomeVoidPointers() {
        Response response = service.createStruct("S", "[{\"name\":\"value\",\"type\":\"NoSuchType *\"}]", false, program, "/Types");
        assertTrue(response.toJson(), response instanceof Response.Err);
        assertNull(structure());
    }

    @Test public void decodedHttpNumbersKeepIntegralOffsetsAndSizes() throws Exception {
        EndpointDef endpoint = new AnnotationScanner(scannerProvider, service).getEndpoints().stream()
            .filter(e -> e.path().equals("/create_struct")).findFirst().orElseThrow();
        String body = "{\"name\":\"S\",\"category_path\":\"/Types\",\"fields\":[{\"name\":\"value\",\"type\":\"uint\",\"offset\":4,\"size\":4}]}";
        ok(endpoint.handler().handle(java.util.Map.of(), JsonHelper.parseBody(new java.io.ByteArrayInputStream(body.getBytes(java.nio.charset.StandardCharsets.UTF_8)))));
        assertEquals(8, structure().getLength());
        assertEquals(4, structure().getComponentAt(4).getLength());
        assertTrue(service.addStructField("S", "", "", -1, program, "[{\"name\":\"bad\",\"type\":\"uint\",\"offset\":8.5}]", false) instanceof Response.Err);
        assertEquals(8, structure().getLength());
    }

    @Test public void pointerAndLongSizesFollowTheTargetAbi() throws Exception {
        ProgramBuilder wide = new ProgramBuilder("wide-types", ProgramBuilder._X64, "gcc", this);
        try {
            HeadlessProgramProvider provider = new HeadlessProgramProvider();
            provider.setCurrentProgram(wide.getProgram());
            DataTypeService wideService = new DataTypeService(provider, new DirectThreadingStrategy());
            ok(wideService.createStruct("Wide", "[{\"name\":\"pointers\",\"type\":\"void *[2]\",\"size\":16},{\"name\":\"count\",\"type\":\"long\",\"size\":8}]", false, wide.getProgram(), ""));
            assertEquals(24, wide.getProgram().getDataTypeManager().getDataType("/Wide").getLength());
        } finally { wide.dispose(); }
    }

    @Test public void invalidReplacementLeavesThePlaceholderIntact() {
        ok(service.createStruct("S", "[{\"name\":\"stub\",\"type\":\"uchar\"}]", false, program, "/Types"));
        assertTrue(service.createStruct("S", "[{\"name\":\"value\",\"type\":\"uint\",\"size\":1}]", true, program, "/Types") instanceof Response.Err);
        assertEquals(1, structure().getLength());
        assertTrue(service.createStruct("S", "[{\"name\":\"first\",\"type\":\"uint\",\"offset\":0},{\"name\":\"second\",\"type\":\"uint\",\"offset\":0}]", true, program, "/Types") instanceof Response.Err);
        assertEquals(1, structure().getLength());
    }
}
