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

    @Test public void structDescriptionsCanBeSetReplacedAndClearedWithoutChangingLayout() {
        ok(service.createStruct("S", "[{\"name\":\"value\",\"type\":\"uint\",\"comment\":\"field documentation\"}]", false, program, "/Types"));
        Structure original = structure();
        String fieldName = original.getComponent(0).getFieldName();
        String description = "Object metadata\nContains \"quoted\" text and Unicode: café";
        ok(service.setStructDescription("S", description, program));
        assertEquals(description, original.getDescription());
        com.google.gson.JsonObject layout = com.google.gson.JsonParser.parseString(
            service.getStructLayout("/Types/S", program).toJson()).getAsJsonObject();
        assertEquals(description, layout.get("description").getAsString());
        ok(service.setStructDescription("/Types/S", "Replacement", program));
        assertEquals("Replacement", original.getDescription());
        ok(service.setStructDescription("S", "", program));
        assertEquals("", original.getDescription());
        assertSame(original, structure());
        assertEquals(4, original.getLength());
        assertEquals(fieldName, original.getComponent(0).getFieldName());
        assertEquals("field documentation", original.getComponent(0).getComment());
    }

    @Test public void structDescriptionsRejectMissingInputsAndNonStructures() {
        ok(service.createStruct("S", "[{\"name\":\"value\",\"type\":\"uint\"}]", false, program, "/Types"));
        ok(service.setStructDescription("S", "Keep me", program));
        assertTrue(service.setStructDescription("S", null, program) instanceof Response.Err);
        assertTrue(service.setStructDescription(null, "text", program) instanceof Response.Err);
        assertTrue(service.setStructDescription(" ", "text", program) instanceof Response.Err);
        assertTrue(service.setStructDescription("Missing", "text", program) instanceof Response.Err);
        ok(service.createEnum("Mode", "[{\"name\":\"A\",\"value\":1}]", 4, program, "/Types"));
        assertTrue(service.setStructDescription("/Types/Mode", "text", program) instanceof Response.Err);
        assertEquals("Keep me", structure().getDescription());
    }

    @Test public void structDescriptionEndpointAcceptsEmptyBodyTextAndQualifiedNames() throws Exception {
        String fields = "[{\"name\":\"value\",\"type\":\"uint\"}]";
        ok(service.createStruct("S", fields, false, program, "/Types"));
        ok(service.createStruct("S", fields, false, program, "/Other"));
        EndpointDef endpoint = new AnnotationScanner(scannerProvider, new CommentService(scannerProvider, new DirectThreadingStrategy())).getEndpoints().stream()
            .filter(e -> e.path().equals("/set_comment")).findFirst().orElseThrow();
        ok(endpoint.handler().handle(java.util.Map.of(), java.util.Map.of("type", "struct", "struct_name", "/Other/S", "comment", "Other description")));
        assertEquals("Other description", program.getDataTypeManager().getDataType("/Other/S").getDescription());
        assertEquals("", structure().getDescription());
        ok(endpoint.handler().handle(java.util.Map.of(), java.util.Map.of("type", "struct", "struct_name", "/Other/S", "comment", "")));
        assertEquals("", program.getDataTypeManager().getDataType("/Other/S").getDescription());
        assertTrue(endpoint.handler().handle(java.util.Map.of(), java.util.Map.of("type", "struct", "struct_name", "/Other/S")) instanceof Response.Err);
        assertTrue(endpoint.handler().handle(java.util.Map.of(), java.util.Map.of("type", "struct", "comment", "text")) instanceof Response.Err);
    }

    @Test public void typedefReplacementAndReferencedDeletionRequireConsent() throws Exception {
        ok(service.createDerivedType("typedef", "int *", "Alias", 1, program));
        ok(service.createDerivedType("typedef", "int *", "Alias", 1, program));
        ok(service.createDerivedType("typedef", "char *", "Alias", 1, program));
        TypeDef alias = (TypeDef) program.getDataTypeManager().getDataType("/Alias");
        assertEquals("char *", alias.getBaseDataType().getName());
        ok(service.createStruct("S", "[{\"name\":\"x\",\"type\":\"int\"}]", false, program, "/Types"));
        builder.withTransaction(() -> {
            StructureDataType parent = new StructureDataType("Parent", 0);
            parent.add(new PointerDataType(structure()), "child", null);
            program.getDataTypeManager().addDataType(parent, null);
            try { program.getListing().createData(builder.addr("0x1000"), structure()); }
            catch (Exception e) { throw new RuntimeException(e); }
        });
        Response blocked = service.deleteDataType("S", false, program, false);
        assertTrue(blocked.toJson(), blocked instanceof Response.Err);
        assertTrue(blocked.toJson().contains("Parent"));
        assertNotNull(structure());
        ok(service.deleteDataType("S", false, program, true));
    }

    @Test public void enumArrayInputUnionDetailsAndKindSearch() {
        ok(service.createEnum("Mode", "[{\"name\":\"MODE_A\",\"value\":1}]", 4, program, "/Types"));
        ok(service.createUnion("U", "[{\"name\":\"bytes\",\"type\":\"uchar[4]\"},{\"name\":\"number\",\"type\":\"uint\"}]", program, "/Types"));
        String details = service.getTypeSize("U", program).toJson();
        assertTrue(details, details.contains("\"fields\""));
        assertTrue(details, details.contains("\"size\":4"));
        String search = service.findDataTypes("", "", "union", false, 0, 100, program).toJson();
        assertTrue(search, search.contains("/Types/U"));
        assertFalse(search, search.contains("/Types/Mode"));
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

    @Test public void deletingAnAppliedTypedefRequiresForceAndPreservesDataOnRejection() throws Exception {
        ok(service.createDerivedType("typedef", "uint", "Alias", 1, program));
        DataType alias = program.getDataTypeManager().getDataType("/Alias");
        builder.withTransaction(() -> {
            try { program.getListing().createData(builder.addr("0x1000"), new ArrayDataType(alias, 2, alias.getLength())); }
            catch (Exception e) { throw new RuntimeException(e); }
        });
        Response response = service.deleteDataType("Alias", false, program, false);
        assertTrue(response.toJson(), response instanceof Response.Err);
        assertNotNull(program.getListing().getDefinedDataAt(builder.addr("0x1000")));
        assertSame(alias, program.getDataTypeManager().getDataType("/Alias"));
        ok(service.deleteDataType("Alias", false, program, true));
        assertNull(program.getListing().getDefinedDataAt(builder.addr("0x1000")));
    }

    @Test public void deletingFunctionReturnAndParameterTypesRequiresForce() throws Exception {
        ok(service.createStruct("S", "[{\"name\":\"value\",\"type\":\"uint\"}]", false, program, "/Types"));
        builder.setBytes("0x1080", "c3");
        builder.disassemble("0x1080", 1);
        builder.createFunction("0x1080");
        Function function = program.getFunctionManager().getFunctionAt(builder.addr("0x1080"));
        builder.withTransaction(() -> {
            try { function.setReturnType(structure(), SourceType.USER_DEFINED); }
            catch (Exception e) { throw new RuntimeException(e); }
        });
        assertTrue(service.deleteDataType("S", false, program, false) instanceof Response.Err);
        assertEquals(structure(), function.getReturnType());
        builder.withTransaction(() -> {
            try {
                function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                function.addParameter(new ParameterImpl("value", new PointerDataType(structure(), program.getDataTypeManager()), program), SourceType.USER_DEFINED);
            } catch (Exception e) { throw new RuntimeException(e); }
        });
        assertTrue(service.deleteDataType("S", false, program, false) instanceof Response.Err);
        assertNotNull(structure());
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
