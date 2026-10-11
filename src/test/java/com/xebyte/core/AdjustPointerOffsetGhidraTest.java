package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.PointerTypedefInspector;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import org.junit.*;

import static org.junit.Assert.*;

public class AdjustPointerOffsetGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private FunctionService service;
    private Function function;

    @BeforeClass public static void initialize() throws Exception { OverrideServiceGhidraTest.initialize(); }

    @Before public void setUp() throws Exception {
        builder = new ProgramBuilder("pointer-adjustor", ProgramBuilder._X86, "windows", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 256);
        builder.setBytes("0x1000", "83 e9 24 8b 01 c3");
        builder.disassemble("0x1000", 6);
        builder.createFunction("0x1000");
        function = program.getFunctionManager().getFunctionAt(builder.addr("0x1000"));
        new DirectThreadingStrategy().executeWrite(program, "Set up adjustor", () -> {
            StructureDataType parent = new StructureDataType(new CategoryPath("/Classes"), "UnifiedDevice", 40);
            parent.replaceAtOffset(0, UnsignedIntegerDataType.dataType, 4, "value", null);
            parent.replaceAtOffset(36, UnsignedIntegerDataType.dataType, 4, "secondary", null);
            program.getDataTypeManager().resolve(parent, null);
            function.getSymbol().setNamespace(program.getSymbolTable().createClass(
                program.getGlobalNamespace(), "UnifiedDevice", SourceType.USER_DEFINED));
            function.setName("scalar_deleting_destructor_adjustor_36", SourceType.USER_DEFINED);
            function.setCallingConvention("__thiscall");
            function.setReturnType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
            return null;
        });
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        provider.trackOpenProgram(program);
        service = new FunctionService(provider, new DirectThreadingStrategy());
    }

    @After public void tearDown() { builder.dispose(); }

    private static void ok(Response response) { assertTrue(response.toJson(), response instanceof Response.Ok); }

    @Test public void implicitThisProducesAdjAndKeepsStorage() {
        Parameter before = FunctionService.findAutoThisParameter(function);
        assertTrue(before.isAutoParameter());
        VariableStorage storage = before.getVariableStorage();
        ok(service.adjustPointerOffset("0x1000", "this", "/Classes/UnifiedDevice", "0x24", "AdjustedThis", program));
        Parameter after = FunctionService.findAutoThisParameter(function);
        assertEquals(0, storage.compareTo(after.getVariableStorage()));
        assertTrue(function.hasCustomVariableStorage());
        assertFalse(after.isAutoParameter());
        TypeDef shifted = (TypeDef) after.getDataType();
        assertEquals(36, PointerTypedefInspector.getPointerComponentOffset(shifted));
        assertEquals(4, shifted.getLength());
        String code = service.decompileFunction(function, program).getDecompiledFunction().getC();
        assertTrue(code, code.contains("ADJ(this)"));
        Response retry = service.adjustPointerOffset("0x1000", "this", "/Classes/UnifiedDevice", "36", "AdjustedThis", program);
        ok(retry);
        assertTrue(retry.toJson(), retry.toJson().contains("\"custom_storage_enabled\":false"));
    }

    @Test public void conflictingTypedefIsNotOverwrittenAndNegativeAndZeroOffsetsPersist() {
        ok(service.adjustPointerOffset("0x1000", "this", "/Classes/UnifiedDevice", "36", "Shared", program));
        assertTrue(service.adjustPointerOffset("0x1000", "this", "/Classes/UnifiedDevice", "-0x24", "Shared", program) instanceof Response.Err);
        assertEquals(36, PointerTypedefInspector.getPointerComponentOffset((TypeDef) function.getParameter(0).getDataType()));
        ok(service.adjustPointerOffset("0x1000", "this", "/Classes/UnifiedDevice", "-0x24", "Negative", program));
        assertEquals(-36, PointerTypedefInspector.getPointerComponentOffset((TypeDef) function.getParameter(0).getDataType()));
        ok(service.adjustPointerOffset("0x1000", "this", "/Classes/UnifiedDevice", "0", "Unshifted", program));
        assertEquals(0, PointerTypedefInspector.getPointerComponentOffset((TypeDef) function.getParameter(0).getDataType()));
    }

    @Test public void invalidRequestsDoNotCreateTypesOrEnableCustomStorage() {
        assertTrue(service.adjustPointerOffset("0x1000", "this", "Missing", "36", "Bad", program) instanceof Response.Err);
        assertTrue(service.adjustPointerOffset("0x1000", "this", "UnifiedDevice *", "36", "Bad", program) instanceof Response.Err);
        assertTrue(service.adjustPointerOffset("0x1000", "missing", "UnifiedDevice", "36", "Bad", program) instanceof Response.Err);
        assertTrue(service.adjustPointerOffset("0x1000", "this", "UnifiedDevice", "2147483648", "Bad", program) instanceof Response.Err);
        assertTrue(service.adjustPointerOffset("0x1000", "this", "UnifiedDevice", "junk", "Bad", program) instanceof Response.Err);
        assertFalse(function.hasCustomVariableStorage());
        assertNull(program.getDataTypeManager().getDataType("/Classes/Bad"));
    }

    @Test public void explicitParameterNeedsNoCustomStorageAndDefaultNameIsReusable() throws Exception {
        new DirectThreadingStrategy().executeWrite(program, "Set up explicit pointer", () -> {
            function.setCallingConvention("__cdecl");
            function.addParameter(new ParameterImpl("self", new PointerDataType(
                program.getDataTypeManager().getDataType("/Classes/UnifiedDevice")), program), SourceType.USER_DEFINED);
            return null;
        });
        builder.withTransaction(() -> program.getListing().clearCodeUnits(builder.addr("0x1000"), builder.addr("0x1009"), false));
        builder.setBytes("0x1000", "8b 44 24 04 83 e8 24 8b 00 c3");
        builder.disassemble("0x1000", 10);
        ok(service.adjustPointerOffset("0x1000", "self", "UnifiedDevice", "36", "", program));
        assertFalse(function.hasCustomVariableStorage());
        assertEquals("UnifiedDevice_ptr_36_4", function.getParameter(0).getDataType().getName());
        String code = service.decompileFunction(function, program).getDecompiledFunction().getC();
        assertTrue(code, code.contains("ADJ(self)"));
        ok(service.adjustPointerOffset("0x1000", "self", "UnifiedDevice", "36", "", program));
    }

    @Test public void stackLocalUsesDecompilerRetypingAndNonPointersAreRejected() throws Exception {
        builder.setBytes("0x1040", "8b 44 24 fc 83 e8 24 8b 00 c3");
        builder.disassemble("0x1040", 10);
        builder.createFunction("0x1040");
        Function localFunction = program.getFunctionManager().getFunctionAt(builder.addr("0x1040"));
        new DirectThreadingStrategy().executeWrite(program, "Set up local pointer", () -> {
            localFunction.setCallingConvention("__cdecl");
            localFunction.addLocalVariable(new LocalVariableImpl("objectPart", new PointerDataType(
                program.getDataTypeManager().getDataType("/Classes/UnifiedDevice")), -4, program), SourceType.USER_DEFINED);
            return null;
        });
        ok(service.adjustPointerOffset("0x1040", "objectPart", "UnifiedDevice", "36", "LocalShift", program));
        String code = service.decompileFunction(localFunction, program).getDecompiledFunction().getC();
        assertTrue(code, code.contains("ADJ(objectPart)"));
        assertFalse(localFunction.hasCustomVariableStorage());
        ok(service.setLocalVariableType(localFunction, "objectPart", "uint", program));
        assertTrue(service.adjustPointerOffset("0x1040", "objectPart", "UnifiedDevice", "36", "NotPointer", program) instanceof Response.Err);
        assertNull(program.getDataTypeManager().getDataType("/Classes/NotPointer"));
    }
}
