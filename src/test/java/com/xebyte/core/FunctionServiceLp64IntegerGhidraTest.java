package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import org.junit.*;

import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/** Native LP64 fixture only: no server, saved project, or target execution. */
public class FunctionServiceLp64IntegerGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private Function function;
    private FunctionService service;

    @BeforeClass public static void initializeGhidra() throws Exception {
        FunctionServiceSynthesizedVariableGhidraTest.initializeGhidra();
    }

    @Before public void setUp() throws Exception {
        builder = new ProgramBuilder("lp64-integer-fixture", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        DataOrganization organization = program.getDataTypeManager().getDataOrganization();
        assertEquals("LP64 pointer width", 8, organization.getPointerSize());
        assertEquals("LP64 long width", 8, organization.getLongSize());
        assertEquals("LP64 long long width", 8, organization.getLongLongSize());
        builder.createMemory(".text", "0x1000", 0x1100);
        // Keep a source() result across a call, so the decompiler synthesizes a local.
        builder.setBytes("0x1000", "53 e8 fa 0f 00 00 48 89 c3 48 85 c0 74 08 48 89 c7 e8 fa 0f 00 00 48 89 d8 5b c3");
        builder.setBytes("0x2000", "c3");
        builder.setBytes("0x2010", "c3");
        builder.disassemble("0x2000", 1);
        builder.disassemble("0x2010", 1);
        builder.createFunction("0x2000");
        builder.createFunction("0x2010");
        builder.disassemble("0x1000", 27);
        function = builder.createFunction("0x1000");
        builder.withTransaction(() -> function.setComment("[RE] Preserve LP64 fixture plate."));
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.trackOpenProgram(program);
        service = new FunctionService(provider, new DirectThreadingStrategy());
    }

    @After public void tearDown() {
        if (builder != null) builder.dispose();
    }

    private HighFunction high() {
        var result = service.decompileFunctionNoRetry(function, program);
        assertNotNull(result);
        assertTrue(result.getErrorMessage(), result.decompileCompleted());
        return result.getHighFunction();
    }

    private HighSymbol local(HighFunction high) {
        var symbols = high.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            if (!symbol.isParameter() && !symbol.getName().startsWith("unaff_")
                    && !symbol.getName().startsWith("in_")
                    && !symbol.getName().startsWith("extraout_")) return symbol;
        }
        throw new AssertionError("No synthesized fixture local");
    }

    private DataType inProgram(DataType type) {
        return type.clone(program.getDataTypeManager());
    }

    /** Keep real storage, PC, and owning function; only model native integer decoding. */
    private HighFunction canonicalView(HighSymbol realSymbol, DataType canonical) {
        HighSymbol decoded = spy(realSymbol);
        doReturn(canonical).when(decoded).getDataType();
        HighFunction view = mock(HighFunction.class);
        LocalSymbolMap locals = mock(LocalSymbolMap.class);
        when(view.getLocalSymbolMap()).thenReturn(locals);
        when(locals.getSymbols()).thenAnswer(i -> List.of(decoded).iterator());
        return view;
    }

    private HighSymbol write(String spelling) {
        HighSymbol before = local(high());
        Response response = service.setLocalVariableType(
            function, before.getName(), spelling, program);
        assertTrue(response.toJson(), response instanceof Response.Ok);
        HighSymbol fresh = service.findSymbolByName(high(), before.getName());
        assertNotNull(fresh);
        assertNotNull("annotation must attach by storage and first-use PC",
            HighFunctionDBUtil.getFunctionVariable(fresh));
        assertEquals("[RE] Preserve LP64 fixture plate.", function.getComment());
        return fresh;
    }

    @Test public void cSpellingChoosesBuiltinInsteadOfImportedTypedef() {
        DataTypeManager dtm = program.getDataTypeManager();
        int tx = program.startTransaction("Imported typedef fixture");
        try {
            dtm.addDataType(new TypedefDataType(new CategoryPath("/Imported"),
                "unsigned long long", UnsignedLongLongDataType.dataType, dtm),
                DataTypeConflictHandler.DEFAULT_HANDLER);
        } finally { program.endTransaction(tx, true); }
        DataType plain = ServiceUtils.resolveDataType(dtm, "unsigned long long");
        assertTrue(plain.getPathName(), plain instanceof UnsignedLongLongDataType);
        assertEquals(CategoryPath.ROOT, plain.getCategoryPath());
        DataType qualified = ServiceUtils.resolveDataType(dtm, "Imported/unsigned long long");
        assertTrue(qualified.getPathName(), qualified instanceof TypeDef);
        assertEquals("/Imported/unsigned long long", qualified.getPathName());
    }

    @Test public void nativeSignedIntegerWriteHasAttachedExactDbType() {
        HighSymbol fresh = write("long long");
        DataType expected = inProgram(LongLongDataType.dataType);
        assertTrue(expected.isEquivalent(HighFunctionDBUtil.getFunctionVariable(fresh).getDataType()));
        assertNull(FunctionService.verifyVariableUpdate(high(), fresh.getName(), expected));
    }

    @Test public void nativeUnsignedIntegerWriteHasAttachedExactDbType() {
        HighSymbol fresh = write("unsigned long long");
        DataType expected = inProgram(UnsignedLongLongDataType.dataType);
        assertTrue(expected.isEquivalent(HighFunctionDBUtil.getFunctionVariable(fresh).getDataType()));
        assertNull(FunctionService.verifyVariableUpdate(high(), fresh.getName(), expected));
    }

    @Test public void signedCanonicalViewRequiresRealAttachedLongLongAnnotation() {
        HighSymbol fresh = write("long long");
        DataType expected = inProgram(LongLongDataType.dataType);
        DataType canonical = AbstractIntegerDataType.getSignedDataType(8, program.getDataTypeManager());
        assertTrue(canonical.getPathName(), canonical instanceof LongDataType);
        assertFalse("fixture must exercise normalization", expected.isEquivalent(canonical));
        assertNull(FunctionService.verifyVariableUpdate(
            canonicalView(fresh, canonical), fresh.getName(), expected));
    }

    @Test public void unsignedCanonicalViewRequiresRealAttachedLongLongAnnotation() {
        HighSymbol fresh = write("unsigned long long");
        DataType expected = inProgram(UnsignedLongLongDataType.dataType);
        DataType canonical = AbstractIntegerDataType.getUnsignedDataType(8, program.getDataTypeManager());
        assertTrue(canonical.getPathName(), canonical instanceof UnsignedLongDataType);
        assertFalse(expected.isEquivalent(canonical));
        assertNull(FunctionService.verifyVariableUpdate(
            canonicalView(fresh, canonical), fresh.getName(), expected));
    }

    @Test public void matchingInferredIntegerWithoutDbAttachmentCannotSucceed() {
        HighSymbol inferred = local(high());
        assertEquals(0, function.getLocalVariables().length);
        assertNull(HighFunctionDBUtil.getFunctionVariable(inferred));
        DataType expected = inProgram(LongLongDataType.dataType);
        String error = FunctionService.verifyVariableUpdate(
            canonicalView(inferred, inProgram(LongDataType.dataType)), inferred.getName(), expected);
        assertNotNull(error);
        assertTrue(error, error.contains("No persisted DB variable"));
    }

    @Test public void staleUndefinedDbAnnotationCannotBorrowInferredIntegerType() throws Exception {
        HighSymbol fresh = write("long long");
        Variable stored = HighFunctionDBUtil.getFunctionVariable(fresh);
        int tx = program.startTransaction("Stale DB regression fixture");
        try { stored.setDataType(Undefined8DataType.dataType, SourceType.USER_DEFINED); }
        finally { program.endTransaction(tx, true); }
        String error = FunctionService.verifyVariableUpdate(
            canonicalView(fresh, inProgram(LongDataType.dataType)), fresh.getName(),
            inProgram(LongLongDataType.dataType));
        assertNotNull(error);
        assertTrue(error, error.contains("Persisted DB type mismatch"));
    }

    @Test public void integerNormalizationPreservesAliasEnumPointerWidthAndSignedness() {
        DataType signed = inProgram(LongLongDataType.dataType);
        DataType unsigned = inProgram(UnsignedLongLongDataType.dataType);
        DataType alias = new TypedefDataType(new CategoryPath("/Imported"),
            "unsigned long long", unsigned, program.getDataTypeManager());
        EnumDataType enumeration = new EnumDataType("Flags", 8);
        enumeration.add("ONE", 1);
        for (DataType other : List.of(unsigned, inProgram(IntegerDataType.dataType), alias,
                enumeration, new PointerDataType(IntegerDataType.dataType, 8))) {
            assertFalse(other.getPathName(), FunctionService.canonicalLp64IntegerTypesMatch(signed, other));
            assertFalse(other.getPathName(), FunctionService.canonicalLp64IntegerTypesMatch(other, signed));
        }
        assertFalse(FunctionService.canonicalLp64IntegerTypesMatch(alias,
            inProgram(UnsignedLongDataType.dataType)));
        assertFalse(FunctionService.canonicalLp64IntegerTypesMatch(unsigned, alias));
        // Non-LP64 long stays strict even when long long has eight bytes.
        assertEquals(4, LongDataType.dataType.getLength());
        assertFalse(FunctionService.canonicalLp64IntegerTypesMatch(signed, LongDataType.dataType));
    }

    @Test public void canonicalViewCannotHideWrongSignednessInAttachedDbAnnotation() {
        HighSymbol fresh = write("unsigned long long");
        String error = FunctionService.verifyVariableUpdate(
            canonicalView(fresh, inProgram(LongDataType.dataType)), fresh.getName(),
            inProgram(LongLongDataType.dataType));
        assertNotNull(error);
        assertTrue(error, error.contains("Persisted DB type mismatch"));
    }

    @Test public void attachedIntegerDoesNotPermitFreshAliasEnumPointerOrDifferentWidth() {
        HighSymbol fresh = write("unsigned long long");
        DataType expected = inProgram(UnsignedLongLongDataType.dataType);
        EnumDataType enumeration = new EnumDataType("Flags", 8);
        enumeration.add("ONE", 1);
        DataType imported = new TypedefDataType(new CategoryPath("/Imported"),
            "ImportedInteger", expected, program.getDataTypeManager());
        for (DataType other : List.of(imported, enumeration,
                new PointerDataType(IntegerDataType.dataType, 8),
                inProgram(UnsignedIntegerDataType.dataType), inProgram(LongDataType.dataType))) {
            String error = FunctionService.verifyVariableUpdate(
                canonicalView(fresh, other), fresh.getName(), expected);
            assertNotNull(other.getPathName(), error);
            assertTrue(error, error.contains("did not survive fresh decompilation"));
        }
    }
}
