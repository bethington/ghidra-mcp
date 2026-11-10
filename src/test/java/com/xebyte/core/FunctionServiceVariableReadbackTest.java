package com.xebyte.core;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighSymbol;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class FunctionServiceVariableReadbackTest {
    private HighSymbol symbol(String name) {
        HighSymbol symbol = mock(HighSymbol.class);
        when(symbol.getName()).thenReturn(name);
        return symbol;
    }

    private String verify(HighSymbol symbol, String name, DataType expected, DataType storedType) {
        return FunctionService.verifyPersistedVariableUpdate(symbol, name, expected, key -> {
            Variable stored = mock(Variable.class);
            when(stored.getName()).thenReturn(name);
            when(stored.getDataType()).thenReturn(storedType);
            return stored;
        });
    }

    @Test public void persistedAnnotationMustRecoverTheRequestedType() {
        DataType pointer = new PointerDataType(IntegerDataType.dataType);
        assertNull(verify(symbol("value"), "value", pointer, pointer));
        String error = verify(symbol("value"), "value", pointer, Undefined8DataType.dataType);
        assertNotNull(error);
        assertTrue(error.contains("Persisted DB type mismatch"));
    }

    @Test public void missingAnnotationCannotClaimSuccess() {
        DataType pointer = new PointerDataType(IntegerDataType.dataType);
        String error = FunctionService.verifyPersistedVariableUpdate(
            symbol("value"), "value", pointer, key -> null);
        assertNotNull(error);
        assertTrue(error.contains("No persisted DB variable"));
        assertNotNull(FunctionService.verifyPersistedVariableUpdate(
            null, "value", pointer, key -> null));
    }

    @Test public void persistedNameMustMatchTheRequest() {
        String error = FunctionService.verifyPersistedVariableUpdate(
            symbol("old"), "new", null, key -> {
                Variable stored = mock(Variable.class);
                when(stored.getName()).thenReturn("old");
                return stored;
            });
        assertNotNull(error);
        assertTrue(error.contains("Persisted DB name mismatch"));
    }

    @Test public void onlyOpaquePointersMayNormalizeToUndefinedPointers() {
        DataType opaque = new PointerDataType(VoidDataType.dataType, 8);
        DataType recovered = new PointerDataType(Undefined1DataType.dataType, 8);
        assertTrue(FunctionService.variableTypesMatch(opaque, recovered));
        assertFalse(FunctionService.variableTypesMatch(
            new PointerDataType(IntegerDataType.dataType, 8), recovered));
        assertFalse(FunctionService.variableTypesMatch(opaque, Undefined8DataType.dataType));
    }

    @Test public void enumAndUnderlyingByteAreNotEquivalentReadback() {
        EnumDataType direction = new EnumDataType("Direction", 1);
        direction.add("LEFT", 0);
        assertNotNull(verify(
            symbol("direction"), "direction", direction, ByteDataType.dataType));
    }

    @Test public void pseudoCodePointerCannotResolveToUnrelatedCodeEnum() {
        EnumDataType errorCode = new EnumDataType("Code", 4);
        errorCode.add("ERROR", 1);
        assertNotNull(FunctionService.validateVariableTypeRequest(
            "code *", new PointerDataType(errorCode)));
        assertNull(FunctionService.validateVariableTypeRequest(
            "Foundation/Code *", new PointerDataType(errorCode)));
        assertNull(FunctionService.validateVariableTypeRequest(
            "void *", new PointerDataType(VoidDataType.dataType)));
        assertNull(FunctionService.validateVariableTypeRequest(
            "code *", new PointerDataType(new FunctionDefinitionDataType("Callback"))));
    }
}
