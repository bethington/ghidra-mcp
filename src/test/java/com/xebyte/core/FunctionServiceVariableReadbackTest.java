package com.xebyte.core;

import ghidra.program.model.data.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class FunctionServiceVariableReadbackTest {
    private HighFunction view(String name, DataType type) {
        HighFunction high = mock(HighFunction.class);
        LocalSymbolMap locals = mock(LocalSymbolMap.class);
        HighSymbol symbol = mock(HighSymbol.class);
        when(high.getLocalSymbolMap()).thenReturn(locals);
        when(locals.getSymbols()).thenAnswer(i -> List.of(symbol).iterator());
        when(symbol.getName()).thenReturn(name);
        when(symbol.getDataType()).thenReturn(type);
        return high;
    }

    private String verify(HighFunction fresh, String name, DataType expected) {
        return FunctionService.verifyVariableUpdate(fresh, name, expected, symbol -> {
            var stored = mock(ghidra.program.model.listing.Variable.class);
            when(stored.getDataType()).thenReturn(expected);
            return stored;
        });
    }

    @Test public void freshViewMustRecoverTheRequestedType() {
        DataType pointer = new PointerDataType(IntegerDataType.dataType);
        assertNull(verify(view("value", pointer), "value", pointer));
        String error = verify(
            view("value", Undefined8DataType.dataType), "value", pointer);
        assertNotNull(error);
        assertTrue(error.contains("did not survive fresh decompilation"));
    }

    @Test public void onlyOpaquePointersMayNormalizeToUndefinedPointers() {
        DataType opaque = new PointerDataType(VoidDataType.dataType, 8);
        DataType recovered = new PointerDataType(Undefined1DataType.dataType, 8);
        assertTrue(FunctionService.variableTypesMatch(opaque, recovered));
        assertFalse(FunctionService.variableTypesMatch(
            new PointerDataType(IntegerDataType.dataType, 8), recovered));
        assertFalse(FunctionService.variableTypesMatch(opaque, Undefined8DataType.dataType));
    }

    @Test public void missingOrSplitSsaNameCannotClaimSuccess() {
        assertNotNull(verify(
            view("new_split", ByteDataType.dataType), "old", ByteDataType.dataType));
        assertNotNull(verify(null, "old", null));
    }

    @Test public void enumAndUnderlyingByteAreNotEquivalentReadback() {
        EnumDataType direction = new EnumDataType("Direction", 1);
        direction.add("LEFT", 0);
        assertNotNull(verify(
            view("direction", ByteDataType.dataType), "direction", direction));
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
