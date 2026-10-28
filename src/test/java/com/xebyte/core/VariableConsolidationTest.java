package com.xebyte.core;

import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SourceType;
import org.junit.Test;
import java.util.Set;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.app.decompiler.DecompileResults;
import java.util.concurrent.Callable;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

/** Behavioral coverage for the variable consolidation in #620. */
public class VariableConsolidationTest {
    private final Program program = mock(Program.class);
    private final Function function = mock(Function.class);
    private final StackFrame frame = mock(StackFrame.class);
    private final ThreadingStrategy threading = new ThreadingStrategy() {
        public <T> T executeRead(Callable<T> action) throws Exception { return action.call(); }
        public <T> T executeWrite(Program p, String name, Callable<T> action) throws Exception { return action.call(); }
    };
    private final FunctionService service = new FunctionService(mock(ProgramProvider.class), threading);

    private void setup() {
        when(function.getStackFrame()).thenReturn(frame);
        when(function.getLocalVariables()).thenReturn(new Variable[0]);
        when(function.getParameters()).thenReturn(new Parameter[0]);
        when(function.getAllVariables()).thenReturn(new Variable[0]);
        when(program.getDataTypeManager()).thenReturn(mock(ghidra.program.model.data.ProgramBasedDataTypeManager.class));
    }

    @Test public void symbolFieldRequiresDecompile() {
        assertTrue(FunctionBundleService.requiresTargetDecompile(Set.of("decompiler_symbols")));
        assertTrue(FunctionFacts.FIELDS.contains("decompiler_symbols"));
        assertFalse(FunctionBundleService.requiresTargetDecompile(Set.of("locals", "parameters")));
    }

    @Test public void createsMissingLocalAtNegativeOffsetWithoutDecompiler() throws Exception {
        setup();
        Variable created = mock(Variable.class);
        when(frame.createVariable(eq("nCount"), eq(-8), any(DataType.class), eq(SourceType.USER_DEFINED))).thenReturn(created);
        Response result = service.setVariables(function,
            "{\"Stack[-0x8]\":{\"name\":\"nCount\",\"type\":\"int\",\"create\":true}}", program);
        verify(frame).createVariable(eq("nCount"), eq(-8), any(DataType.class), eq(SourceType.USER_DEFINED));
        assertEquals(0, ((Map<?, ?>) ((Response.Ok) result).data()).get("failed"));
    }

    @Test public void invalidReplacementNameNeverClearsExistingLocal() {
        setup();
        Variable existing = mock(Variable.class);
        when(existing.isStackVariable()).thenReturn(true);
        when(existing.getStackOffset()).thenReturn(-8);
        when(existing.getLength()).thenReturn(4);
        when(function.getLocalVariables()).thenReturn(new Variable[]{existing});
        Response result = service.setVariables(function,
            "{\"Stack[-0x8]\":{\"name\":\"bad name\",\"type\":\"int\",\"create\":true,\"replace\":true}}", program);
        verify(function, never()).removeVariable(any());
        verify(frame, never()).clearVariable(anyInt());
        assertTrue(result.toJson(), result.toJson().contains("name"));
    }

    private Variable local(int offset, int length) {
        Variable variable = mock(Variable.class);
        when(variable.isStackVariable()).thenReturn(true);
        when(variable.getStackOffset()).thenReturn(offset);
        when(variable.getLength()).thenReturn(length);
        when(variable.getName()).thenReturn("local_" + Math.abs(offset));
        when(variable.getDataType()).thenReturn(IntegerDataType.dataType);
        return variable;
    }

    @Test public void replacementClearsEveryOverlappingLocalButNotNeighbors() throws Exception {
        setup();
        Variable first = local(-16, 4), second = local(-12, 4), neighbor = local(-8, 4);
        when(function.getLocalVariables()).thenReturn(new Variable[]{first, second, neighbor});
        when(function.getAllVariables()).thenReturn(new Variable[]{first, second, neighbor});
        when(frame.createVariable(eq("nCount"), eq(-16), any(DataType.class), eq(SourceType.USER_DEFINED)))
            .thenReturn(mock(Variable.class));
        service.setVariables(function,
            "{\"Stack[-0x10]\":{\"name\":\"nCount\",\"type\":\"longlong\",\"create\":true,\"replace\":true}}", program);
        verify(function).removeVariable(first);
        verify(function).removeVariable(second);
        verify(function, never()).removeVariable(neighbor);
        verify(frame).createVariable(eq("nCount"), eq(-16), any(DataType.class), eq(SourceType.USER_DEFINED));
    }

    @Test public void replacementRefusesParameterOverlapEvenWhenStartingInEmptySlot() throws Exception {
        setup();
        Parameter parameter = mock(Parameter.class);
        when(parameter.isStackVariable()).thenReturn(true);
        when(parameter.getStackOffset()).thenReturn(4);
        when(parameter.getLength()).thenReturn(4);
        when(function.getParameters()).thenReturn(new Parameter[]{parameter});
        Response result = service.setVariables(function,
            "{\"Stack[0]\":{\"name\":\"nCount\",\"type\":\"longlong\",\"create\":true,\"replace\":true}}", program);
        verify(function, never()).removeVariable(any());
        verify(frame, never()).createVariable(anyString(), anyInt(), any(), any());
        assertTrue(result.toJson(), result.toJson().toLowerCase().contains("parameter"));
    }

    @Test public void overlapRequiresExplicitReplacement() throws Exception {
        setup();
        Variable existing = local(-4, 4);
        when(function.getLocalVariables()).thenReturn(new Variable[]{existing});
        Response result = service.setVariables(function,
            "{\"Stack[-8]\":{\"name\":\"nCount\",\"type\":\"longlong\",\"create\":true}}", program);
        verify(function, never()).removeVariable(any());
        verify(frame, never()).createVariable(anyString(), anyInt(), any(), any());
        assertTrue(result.toJson(), result.toJson().contains("replace"));
    }

    @Test public void undefinedReplacementTypeNeverRemovesLocal() throws Exception {
        setup();
        Variable existing = local(-8, 4);
        when(function.getLocalVariables()).thenReturn(new Variable[]{existing});
        Response result = service.setVariables(function,
            "{\"Stack[-8]\":{\"name\":\"nCount\",\"type\":\"undefined4\",\"create\":true,\"replace\":true}}", program);
        verify(function, never()).removeVariable(any());
        verify(frame, never()).createVariable(anyString(), anyInt(), any(), any());
        assertTrue(result.toJson(), result.toJson().contains("undefined"));
    }

    @Test public void invalidCreationIsValidatedBeforeAnyOtherCreation() throws Exception {
        setup();
        service.setVariables(function,
            "{\"Stack[-8]\":{\"name\":\"nCount\",\"type\":\"int\",\"create\":true},"
            + "\"Stack[-16]\":{\"name\":\"bad name\",\"type\":\"int\",\"create\":true}}", program);
        verify(frame, never()).createVariable(anyString(), anyInt(), any(), any());
    }

    @Test public void creationReportsHungarianWarning() throws Exception {
        setup();
        when(frame.createVariable(anyString(), anyInt(), any(), any())).thenReturn(mock(Variable.class));
        Response result = service.setVariables(function,
            "{\"Stack[-8]\":{\"name\":\"pCount\",\"type\":\"int\",\"create\":true}}", program);
        verify(frame).createVariable(eq("pCount"), eq(-8), any(), any());
        assertTrue(result.toJson(), result.toJson().contains("pointer prefix"));
    }

    @Test public void createFlagMustBeBoolean() throws Exception {
        setup();
        Response result = service.setVariables(function,
            "{\"Stack[-8]\":{\"name\":\"nCount\",\"type\":\"int\",\"create\":\"true\"}}", program);
        verify(frame, never()).createVariable(anyString(), anyInt(), any(), any());
        assertTrue(result.toJson(), result.toJson().contains("boolean"));
    }

    @Test public void symbolFieldReturnsStorageAndOnlyDecompilesOnce() {
        setup();
        Address entry = mock(Address.class);
        AddressSpace space = mock(AddressSpace.class);
        AddressFactory factory = mock(AddressFactory.class);
        AddressSetView body = mock(AddressSetView.class);
        when(entry.getAddressSpace()).thenReturn(space);
        when(entry.toString(false)).thenReturn("1000");
        when(program.getAddressFactory()).thenReturn(factory);
        when(factory.getAddressSpaces()).thenReturn(new AddressSpace[0]);
        when(function.getEntryPoint()).thenReturn(entry);
        when(function.getBody()).thenReturn(body);
        DecompileResults result = mock(DecompileResults.class);
        HighFunction high = mock(HighFunction.class);
        LocalSymbolMap symbols = mock(LocalSymbolMap.class);
        HighSymbol symbol = mock(HighSymbol.class);
        when(symbol.getName()).thenReturn("iVar1");
        when(symbol.getDataType()).thenReturn(IntegerDataType.dataType);
        when(symbols.getSymbols()).thenAnswer(i -> List.of(symbol).iterator());
        when(high.getLocalSymbolMap()).thenReturn(symbols);
        when(result.decompileCompleted()).thenReturn(true);
        when(result.getHighFunction()).thenReturn(high);
        AtomicInteger calls = new AtomicInteger();
        Map<String, Object> facts = FunctionFacts.build(program, function,
            new FunctionFacts.Options(Set.of("decompiler_symbols"), false, 0, 3, false), f -> {
                calls.incrementAndGet(); return result;
            });
        assertEquals(1, calls.get());
        assertEquals(List.of(Map.of("name", "iVar1", "type", "int", "storage", "")), facts.get("decompiler_symbols"));
        assertFalse(facts.containsKey("decompiled_code"));
    }
}
