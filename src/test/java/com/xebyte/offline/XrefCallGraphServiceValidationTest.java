package com.xebyte.offline;

import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.core.XrefCallGraphService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import junit.framework.TestCase;

import java.util.Set;

import static org.mockito.Mockito.*;

/**
 * Graceful-degradation coverage for XrefCallGraphService (~1.3K LOC, previously no behavioral
 * tests). With a stub provider and no program loaded, every program-scoped tool must return a
 * clean error rather than throw — these assert the "No program loaded" contract and that the
 * methods don't NPE when invoked without a binary.
 */
public class XrefCallGraphServiceValidationTest extends TestCase {

    private XrefCallGraphService xref;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        xref = new XrefCallGraphService(ServiceFactory.stubProvider(), ts);
    }

    private static void assertNoProgram(Response r) {
        assertNotNull("method returned null instead of an error Response", r);
        assertTrue("expected a graceful 'No program loaded' error, got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }

    public void testGetXrefsToDegradesGracefully() {
        assertNoProgram(xref.getXrefsTo("0x401000", 0, 100, ""));
    }

    public void testGetXrefsFromDegradesGracefully() {
        assertNoProgram(xref.getXrefsFrom("0x401000", 0, 100, ""));
    }

    public void testGetFunctionJumpTargetsDegradesGracefully() {
        assertNoProgram(xref.getFunctionJumpTargets("FUN_00401000", 0, 100));
    }

    public void testProgramNotFoundWhenNamedProgramMissing() {
        Response r = xref.getXrefsTo("0x401000", 0, 100, "Nonexistent.dll");
        assertTrue("expected program-not-found error, got: " + r.toJson(),
                r.toJson().contains("Program not found: Nonexistent.dll"));
    }

    public void testGetFunctionCallersFallsBackToCallingFunctions() {
        Program program = mock(Program.class);
        ProgramProvider provider = mock(ProgramProvider.class);
        ThreadingStrategy ts = new NoopThreadingStrategy();
        XrefCallGraphService service = new XrefCallGraphService(provider, ts);
        FunctionManager fm = mock(FunctionManager.class);
        Function target = mock(Function.class);
        Function caller = mock(Function.class);
        Address entry = mock(Address.class);
        ReferenceManager refMgr = mock(ReferenceManager.class);
        ReferenceIterator refIter = mock(ReferenceIterator.class);
        SymbolTable symbolTable = mock(SymbolTable.class);
        SymbolIterator symbolIter = mock(SymbolIterator.class);
        Symbol symbol = mock(Symbol.class);

        when(provider.getCurrentProgram()).thenReturn(program);
        when(program.getFunctionManager()).thenReturn(fm);
        when(program.getReferenceManager()).thenReturn(refMgr);
        when(program.getSymbolTable()).thenReturn(symbolTable);
        when(symbolTable.getSymbols("target")).thenReturn(symbolIter);
        when(symbolIter.hasNext()).thenReturn(true, false);
        when(symbolIter.next()).thenReturn(symbol);
        when(symbol.getSymbolType()).thenReturn(SymbolType.FUNCTION);
        when(symbol.getAddress()).thenReturn(entry);
        when(fm.getFunctionAt(entry)).thenReturn(target);
        when(target.getEntryPoint()).thenReturn(entry);
        when(refMgr.getReferencesTo(entry)).thenReturn(refIter);
        when(refIter.hasNext()).thenReturn(false);
        when(target.getCallingFunctions(null)).thenReturn(Set.of(caller));
        when(caller.getName()).thenReturn("caller_func");
        when(caller.getEntryPoint()).thenReturn(entry);
        when(entry.toString()).thenReturn("00100000");

        Response r = service.getFunctionCallers("target", "", 0, 10, "");

        assertTrue(r instanceof Response.Text);
        assertTrue(((Response.Text) r).content().contains("caller_func @ 00100000"));
    }
}
