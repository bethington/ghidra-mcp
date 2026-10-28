package com.xebyte.offline;

import com.xebyte.core.partition.PartitionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Offline tests for {@link PartitionContext} eligibility scanning.
 */
public class PartitionContextTest {

    @Test
    public void scanEligibilityCountsMissingInstructionsSeparatelyFromThunks() {
        Program program = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        Listing listing = mock(Listing.class);
        when(program.getFunctionManager()).thenReturn(fm);
        when(program.getListing()).thenReturn(listing);

        Function external = mock(Function.class);
        Function thunk = mock(Function.class);
        Function noInsn = mock(Function.class);
        Function ok = mock(Function.class);

        Address extAddr = mock(Address.class);
        Address thunkAddr = mock(Address.class);
        Address missingAddr = mock(Address.class);
        Address okAddr = mock(Address.class);

        when(external.isExternal()).thenReturn(true);
        when(external.isThunk()).thenReturn(false);
        when(external.getEntryPoint()).thenReturn(extAddr);

        when(thunk.isExternal()).thenReturn(false);
        when(thunk.isThunk()).thenReturn(true);
        when(thunk.getEntryPoint()).thenReturn(thunkAddr);

        when(noInsn.isExternal()).thenReturn(false);
        when(noInsn.isThunk()).thenReturn(false);
        when(noInsn.getEntryPoint()).thenReturn(missingAddr);

        when(ok.isExternal()).thenReturn(false);
        when(ok.isThunk()).thenReturn(false);
        when(ok.getEntryPoint()).thenReturn(okAddr);

        when(listing.getInstructionAt(missingAddr)).thenReturn(null);
        when(listing.getInstructionAt(okAddr)).thenReturn(mock(Instruction.class));

        FunctionIterator it = mock(FunctionIterator.class);
        when(fm.getFunctions(true)).thenReturn(it);
        when(it.hasNext()).thenReturn(true, true, true, true, false);
        when(it.next()).thenReturn(external, thunk, noInsn, ok);

        PartitionContext.EligibilityScan scan = PartitionContext.scanEligibility(program);
        assertEquals(4, scan.totalFunctions());
        assertEquals(2, scan.externalOrThunk());
        assertEquals(1, scan.noInstructionAtEntry());
        assertEquals(1, scan.eligible());
    }
}
