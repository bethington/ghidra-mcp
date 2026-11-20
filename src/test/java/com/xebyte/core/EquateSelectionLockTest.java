package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import org.junit.Test;
import java.util.*;
import java.util.concurrent.Callable;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/** Program-dependent selection must happen inside the injected strategy, for every action. */
public class EquateSelectionLockTest {
    private static final class GuardedStrategy extends DirectThreadingStrategy {
        boolean inside;
        int writes;
        Runnable before = () -> {};
        @Override public <T> T executeWrite(Program p, String name, Callable<T> action) throws Exception {
            writes++;
            return super.executeWrite(p, name, () -> {
                inside = true;
                try { before.run(); return action.call(); }
                finally { inside = false; }
            });
        }
    }
    @Test public void everyActionSelectsAndMutatesUnderInjectedStrategy() throws Exception {
        GuardedStrategy strategy = new GuardedStrategy();
        Program program = mock(Program.class);
        EquateTable table = mock(EquateTable.class);
        Listing listing = mock(Listing.class);
        Address address = new GenericAddressSpace("ram",32,AddressSpace.TYPE_RAM,0).getAddress(0x1000);
        Instruction instruction = mock(Instruction.class);
        Equate eq = mock(Equate.class);
        when(program.getEquateTable()).thenAnswer(i -> { assertTrue("equate selection escaped write lock",strategy.inside); return table; });
        when(program.getListing()).thenAnswer(i -> { assertTrue("instruction selection escaped write lock",strategy.inside); return listing; });
        when(listing.getInstructionAt(address)).thenReturn(instruction);
        when(instruction.getAddress()).thenReturn(address);
        when(instruction.getNumOperands()).thenReturn(1);
        when(instruction.getOpObjects(0)).thenReturn(new Object[]{new Scalar(8,3)});
        when(table.getEquates(address,0)).thenReturn(List.of());
        when(table.getEquate("A")).thenAnswer(i -> { assertTrue(strategy.inside); return eq; });
        when(table.getEquates()).thenAnswer(i -> List.of(eq).iterator());
        when(eq.getName()).thenReturn("A"); when(eq.getValue()).thenReturn(3L);
        when(eq.getReferences()).thenReturn(new EquateReference[0]);
        doAnswer(i -> { assertTrue("apply escaped lock",strategy.inside); return null; }).when(eq).addReference(address,0);
        doAnswer(i -> { assertTrue("rename escaped lock",strategy.inside); return null; }).when(eq).renameEquate("B");
        doAnswer(i -> { assertTrue("remove escaped lock",strategy.inside); return true; }).when(table).removeEquate("A");
        ListingService service = new ListingService(mock(ProgramProvider.class), strategy);
        assertTrue(service.setEquate("apply","A","3",address,0,null,null,false,1000,program) instanceof Response.Ok);
        assertTrue(service.setEquate("rename","A",null,null,-1,null,"B",false,1000,program) instanceof Response.Ok);
        assertTrue(service.setEquate("remove","A",null,null,-1,null,null,true,1000,program) instanceof Response.Ok);
        assertEquals(3,strategy.writes);
        verify(eq).addReference(address,0); verify(eq).renameEquate("B"); verify(table).removeEquate("A");
    }
    @Test public void staleTypedFunctionIsRefusedUnderLock() {
        GuardedStrategy strategy = new GuardedStrategy();
        Program program = mock(Program.class);
        Function function = mock(Function.class);
        FunctionManager manager = mock(FunctionManager.class);
        when(function.getProgram()).thenReturn(program);
        when(program.getFunctionManager()).thenAnswer(i -> { assertTrue(strategy.inside); return manager; });
        ListingService service = new ListingService(mock(ProgramProvider.class),strategy);
        Response r = service.setEquate("apply","A","3",null,-1,function,null,false,1000,program);
        assertTrue(r.toJson(),r instanceof Response.Err);
        assertEquals(1,strategy.writes);
        verify(program,never()).getListing(); verify(program,never()).getEquateTable();
    }
}
